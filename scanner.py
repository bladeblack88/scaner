#!/usr/bin/env python3
"""Local Wi-Fi device and camera-port scanner for Android/Termux.

Only scans the private /24 containing the phone's Wi-Fi IPv4 address.
Run on your own network or a network you are authorized to inspect.
"""
import concurrent.futures
import html
import ipaddress
import json
import re
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

PORTS = {
    80: "HTTP",
    81: "HTTP-alt",
    443: "HTTPS",
    554: "RTSP",
    8000: "Camera/DVR (possible)",
    8080: "HTTP-alt",
    8081: "HTTP-alt",
    8554: "RTSP-alt",
    8899: "Possible camera service",
    34567: "Possible DVR service",
}
MAX_WORKERS = 64
CONNECT_TIMEOUT = 0.35
HTTP_TIMEOUT = 1.0


def get_wifi_ipv4():
    """Find a private IPv4 address, preferring wlan0 on Android."""
    try:
        out = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", "wlan0"],
            capture_output=True, text=True, timeout=3
        ).stdout
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        if match:
            return ipaddress.ip_interface(f"{match.group(1)}/{match.group(2)}")
    except (OSError, subprocess.SubprocessError):
        pass

    # Fallback: inspect all interfaces and skip loopback.
    try:
        out = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"],
            capture_output=True, text=True, timeout=3
        ).stdout
        for line in out.splitlines():
            if " lo " in line:
                continue
            match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if match:
                iface = ipaddress.ip_interface(f"{match.group(1)}/{match.group(2)}")
                if iface.ip.is_private:
                    return iface
    except (OSError, subprocess.SubprocessError):
        pass

    # Last-resort route lookup; may return a VPN address on some devices.
    try:
        ip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip.connect(("192.0.2.1", 80))
        addr = ip.getsockname()[0]
        ip.close()
        iface = ipaddress.ip_interface(addr + "/24")
        if iface.ip.is_private:
            return iface
    except OSError:
        pass
    raise RuntimeError("Не удалось определить IP Wi-Fi. Подключите телефон к Wi-Fi и повторите.")


def read_http_banner(host, port, tls=False):
    """Try a tiny HTTP request and return safe identifying headers/title."""
    import ssl
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(HTTP_TIMEOUT)
    try:
        sock.connect((host, port))
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.settimeout(HTTP_TIMEOUT)
        request = f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: LocalCameraScanner/1.0\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode("ascii", "ignore"))
        data = sock.recv(4096).decode("latin-1", "replace")
        headers = data.split("\r\n\r\n", 1)[0]
        server = ""
        for line in headers.splitlines():
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()[:120]
                break
        title_match = re.search(r"<title[^>]*>(.*?)</title>", data, re.I | re.S)
        title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:120] if title_match else ""
        return {"server": server, "title": title}
    except (OSError, ssl.SSLError):
        return {}
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_rtsp(host, port):
    """Send RTSP OPTIONS; some cameras answer with an RTSP status line."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(HTTP_TIMEOUT)
    try:
        s.connect((host, port))
        s.sendall(f"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: LocalCameraScanner\r\n\r\n".encode())
        data = s.recv(1024).decode("latin-1", "replace")
        return data.startswith("RTSP/")
    except OSError:
        return False
    finally:
        s.close()


def scan_one(host):
    open_ports = []
    details = {}
    for port, label in PORTS.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        try:
            s.connect((str(host), port))
            open_ports.append({"port": port, "service": label})
        except OSError:
            pass
        finally:
            s.close()

    if not open_ports:
        return None

    for item in open_ports:
        p = item["port"]
        if p in (80, 81, 8080, 8081):
            details[str(p)] = read_http_banner(str(host), p)
        elif p == 443:
            details[str(p)] = read_http_banner(str(host), p, tls=True)
        elif p in (554, 8554):
            item["rtsp_response"] = probe_rtsp(str(host), p)

    camera_score = 0
    reasons = []
    ports = {x["port"] for x in open_ports}
    if ports.intersection({554, 8554}):
        camera_score += 3
        reasons.append("RTSP-порт")
    if ports.intersection({8000, 8899, 34567}):
        camera_score += 2
        reasons.append("порт, часто встречающийся у камер/DVR")
    if any(x.get("rtsp_response") for x in open_ports):
        camera_score += 3
        reasons.append("получен RTSP-ответ")
    for banner in details.values():
        text = (banner.get("server", "") + " " + banner.get("title", "")).lower()
        if any(word in text for word in ("camera", "ipcam", "dvr", "nvr", "webcam", "surveillance")):
            camera_score += 2
            reasons.append("похоже на веб-интерфейс камеры")

    return {
        "ip": str(host),
        "ports": open_ports,
        "http": details,
        "camera_hint": camera_score >= 2,
        "camera_reasons": reasons,
    }


def run_scan():
    iface = get_wifi_ipv4()
    # Keep the scan bounded and predictable on a phone.
    network = iface.network
    if network.prefixlen < 24:
        network = ipaddress.ip_network(f"{iface.ip}/24", strict=False)
    hosts = list(network.hosts())
    started = time.time()
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(scan_one, host) for host in hosts if host != iface.ip]
        for future in concurrent.futures.as_completed(futures):
            try:
                item = future.result()
                if item:
                    results.append(item)
            except Exception:
                pass
    results.sort(key=lambda x: tuple(int(p) for p in x["ip"].split(".")))
    return {
        "network": str(network),
        "phone_ip": str(iface.ip),
        "scanned": len(hosts) - 1,
        "duration_seconds": round(time.time() - started, 1),
        "devices": results,
        "note": "Открытый порт не доказывает, что устройство является камерой. RTSP/ONVIF могут быть отключены или закрыты.",
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if urlparse(self.path).path == "/api/scan":
            try:
                payload = json.dumps(run_scan(), ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except Exception as exc:
                payload = json.dumps({"error": str(exc)}, ensure_ascii=False).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            return
        if urlparse(self.path).path in ("/", "/index.html"):
            try:
                with open("index.html", "rb") as f:
                    payload = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except OSError:
                self.send_error(404, "index.html not found")
            return
        self.send_error(404)

    def log_message(self, fmt, *args):
        print("[web]", fmt % args)


if __name__ == "__main__":
    print("Local Camera Scanner")
    print("Откройте на этом телефоне: http://127.0.0.1:8765")
    print("Сканирование ограничено локальной частной сетью /24.")
    ThreadingHTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
