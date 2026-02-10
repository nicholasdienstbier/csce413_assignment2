#!/usr/bin/env python3
"""Minimal HTTP honeypot - looks like Apache, logs all requests."""

import json
import logging
import os
import socket
import threading
from datetime import datetime

LOG_PATH = "/app/logs/honeypot.log"
os.makedirs("/app/logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()],
)
log = logging.getLogger("honeypot")

FAKE_PAGE = b"""HTTP/1.1 200 OK\r
Server: Apache/2.4.54 (Ubuntu)\r
Content-Type: text/html\r
\r
<html><body><h1>It works!</h1><p>Apache/2.4.54 (Ubuntu)</p></body></html>"""


def handle(conn, addr):
    ip, port = addr
    try:
        data = conn.recv(1024).decode("utf-8", errors="replace")
        first_line = data.splitlines()[0] if data else ""
        log.info(json.dumps({
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "src_ip": ip,
            "src_port": port,
            "request": first_line,
        }))
        conn.sendall(FAKE_PAGE)
    except Exception:
        pass
    finally:
        conn.close()


if __name__ == "__main__":
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 80))
    srv.listen(32)
    log.info("Honeypot listening on port 80")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=[conn, addr], daemon=True).start()