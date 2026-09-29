"""Circuit-breaker lab: one image, two roles.

ROLE=live      192.88.96.10 - a healthy target with a real surface (pages, a JS
               bundle naming endpoints, /api/*, missing security headers). Recon
               finds real findings here; they are what the prune must KEEP when
               the sibling host degrades.

ROLE=deadtcp   192.88.96.20 - a host whose ports ACCEPT the TCP connect (so the
               port scan sees them open and the host enters scope) and then
               immediately CLOSE the socket with no HTTP response. Every
               requests-based probe (security_checks, js, graphql, ai_surface,
               the crawler skip gates) raises requests.exceptions.ConnectionError,
               which HostHealth counts as a connection failure. After 3 the host
               breaker opens: the remaining probes are skipped, the host is added
               to recon_skipped_hosts, and coverage is reported as degraded.

Neither host is in any DNS zone; the project is created in IP mode over the two
addresses. 192.88.96.0/24 is the deprecated 6to4 relay prefix (same trick as the
other recon labs): Python's SSRF guard treats it as global so probes go through,
but nothing leaves the host.
"""
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROLE = os.environ.get("ROLE", "live")
PORTS = [int(p) for p in os.environ.get("PORTS", "80").split(",")]

INDEX = b"""<!doctype html>
<html><head><title>CB lab</title></head>
<body>
<h1>Circuit-breaker lab - healthy host</h1>
<ul>
  <li><a href="/about">About</a></li>
  <li><a href="/login">Login</a></li>
  <li><a href="/api/status">API status</a></li>
</ul>
<script src="/static/app.js"></script>
</body></html>
"""

ABOUT = b"""<!doctype html>
<html><head><title>About</title></head>
<body><p>Healthy host. Nothing sensitive here.</p>
<script src="/static/app.js"></script></body></html>
"""

# A JS bundle that names first-party endpoints so js_recon has real work.
APP_JS = b"""// app bundle
const API_BASE = "/api";
fetch(API_BASE + "/status");
fetch(API_BASE + "/users");
const cfg = { endpoint: "/api/v1/orders", ws: "/socket" };
export { cfg };
"""

LOGIN = b"""<!doctype html>
<html><head><title>Login</title></head>
<body><form method="post" action="/login">
<input name="user"><input name="pass" type="password">
<button>Sign in</button></form></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "cblab/1.0"

    def log_message(self, fmt, *args):
        sys.stdout.write(f"[{ROLE}:{self.server.server_port}] {self.client_address[0]} "
                         f"{self.command} {self.path}\n")
        sys.stdout.flush()

    def _send(self, status, body, ctype="text/html; charset=utf-8"):
        # Deliberately omit security headers so security_checks finds real
        # findings on the healthy host (X-Frame-Options, CSP, Referrer-Policy...).
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            return self._send(200, INDEX)
        if path == "/about":
            return self._send(200, ABOUT)
        if path == "/login":
            return self._send(200, LOGIN)
        if path == "/static/app.js":
            return self._send(200, APP_JS, "application/javascript")
        if path == "/robots.txt":
            return self._send(200, b"User-agent: *\nDisallow: /admin\n", "text/plain")
        if path.startswith("/api/"):
            return self._send(200, b'{"ok": true}', "application/json")
        return self._send(404, b"not found", "text/plain")

    do_HEAD = do_GET

    def do_OPTIONS(self):
        self._send(204, b"")

    def do_POST(self):
        self._send(200, b'{"ok": true}', "application/json")


def _dead_listener(port: int):
    """Accept a connection then close it at once: the peer sees the socket go
    away before any HTTP bytes, which requests raises as ConnectionError."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(64)
    sys.stdout.write(f"[deadtcp:{port}] accepting-then-closing\n")
    sys.stdout.flush()
    while True:
        try:
            conn, addr = srv.accept()
        except OSError:
            continue
        sys.stdout.write(f"[deadtcp:{port}] {addr[0]} connect -> drop\n")
        sys.stdout.flush()
        try:
            # Force an immediate RST rather than a graceful FIN so the client
            # gets a hard reset (ECONNRESET) on read.
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            __import__("struct").pack("ii", 1, 0))
            conn.close()
        except OSError:
            pass


def main():
    if ROLE == "deadtcp":
        threads = [threading.Thread(target=_dead_listener, args=(p,), daemon=True)
                   for p in PORTS]
        for t in threads:
            t.start()
        print(f"[deadtcp] listening on {PORTS} (accept-then-reset)", flush=True)
        for t in threads:
            t.join()
        return
    servers = [ThreadingHTTPServer(("0.0.0.0", port), Handler) for port in PORTS]
    for srv in servers[1:]:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"[{ROLE}] listening on {PORTS}", flush=True)
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
