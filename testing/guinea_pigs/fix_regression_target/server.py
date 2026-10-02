"""Fix-regression lab: one image, two roles, several ports per host.

Proves, end to end through a real IP-mode recon run, the recon fixes that a
standard pipeline reaches, WITH negative controls so a passing run also proves
no new false positive and no breaking change.

ROLE=rich   192.88.95.10  the positive host. Open service ports the port/service
            security checks (which used to never run at all) now fire on:
              22    open TCP            -> admin_port_exposed  (SSH)
              3306  open TCP            -> database_exposed     (MySQL, high)
              6379  real PING -> +PONG  -> redis_no_auth (critical) + database_exposed
              8443  TLS, GET /api is a
                    real APIVersions doc -> kubernetes_api_exposed (critical)
              80    a normal web surface (landing, /about, /login, a JS bundle
                    naming endpoints, /api/*) so a full recon still builds the
                    usual graph (IP, Ports, BaseURL, Endpoints, Technology,
                    http_probe header findings, js endpoints) -- the no-breaking
                    -change control. /api answers 401 JSON + WWW-Authenticate:
                    Bearer, so ip_api_exposed is MEDIUM (a protected API on a
                    bare IP), not the old blanket "high".

ROLE=knegative 192.88.95.20  the negative-control host.
              443   TLS, GET /api returns an HTML page whose prose contains the
                    words "kind" and "apiVersion". The OLD kubernetes check fired
                    on a bare 'kind' substring; the fixed matcher needs a real
                    kube-apiserver document, so kubernetes_api_exposed must be
                    ABSENT for this host. GET / is a normal landing page (so
                    direct_ip_https still fires, unchanged) that sets TWO
                    cookies in one response: an HttpOnly CSRF cookie and a
                    flagless session cookie, at the exact URL the session-cookie
                    check requests.

192.88.95.0/24: 192.88.0.0/16 is globally-classified (not is_private), so
recon's SSRF/ip_filter guard lets probes through, but nothing leaves the host --
the scan runs network_mode=host and reaches the lab over the local bridge route.
Neither host is in any DNS zone; the project is created in IP mode over the two
addresses.
"""
import os
import socket
import ssl
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROLE = os.environ.get("ROLE", "rich")
HTTP_PORTS = [int(p) for p in os.environ.get("HTTP_PORTS", "").split(",") if p]
TLS_PORTS = [int(p) for p in os.environ.get("TLS_PORTS", "").split(",") if p]
OPEN_TCP_PORTS = [int(p) for p in os.environ.get("OPEN_TCP_PORTS", "").split(",") if p]
REDIS_PORTS = [int(p) for p in os.environ.get("REDIS_PORTS", "").split(",") if p]

CERT = "/app/tls/cert.pem"
KEY = "/app/tls/key.pem"

INDEX = b"""<!doctype html>
<html><head><title>Fix-regression lab</title></head>
<body>
<h1>Fix-regression lab</h1>
<ul>
  <li><a href="/about">About</a></li>
  <li><a href="/login">Login</a></li>
  <li><a href="/api/status">API status</a></li>
  <li><a href="/api/users">API users</a></li>
</ul>
<script src="/static/app.js"></script>
</body></html>
"""

ABOUT = b"""<!doctype html>
<html><head><title>About</title></head>
<body><p>A healthy host with a real surface.</p>
<script src="/static/app.js"></script></body></html>
"""

# Names first-party endpoints so js_recon has real work, like the other labs.
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

# Host B /api: mentions k8s words in PROSE but is NOT a kube-apiserver document.
# The fixed matcher must not fire on it.
K8S_WORD_TRAP = (b"<!doctype html><html><head><title>Docs</title></head><body>"
                 b"<h1>Our API</h1><p>Please be so kind as to read the docs. "
                 b"Every object has a kind and an apiVersion field.</p></body></html>")

# Host A :8443 /api: a real kube-apiserver discovery document.
K8S_REAL = b'{"kind":"APIVersions","versions":["v1"],"serverAddressByClientCIDRs":[]}'


class RichHandler(BaseHTTPRequestHandler):
    """Host A. Plain HTTP on :80 and the k8s-positive doc on :8443/api."""

    server_version = "fixreglab/1.0"
    # Drop an idle or half-sent connection after 10 s, as nginx's
    # client_header_timeout does. Without it nmap's vuln-category HTTP scripts
    # (http-slowloris-check waits for the server to drop such connections) run
    # past nmap's 300 s host timeout and the host is never fully scanned.
    timeout = 10

    def log_message(self, fmt, *args):
        # getattr: an error logged before the request line parsed (a malformed
        # probe, a read that timed out) has no command or path yet, and raising
        # here aborts the connection instead of answering 400/408.
        headers = getattr(self, "headers", None)
        agent = (headers.get("User-Agent", "-") if headers else "-")[:60]
        sys.stdout.write(f"[{ROLE}:{self.server.server_port}] {self.client_address[0]} "
                         f"{getattr(self, 'command', None) or '-'} "
                         f"{getattr(self, 'path', None) or (fmt % args)} ua={agent!r}\n")
        sys.stdout.flush()

    def _send(self, status, body, ctype="text/html; charset=utf-8", extra=None):
        # Security headers are deliberately omitted so http_probe finds the usual
        # missing-header findings (the normal-graph control).
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        port = self.server.server_port
        path = self.path.split("?", 1)[0]

        if port == 8443:
            # Only /api is the kube-apiserver document; everything else is plain.
            if path == "/api":
                return self._send(200, K8S_REAL, "application/json")
            return self._send(200, INDEX)

        if path in ("/", "/index.html"):
            return self._send(200, INDEX)
        if path == "/about":
            return self._send(200, ABOUT)
        if path == "/login":
            # TWO Set-Cookie headers in ONE response: a session cookie with no
            # flags next to an HttpOnly CSRF cookie. The old cookie check read
            # the merged header, so the CSRF cookie's HttpOnly hid the session
            # cookie's missing one. Exercised directly against this live response.
            return self._send(200, LOGIN, extra=[
                ("Set-Cookie", "csrftoken=abc123; Path=/; HttpOnly"),
                ("Set-Cookie", "sessionid=xyz789; Path=/"),
            ])
        if path == "/static/app.js":
            return self._send(200, APP_JS, "application/javascript")
        if path == "/robots.txt":
            return self._send(200, b"User-agent: *\nDisallow: /admin\n", "text/plain")
        # ip_api_exposed probes /api first: a protected JSON API on the bare IP.
        # 401 + a JSON body + Bearer challenge -> medium (not the old blanket high).
        if path == "/api":
            return self._send(401, b'{"error":"authentication required"}',
                              "application/json", extra=[("WWW-Authenticate", "Bearer")])
        if path.startswith("/api/"):
            return self._send(200, b'{"ok": true}', "application/json")
        return self._send(404, b"not found", "text/plain")

    do_HEAD = do_GET

    def do_POST(self):
        self._send(200, b'{"ok": true}', "application/json")


class NegHandler(RichHandler):
    """Host B :443. /api is the k8s word-trap; the rest is a normal site."""

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/api":
            return self._send(200, K8S_WORD_TRAP)
        if path in ("/", "/index.html"):
            # The session-cookie check requests https://<host>/ exactly, so the
            # two-cookie response lives here: an HttpOnly CSRF cookie next to a
            # flagless session cookie. The old check read the merged header and
            # let the CSRF cookie's HttpOnly hide the session cookie's gap.
            return self._send(200, INDEX, extra=[
                ("Set-Cookie", "csrftoken=abc123; Path=/; HttpOnly"),
                ("Set-Cookie", "sessionid=xyz789; Path=/"),
            ])
        if path == "/static/app.js":
            return self._send(200, APP_JS, "application/javascript")
        return self._send(404, b"not found", "text/plain")

    do_HEAD = do_GET


def _tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    return ctx


#: Port -> the Server header that port presents, e.g. "8080=nginx/1.25.3". Both
#: hosts serve 8080 under DIFFERENT products: the case where nmap's per-host
#: technology link used to go to whichever host first had that port number.
SERVER_HEADERS = dict(
    item.split("=", 1) for item in os.environ.get("SERVER_HEADERS", "").split(";") if "=" in item)


def _serve_http(port, handler, tls):
    ident = SERVER_HEADERS.get(str(port))
    if ident:
        # version_string() is server_version + " " + sys_version.
        handler = type(f"{handler.__name__}_{port}", (handler,),
                       {"server_version": ident, "sys_version": ""})
    srv = ThreadingHTTPServer(("0.0.0.0", port), handler)
    if tls:
        srv.socket = _tls_context().wrap_socket(srv.socket, server_side=True)
    sys.stdout.write(f"[{ROLE}] {'https' if tls else 'http'} listening on :{port}\n")
    sys.stdout.flush()
    srv.serve_forever()


def _redis_listener(port):
    """Answer PING with +PONG and no auth, like an unprotected Redis."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(64)
    sys.stdout.write(f"[{ROLE}] redis-ish listening on :{port}\n")
    sys.stdout.flush()
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            continue
        threading.Thread(target=_redis_conn, args=(conn,), daemon=True).start()


def _redis_conn(conn):
    try:
        conn.settimeout(5)
        data = conn.recv(256)
        if b"PING" in data.upper():
            conn.sendall(b"+PONG\r\n")
        else:
            # A real Redis rejects an unknown command; "+OK" made nmap -sV read
            # the port as popa3d.
            conn.sendall(b"-ERR unknown command\r\n")
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _mysql_handshake():
    """A complete MySQL protocol-v10 greeting, so nmap -sV names it MySQL 8.0.32.

    A truncated greeting left the product blank and the port unidentified.
    """
    payload = (b"\x0a" + b"8.0.32\x00"                 # protocol 10, server version
               + struct.pack("<I", 42)                    # connection id
               + b"abcdefgh" + b"\x00"                    # auth-plugin-data part 1 + filler
               + struct.pack("<H", 0xffff)                 # capability flags (lower)
               + b"\xff" + struct.pack("<H", 0x0002)      # charset, status flags
               + struct.pack("<H", 0xc3ff)                 # capability flags (upper)
               + b"\x15" + b"\x00" * 10                   # auth data len + reserved
               + b"ijklmnopqrst\x00"                       # auth-plugin-data part 2
               + b"caching_sha2_password\x00")
    return struct.pack("<I", len(payload))[:3] + b"\x00" + payload


def _open_tcp_listener(port):
    """Accept and hold briefly so the connect scan sees the port open."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(64)
    sys.stdout.write(f"[{ROLE}] open-tcp listening on :{port}\n")
    sys.stdout.flush()
    # A tiny service banner on connect keeps nmap -sV from hanging the port.
    banner = {22: b"SSH-2.0-OpenSSH_8.9\r\n", 3306: _mysql_handshake()}.get(port, b"")
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            continue
        try:
            if banner:
                conn.sendall(banner)
        except OSError:
            pass
        finally:
            try:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                conn.close()
            except OSError:
                pass


def main():
    handler = NegHandler if ROLE == "knegative" else RichHandler
    threads = []
    for port in REDIS_PORTS:
        threads.append(threading.Thread(target=_redis_listener, args=(port,), daemon=True))
    for port in OPEN_TCP_PORTS:
        threads.append(threading.Thread(target=_open_tcp_listener, args=(port,), daemon=True))
    for port in TLS_PORTS:
        threads.append(threading.Thread(target=_serve_http, args=(port, handler, True), daemon=True))
    # Keep one HTTP server in the foreground; start the rest as threads.
    http_threads = HTTP_PORTS[1:]
    for port in http_threads:
        threads.append(threading.Thread(target=_serve_http, args=(port, handler, False), daemon=True))
    for t in threads:
        t.start()
    if HTTP_PORTS:
        _serve_http(HTTP_PORTS[0], handler, False)
    else:
        for t in threads:
            t.join()


if __name__ == "__main__":
    main()
