"""HTTP/1.1 BACK-END for the HTTP/2 downgrade smuggling lab (class 3).

Ordinary h1 keep-alive origin: it honors Content-Length and serves the flag at
/admin. It is the h1 upstream that the h2 edge downgrades to. The desync comes from
the edge copying the attacker's (lying) content-length verbatim during the h2->h1
rewrite, so this backend just has to behave like a normal h1 server.

Raw socket server on purpose. Generic vulnerable-lab origin.
"""

import os
import re
import socket
import threading

HOST = "0.0.0.0"
PORT = int(os.environ.get("BACKEND_PORT", "5000"))
FLAG = os.environ.get("HRS_FLAG", "REDAMON_HRS{h2_downgrade_crlf_injection}")

LANDING = (
    "<!doctype html><html><head><title>API Gateway (backend)</title></head>"
    "<body><h1>API Gateway</h1><p>Public h1 backend behind the HTTP/2 edge.</p>"
    "<p>Internal operators: admin console at <code>/admin</code> (restricted at the "
    "edge).</p></body></html>"
)
ADMIN_BODY = (
    "<!doctype html><html><head><title>Admin Console</title></head>"
    "<body><h1>Admin Console (internal)</h1>"
    "<p>Reached without coming through the edge routing: the h2 edge copied a lying "
    "content-length into the h1 rewrite, so the backend framed the request wrong.</p>"
    f"<p>FLAG: {FLAG}</p></body></html>"
)


def _resp(status_line, body):
    body_bytes = body.encode() if isinstance(body, str) else body
    headers = [
        status_line, "Server: gunicorn-lab/backend", "X-Backend-Server: api-gateway",
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
            path = (head.split(b"\r\n", 1)[0].decode("latin-1", "replace").split(" ") + ["/"])[1]
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
            elif path == "/" or True:
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
    print(f"[backend] h1 listening on {HOST}:{PORT}", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
