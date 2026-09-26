"""Deliberately vulnerable BACK-END for the HTTP request smuggling lab.

This is the back tier of a two-tier HTTP deployment. It speaks HTTP/1.1 with
keep-alive and honors `Transfer-Encoding: chunked` (it reads the chunked body and
IGNORES `Content-Length` when both are present). Paired with a front proxy that
does the opposite (honors Content-Length), that disagreement is a classic CL.TE
desync.

It is written as a raw socket server on purpose: a framework (Flask/gunicorn)
would normalize framing and refuse the ambiguous requests the lab needs. Nothing
here is target-specific to any scanner; it is a standard vulnerable-lab origin.

Routes:
  GET  /            landing page (reveals a two-tier deployment)
  GET  /admin       INTERNAL ONLY: returns the flag. The front proxy blocks this
                    path for direct requests; it is only reachable by smuggling a
                    request past the front tier.
  POST /            echo-ish 200 used as the smuggling carrier request
  everything else   404
"""

import os
import socket
import threading

HOST = "0.0.0.0"
PORT = int(os.environ.get("BACKEND_PORT", "5000"))
FLAG = os.environ.get("HRS_FLAG", "REDAMON_HRS{cl_te_desync_reached_the_backend}")

LANDING = (
    "<!doctype html><html><head><title>Orders API (backend)</title></head>"
    "<body><h1>Orders API</h1>"
    "<p>Public backend application server. Behind the edge proxy.</p>"
    "<p>Internal operators: the admin console lives at <code>/admin</code> "
    "(restricted at the edge).</p>"
    "</body></html>"
)

ADMIN_BODY = (
    "<!doctype html><html><head><title>Admin Console</title></head>"
    "<body><h1>Admin Console (internal)</h1>"
    "<p>If you can read this without coming through the edge, the request "
    "boundary between the edge and this backend disagreed.</p>"
    f"<p>FLAG: {FLAG}</p>"
    "</body></html>"
)


def _resp(status_line, body, extra=None):
    body_bytes = body.encode() if isinstance(body, str) else body
    headers = [
        status_line,
        "Server: gunicorn-lab/backend",
        "X-Backend-Server: orders-api",
        "Content-Type: text/html; charset=utf-8",
        f"Content-Length: {len(body_bytes)}",
        "Connection: keep-alive",
    ]
    if extra:
        headers.extend(extra)
    return ("\r\n".join(headers) + "\r\n\r\n").encode() + body_bytes


def _read_headers(buf, conn):
    """Return (header_bytes, rest) reading more from conn until CRLFCRLF."""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return None, buf
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head + b"\r\n\r\n", rest


def _parse(head):
    lines = head.split(b"\r\n")
    request_line = lines[0].decode("latin-1", "replace")
    parts = request_line.split(" ")
    method = parts[0] if parts else ""
    path = parts[1] if len(parts) > 1 else "/"
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers[k.strip().lower().decode("latin-1", "replace")] = v.strip().decode("latin-1", "replace")
    return method, path, headers


def _read_chunked_body(rest, conn):
    """Consume a chunked body from `rest` (+ more from conn). Return leftover bytes
    after the terminating 0-length chunk. Ignores Content-Length by design."""
    buf = rest
    while True:
        # need a chunk-size line
        while b"\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return buf
            buf += chunk
        size_line, _, buf = buf.partition(b"\r\n")
        try:
            size = int(size_line.strip().split(b";")[0], 16)
        except ValueError:
            # malformed chunk size -> stop consuming, treat rest as leftover
            return buf
        if size == 0:
            # consume the trailing CRLF after the last chunk if present
            while b"\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            _, _, buf = buf.partition(b"\r\n")
            return buf
        while len(buf) < size + 2:
            chunk = conn.recv(4096)
            if not chunk:
                return buf
            buf += chunk
        buf = buf[size + 2:]  # skip chunk data + trailing CRLF


def _read_cl_body(rest, conn, length):
    buf = rest
    while len(buf) < length:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf[length:]


def handle(conn, addr):
    leftover = b""
    try:
        while True:
            head, rest = _read_headers(leftover, conn)
            if head is None:
                return
            method, path, headers = _parse(head)
            # Framing: honor Transfer-Encoding over Content-Length (the desync).
            te = headers.get("transfer-encoding", "").lower()
            if "chunked" in te:
                leftover = _read_chunked_body(rest, conn)
            elif "content-length" in headers:
                try:
                    length = int(headers["content-length"])
                except ValueError:
                    length = 0
                leftover = _read_cl_body(rest, conn, length)
            else:
                leftover = rest

            # Route
            if path.startswith("/admin"):
                conn.sendall(_resp("HTTP/1.1 200 OK", ADMIN_BODY))
            elif path == "/" and method == "GET":
                conn.sendall(_resp("HTTP/1.1 200 OK", LANDING))
            elif method == "POST":
                conn.sendall(_resp("HTTP/1.1 200 OK", "<html><body>ok</body></html>"))
            elif path == "/" or method == "GET":
                conn.sendall(_resp("HTTP/1.1 200 OK", LANDING))
            else:
                conn.sendall(_resp("HTTP/1.1 404 Not Found", "<html><body>not found</body></html>"))
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
    print(f"[backend] listening on {HOST}:{PORT} (honors Transfer-Encoding)", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
