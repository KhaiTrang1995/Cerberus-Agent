"""Deliberately vulnerable BACK-END for the CL.0 request smuggling lab.

The back tier of a two-tier HTTP deployment. It speaks HTTP/1.1 with keep-alive.
The vulnerability is CL.0: for a set of SERVER-GENERATED endpoints (a health check,
static assets, a directory redirect) it answers WITHOUT reading the request body,
even when a Content-Length promises one. Those unread body bytes stay in the socket
buffer and are parsed as the START of the next request on that connection.

Normal application endpoints DO read the Content-Length body, which gives the
paused-request oracle a clean differential (early answer on a CL.0 endpoint vs
waiting on a normal one).

Raw socket server on purpose (a framework would normalize framing). Generic
vulnerable-lab origin; nothing scanner-specific.

Routes:
  GET  /            landing page (reads body if any)
  POST /submit      normal app endpoint: READS the Content-Length body, then answers
  GET|POST /health  CL.0: answers 200 WITHOUT reading the body (health check)
  GET|POST /static/*   CL.0: answers 200 WITHOUT reading the body (static asset)
  GET|POST /assets  CL.0: answers a 301 redirect WITHOUT reading the body
  GET  /admin       INTERNAL ONLY: the flag. The edge blocks this path directly; it
                    is only reachable by smuggling past the edge via the CL.0 desync.
"""

import os
import socket
import threading

HOST = "0.0.0.0"
PORT = int(os.environ.get("BACKEND_PORT", "5000"))
FLAG = os.environ.get("HRS_FLAG", "REDAMON_HRS{cl_0_desync_body_ignored_by_backend}")

LANDING = (
    "<!doctype html><html><head><title>Files API (backend)</title></head>"
    "<body><h1>Files API</h1><p>Public backend application server behind the edge.</p>"
    "<p>Internal operators: the admin console is at <code>/admin</code> "
    "(restricted at the edge). Health probe at <code>/health</code>.</p></body></html>"
)
ADMIN_BODY = (
    "<!doctype html><html><head><title>Admin Console</title></head>"
    "<body><h1>Admin Console (internal)</h1>"
    "<p>Reached without coming through the edge: the edge and this backend disagreed "
    "on whether the carrier request had a body (CL.0).</p>"
    f"<p>FLAG: {FLAG}</p></body></html>"
)

# Endpoints that answer WITHOUT reading the body == the CL.0 candidate set.
CL0_PREFIXES = ("/health", "/static", "/favicon.ico", "/robots.txt", "/assets")


def _resp(status_line, body, extra=None):
    body_bytes = body.encode() if isinstance(body, str) else body
    headers = [
        status_line,
        "Server: gunicorn-lab/backend",
        "X-Backend-Server: files-api",
        "Content-Type: text/html; charset=utf-8",
        f"Content-Length: {len(body_bytes)}",
        "Connection: keep-alive",
    ]
    if extra:
        headers.extend(extra)
    return ("\r\n".join(headers) + "\r\n\r\n").encode() + body_bytes


def _read_headers(buf, conn):
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return None, buf
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head + b"\r\n\r\n", rest


def _parse(head):
    lines = head.split(b"\r\n")
    parts = lines[0].decode("latin-1", "replace").split(" ")
    method = parts[0] if parts else ""
    path = parts[1] if len(parts) > 1 else "/"
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers[k.strip().lower().decode("latin-1", "replace")] = v.strip().decode("latin-1", "replace")
    return method, path, headers


def _read_cl_body(rest, conn, length):
    buf = rest
    while len(buf) < length:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf[length:]


def _is_cl0(path):
    return any(path == p or path.startswith(p) for p in CL0_PREFIXES)


def handle(conn, addr):
    leftover = b""
    try:
        while True:
            head, rest = _read_headers(leftover, conn)
            if head is None:
                return
            method, path, headers = _parse(head)

            if _is_cl0(path):
                # CL.0: answer WITHOUT consuming the body. The unread body (rest +
                # whatever else the peer sent) stays as the next request's bytes.
                leftover = rest
                if path.startswith("/assets"):
                    conn.sendall(_resp("HTTP/1.1 301 Moved Permanently", "",
                                       extra=["Location: /static/"]))
                else:
                    conn.sendall(_resp("HTTP/1.1 200 OK", "OK"))
                continue

            # Normal endpoints DO read the Content-Length body.
            try:
                length = int(headers.get("content-length", "0"))
            except ValueError:
                length = 0
            leftover = _read_cl_body(rest, conn, length)

            if path.startswith("/admin"):
                conn.sendall(_resp("HTTP/1.1 200 OK", ADMIN_BODY))
            elif path == "/submit":
                conn.sendall(_resp("HTTP/1.1 200 OK", "<html><body>submitted</body></html>"))
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
    print(f"[backend] listening on {HOST}:{PORT} (CL.0 on {CL0_PREFIXES})", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
