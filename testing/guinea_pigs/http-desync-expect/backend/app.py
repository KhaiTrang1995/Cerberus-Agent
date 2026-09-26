"""Deliberately vulnerable BACK-END for the Expect / obfuscation desync lab (class 5).

Back tier of a two-tier HTTP deployment, HTTP/1.1 keep-alive. Two deliberate quirks:

  1. It honors Transfer-Encoding LIBERALLY: any `transfer-encoding` header whose value
     merely CONTAINS "chunked" (tab-separated, "xchunked", duplicated, odd casing) is
     read as chunked. The strict edge in front recognizes only the canonical spelling,
     so an obfuscated Transfer-Encoding flips exactly one parser -> CL.TE desync. This
     is the target the byte-mutation fuzzing loop is meant to find.
  2. On `Expect: 100-continue` it answers WITHOUT reading the body (a broken
     100-continue handler), so the promised body becomes the next request -> a CL.0
     desync triggered by the Expect header alone.

Raw socket server on purpose. Generic vulnerable-lab origin; nothing scanner-specific.
"""

import os
import re
import socket
import threading

HOST = "0.0.0.0"
PORT = int(os.environ.get("BACKEND_PORT", "5000"))
FLAG = os.environ.get("HRS_FLAG", "REDAMON_HRS{expect_or_obfuscated_te_flips_the_parser}")

LANDING = (
    "<!doctype html><html><head><title>Upload API (backend)</title></head>"
    "<body><h1>Upload API</h1><p>Public backend application server behind the edge.</p>"
    "<p>Internal operators: admin console at <code>/admin</code> (restricted at the "
    "edge). Submit endpoint at <code>/submit</code>.</p></body></html>"
)
ADMIN_BODY = (
    "<!doctype html><html><head><title>Admin Console</title></head>"
    "<body><h1>Admin Console (internal)</h1>"
    "<p>Reached without coming through the edge: the edge and this backend disagreed on "
    "the request framing (an obfuscated Transfer-Encoding, or an Expect header the edge "
    "mishandled).</p>"
    f"<p>FLAG: {FLAG}</p></body></html>"
)

_TE_RE = re.compile(rb"(?i)^transfer-encoding\s*:(.*)$")


def _resp(status_line, body, extra=None):
    body_bytes = body.encode() if isinstance(body, str) else body
    headers = [
        status_line, "Server: gunicorn-lab/backend", "X-Backend-Server: upload-api",
        "Content-Type: text/html; charset=utf-8",
        f"Content-Length: {len(body_bytes)}", "Connection: keep-alive",
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
    return method, path, lines[1:]


def _has_expect_100(header_lines):
    for line in header_lines:
        if re.match(rb"(?i)^expect\s*:", line) and b"100-continue" in line.lower():
            return True
    return False


def _liberal_chunked(header_lines):
    for line in header_lines:
        m = _TE_RE.match(line)
        if m and b"chunked" in m.group(1).lower():
            return True
    return False


def _content_length(header_lines):
    for line in header_lines:
        if re.match(rb"(?i)^content-length\s*:", line):
            try:
                return int(line.split(b":", 1)[1].strip())
            except ValueError:
                return 0
    return 0


def _read_chunked(rest, conn):
    buf = rest
    while True:
        while b"\r\n" not in buf:
            c = conn.recv(4096)
            if not c:
                return buf
            buf += c
        size_line, _, buf = buf.partition(b"\r\n")
        try:
            size = int(size_line.strip().split(b";")[0], 16)
        except ValueError:
            return buf
        if size == 0:
            while b"\r\n" not in buf:
                c = conn.recv(4096)
                if not c:
                    break
                buf += c
            _, _, buf = buf.partition(b"\r\n")
            return buf
        while len(buf) < size + 2:
            c = conn.recv(4096)
            if not c:
                return buf
            buf += c
        buf = buf[size + 2:]


def _read_cl(rest, conn, length):
    buf = rest
    while len(buf) < length:
        c = conn.recv(4096)
        if not c:
            break
        buf += c
    return buf[length:]


def handle(conn, addr):
    leftover = b""
    try:
        while True:
            head, rest = _read_headers(leftover, conn)
            if head is None:
                return
            method, path, hlines = _parse(head)

            if _has_expect_100(hlines):
                # broken 100-continue: answer WITHOUT reading the body (CL.0)
                leftover = rest
            elif _liberal_chunked(hlines):
                leftover = _read_chunked(rest, conn)
            else:
                leftover = _read_cl(rest, conn, _content_length(hlines))

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
    print(f"[backend] listening on {HOST}:{PORT} (liberal TE + Expect CL.0)", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
