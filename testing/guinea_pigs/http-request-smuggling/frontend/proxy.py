"""Deliberately vulnerable FRONT proxy for the HTTP request smuggling lab.

This is the edge tier. It determines where one request ends using
`Content-Length` ONLY and forwards the raw client bytes (both the Content-Length
AND the Transfer-Encoding headers, unchanged) to a POOLED keep-alive connection
to the backend. Because the backend honors Transfer-Encoding instead, the two
tiers disagree on the request boundary -> CL.TE desync.

It also enforces an EDGE access control: a direct request whose path starts with
`/admin` is blocked with 403. The only way to reach the backend's `/admin` is to
smuggle a request past this check inside the body of an allowed request, so it is
never seen as a request line by this proxy.

Written as a raw socket relay on purpose (a real proxy would normalize framing).
Generic vulnerable-lab edge; nothing scanner-specific.
"""

import os
import socket
import threading

HOST = "0.0.0.0"
PORT = int(os.environ.get("FRONT_PORT", "8080"))
BACKEND_HOST = os.environ.get("BACKEND_HOST", "backend")
BACKEND_PORT = int(os.environ.get("BACKEND_PORT", "5000"))
UPSTREAM_READ_TIMEOUT = float(os.environ.get("UPSTREAM_READ_TIMEOUT", "8"))

_lock = threading.Lock()
_upstream = None

BLOCK_BODY = (
    "<!doctype html><html><head><title>403 Forbidden</title></head>"
    "<body><h1>403 Forbidden</h1>"
    "<p>Blocked by the edge proxy. The admin console is restricted at the edge.</p>"
    "</body></html>"
)


def _front_resp(status_line, body):
    body_bytes = body.encode()
    headers = [
        status_line,
        "Server: RedAmonEdge/1.0",
        "Via: 1.1 redamon-edge",
        "X-Edge-Proxy: redamon-edge",
        "Content-Type: text/html; charset=utf-8",
        f"Content-Length: {len(body_bytes)}",
        "Connection: keep-alive",
    ]
    return ("\r\n".join(headers) + "\r\n\r\n").encode() + body_bytes


def _connect_upstream():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(UPSTREAM_READ_TIMEOUT)
    s.connect((BACKEND_HOST, BACKEND_PORT))
    return s


def _get_upstream():
    global _upstream
    if _upstream is None:
        _upstream = _connect_upstream()
    return _upstream


def _reset_upstream():
    global _upstream
    try:
        if _upstream is not None:
            _upstream.close()
    except OSError:
        pass
    _upstream = None


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


def _read_cl_body(rest, conn, length):
    buf = rest
    while len(buf) < length:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf[:length], buf[length:]


def _stamp_edge_headers(head):
    """Insert the edge's own hop headers after the status line so recon can see a
    proxy sits in front of a distinct backend (Via / X-Edge-Proxy)."""
    lines = head.split(b"\r\n")
    status = lines[0]
    rest = lines[1:]
    stamped = [status, b"Via: 1.1 redamon-edge", b"X-Edge-Proxy: redamon-edge"] + rest
    return b"\r\n".join(stamped)


def _read_one_response(up):
    """Read exactly one HTTP response from upstream (parse Content-Length)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = up.recv(4096)
        if not chunk:
            raise ConnectionError("upstream closed")
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                length = int(line.partition(b":")[2].strip())
            except ValueError:
                length = 0
    body = rest
    while len(body) < length:
        chunk = up.recv(4096)
        if not chunk:
            break
        body += chunk
    return _stamp_edge_headers(head) + b"\r\n\r\n" + body[:length], body[length:]


def handle(conn, addr):
    conn.settimeout(30)
    leftover = b""
    try:
        while True:
            head, rest = _read_headers(leftover, conn)
            if head is None:
                return
            method, path, headers = _parse(head)
            # FRONT uses Content-Length only (the vulnerability).
            try:
                length = int(headers.get("content-length", "0"))
            except ValueError:
                length = 0
            body, leftover = _read_cl_body(rest, conn, length)

            # Edge access control: block /admin for DIRECT requests only. A
            # smuggled /admin (inside a body) never appears as a request line here.
            if path.startswith("/admin"):
                conn.sendall(_front_resp("HTTP/1.1 403 Forbidden", BLOCK_BODY))
                continue

            raw = head + body  # forward BYTES AS-IS (CL and TE headers unchanged)
            with _lock:
                try:
                    up = _get_upstream()
                    up.sendall(raw)
                    resp, _extra = _read_one_response(up)
                except (ConnectionError, OSError, socket.timeout):
                    _reset_upstream()
                    conn.sendall(_front_resp("HTTP/1.1 504 Gateway Timeout",
                                             "<html><body>upstream timeout</body></html>"))
                    continue
            conn.sendall(resp)
    except (ConnectionError, OSError, socket.timeout):
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
    print(f"[front] listening on {HOST}:{PORT} -> {BACKEND_HOST}:{BACKEND_PORT} "
          f"(honors Content-Length; blocks /admin at edge)", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
