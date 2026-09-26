"""Deliberately vulnerable FRONT proxy for the Expect / obfuscation desync lab (class 5).

The edge tier. It recognizes Transfer-Encoding STRICTLY: only the exact canonical
spelling `Transfer-Encoding: chunked` (one header, colon + single space, value exactly
"chunked") is honored as chunked. ANY obfuscation (tab separator, space-before-colon,
"xchunked", a duplicate TE header, odd casing beyond the name) is NOT recognized, and
the edge falls back to Content-Length. The backend honors those obfuscations, so an
obfuscated Transfer-Encoding desyncs exactly this edge (CL.TE).

It frames the body accordingly, forwards the raw bytes to a pooled keep-alive upstream
(one connection across clients, serialized), and blocks /admin at the edge. A request
smuggled inside a CL-framed body poisons the shared socket and the next client's
request receives the smuggled response.

Raw-socket relay on purpose; generic vulnerable-lab edge.
"""

import os
import re
import socket
import threading

HOST = "0.0.0.0"
PORT = int(os.environ.get("FRONT_PORT", "80"))
BACKEND_HOST = os.environ.get("BACKEND_HOST", "backend")
BACKEND_PORT = int(os.environ.get("BACKEND_PORT", "5000"))
UPSTREAM_READ_TIMEOUT = float(os.environ.get("UPSTREAM_READ_TIMEOUT", "8"))

_lock = threading.Lock()
_upstream = None
_up_buf = b""  # bytes already read from upstream past the last response (carry-over)
_TE_LINE = re.compile(rb"(?i)^transfer-encoding\s*:")

BLOCK_BODY = (
    "<!doctype html><html><head><title>403 Forbidden</title></head>"
    "<body><h1>403 Forbidden</h1><p>Blocked by the edge proxy. The admin console is "
    "restricted at the edge.</p></body></html>"
)


def _front_resp(status_line, body):
    body_bytes = body.encode()
    headers = [
        status_line, "Server: RedAmonEdge/1.0", "Via: 1.1 redamon-edge",
        "X-Edge-Proxy: redamon-edge", "Content-Type: text/html; charset=utf-8",
        f"Content-Length: {len(body_bytes)}", "Connection: keep-alive",
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
    global _upstream, _up_buf
    try:
        if _upstream is not None:
            _upstream.close()
    except OSError:
        pass
    _upstream = None
    _up_buf = b""


def _read_headers(buf, conn):
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return None, buf
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head + b"\r\n\r\n", rest


def _path(head):
    parts = head.split(b"\r\n", 1)[0].decode("latin-1", "replace").split(" ")
    return parts[1] if len(parts) > 1 else "/"


def _canonical_te(head):
    """True only for the EXACT canonical chunked spelling: one TE header, value
    exactly 'chunked' after a ': ' separator. Any obfuscation returns False."""
    te = [l for l in head.split(b"\r\n") if _TE_LINE.match(l)]
    return len(te) == 1 and te[0].strip().lower() == b"transfer-encoding: chunked"


def _content_length(head):
    for line in head.split(b"\r\n")[1:]:
        if re.match(rb"(?i)^content-length\s*:", line):
            try:
                return int(line.split(b":", 1)[1].strip())
            except ValueError:
                return 0
    return 0


def _read_chunked(rest, conn):
    """Consume a canonical chunked body from the client; return (consumed, leftover)."""
    consumed = b""
    buf = rest
    while True:
        while b"\r\n" not in buf:
            c = conn.recv(4096)
            if not c:
                return consumed + buf, b""
            buf += c
        size_line, sep, buf = buf.partition(b"\r\n")
        consumed += size_line + sep
        try:
            size = int(size_line.strip().split(b";")[0], 16)
        except ValueError:
            return consumed + buf, b""
        if size == 0:
            while b"\r\n" not in buf:
                c = conn.recv(4096)
                if not c:
                    break
                buf += c
            trailer, sep2, buf = buf.partition(b"\r\n")
            consumed += trailer + sep2
            return consumed, buf
        while len(buf) < size + 2:
            c = conn.recv(4096)
            if not c:
                return consumed + buf, b""
            buf += c
        consumed += buf[:size + 2]
        buf = buf[size + 2:]


def _read_cl(rest, conn, length):
    buf = rest
    while len(buf) < length:
        c = conn.recv(4096)
        if not c:
            break
        buf += c
    return buf[:length], buf[length:]


def _stamp(head):
    lines = head.split(b"\r\n")
    return b"\r\n".join([lines[0], b"Via: 1.1 redamon-edge", b"X-Edge-Proxy: redamon-edge"] + lines[1:])


def _read_one_response(up):
    """Read exactly one HTTP response from upstream by Content-Length, CARRYING OVER
    any extra bytes (the start of the next queued response) so a desync's second
    response is not lost. That carry-over is what makes queue poisoning observable
    regardless of response timing."""
    global _up_buf
    up.settimeout(UPSTREAM_READ_TIMEOUT)
    buf = _up_buf
    while b"\r\n\r\n" not in buf:
        d = up.recv(4096)
        if not d:
            raise ConnectionError("upstream closed")
        buf += d
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
        d = up.recv(4096)
        if not d:
            break
        body += d
    _up_buf = body[length:]  # keep the start of the next response for the next read
    return _stamp(head) + b"\r\n\r\n" + body[:length]


def handle(conn, addr):
    conn.settimeout(30)
    leftover = b""
    try:
        while True:
            head, rest = _read_headers(leftover, conn)
            if head is None:
                return
            if _path(head).startswith("/admin"):
                conn.sendall(_front_resp("HTTP/1.1 403 Forbidden", BLOCK_BODY))
                leftover = rest
                continue
            # STRICT: honor chunked only in the exact canonical form; else Content-Length.
            if _canonical_te(head):
                body, leftover = _read_chunked(rest, conn)
            else:
                body, leftover = _read_cl(rest, conn, _content_length(head))
            raw = head + body
            with _lock:
                try:
                    up = _get_upstream()
                    up.sendall(raw)
                    resp = _read_one_response(up)
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
    print(f"[edge] listening on {HOST}:{PORT} -> {BACKEND_HOST}:{BACKEND_PORT} "
          f"(strict canonical TE; CL fallback; blocks /admin)", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
