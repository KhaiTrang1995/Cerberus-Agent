"""Deliberately vulnerable FRONT proxy for the CL.0 request smuggling lab.

The edge tier. Like a real reverse proxy it STREAMS the request: it forwards the
headers to a pooled keep-alive upstream immediately and then relays the body as it
arrives, rather than buffering the whole body first. That streaming is what makes
the paused-request oracle observable through the edge: on a CL.0 endpoint the
backend answers before the body is sent, and that early answer reaches the client.

It frames by Content-Length and pools ONE upstream connection across clients
(serialized), so a request smuggled inside a CL.0 carrier body poisons the shared
front->back socket and the NEXT client's request receives the smuggled response.

It also blocks /admin at the edge (403). The only way to the backend's /admin is to
smuggle past this check via the CL.0 desync.

Raw-socket relay on purpose; generic vulnerable-lab edge.
"""

import os
import socket
import threading
import time

HOST = "0.0.0.0"
PORT = int(os.environ.get("FRONT_PORT", "80"))
BACKEND_HOST = os.environ.get("BACKEND_HOST", "backend")
BACKEND_PORT = int(os.environ.get("BACKEND_PORT", "5000"))
UPSTREAM_READ_TIMEOUT = float(os.environ.get("UPSTREAM_READ_TIMEOUT", "6"))
CLIENT_BODY_TIMEOUT = float(os.environ.get("CLIENT_BODY_TIMEOUT", "3"))

_lock = threading.Lock()
_upstream = None

BLOCK_BODY = (
    "<!doctype html><html><head><title>403 Forbidden</title></head>"
    "<body><h1>403 Forbidden</h1><p>Blocked by the edge proxy. The admin console is "
    "restricted at the edge.</p></body></html>"
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
    parts = lines[0].decode("latin-1", "replace").split(" ")
    method = parts[0] if parts else ""
    path = parts[1] if len(parts) > 1 else "/"
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers[k.strip().lower().decode("latin-1", "replace")] = v.strip().decode("latin-1", "replace")
    return method, path, headers


def _stamp_edge_headers(head):
    lines = head.split(b"\r\n")
    return b"\r\n".join([lines[0], b"Via: 1.1 redamon-edge", b"X-Edge-Proxy: redamon-edge"] + lines[1:])


def _read_one_response(up):
    """Read exactly one HTTP response from upstream (by Content-Length). Raises
    socket.timeout if the backend never answers within the read window (the
    'back-end waited for a body' signal for the paused oracle)."""
    up.settimeout(UPSTREAM_READ_TIMEOUT)
    buf = b""
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
    return _stamp_edge_headers(head) + b"\r\n\r\n" + body[:length]


def _forward_body(client, up, prebody, cl):
    """Stream up to `cl` body bytes from the client to upstream. If the client pauses
    (sends no body), time out quickly and stop -- that is the paused case."""
    remaining = cl
    if prebody:
        take = prebody[:remaining]
        try:
            up.sendall(take)
        except OSError:
            return
        remaining -= len(take)
    client.settimeout(CLIENT_BODY_TIMEOUT)
    while remaining > 0:
        try:
            d = client.recv(min(4096, remaining))
        except (socket.timeout, OSError):
            return
        if not d:
            return
        try:
            up.sendall(d)
        except OSError:
            return
        remaining -= len(d)


def handle(conn, addr):
    conn.settimeout(30)
    try:
        leftover = b""
        while True:
            head, rest = _read_headers(leftover, conn)
            if head is None:
                return
            leftover = b""
            method, path, headers = _parse(head)
            if path.startswith("/admin"):
                conn.sendall(_front_resp("HTTP/1.1 403 Forbidden", BLOCK_BODY))
                continue
            try:
                cl = int(headers.get("content-length", "0"))
            except ValueError:
                cl = 0
            with _lock:
                try:
                    up = _get_upstream()
                    up.sendall(head)
                    t = threading.Thread(target=_forward_body, args=(conn, up, rest, cl), daemon=True)
                    t.start()
                    resp = _read_one_response(up)
                    t.join(timeout=1)
                except (socket.timeout,):
                    _reset_upstream()
                    conn.sendall(_front_resp("HTTP/1.1 504 Gateway Timeout",
                                             "upstream did not answer (backend waited for a body)"))
                    continue
                except (ConnectionError, OSError):
                    _reset_upstream()
                    conn.sendall(_front_resp("HTTP/1.1 502 Bad Gateway", "upstream error"))
                    continue
            conn.sendall(resp)
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
    print(f"[edge] listening on {HOST}:{PORT} -> {BACKEND_HOST}:{BACKEND_PORT} "
          f"(streaming; Content-Length framing; blocks /admin)", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
