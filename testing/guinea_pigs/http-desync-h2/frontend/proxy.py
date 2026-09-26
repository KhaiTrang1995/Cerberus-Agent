"""Deliberately vulnerable HTTP/2 EDGE for the h2 downgrade smuggling lab (class 3).

Speaks HTTP/2 cleartext (h2c, prior knowledge) to clients and DOWNGRADES each request
to HTTP/1.1 for a pooled keep-alive backend. The bug: during the h2->h1 rewrite it
copies the client's `content-length` header VERBATIM instead of recomputing it from the
DATA frames, and forwards all DATA bytes. So a client that sends an h2 request whose
`content-length` LIES (is shorter than the DATA) makes the h1 backend read only
content-length bytes and leave the rest as the next request -> H2.CL desync.

It also blocks /admin at the edge. The only way to the backend /admin is to smuggle a
request in the DATA past the lying content-length.

Uses the `h2` library with inbound validation disabled so it accepts the malformed
(lying content-length) request a compliant server would reject. Generic vulnerable-lab
edge; nothing scanner-specific.
"""

import os
import re
import socket
import threading

import h2.config
import h2.connection
import h2.events
import h2.exceptions

HOST = "0.0.0.0"
PORT = int(os.environ.get("FRONT_PORT", "80"))
BACKEND_HOST = os.environ.get("BACKEND_HOST", "backend")
BACKEND_PORT = int(os.environ.get("BACKEND_PORT", "5000"))
UPSTREAM_READ_TIMEOUT = float(os.environ.get("UPSTREAM_READ_TIMEOUT", "8"))

_lock = threading.Lock()
_upstream = None
_up_buf = b""

BLOCK_BODY = (b"<!doctype html><html><head><title>403 Forbidden</title></head>"
              b"<body><h1>403 Forbidden</h1><p>Blocked by the edge proxy. The admin "
              b"console is restricted at the edge.</p></body></html>")


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


def _read_one_h1_response(up):
    """Read one h1 response by Content-Length, carrying over extra bytes (the start of
    the next queued response) so a desync's second response is not lost."""
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
    _up_buf = body[length:]
    status = 200
    m = re.match(rb"HTTP/1\.1 (\d{3})", head)
    if m:
        status = int(m.group(1))
    return status, body[:length]


_HOP = {"connection", "keep-alive", "proxy-connection", "transfer-encoding",
        "upgrade", "te", "host", "content-length"}


def _downgrade_and_forward(method, path, authority, headers, data):
    """Build the h1 request COPYING each h2 header value VERBATIM (no escaping), which
    is the bug: an h2 header value carrying CRLF splits the h1 request. Forward to the
    pooled backend and return (status, body)."""
    lines = [f"{method} {path} HTTP/1.1", f"Host: {authority or 'x'}"]
    for k, v in headers:
        if k.startswith(":") or k.lower() in _HOP:
            continue
        lines.append(f"{k}: {v}")  # verbatim -> CRLF in v injects new h1 headers/requests
    if data:
        lines.append(f"Content-Length: {len(data)}")
    h1 = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + data
    with _lock:
        try:
            up = _get_upstream()
            up.sendall(h1)
            return _read_one_h1_response(up)
        except (ConnectionError, OSError, socket.timeout):
            _reset_upstream()
            return 502, b"<html><body>upstream error</body></html>"


def _respond(conn, h2conn, sid, status, body, ctype=b"text/html; charset=utf-8"):
    h2conn.send_headers(sid, [
        (":status", str(status)),
        ("server", "RedAmonEdge-h2/1.0"),
        ("via", "2 redamon-edge"),
        ("x-edge-proxy", "redamon-edge-h2"),
        ("content-type", ctype.decode()),
        ("content-length", str(len(body))),
    ])
    h2conn.send_data(sid, body, end_stream=True)
    conn.sendall(h2conn.data_to_send())


def handle(conn, addr):
    conn.settimeout(30)
    config = h2.config.H2Configuration(
        client_side=False, validate_inbound_headers=False, header_encoding="latin-1")
    h2conn = h2.connection.H2Connection(config=config)
    h2conn.initiate_connection()
    conn.sendall(h2conn.data_to_send())
    streams = {}
    try:
        while True:
            data = conn.recv(65535)
            if not data:
                return
            events = h2conn.receive_data(data)
            for event in events:
                if isinstance(event, h2.events.RequestReceived):
                    streams[event.stream_id] = {"headers": list(event.headers), "data": b""}
                elif isinstance(event, h2.events.DataReceived):
                    streams.setdefault(event.stream_id, {"headers": [], "data": b""})
                    streams[event.stream_id]["data"] += event.data
                    if event.flow_controlled_length:
                        h2conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    req = streams.pop(event.stream_id, {"headers": [], "data": b""})
                    hdrs = {}
                    for k, v in req["headers"]:
                        hdrs.setdefault(k.lower(), v)
                    path = hdrs.get(":path", "/")
                    method = hdrs.get(":method", "GET")
                    authority = hdrs.get(":authority", "")
                    if path.startswith("/admin"):
                        _respond(conn, h2conn, event.stream_id, 403, BLOCK_BODY)
                    else:
                        status, body = _downgrade_and_forward(
                            method, path, authority, req["headers"], req["data"])
                        _respond(conn, h2conn, event.stream_id, status, body)
            out = h2conn.data_to_send()
            if out:
                conn.sendall(out)
    except (ConnectionError, OSError, socket.timeout, h2.exceptions.ProtocolError):
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
    print(f"[edge] h2c listening on {HOST}:{PORT} -> h1 {BACKEND_HOST}:{BACKEND_PORT} "
          f"(copies content-length verbatim; blocks /admin)", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
