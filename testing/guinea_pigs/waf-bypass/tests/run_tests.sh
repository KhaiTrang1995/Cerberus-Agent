#!/usr/bin/env bash
# Self-test: assert the class-13 differential holds (edge blocks a signature probe that
# the origin serves). Requires the lab up: docker compose up -d --build
set -u
EDGE="https://172.25.0.91"
ORIGIN="https://172.25.0.92"
PROBE="?rdmnwafprobe=../../../../etc/passwd"
fail=0

code() { curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$1"; }

edge_probe=$(code "$EDGE/$PROBE")
origin_probe=$(code "$ORIGIN/$PROBE")
edge_clean=$(code "$EDGE/?rdmnwafprobe=hello")

echo "edge(probe)=$edge_probe  origin(probe)=$origin_probe  edge(clean)=$edge_clean"

[ "$edge_probe" = "403" ]  || { echo "FAIL: edge should block the probe (403)"; fail=1; }
[ "$origin_probe" = "200" ] || { echo "FAIL: origin should serve the probe (200)"; fail=1; }
[ "$edge_clean" = "200" ]  || { echo "FAIL: edge should serve clean traffic (200)"; fail=1; }

if [ "$fail" = "0" ]; then echo "PASS: WAF blocked-vs-allowed differential holds"; fi
exit $fail
