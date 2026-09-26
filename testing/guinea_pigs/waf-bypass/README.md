# WAF Bypass via Direct Origin Access — Guinea Pig (taxonomy class 13)

A signature WAF **edge** in front of an **origin** that is *also* reachable directly by
IP. The class-13 finding is the **blocked-vs-allowed differential**: a probe the edge
refuses (403) but the origin serves (200) proves the WAF can be bypassed by addressing
the origin directly.

```
 attacker ─▶  edge (WAF, 172.25.0.91:443)  ─▶  origin (172.25.0.92:443)
                 blocks signature probes         serves everything, no WAF
                 └──────────── origin also reachable directly ───────────┘
```

- **`172.25.0.91`** — the WAF edge. Returns **403** on classic signatures
  (`../`, `etc/passwd`, url-encoded `<script`, `%27`, `union select`); proxies clean
  traffic to the origin.
- **`172.25.0.92`** — the origin, directly reachable, **no WAF**. Serves 200 for every
  request, including the probes.

Both serve HTTPS with a baked self-signed cert (the recon check uses `verify=False`).
Fixed IPs on `redamon-network` so a scan/probe can be pinned to stable addresses.

## Run it

```bash
cd testing/guinea_pigs/waf-bypass
docker compose up -d --build
bash tests/run_tests.sh          # asserts edge-blocks / origin-serves
```

Tear down: `docker compose down`.

## How RedAmon detects it

`recon/helpers/security_checks.py::_waf_payload_differential` sends a canonical
WAF-signature probe as a throwaway query param to the hostname (edge) and to the origin
IP with the real Host header. When the edge blocks it and the origin serves it, it emits
a high-severity `waf_bypass` finding with `detection_method="payload_differential"`. The
finding is the differential, never the payload — this is a WAF-efficacy test.

Verified against this lab: `check_waf_bypass("172.25.0.91", "172.25.0.92")` returns the
finding (`edge_status=403; origin_status=200`).
