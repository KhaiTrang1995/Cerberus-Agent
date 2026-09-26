# Expect / Obfuscation Desync — Guinea Pig (end-to-end validation target)

A deliberately vulnerable target for the **Expect / obfuscation** leg of the RedAmon
`http_request_smuggling` agent skill (class 5). It exercises the two class-5 ideas:
the **byte-mutation fuzzing** of framing headers, and the **`Expect: 100-continue`**
0.CL trigger.

```
   client ──▶  strict-TE EDGE  ──(pooled keep-alive)──▶  BACKEND origin
              :9096 (80)                                 :9097 (5000)
              honors ONLY canonical                      honors TE LIBERALLY (tab, xchunked, dup)
              "Transfer-Encoding: chunked"               + Expect:100-continue => CL.0
              CL-fallback for any obfuscation            serves the flag at /admin
              blocks /admin at the edge
```

Two desync vectors, one flag (reached through the edge-blocked `/admin`):

1. **Obfuscated Transfer-Encoding (the fuzzing target).** The edge recognizes chunked
   ONLY in the exact canonical spelling `Transfer-Encoding: chunked`. Any obfuscation
   (tab separator, space-before-colon, `xchunked`, a duplicate TE header) is not
   recognized, so the edge falls back to Content-Length while the backend still honors
   it as chunked -> CL.TE. A canonical TE is **safe** (both agree); only a mutated
   spelling desyncs, which is exactly what the byte-mutation loop is meant to discover.
2. **`Expect: 100-continue` (the Expect trigger).** The backend answers a request
   carrying `Expect: 100-continue` without reading its body (a broken 100-continue
   handler = CL.0), so the promised body becomes the next request.

## Endpoints

| URL | Result |
| --- | --- |
| `http://<edge>/` | 200 landing (stamped `Via: 1.1 redamon-edge`) |
| `http://<edge>/admin` | **403** — blocked at the edge |
| `http://<backend-direct>/admin` | 200 + FLAG (distinct backend `X-Backend-Server: upload-api`) |

Flag: `REDAMON_HRS{expect_or_obfuscated_te_flips_the_parser}`

## Run

```bash
docker compose up -d --build
python3 tests/verify_expect.py      # control + canonical-safe + obfuscated-TE + Expect
```

A successful queue-poison leaves the pooled edge->backend socket off by one, so the
self-test restarts the edge container between the two terminal desync vectors. The
edge carries over unconsumed upstream bytes, so the smuggled second response is served
to the follow-up regardless of response timing.

**Known behavior (realistic, not a bug).** Because the edge->backend socket is pooled
and shared, the FIRST successful desync poisons it, so a follow-up issued after a
*later* probe can receive the earlier probe's queued `/admin` response. During a rapid
fuzzing sweep this can make the agent attribute the desync to more mutations than truly
flip the parser (e.g. reporting a case-variant like `ChUnKeD` alongside the genuinely
obfuscated `xchunked`). Only `xchunked`, a tab separator, a space-before-colon, and a
duplicated TE header actually flip this edge; canonical `Transfer-Encoding: chunked`
and case-only variants are honored and stay safe. Restart the edge between probes (as
the self-test does) for clean per-mutation attribution.

## Point RedAmon at it

```bash
docker network connect redamon-network exp-guinea-edge
docker network connect redamon-network exp-guinea-backend
```

Create a project with **target = `http://exp-guinea-edge`**, enable the **HTTP Request
Smuggling / Desync** skill (OFF by default), and ask the agent to fuzz the framing
headers / test `Expect: 100-continue` and reach the edge-blocked `/admin`.

## Files

| File | Role |
| --- | --- |
| `frontend/proxy.py` | strict-canonical-TE edge; CL fallback; blocks `/admin`; pools one upstream with carry-over |
| `backend/app.py` | origin with liberal TE + Expect CL.0; serves the flag at `/admin` |
| `docker-compose.yml` | edge `:9096`, direct backend `:9097` |
| `tests/verify_expect.py` | self-check: canonical-safe + obfuscated-TE + Expect smuggle |
