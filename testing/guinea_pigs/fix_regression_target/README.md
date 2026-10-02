# Fix-regression guinea pig

End-to-end proof, through a real IP-mode recon run, that the recon fixes work
and that nothing that worked before broke. Every positive check has a negative
control next to it, so a green run proves both.

```bash
docker compose up -d --build        # 192.88.95.10 + 192.88.95.20, no host ports
docker compose down
```

## Running the proof

1. **A full recon over MCP.** Create an IP-mode, `internal` project over both
   addresses with all six `scanModules`, `naabuCustomPorts`
   `22,80,443,3306,6379,8080,8443`, `nmapEnabled`, `securityCheckEnabled` and
   `nucleiAutoUpdateTemplates: false`. Run `preflight_scope_check`, then
   `start_recon`.
2. **Assert the graph:** `python3 validate_e2e.py <projectId>`. Nineteen
   read-only Cypher assertions through MCP `query_graph`; exit 0 only when all
   hold. The MCP token is read from the repo `.env` and never printed.
3. **Old vs fixed, side by side:** `./run_direct_checks.sh [old-git-ref]` runs
   the pre-fix and the fixed security-check code against the live lab.
   The default ref, `c2794cb6`, is the last commit before the fixes.

## Hosts and what each port proves

| Host | Port | Serves | Proves |
|---|---|---|---|
| `.10` | 22 | SSH banner | `admin_port_exposed` (SSH) fires |
| `.10` | 3306 | a complete MySQL v10 greeting | `database_exposed` (MySQL, high) fires; nmap names it MySQL 8.0.32 |
| `.10` | 6379 | `PING` → `+PONG`, no auth | `redis_no_auth` (critical) + `database_exposed` (Redis, medium) fire |
| `.10` | 8443 | TLS, `GET /api` = a real `APIVersions` document | `kubernetes_api_exposed` (critical) fires |
| `.10` | 80 | landing, `/about`, `/login`, JS bundle, `/api/*` | the normal graph is still built: IP, Ports, BaseURL, Endpoints, Technology, header and direct-IP findings |
| `.10` | 80 | `GET /api` = 401 JSON + `WWW-Authenticate: Bearer` | `ip_api_exposed` is **medium** ("Authenticated API…"), not the old blanket high |
| `.10` / `.20` | 8080 | nginx on `.10`, Apache on `.20`: one port number, two products | nmap links each Technology to **its own** IP's port, not the first host with that port |
| `.20` | 443 | TLS, `GET /api` = HTML that only *mentions* "kind" and "apiVersion" | **negative:** no `kubernetes_api_exposed` (the old bare-substring matcher fired here) |
| `.20` | 443 | `GET /` sets an HttpOnly CSRF cookie **and** a flagless session cookie in one response | `session_no_httponly` fires for the session cookie (the old check let the CSRF cookie's HttpOnly hide it) |

The port/service checks (`admin_port_exposed`, `database_exposed`,
`redis_no_auth`, `kubernetes_api_exposed`) never ran before the fix: the loop
iterated `port_scan`'s section names instead of its IPs. Each finding must now
be its own node per IP and port, linked from its IP.

`.20` serves only 443 and 8080, so it must carry no port/service finding. The
run is IP mode, so it must carry no SPF/DMARC/DNSSEC finding either: the scan's
root, `ip-targets.<project_id>`, is in no DNS zone.

## What the end-to-end runs found

The lab found two real defects, both now fixed with regression tests:

- **IP mode reported `dmarc_missing`** for its synthetic `ip-targets.<id>` root,
  a name in no DNS zone. DNS checks no longer run on that root
  (`recon/tests/test_regression_ip_mode_dns_false_positive.py`).
- **No MITRE CVE year could be downloaded.** Upstream CVE2CAPEC now publishes
  each year only as `CVE-<year>.jsonl.gz`, so the plain URL 404'd for every
  year, and a missing year was re-requested on every scan. Years now come from
  the gzip copy, and a year upstream lacks is retried once per TTL
  (`recon/tests/test_regression_mitre_upstream_gzip.py`).

## Lab gotchas

- **The HTTP servers drop idle connections after 10 s**, as nginx does. Without
  that, nmap's vuln-category HTTP scripts outlast its 300 s host timeout and
  `.10` is never fully scanned.
- **Log a request defensively.** An error logged before a request line parses
  (a malformed probe, a timed-out read) has no `command` or `path`; reading them
  raised inside the logger and aborted the connection instead of answering 400.
- **Make each fake service look like the real one**, or nmap mislabels it: a
  truncated MySQL greeting left the product blank, and a Redis that answered
  `+OK` to everything was read as popa3d.
- **Which lab host a crawler reaches varies between runs.** The crawl assertion
  therefore checks that the linked pages became Endpoints under some lab
  BaseURL, not under a fixed one.
- **The TLS cert is self-signed.** JS recon verifies TLS and logs an `SSLError`
  for 443/8443; the same bundle is served over plain HTTP on `.10:80`.
- **Grep these logs with `grep -a`.** nmap's probes put raw bytes in request
  paths; plain `grep` switches to binary mode and silently stops printing.
- **192.88.95.0/24 belongs to this lab.** Other labs hold 192.88.96–99.0/24,
  and 192.88.100.0/24 is real address space.
- **Recreate, do not restart, after editing `server.py`.** Snap Docker binds a
  file by inode.

> These hosts imitate exposed services so the checks have something real to
> answer. Run them only on a local Docker host; they publish no host ports.
