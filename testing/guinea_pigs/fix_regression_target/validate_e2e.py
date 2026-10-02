"""End-to-end assertions for the fix-regression lab, run entirely through MCP.

Run after a full recon of the lab:  python3 validate_e2e.py <projectId>

Every check is exact, read-only Cypher through query_graph (tenant-scoped by the
server). Exit 0 only when every assertion holds.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mcp_client as mcp  # noqa: E402

if len(sys.argv) != 2:
    sys.exit("usage: validate_e2e.py <projectId>   (an IP-mode project over 192.88.95.10 + .20)")
P = sys.argv[1]
A, B = "192.88.95.10", "192.88.95.20"
PORT_CHECKS = ["admin_port_exposed", "database_exposed", "redis_no_auth",
               "kubernetes_api_exposed", "smtp_open_relay"]


def q(cypher):
    out, err = mcp.call("query_graph", {"projectId": P, "cypher": cypher})
    if err or not isinstance(out, dict):
        raise RuntimeError(f"query failed: {out}")
    return out.get("records", [])


results = []


def check(name, ok, detail):
    results.append((name, bool(ok), detail))


def vulns(where):
    return q(f"""MATCH (v:Vulnerability) WHERE v.source = 'security_check' AND {where}
                 OPTIONAL MATCH (i:IP)-[:HAS_VULNERABILITY]->(v)
                 RETURN v.id AS id, v.type AS type, v.severity AS severity,
                        v.matched_ip AS ip, v.port AS port, v.matched_at AS matched_at,
                        v.name AS name, collect(i.address) AS from_ips""")


mcp.init()

# ---- POSITIVE: the port/service checks that never ran now fire --------------
redis = vulns(f"v.type = 'redis_no_auth' AND v.matched_ip = '{A}'")
check("P1 redis_no_auth on .10:6379 is critical, linked from its IP",
      len(redis) == 1 and redis[0]["severity"] == "critical" and redis[0]["port"] == 6379
      and redis[0]["from_ips"] == [A] and redis[0]["matched_at"] == f"{A}:6379", redis)

db = vulns(f"v.type = 'database_exposed' AND v.matched_ip = '{A}'")
by_port = {r["port"]: r for r in db}
check("P2 database_exposed: MySQL 3306 high + Redis 6379 medium, two distinct nodes",
      set(by_port) == {3306, 6379} and by_port[3306]["severity"] == "high"
      and by_port[6379]["severity"] == "medium" and len({r["id"] for r in db}) == 2, db)

admin = vulns(f"v.type = 'admin_port_exposed' AND v.matched_ip = '{A}'")
check("P3 admin_port_exposed: SSH on port 22",
      len(admin) == 1 and admin[0]["port"] == 22 and admin[0]["severity"] == "medium", admin)

k8s_a = q(f"""MATCH (v:Vulnerability {{type: 'kubernetes_api_exposed'}})
              WHERE v.url CONTAINS '{A}' OR v.matched_ip = '{A}'
              RETURN v.severity AS severity, v.url AS url""")
check("P4 kubernetes_api_exposed on .10 (real APIVersions on 8443) is critical",
      len(k8s_a) == 1 and k8s_a[0]["severity"] == "critical" and ":8443" in (k8s_a[0]["url"] or ""), k8s_a)

ipapi = q(f"""MATCH (v:Vulnerability {{type: 'ip_api_exposed'}})
              WHERE v.matched_ip = '{A}' OR v.url CONTAINS '{A}'
              RETURN v.severity AS severity, v.name AS name""")
check("P5 ip_api_exposed on .10 (401 JSON + Bearer) is MEDIUM, not high",
      len(ipapi) == 1 and ipapi[0]["severity"] == "medium"
      and ipapi[0]["name"] == "Authenticated API Endpoint Exposed on IP", ipapi)

orphans = q("""MATCH (v:Vulnerability) WHERE v.source = 'security_check'
               AND v.type IN $types AND NOT (()-[:HAS_VULNERABILITY]->(v))
               RETURN v.type AS type, v.port AS port""".replace("$types", json.dumps(PORT_CHECKS)))
check("P6 no port/service finding is left unlinked", orphans == [], orphans)

# ---- NEGATIVE CONTROLS: no new false positive -------------------------------
k8s_b = q(f"""MATCH (v:Vulnerability {{type: 'kubernetes_api_exposed'}})
              WHERE v.url CONTAINS '{B}' OR v.matched_ip = '{B}'
              RETURN v.url AS url""")
check("N1 NO kubernetes_api_exposed on .20 (page that only SAYS 'kind')", k8s_b == [], k8s_b)

b_ports = vulns(f"v.matched_ip = '{B}' AND v.type IN {json.dumps(PORT_CHECKS)}")
check("N2 NO port/service finding on .20 (only 443/8080 open, no service ports)", b_ports == [], b_ports)

dns = q("""MATCH (v:Vulnerability) WHERE v.source = 'security_check'
           AND v.type IN ['spf_missing', 'dmarc_missing', 'dnssec_missing', 'zone_transfer']
           RETURN v.type AS type""")
check("N3 NO DNS finding in IP mode (no domain to check)", dns == [], dns)

# ---- nmap per IP: a product links to its own host's port only ----------------
tech = q("""MATCH (i:IP)-[:HAS_PORT]->(p:Port)-[:HAS_TECHNOLOGY]->(t:Technology)
            RETURN i.address AS ip, p.number AS port, t.name AS tech ORDER BY ip, port""")
def on(word):
    return {(r["ip"], r["port"]) for r in tech if word in (r["tech"] or "").lower()}


check("C3 shared port 8080: nginx only on .10:8080, Apache only on .20:8080 (per-IP link)",
      on("nginx") == {(A, 8080)} and on("apache") == {(B, 8080)}, tech)
check("C3b OpenSSH and MySQL only on .10",
      on("openssh") == {(A, 22)} and on("mysql") == {(A, 3306)}, tech)

scanned = q(f"""MATCH (p:Port {{ip_address: '{A}'}}) WHERE p.number IN [22, 3306]
                RETURN p.number AS port, p.nmap_scanned AS nmap, p.product AS product""")
check("C2 nmap scanned .10 to completion (22 and 3306 enriched)",
      len(scanned) == 2 and all(r["nmap"] and r["product"] for r in scanned), scanned)

# ---- NORMAL GRAPH: no breaking change ---------------------------------------
ips = [r["address"] for r in q("MATCH (i:IP) RETURN i.address AS address ORDER BY address")]
check("G1 both IP nodes present", ips == [A, B], ips)

ports = {r["ip"]: sorted(r["ports"]) for r in q(
    "MATCH (i:IP)-[:HAS_PORT]->(p:Port) RETURN i.address AS ip, collect(p.number) AS ports")}
check("G2 ports linked to the right IP: .10={22,80,3306,6379,8080,8443}, .20={443,8080}",
      ports.get(A) == [22, 80, 3306, 6379, 8080, 8443] and ports.get(B) == [443, 8080], ports)

baseurls = sorted(r["url"] for r in q("MATCH (b:BaseURL) RETURN b.url AS url"))
check("G3 BaseURLs for .10 (http) and .20 (https)",
      any(u.startswith(f"http://{A}") for u in baseurls)
      and any(u.startswith(f"https://{B}") for u in baseurls), baseurls)

# Which lab host a crawler reaches first varies from run to run; what must hold
# is that a crawl turns the lab's linked pages into Endpoints under their BaseURL.
crawled = {r["base"]: set(r["paths"]) for r in q(
    "MATCH (b:BaseURL)-[:HAS_ENDPOINT]->(e:Endpoint) RETURN b.url AS base, collect(e.path) AS paths")}
check("G4 the crawl wrote the lab's linked pages as Endpoints (/about, /login, /api/status)",
      any({"/about", "/login", "/api/status"} <= paths for paths in crawled.values()),
      {b: sorted(p) for b, p in crawled.items()})

nmapped = q("MATCH (p:Port) WHERE p.nmap_scanned = true RETURN p.ip_address AS ip, p.number AS port, p.product AS product")
check("G5 nmap enriched Port nodes (version detection ran)", len(nmapped) >= 1, nmapped)

normal = sorted({r["type"] for r in q(
    "MATCH (v:Vulnerability) WHERE v.source = 'security_check' RETURN v.type AS type")})
check("G6 the long-standing checks still fire (direct-IP / header checks)",
      any(t.startswith("direct_ip") or t.startswith("missing_") for t in normal), normal)

status, _ = mcp.call("get_recon_status", {"projectId": P})
check("G7 recon finished successfully",
      isinstance(status, dict) and status.get("status") in ("completed", "complete", "success", "idle")
      and not status.get("error"), {k: status.get(k) for k in ("status", "error", "currentPhase")}
      if isinstance(status, dict) else status)

# ---- report -----------------------------------------------------------------
w = max(len(n) for n, _, _ in results)
for name, ok, detail in results:
    print(f"{'PASS' if ok else 'FAIL'}  {name.ljust(w)}")
    if not ok:
        print(f"      detail: {json.dumps(detail, default=str)[:600]}")
passed = sum(ok for _, ok, _ in results)
print(f"\n{passed}/{len(results)} assertions passed")
sys.exit(0 if passed == len(results) else 1)
