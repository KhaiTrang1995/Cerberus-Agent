"""nmap results reach the right IP and the right ports.

C3 - the nmap graph writer links a service's Technology, and an NSE finding's
     FOUND_ON / HAS_KNOWN_CVE, to the IP the entry came from, not to the first
     host that happens to have the same port open.
C4 - merge_nmap_into_port_scan never enriches a port_scan entry with another
     IP's nmap data.
C5 - open ports nmap confirms that naabu/masscan missed are added to port_scan
     and get Port/Service nodes; the enrichment counter counts real matches.

The Neo4j session is a fake that records every query and its parameters.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from graph_db.mixins.recon.port_mixin import PortMixin  # noqa: E402

IP_A = "192.0.2.10"
IP_B = "192.0.2.11"


class _Result:
    def __init__(self, record=None):
        self._record = record

    def single(self):
        return self._record

    def __iter__(self):
        return iter([])


class _Session:
    """Records queries; a Port/Service MATCH matches only what 'exists'."""

    def __init__(self, existing=()):
        self.calls = []
        self.existing = set(existing)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        flat = " ".join(query.split())
        self.calls.append((flat, params))
        key = (params.get("ip_addr"), params.get("port_number"))
        if "MERGE (p:Port" in flat:
            self.existing.add(key)
        if "AS matched" in flat:
            return _Result({"matched": 1 if key in self.existing else 0})
        return _Result()

    def queries(self, needle):
        return [(q, p) for q, p in self.calls if needle in q]


class _Graph(PortMixin):
    def __init__(self, session):
        self.driver = mock.MagicMock()
        self.driver.session.return_value = session


def _pd(port, product="", version="", service="http", state="open"):
    return {"port": port, "protocol": "tcp", "state": state, "service": service,
            "product": product, "version": version, "extrainfo": "", "cpe": "", "scripts": {}}


def _write(nmap_scan, existing=()):
    session = _Session(existing)
    stats = _Graph(session).update_graph_from_nmap({"nmap_scan": nmap_scan}, "u1", "p1")
    return session, stats


def _two_hosts_same_port(with_ip=True):
    def svc(product, version, ip):
        entry = {"product": product, "version": version, "port": 80, "host": ip, "cpe": ""}
        if with_ip:
            entry["ip"] = ip
        return entry

    return {
        "by_host": {
            "a.example.com": {"host": "a.example.com", "ip": IP_A, "ports": [80],
                              "port_details": [_pd(80, "nginx", "1.25.0")]},
            "b.example.com": {"host": "b.example.com", "ip": IP_B, "ports": [80],
                              "port_details": [_pd(80, "Apache httpd", "2.4.49")]},
        },
        "services_detected": [svc("nginx", "1.25.0", IP_A), svc("Apache httpd", "2.4.49", IP_B)],
        "nse_vulns": [{"host": IP_B, "ip": IP_B, "port": 80, "script_id": "http-vuln-x",
                       "state": "VULNERABLE", "output": "VULNERABLE", "cve": "CVE-2021-41773"}],
    }


class TestTechnologyGoesToItsOwnIp:
    def test_each_service_links_its_technology_on_its_own_ip(self):
        session, _ = _write(_two_hosts_same_port())
        uses = {(p["ip_addr"], p["tech_name"]) for _, p in session.queries("USES_TECHNOLOGY")}
        has = {(p["ip_addr"], p["tech_name"]) for _, p in session.queries("[:HAS_TECHNOLOGY]")}
        expected = {(IP_A, "nginx/1.25.0"), (IP_B, "Apache httpd/2.4.49")}
        assert uses == expected and has == expected

    def test_nse_links_use_the_technology_of_the_findings_ip(self):
        session, _ = _write(_two_hosts_same_port())
        (found_on,) = [p for _, p in session.queries("[:FOUND_ON]")]
        assert found_on["ip_addr"] == IP_B and found_on["tech_name"] == "Apache httpd/2.4.49"
        (known,) = [p for _, p in session.queries("[:HAS_KNOWN_CVE]")]
        assert known["tech_name"] == "Apache httpd/2.4.49"

    def test_legacy_entries_without_an_ip_keep_the_old_lookup(self):
        session, _ = _write(_two_hosts_same_port(with_ip=False))
        uses = [p["ip_addr"] for _, p in session.queries("USES_TECHNOLOGY")]
        assert uses == [IP_A, IP_A]       # first host with the port, as before
        (found_on,) = [p for _, p in session.queries("[:FOUND_ON]")]
        assert found_on["tech_name"] == "nginx/1.25.0"

    def test_an_nse_finding_on_a_host_with_no_detected_service_links_nothing(self):
        data = _two_hosts_same_port()
        data["services_detected"] = data["services_detected"][:1]   # only IP_A's service
        session, _ = _write(data)
        assert session.queries("[:FOUND_ON]") == []


class TestConfirmedPortsReachTheGraph:
    def test_a_new_open_port_gets_tenant_scoped_port_and_service_nodes(self):
        data = {"by_host": {"a.example.com": {"ip": IP_A, "ports": [80, 8443],
                                              "port_details": [_pd(80), _pd(8443, "x", "1",
                                                                            service="https-alt")]}},
                "services_detected": [], "nse_vulns": [],
                "new_open_ports": [{"ip": IP_A, "port": 8443, "protocol": "tcp",
                                    "service": "https-alt"}]}
        session, stats = _write(data, existing={(IP_A, 80)})
        (port_q, port_p) = session.queries("MERGE (p:Port")[0]
        assert ("MERGE (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr, "
                "user_id: $user_id, project_id: $project_id})") in port_q
        assert "MERGE (i:IP {address: $ip_addr, user_id: $user_id, project_id: $project_id})" in port_q
        assert "MERGE (i)-[:HAS_PORT]->(p)" in port_q
        assert "ON CREATE SET p.source = 'nmap'" in port_q
        assert (port_p["ip_addr"], port_p["port_number"], port_p["protocol"]) == (IP_A, 8443, "tcp")
        assert (port_p["user_id"], port_p["project_id"]) == ("u1", "p1")
        (svc_q, svc_p) = session.queries("MERGE (svc:Service")[0]
        assert "MERGE (p)-[:RUNS_SERVICE]->(svc)" in svc_q
        assert svc_p["service_name"] == "https-alt" and svc_p["user_id"] == "u1"
        # Created before the enrichment, so the new port is enriched like the others.
        assert stats["ports_enriched"] == 2

    def test_without_new_ports_no_port_or_service_node_is_created(self):
        session, _ = _write(_two_hosts_same_port(), existing={(IP_A, 80), (IP_B, 80)})
        assert session.queries("MERGE (p:Port") == []
        assert session.queries("MERGE (svc:Service") == []

    def test_ports_enriched_counts_only_ports_that_exist(self):
        data = {"by_host": {"a.example.com": {"ip": IP_A, "ports": [80, 443],
                                              "port_details": [_pd(80, "nginx"), _pd(443, "nginx")]}},
                "services_detected": [], "nse_vulns": []}
        _, stats = _write(data, existing={(IP_A, 80)})
        assert stats["ports_enriched"] == 1
        assert stats["services_enriched"] == 1


# --- merge_nmap_into_port_scan --------------------------------------------------


@pytest.fixture
def recon_main():
    stub = {
        'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False, 'TARGET_IPS': [],
        'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery'],
        'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        yield rm


def _port_scan():
    """naabu's shape: two hostnames on IP_A, one on IP_B."""
    return {
        "scan_metadata": {"scanners": ["naabu"]},
        "by_host": {
            "a.example.com": {"host": "a.example.com", "ip": IP_A, "ports": [80],
                              "port_details": [{"port": 80, "protocol": "tcp", "service": "http"}],
                              "cdn": None, "is_cdn": False},
            "www.example.com": {"host": "www.example.com", "ip": IP_A, "ports": [80],
                                "port_details": [{"port": 80, "protocol": "tcp", "service": "http"}],
                                "cdn": None, "is_cdn": False},
            "b.example.com": {"host": "b.example.com", "ip": IP_B, "ports": [443],
                              "port_details": [{"port": 443, "protocol": "tcp", "service": "https"}],
                              "cdn": None, "is_cdn": False},
        },
        "by_ip": {
            IP_A: {"ip": IP_A, "hostnames": ["a.example.com", "www.example.com"], "ports": [80],
                   "cdn": None, "is_cdn": False},
            IP_B: {"ip": IP_B, "hostnames": ["b.example.com"], "ports": [443],
                   "cdn": None, "is_cdn": False},
        },
        "all_ports": [80, 443],
        "summary": {"hosts_scanned": 3, "ips_scanned": 2, "hosts_with_open_ports": 3,
                    "total_open_ports": 3, "unique_ports": [80, 443], "unique_port_count": 2,
                    "cdn_hosts": 0},
    }


def _nmap(by_ip_details):
    by_host = {}
    for host, ip, details in by_ip_details:
        by_host[host] = {"host": host, "ip": ip, "ports": [d["port"] for d in details],
                         "port_details": details}
    return {"by_host": by_host, "services_detected": [], "nse_vulns": []}


class TestMergeAddsConfirmedPorts:
    def test_an_extra_open_port_joins_port_scan_in_naabus_shape(self, recon_main):
        combined = {"port_scan": _port_scan(), "nmap_scan": _nmap([
            ("a.example.com", IP_A, [_pd(80, "nginx", "1.25.0"),
                                     _pd(8443, "Jetty", "9.4", service="https-alt")]),
            ("b.example.com", IP_B, [_pd(443, "nginx", "1.25.0")]),
        ])}
        recon_main.merge_nmap_into_port_scan(combined)
        ps = combined["port_scan"]
        assert ps["by_ip"][IP_A]["ports"] == [80, 8443]
        assert ps["by_ip"][IP_B]["ports"] == [443]
        for host in ("a.example.com", "www.example.com"):
            assert ps["by_host"][host]["ports"] == [80, 8443]
            added = ps["by_host"][host]["port_details"][-1]
            assert added == {"port": 8443, "protocol": "tcp", "service": "https-alt",
                             "product": "Jetty", "version": "9.4"}
        assert ps["by_host"]["b.example.com"]["ports"] == [443]
        assert ps["all_ports"] == [80, 443, 8443]
        assert ps["summary"]["total_open_ports"] == 5
        assert ps["summary"]["unique_ports"] == [80, 443, 8443]
        assert ps["summary"]["unique_port_count"] == 3
        assert combined["nmap_scan"]["new_open_ports"] == [
            {"ip": IP_A, "port": 8443, "protocol": "tcp", "service": "https-alt"}]

    def test_nothing_new_keeps_todays_output(self, recon_main):
        combined = {"port_scan": _port_scan(), "nmap_scan": _nmap([
            ("a.example.com", IP_A, [_pd(80, "nginx", "1.25.0")]),
        ])}
        expected = _port_scan()
        expected["by_host"]["a.example.com"]["port_details"][0].update(
            {"product": "nginx", "version": "1.25.0"})
        expected["scan_metadata"]["scanners"] = ["naabu", "nmap"]
        nmap_before = copy.deepcopy(combined["nmap_scan"])
        recon_main.merge_nmap_into_port_scan(combined)
        assert combined["port_scan"] == expected
        assert combined["nmap_scan"] == nmap_before

    def test_a_port_that_is_not_open_is_never_added(self, recon_main):
        combined = {"port_scan": _port_scan(), "nmap_scan": _nmap([
            ("a.example.com", IP_A, [_pd(80, "nginx"), _pd(8443, state="filtered")]),
        ])}
        recon_main.merge_nmap_into_port_scan(combined)
        assert combined["port_scan"]["by_ip"][IP_A]["ports"] == [80]
        assert "new_open_ports" not in combined["nmap_scan"]

    def test_a_cdn_edges_extra_ports_are_not_adopted(self, recon_main):
        port_scan = _port_scan()
        port_scan["by_ip"][IP_A].update({"cdn": "cloudflare", "is_cdn": True})
        combined = {"port_scan": port_scan, "nmap_scan": _nmap([
            ("a.example.com", IP_A, [_pd(80, "cloudflare"), _pd(8443, "cloudflare")]),
        ])}
        recon_main.merge_nmap_into_port_scan(combined)
        assert combined["port_scan"]["by_ip"][IP_A]["ports"] == [80]
        assert "new_open_ports" not in combined["nmap_scan"]

    def test_an_entry_for_another_ip_is_not_enriched(self, recon_main):
        # The hostname key points at IP_A in port_scan, but this nmap entry is IP_B's.
        combined = {"port_scan": _port_scan(), "nmap_scan": _nmap([
            ("a.example.com", IP_B, [_pd(80, "Apache httpd", "2.4.49")]),
        ])}
        recon_main.merge_nmap_into_port_scan(combined)
        pd = combined["port_scan"]["by_host"]["a.example.com"]["port_details"][0]
        assert "product" not in pd
