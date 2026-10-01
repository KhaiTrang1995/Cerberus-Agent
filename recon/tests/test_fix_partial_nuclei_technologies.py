"""Partial Nuclei: the CVE lookup and the AI tag selector see the graph's technologies.

The partial-recon vuln builder rebuilt http_probe.by_url from BaseURLs with
url/host/status/content_type/CDN fields only. cve_helpers.run_cve_lookup builds
its technology set ONLY from by_url technologies + server and nmap_scan
services, so in partial mode it found nothing and the modal's "CVE lookup"
option was a no-op; the Nuclei AI tag selector got an empty fingerprint too.
User-typed URLs carried none either.

The builder now rebuilds the full pipeline's "Name:version" strings from the
Endpoint -[:USES_TECHNOLOGY]-> Technology edges httpx/wappalyzer wrote, the
Server header from the probed Endpoint, and nmap's Port product/version.

Fixture names are under example.test only.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules import graph_builders as gb  # noqa: E402

ROOT = "example.test"
SUBS = [("www.example.test", "192.88.98.10"), ("mail.example.test", "192.88.98.11")]
BASEURLS = [
    {"url": "https://www.example.test", "host": "www.example.test", "status_code": 200,
     "content_type": "text/html", "is_cdn": False, "cdn": None, "asn": None,
     "server": "nginx/1.19.0"},
    {"url": "https://mail.example.test", "host": "mail.example.test", "status_code": 302,
     "content_type": "text/html", "is_cdn": False, "cdn": None, "asn": None,
     "server": None},
]
# What _URL_TECHNOLOGIES returns: per BaseURL, the httpx/wappalyzer strings.
URL_TECHS = {
    "https://www.example.test": ["Nginx:1.19.0", "PHP:8.1.2", "jQuery"],
    "https://stale.other.test": ["Apache:2.4.49"],          # not a target of this run
}
PORTS = [
    {"ip": "192.88.98.11", "port": 22, "product": "OpenSSH", "version": "8.9p1", "cpe": "cpe:/a:openbsd:openssh:8.9p1"},
    {"ip": "192.88.98.99", "port": 21, "product": "vsftpd", "version": "3.0.3", "cpe": ""},
]


class _Session:
    def __init__(self, calls, url_techs, ports, baseurls):
        self.calls, self.url_techs, self.ports, self.baseurls = calls, url_techs, ports, baseurls

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, cypher, **params):
        self.calls.append((cypher, params))
        if "USES_TECHNOLOGY" in cypher:
            urls = params.get("urls")
            return [{"url": u, "technologies": t} for u, t in self.url_techs.items()
                    if urls is None or u in urls]
        if "MATCH (p:Port" in cypher:
            return [dict(p) for p in self.ports if p["ip"] in params["ips"]]
        if "collect(DISTINCT s.name)" in cypher:
            return _Rows([{"subdomains": [s for s, _ in SUBS]}])
        if "HAS_SUBDOMAIN" in cypher:
            return [{"root": ROOT, "subdomain": s, "address": ip, "version": "ipv4",
                     "is_cdn": None, "cdn_name": None, "asn": None} for s, ip in SUBS]
        if "MATCH (b:BaseURL" in cypher and "AS status_code" in cypher:
            return [dict(b) for b in self.baseurls]
        if "MATCH (b:BaseURL" in cypher and "AS server" in cypher:
            return [{"url": b["url"], "server": b.get("server")} for b in self.baseurls
                    if b["url"] in params["urls"]]
        return []


class _Rows(list):
    def single(self):
        return self[0] if self else None


def _fake_client(calls, url_techs=URL_TECHS, ports=PORTS, baseurls=BASEURLS):
    class _Client:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def verify_connection(self):
            return True

        @property
        def driver(self):
            driver = mock.MagicMock()
            driver.session.side_effect = lambda: _Session(calls, url_techs, ports, baseurls)
            return driver
    return _Client


def _build(monkeypatch, **kw):
    calls = []
    monkeypatch.setattr("graph_db.Neo4jClient", _fake_client(calls, **kw))
    data = gb._build_vuln_scan_data_from_graph([ROOT], "u1", "p1", include_root_domain=False)
    return data, calls


# --------------------------------------------------------------------------- #
# Builder
# --------------------------------------------------------------------------- #
def test_by_url_carries_technologies_and_server(monkeypatch):
    data, _ = _build(monkeypatch)
    www = data["http_probe"]["by_url"]["https://www.example.test"]
    assert www["technologies"] == ["Nginx:1.19.0", "PHP:8.1.2", "jQuery"]
    assert www["server"] == "nginx/1.19.0"
    mail = data["http_probe"]["by_url"]["https://mail.example.test"]
    assert mail["technologies"] == [] and mail["server"] is None
    # a BaseURL the run does not target never gets an entry
    assert "https://stale.other.test" not in data["http_probe"]["by_url"]


def test_nmap_services_come_from_this_runs_ips_only(monkeypatch):
    data, calls = _build(monkeypatch)
    assert data["nmap_scan"]["services_detected"] == [
        {"product": "OpenSSH", "version": "8.9p1", "port": 22, "host": "192.88.98.11",
         "cpe": "cpe:/a:openbsd:openssh:8.9p1"}]
    (params,) = [p for q, p in calls if "MATCH (p:Port" in q]
    assert params["ips"] == ["192.88.98.10", "192.88.98.11"]


def test_new_reads_are_tenant_scoped(monkeypatch):
    _, calls = _build(monkeypatch)
    new = [(q, p) for q, p in calls if "USES_TECHNOLOGY" in q or "MATCH (p:Port" in q]
    assert len(new) == 2
    for q, p in new:
        assert p["uid"] == "u1" and p["pid"] == "p1"
    tech_q = next(q for q, _ in new if "USES_TECHNOLOGY" in q)
    assert "BaseURL {user_id: $uid, project_id: $pid}" in tech_q
    assert "Technology {user_id: $uid, project_id: $pid}" in tech_q
    assert "detected_by" in tech_q          # httpx/wappalyzer edges only
    port_q = next(q for q, _ in new if "MATCH (p:Port" in q)
    assert "Port {user_id: $uid, project_id: $pid}" in port_q


def test_existing_fields_are_unchanged(monkeypatch):
    data, _ = _build(monkeypatch)
    www = data["http_probe"]["by_url"]["https://www.example.test"]
    assert {k: v for k, v in www.items() if k not in ("technologies", "server")} == {
        "url": "https://www.example.test", "host": "www.example.test", "status_code": 200,
        "content_type": "text/html", "is_cdn": False, "cdn": None, "asn": None,
        "ip": "192.88.98.10"}


def test_a_graph_without_technologies_or_nmap_adds_nothing_else(monkeypatch):
    data, _ = _build(monkeypatch, url_techs={}, ports=[])
    assert all(e["technologies"] == [] for e in data["http_probe"]["by_url"].values())
    assert "nmap_scan" not in data


def test_a_record_without_the_server_column_reads_none(monkeypatch):
    legacy = [{k: v for k, v in b.items() if k != "server"} for b in BASEURLS]
    data, _ = _build(monkeypatch, baseurls=legacy)
    assert data["http_probe"]["by_url"]["https://www.example.test"]["server"] is None


# --------------------------------------------------------------------------- #
# The consumers: CVE lookup + Nuclei AI tag fingerprint
# --------------------------------------------------------------------------- #
def test_cve_lookup_now_queries_the_graph_technologies(monkeypatch):
    from recon.helpers import cve_helpers

    data, _ = _build(monkeypatch)
    queried = []

    def fake_nvd(name, version, max_results, keys, admitted=False):
        queried.append((name, version))
        return SimpleNamespace(data=[], answered=True, outcome=None, detail="")

    with patch.object(cve_helpers, "_nvd_query", side_effect=fake_nvd), \
         patch.object(cve_helpers.time, "sleep"):
        out = cve_helpers.run_cve_lookup(data, enabled=True, source="nvd")
    assert out["technology_cves"]["technologies_checked"] >= 3
    names = {n for n, _ in queried}
    assert {"nginx", "php", "openssh"} <= names
    assert ("nginx", "1.19.0") in queried


def test_nuclei_tag_fingerprint_is_no_longer_empty(monkeypatch):
    from recon.main_recon_modules.vuln_scan import _build_tech_fingerprint

    data, _ = _build(monkeypatch)
    fp = _build_tech_fingerprint(data["http_probe"])
    assert "nginx:1.19.0" in fp["technologies"] and "jquery" in fp["technologies"]
    assert fp["servers"] == ["nginx"]


# --------------------------------------------------------------------------- #
# User-typed URLs
# --------------------------------------------------------------------------- #
def _recon(by_url):
    return {
        "domain": ROOT, "domains": [ROOT], "subdomains": [],
        "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False}, "subdomains": {}},
        "http_probe": {"by_url": by_url},
        "port_scan": {"by_ip": {}},
        "resource_enum": {"by_base_url": {}, "discovered_urls": []},
        "metadata": {"include_root_domain": False},
    }


@pytest.fixture
def fake_graph_module(monkeypatch):
    client = MagicMock()
    client.verify_connection.return_value = True
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.update_graph_from_vuln_scan.return_value = {}
    module = MagicMock()
    module.Neo4jClient.return_value = client
    monkeypatch.setitem(sys.modules, "graph_db", module)


def _run_nuclei(monkeypatch, recon, user_urls, fingerprints, include_graph=True):
    from recon.partial_recon_modules import vulnerability_scanning as vs

    seen = {}
    lookups = MagicMock(side_effect=lambda bases, uid, pid: {
        b: fingerprints[b] for b in bases if b in fingerprints})
    monkeypatch.setattr(vs, "_build_vuln_scan_data_from_graph", MagicMock(return_value=recon))
    monkeypatch.setattr(vs, "graph_url_fingerprints", lookups)

    def fake_vuln_scan(rd, settings=None):
        seen["recon"] = rd
        return rd

    with patch("recon.main_recon_modules.vuln_scan.run_vuln_scan", side_effect=fake_vuln_scan):
        vs.run_nuclei({"_settings": {"MITRE_ENABLED": False}, "domains": [ROOT], "domain": ROOT,
                       "include_graph_targets": include_graph,
                       "user_targets": {"urls": user_urls, "url_attach_to": None}})
    return seen["recon"]["http_probe"]["by_url"], lookups


def test_user_url_inherits_its_loaded_baseurls_fingerprint(monkeypatch, fake_graph_module):
    base = {"url": "https://www.example.test", "host": "www.example.test", "status_code": 200,
            "content_type": "text/html", "technologies": ["Nginx:1.19.0"], "server": "nginx/1.19.0"}
    by_url, lookups = _run_nuclei(monkeypatch, _recon({"https://www.example.test": base}),
                                  ["https://www.example.test/login?next=1"], {})
    entry = by_url["https://www.example.test/login?next=1"]
    assert entry["technologies"] == ["Nginx:1.19.0"] and entry["server"] == "nginx/1.19.0"
    lookups.assert_not_called()          # already loaded: no extra graph read


def test_user_url_on_an_unloaded_baseurl_reads_the_graph(monkeypatch, fake_graph_module):
    fps = {"https://api.example.test:8443": {"technologies": ["Express"], "server": "envoy"}}
    by_url, lookups = _run_nuclei(monkeypatch, _recon({}), ["https://api.example.test:8443/v1"],
                                  fps, include_graph=False)
    assert lookups.call_args.args[0] == ["https://api.example.test:8443"]
    entry = by_url["https://api.example.test:8443/v1"]
    assert entry["technologies"] == ["Express"] and entry["server"] == "envoy"
    # The fields the injection always wrote are unchanged.
    assert (entry["host"], entry["status_code"], entry["content_type"]) == (
        "api.example.test", 200, "text/html")


def test_user_url_with_no_graph_fingerprint_gets_empty_fields(monkeypatch, fake_graph_module):
    by_url, _ = _run_nuclei(monkeypatch, _recon({}), ["https://new.example.test"], {},
                            include_graph=False)
    entry = by_url["https://new.example.test"]
    assert entry["technologies"] == [] and entry["server"] is None


def test_graph_url_fingerprints_never_raises(monkeypatch):
    broken = MagicMock(side_effect=RuntimeError("bolt down"))
    monkeypatch.setattr("graph_db.Neo4jClient", broken)
    assert gb.graph_url_fingerprints(["https://www.example.test"], "u1", "p1") == {}
    assert gb.graph_url_fingerprints([], "u1", "p1") == {}


def test_graph_url_fingerprints_reads_server_and_technologies(monkeypatch):
    calls = []
    monkeypatch.setattr("graph_db.Neo4jClient", _fake_client(calls))
    out = gb.graph_url_fingerprints(["https://www.example.test"], "u1", "p1")
    assert out == {"https://www.example.test": {
        "technologies": ["Nginx:1.19.0", "PHP:8.1.2", "jQuery"], "server": "nginx/1.19.0"}}
    server_q = next(q for q, _ in calls if "AS server" in q)
    assert "BaseURL {user_id: $uid, project_id: $pid}" in server_q
    assert all(p.get("uid") == "u1" and p.get("pid") == "p1" for _, p in calls)
