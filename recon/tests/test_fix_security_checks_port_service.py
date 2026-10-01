"""Port/service security checks read the port scan the pipeline really writes.

run_port_service_checks iterated recon_data["port_scan"] itself, so its "IPs"
were the section names (scan_metadata, by_host, by_ip, ...), and it required
a per-port {"state": "open"} that by_ip entries never carry. Admin ports,
database ports, unauthenticated Redis, SMTP open relay and the Kubernetes API
were never checked on a real host, in full or partial recon.

The Kubernetes matcher fired on any 200/401/403 page whose text contained
"kind", "kubernetes" or "apiversion" ("kindly", a JS `kind:`), with redirects
followed. It now needs a Kubernetes API document, and probes only the ports
the scan found open.

All addresses are RFC 5737 / RFC 3849 documentation ranges.
"""
from __future__ import annotations

import json
from unittest import mock

import pytest
import requests

from recon.helpers import circuit_breaker as cb
from recon.helpers import security_checks as sc

IP = "198.51.100.20"
IP2 = "198.51.100.21"
ALL_CHECKS = {
    "admin_port_exposed": True, "database_exposed": True, "redis_no_auth": True,
    "kubernetes_api_exposed": True, "smtp_open_relay": True,
}


def _resp(status=200, headers=None, text=""):
    r = mock.MagicMock()
    r.status_code = status
    r.headers = headers or {}
    r.text = text
    r.content = text.encode()
    r.history = []
    return r


def _only(*names):
    """An enabled_checks dict with just `names` on: an absent check defaults to on."""
    return {name: name in names for name in ALL_CHECKS}


def _by_ip_entry(ip, ports, is_cdn=False, cdn=None):
    return {"ip": ip, "hostnames": ["db.example.test"], "ports": list(ports),
            "cdn": cdn, "is_cdn": is_cdn}


def _full_pipeline_port_scan(by_ip):
    """The shape port_scan.py / merge_port_scan_results hand downstream."""
    return {
        "scan_metadata": {"scan_type": "syn", "scanners": ["naabu"]},
        "by_host": {"db.example.test": {"host": "db.example.test", "ip": IP,
                                        "ports": [22], "port_details": [{"port": 22}]}},
        "by_ip": by_ip,
        "all_ports": [22, 25, 3306, 6379],
        "ip_to_hostnames": {IP: ["db.example.test"]},
        "summary": {"hosts_scanned": 1},
    }


class _FakeSock:
    """A socket that answers each recv() with the next scripted line."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []

    def recv(self, _n):
        return self.replies.pop(0) if self.replies else b""

    def send(self, data):
        self.sent.append(data)
        return len(data)

    def sendall(self, data):
        self.sent.append(data)

    def settimeout(self, _t):
        pass

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _fake_connect(by_port):
    """create_connection stand-in: scripted replies per port, refused otherwise."""
    calls = []

    def connect(address, timeout=None, *a, **k):
        calls.append(address)
        replies = by_port.get(address[1])
        if replies is None:
            raise ConnectionRefusedError("refused")
        return _FakeSock(replies)

    return connect, calls


def _run(port_scan, enabled=None, get=None, connect=None, **kwargs):
    get = get or mock.MagicMock(side_effect=requests.ConnectionError("no http"))
    connect = connect or _fake_connect({})[0]
    with mock.patch.object(sc.requests, "get", get), \
         mock.patch.object(sc.socket, "create_connection", side_effect=connect):
        return sc.run_port_service_checks(
            {"port_scan": port_scan}, enabled or ALL_CHECKS,
            timeout=1, max_workers=1, **kwargs)


def _types(findings):
    return sorted((f["type"], f.get("port")) for f in findings)


class TestTheRealPortScanShapeIsRead:
    def test_full_pipeline_by_ip_produces_admin_and_database_findings(self):
        findings = _run(_full_pipeline_port_scan({IP: _by_ip_entry(IP, [22, 3306])}),
                        enabled=_only("admin_port_exposed", "database_exposed"))
        assert _types(findings) == [("admin_port_exposed", 22), ("database_exposed", 3306)]
        assert {f["ip"] for f in findings} == {IP}

    def test_partial_recon_by_ip_only_shape_is_read(self):
        findings = _run({"by_ip": {IP: _by_ip_entry(IP, [3389])}},
                        enabled=_only("admin_port_exposed"))
        assert _types(findings) == [("admin_port_exposed", 3389)]

    def test_section_names_are_never_probed_as_hosts(self):
        get = mock.MagicMock(side_effect=requests.ConnectionError("x"))
        connect, calls = _fake_connect({})
        _run(_full_pipeline_port_scan({IP: _by_ip_entry(IP, [6443])}), get=get, connect=connect)
        hosts = {c.args[0].split("/")[2].rsplit(":", 1)[0] for c in get.call_args_list}
        hosts |= {addr[0] for addr in calls}
        assert hosts <= {IP}, hosts

    def test_port_details_are_read_too(self):
        entry = {"ip": IP, "ports": [], "port_details": [{"port": 5432, "protocol": "tcp"}]}
        findings = _run({"by_ip": {IP: entry}}, enabled=_only("database_exposed"))
        assert _types(findings) == [("database_exposed", 5432)]

    def test_legacy_state_open_map_is_still_read(self):
        legacy = {IP: {"22": {"state": "open"}, "3306": {"state": "closed"}}}
        findings = _run(legacy, enabled=_only("admin_port_exposed", "database_exposed"))
        assert _types(findings) == [("admin_port_exposed", 22)]

    def test_each_ip_reports_its_own_ports(self):
        by_ip = {IP: _by_ip_entry(IP, [22]), IP2: _by_ip_entry(IP2, [23])}
        findings = _run({"by_ip": by_ip}, enabled=_only("admin_port_exposed"))
        assert sorted((f["ip"], f["port"]) for f in findings) == [(IP, 22), (IP2, 23)]


class TestSocketChecksRunOnTheirOpenPort:
    def test_redis_without_auth_is_reported(self):
        connect, calls = _fake_connect({6379: [b"+PONG\r\n"]})
        findings = _run({"by_ip": {IP: _by_ip_entry(IP, [6379])}},
                        enabled=_only("redis_no_auth"), connect=connect)
        assert _types(findings) == [("redis_no_auth", 6379)]
        assert calls == [(IP, 6379)]

    def test_redis_asking_for_auth_is_not_reported(self):
        connect, _ = _fake_connect({6379: [b"-NOAUTH Authentication required.\r\n"]})
        findings = _run({"by_ip": {IP: _by_ip_entry(IP, [6379])}},
                        enabled=_only("redis_no_auth"), connect=connect)
        assert findings == []

    def test_smtp_open_relay_is_reported(self):
        connect, calls = _fake_connect({25: [b"220 mail ESMTP\r\n", b"250 hello\r\n",
                                             b"250 ok\r\n", b"250 ok\r\n"]})
        findings = _run({"by_ip": {IP: _by_ip_entry(IP, [25])}},
                        enabled=_only("smtp_open_relay"), connect=connect)
        assert _types(findings) == [("smtp_open_relay", 25)]
        assert calls == [(IP, 25)]

    def test_smtp_refusing_relay_is_not_reported(self):
        connect, _ = _fake_connect({25: [b"220 mail ESMTP\r\n", b"250 hello\r\n",
                                         b"250 ok\r\n", b"554 relay denied\r\n"]})
        findings = _run({"by_ip": {IP: _by_ip_entry(IP, [25])}},
                        enabled=_only("smtp_open_relay"), connect=connect)
        assert findings == []

    def test_ipv6_target_is_reachable_by_the_socket_checks(self):
        v6 = "2001:db8::20"
        connect, calls = _fake_connect({6379: [b"+PONG\r\n"]})
        findings = _run({"by_ip": {v6: _by_ip_entry(v6, [6379])}},
                        enabled=_only("redis_no_auth"), connect=connect)
        assert _types(findings) == [("redis_no_auth", 6379)]
        assert calls == [(v6, 6379)]


class TestTargetsThatMustNotBeChecked:
    def test_a_reliable_cdn_edge_ip_is_skipped(self):
        get = mock.MagicMock(side_effect=requests.ConnectionError("x"))
        connect, calls = _fake_connect({6379: [b"+PONG\r\n"]})
        findings = _run({"by_ip": {IP: _by_ip_entry(IP, [22, 6379, 6443],
                                                    is_cdn=True, cdn="cloudflare")}},
                        get=get, connect=connect)
        assert findings == []
        assert get.call_count == 0 and calls == []

    def test_a_generic_cloud_label_is_still_checked(self):
        # "aws" marks bare EC2/ALB origins too: their ports are the target's.
        findings = _run({"by_ip": {IP: _by_ip_entry(IP, [22], is_cdn=True, cdn="aws")}},
                        enabled=_only("admin_port_exposed"))
        assert _types(findings) == [("admin_port_exposed", 22)]

    def test_cdn_ips_passed_by_the_caller_are_skipped(self):
        findings = _run({"by_ip": {IP: _by_ip_entry(IP, [22])}},
                        enabled=_only("admin_port_exposed"), cdn_ips={IP})
        assert findings == []

    def test_an_roe_excluded_ip_is_skipped(self):
        connect, calls = _fake_connect({6379: [b"+PONG\r\n"]})
        findings = _run({"by_ip": {IP: _by_ip_entry(IP, [22, 6379]),
                                   IP2: _by_ip_entry(IP2, [22])}},
                        connect=connect, roe_excluded_hosts=["198.51.100.20/32"])
        assert {f["ip"] for f in findings} == {IP2}
        assert calls == []

    def test_a_host_down_is_skipped(self):
        for scheme in ("https", "http"):
            for _ in range(3):
                cb.host_health.record_failure(f"{scheme}://{IP}", requests.ConnectionError("x"))
        findings = _run({"by_ip": {IP: _by_ip_entry(IP, [22])}},
                        enabled=_only("admin_port_exposed"))
        assert findings == []

    def test_an_ip_without_open_ports_sends_nothing(self):
        get = mock.MagicMock(side_effect=requests.ConnectionError("x"))
        connect, calls = _fake_connect({})
        assert _run({"by_ip": {IP: _by_ip_entry(IP, [])}}, get=get, connect=connect) == []
        assert get.call_count == 0 and calls == []


K8S_VERSIONS = json.dumps({
    "kind": "APIVersions", "versions": ["v1"],
    "serverAddressByClientCIDRs": [{"clientCIDR": "0.0.0.0/0", "serverAddress": "10.0.0.1:6443"}],
})


def _k8s_status(code, reason):
    return json.dumps({"kind": "Status", "apiVersion": "v1", "metadata": {},
                       "status": "Failure", "message": reason.lower(),
                       "reason": reason, "code": code})


class TestKubernetesProbesOnlyOpenApiPorts:
    def test_no_kubernetes_port_open_means_no_probe(self):
        get = mock.MagicMock(return_value=_resp(200, text=K8S_VERSIONS))
        findings = _run({"by_ip": {IP: _by_ip_entry(IP, [22])}},
                        enabled=_only("kubernetes_api_exposed"), get=get)
        assert findings == [] and get.call_count == 0

    def test_only_the_open_api_port_is_probed_without_redirects(self):
        get = mock.MagicMock(return_value=_resp(200, text=K8S_VERSIONS))
        findings = _run({"by_ip": {IP: _by_ip_entry(IP, [22, 6443])}},
                        enabled=_only("kubernetes_api_exposed"), get=get)
        assert [c.args[0] for c in get.call_args_list] == [f"https://{IP}:6443/api"]
        assert get.call_args.kwargs.get("allow_redirects") is False
        assert _types(findings) == [("kubernetes_api_exposed", 6443)]
        assert findings[0]["severity"] == "critical"
        assert findings[0]["url"] == f"https://{IP}:6443/api"


class TestKubernetesMatcher:
    def _check(self, status, text, headers=None):
        get = mock.MagicMock(return_value=_resp(status, headers or {}, text))
        with mock.patch.object(sc.requests, "get", get):
            return sc.check_kubernetes_api_exposed(IP, timeout=1, ports=[6443])

    def test_anonymous_discovery_is_critical(self):
        f = self._check(200, K8S_VERSIONS)
        assert f["type"] == "kubernetes_api_exposed" and f["severity"] == "critical"
        assert f["port"] == 6443 and f["ip"] == IP and f["status_code"] == 200

    @pytest.mark.parametrize("code,reason", [(401, "Unauthorized"), (403, "Forbidden")])
    def test_an_api_status_object_asking_for_auth_is_high(self, code, reason):
        f = self._check(code, _k8s_status(code, reason))
        assert f["severity"] == "high" and f["status_code"] == code

    @pytest.mark.parametrize("status,text", [
        (200, "<html><body>We kindly ask you to log in.</body></html>"),
        (200, "<script>const t={kind:'page',apiVersion:2}</script>"),
        (200, "<h1>Kubernetes training course</h1>"),
        (200, json.dumps({"kind": "Product", "id": 3})),
        (200, json.dumps({"data": {"__schema": {"types": [{"kind": "OBJECT"}]}}})),
        (401, "<html>401 Authorization Required - kubernetes dashboard</html>"),
        (403, "<html><center>403 Forbidden</center><hr>nginx</html>"),
        (403, json.dumps({"kind": "Status", "apiVersion": "v1", "code": 401})),
        (404, _k8s_status(404, "NotFound")),
    ])
    def test_a_page_that_only_mentions_the_words_is_not_kubernetes(self, status, text):
        assert self._check(status, text) is None

    def test_a_redirect_is_not_followed(self):
        get = mock.MagicMock(return_value=_resp(302, {"Location": "https://login.example.test/"}))
        with mock.patch.object(sc.requests, "get", get):
            assert sc.check_kubernetes_api_exposed(IP, timeout=1, ports=[443]) is None
        assert get.call_args.kwargs.get("allow_redirects") is False

    def test_default_ports_are_unchanged_for_direct_callers(self):
        get = mock.MagicMock(return_value=_resp(404, text="nope"))
        with mock.patch.object(sc.requests, "get", get):
            sc.check_kubernetes_api_exposed(IP, timeout=1)
        assert [c.args[0] for c in get.call_args_list] == [
            f"https://{IP}:6443/api", f"https://{IP}:8443/api", f"https://{IP}:443/api"]

    def test_ipv6_api_url_is_bracketed(self):
        get = mock.MagicMock(return_value=_resp(200, text=K8S_VERSIONS))
        with mock.patch.object(sc.requests, "get", get):
            f = sc.check_kubernetes_api_exposed("2001:db8::20", timeout=1, ports=[6443])
        assert get.call_args.args[0] == "https://[2001:db8::20]:6443/api"
        assert f["url"] == "https://[2001:db8::20]:6443/api"
