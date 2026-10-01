"""Shodan's CDN filter in the full pipeline (C7).

Shodan runs in GROUP 3 beside the port scan, on a snapshot taken before naabu
flags any CDN IP, so collect_cdn_ips found nothing and every CDN edge was looked
up and attached to the target. Two fixes, neither of which serialises the group:

  - the OSINT IP filter also skips addresses inside the published CDN prefixes
    (offline: no request is made for them);
  - at the fan-in, once port_scan is known, Shodan results for IPs naabu
    flagged as CDN are dropped.
"""
from __future__ import annotations

import copy
import inspect
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.main_recon_modules import ip_filter, shodan_enrich  # noqa: E402

PUBLISHED_CDN_IP = "104.16.0.5"     # inside a published Cloudflare prefix
ORIGIN_IP = "93.184.216.34"
FLAGGED_CDN_IP = "192.0.2.50"      # flagged is_cdn by naabu


@pytest.fixture
def no_network(monkeypatch):
    from recon.helpers import cdn_ranges
    fetch = mock.Mock(side_effect=AssertionError("the CDN filter must not fetch"))
    monkeypatch.setattr(cdn_ranges.requests, "get", fetch)
    return fetch


class TestPublishedPrefixesBeforeThePortScan:
    def test_a_published_cdn_ip_is_skipped_with_no_port_scan_yet(self, no_network):
        kept = ip_filter.filter_ips_for_enrichment([PUBLISHED_CDN_IP, ORIGIN_IP], {}, "Test")
        assert kept == [ORIGIN_IP]
        no_network.assert_not_called()

    def test_shodan_never_looks_up_a_published_cdn_ip(self, no_network, monkeypatch):
        looked_up = []

        def fake_lookup(ips, api_key, key_rotator=None, max_workers=5):
            looked_up.extend(ips)
            return []

        monkeypatch.setattr(shodan_enrich, "_run_host_lookup", fake_lookup)
        snapshot = {"domain": "example.com", "metadata": {},
                    "dns": {"domain": {"ips": {"ipv4": [PUBLISHED_CDN_IP]}},
                            "subdomains": {"www.example.com": {"ips": {"ipv4": [ORIGIN_IP]}}}}}
        shodan_enrich.run_shodan_enrichment_isolated(
            snapshot, {"SHODAN_API_KEY": "k", "SHODAN_HOST_LOOKUP": True})
        assert looked_up == [ORIGIN_IP]

    def test_ips_outside_every_cdn_range_are_kept_as_before(self, no_network):
        ips = [ORIGIN_IP, "8.8.8.8", "1.1.1.1"]
        assert ip_filter.filter_ips_for_enrichment(ips, {}, "Test") == ips

    def test_the_osint_group_after_the_port_scan_filters_as_before(self, no_network):
        combined = {"port_scan": {"by_ip": {"8.8.4.4": {"is_cdn": True}, ORIGIN_IP: {}}}}
        kept = ip_filter.filter_ips_for_enrichment(["8.8.4.4", ORIGIN_IP], combined, "Test")
        assert kept == [ORIGIN_IP]


def _shodan_data():
    return {
        "hosts": [{"ip": FLAGGED_CDN_IP, "ports": [80, 443, 8443]},
                  {"ip": ORIGIN_IP, "ports": [22]}],
        "reverse_dns": {FLAGGED_CDN_IP: ["edge.cdn.example"], ORIGIN_IP: ["www.example.com"]},
        "domain_dns": {"subdomains": ["www"]},
        "cves": [{"cve_id": "CVE-2020-0001", "ip": FLAGGED_CDN_IP, "source": "shodan"},
                 {"cve_id": "CVE-2020-0002", "ip": ORIGIN_IP, "source": "shodan"}],
    }


def _port_scan(cdn=True):
    return {"by_ip": {FLAGGED_CDN_IP: {"ip": FLAGGED_CDN_IP, "is_cdn": cdn, "ports": [443]},
                      ORIGIN_IP: {"ip": ORIGIN_IP, "is_cdn": False, "ports": [22]}}}


class TestTheFanInDropsCdnResults:
    def test_results_for_an_ip_the_port_scan_flagged_are_dropped(self, no_network):
        data = _shodan_data()
        dropped = shodan_enrich.drop_cdn_ips(data, {"port_scan": _port_scan()})
        assert dropped == 1
        assert [h["ip"] for h in data["hosts"]] == [ORIGIN_IP]
        assert list(data["reverse_dns"]) == [ORIGIN_IP]
        assert [c["ip"] for c in data["cves"]] == [ORIGIN_IP]
        assert data["domain_dns"] == {"subdomains": ["www"]}

    def test_with_no_cdn_ip_the_data_is_untouched(self, no_network):
        data = _shodan_data()
        assert shodan_enrich.drop_cdn_ips(data, {"port_scan": _port_scan(cdn=False)}) == 0
        assert data == _shodan_data()


class TestThePipelineAppliesIt:
    @pytest.fixture
    def recon_main(self):
        stub = {
            'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False,
            'TARGET_IPS': [], 'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
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

    def test_the_fan_in_helper_drops_flagged_ips(self, recon_main, no_network):
        combined = {"shodan": _shodan_data(), "port_scan": _port_scan()}
        recon_main._drop_shodan_cdn_ips(combined)
        assert [h["ip"] for h in combined["shodan"]["hosts"]] == [ORIGIN_IP]

    def test_without_a_port_scan_nothing_changes(self, recon_main, no_network):
        combined = {"shodan": _shodan_data()}
        before = copy.deepcopy(combined)
        recon_main._drop_shodan_cdn_ips(combined)
        assert combined == before

    @pytest.mark.parametrize("func", ["run_ip_recon", "run_domain_recon"])
    def test_both_fan_ins_drop_cdn_results_before_the_graph_write(self, recon_main, func):
        body = inspect.getsource(getattr(recon_main, func))
        merge = body.index("merge_port_scan_results(combined_result)")
        drop = body.index("_drop_shodan_cdn_ips(combined_result)")
        write = body.index('_graph_update_bg("update_graph_from_shodan"')
        assert merge < drop < write
