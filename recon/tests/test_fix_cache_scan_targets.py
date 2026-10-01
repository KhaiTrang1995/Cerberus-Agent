"""Cache-poisoning scan targets: the right hosts, and a fair cap.

Two bugs in cache_scan.scanner._collect_target_urls:

1. extract_targets_from_recon returns (ips, hostnames, map), but the scanner
   unpacked it as (hostnames, ips, _). build_target_urls' fallback pass (hosts
   httpx never probed) therefore minted http(s)://<ip> URLs - an IPv6 one
   unbracketed - and the un-probed hostnames it exists for were never scanned.

2. The 200-URL cap was a head slice of a plain sorted() list: http:// sorts
   before https://, digits before letters, so the budget went to the first few
   hosts (bare IPs, plain http) and every later host was dropped silently.

Fixture names are under shop.test only.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.cache_scan import scanner  # noqa: E402
from recon.helpers.target_helpers import build_target_urls, extract_targets_from_recon  # noqa: E402


def _recon(subdomains=None, probed=(), endpoints=None):
    return {
        "domain": "shop.test",
        "dns": {"domain": {}, "subdomains": subdomains or {}},
        "http_probe": {"by_url": {u: {"url": u, "status_code": 200} for u in probed}},
        "resource_enum": {"by_base_url": endpoints or {}, "discovered_urls": []},
        "metadata": {"include_root_domain": False},
    }


def _sub(*ips):
    return {"has_records": True,
            "ips": {"ipv4": [i for i in ips if ":" not in i], "ipv6": [i for i in ips if ":" in i]}}


# --------------------------------------------------------------------------- #
# 1. the unpack
# --------------------------------------------------------------------------- #
def test_unprobed_hostnames_are_targets_not_their_ips():
    rd = _recon(subdomains={"www.shop.test": _sub("192.88.98.10"),
                            "v6.shop.test": _sub("2001:db8::10")},
                probed=["https://api.shop.test"])
    urls = scanner._collect_target_urls(rd, {})
    assert urls == ["http://v6.shop.test", "http://www.shop.test", "https://api.shop.test",
                    "https://v6.shop.test", "https://www.shop.test"]
    assert not any("192.88.98.10" in u or "2001:db8" in u for u in urls)


def test_at_or_under_the_cap_the_set_is_exactly_the_correct_unpack():
    rd = _recon(subdomains={f"h{i}.shop.test": _sub(f"192.88.98.{i}") for i in range(40)},
                probed=[f"https://p{i}.shop.test" for i in range(30)],
                endpoints={"https://p1.shop.test": {"endpoints": {
                    "/search": {"parameters": {"query": [{"name": "q", "sample_values": ["x"]}]}}}}})
    ips, hostnames, _ = extract_targets_from_recon(rd)
    expected = build_target_urls(hostnames, ips, rd, scan_all_ips=False)
    assert len(expected) <= scanner._MAX_URLS
    assert scanner._collect_target_urls(rd, {}) == expected


def test_roe_filter_still_applies_after_the_fix():
    rd = _recon(subdomains={"www.shop.test": _sub("192.88.98.10"),
                            "pay.secret.shop.test": _sub("192.88.98.11")})
    urls = scanner._collect_target_urls(rd, {"ROE_ENABLED": True,
                                             "ROE_EXCLUDED_HOSTS": ["secret.shop.test"]})
    assert urls == ["http://www.shop.test", "https://www.shop.test"]


# --------------------------------------------------------------------------- #
# 2. the cap
# --------------------------------------------------------------------------- #
def test_over_the_cap_every_host_keeps_a_share(capsys):
    probed = ([f"http://192.88.98.10/p{i:03d}" for i in range(150)]
              + [f"https://a.shop.test/p{i:03d}" for i in range(150)]
              + [f"https://z.shop.test/p{i:03d}" for i in range(10)])
    urls = scanner._collect_target_urls(_recon(probed=probed), {})
    assert len(urls) == scanner._MAX_URLS
    hosts = {u.split("/")[2] for u in urls}
    assert hosts == {"192.88.98.10", "a.shop.test", "z.shop.test"}
    # Round-robin: z keeps all 10, the remaining 190 split evenly.
    assert sum("z.shop.test" in u for u in urls) == 10
    assert sum("a.shop.test" in u for u in urls) == 95
    assert sum("192.88.98.10" in u for u in urls) == 95
    assert urls == sorted(urls)                                    # input order kept
    out = capsys.readouterr().out
    assert "scanning 200 of 310 URL(s)" in out and "dropped 110" in out


def test_tight_budget_prefers_hostnames_and_https():
    probed = []
    for i in range(150):
        probed += [f"http://h{i:03d}.shop.test", f"https://h{i:03d}.shop.test"]
    probed += [f"https://192.88.98.{i}" for i in range(60)]
    urls = scanner._collect_target_urls(_recon(probed=probed), {})
    assert len(urls) == scanner._MAX_URLS
    named = [u for u in urls if "shop.test" in u]
    # Round one gives every hostname its https URL before any host gets a second.
    assert {u for u in named if u.startswith("https://")} == {
        f"https://h{i:03d}.shop.test" for i in range(150)}
    # The 50 left go to the next hosts in line: the bare IPs (round one).
    assert sum(u.startswith("https://192.88.98.") for u in urls) == 50
    assert not any(u.startswith("http://h") for u in urls)


def test_cap_helper_is_identity_at_or_below_the_cap(capsys):
    urls = [f"http://192.88.98.{i}" for i in range(5)]
    assert scanner._cap_urls(urls, 5) is urls
    assert capsys.readouterr().out == ""
