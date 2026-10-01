"""No-rate-limiting check: real URL sources, and only processed attempts count.

run_rate_limit_checks read recon_data["nuclei_scan"] and recon_data["httpx"],
which nothing writes: nuclei's URL lists live under vuln_scan.discovered_urls
and httpx's live URLs under http_probe.by_url. A host:port URL was dropped by
a netloc == hostname comparison. check_no_rate_limiting counted every non-429
answer as an accepted login attempt (404, 405, 403, 400, 5xx), and took any
page containing "rate" and "limit" ("generate", "unlimited") as throttling.

Hosts are under example.test (RFC 2606).
"""
from __future__ import annotations

from unittest import mock

import pytest
import requests

from recon.helpers import security_checks as sc

HOST = "app.example.test"
LOGIN = f"https://{HOST}/account/login"


def _resp(status=200, headers=None, text=""):
    r = mock.MagicMock()
    r.status_code = status
    r.headers = headers or {}
    r.text = text
    r.content = text.encode()
    r.history = []
    return r


def _probe(urls, post_status=200, post_text="", post_headers=None, get_status=200):
    get = mock.MagicMock(return_value=_resp(get_status, text="<form>login</form>"))
    post = mock.MagicMock(return_value=_resp(post_status, post_headers, post_text))
    with mock.patch.object(sc.requests, "get", get), \
         mock.patch.object(sc.requests, "post", post):
        findings = sc.check_no_rate_limiting(urls, HOST, timeout=1)
    return findings, post


def _run_checks(recon_data):
    get = mock.MagicMock(return_value=_resp(200, text="<form>login</form>"))
    post = mock.MagicMock(return_value=_resp(401, text="invalid credentials"))
    with mock.patch.object(sc.requests, "get", get), \
         mock.patch.object(sc.requests, "post", post):
        findings = sc.run_rate_limit_checks(
            [HOST], recon_data, {"no_rate_limiting": True}, timeout=1, max_workers=1)
    return findings, {c.args[0] for c in post.call_args_list}


FALLBACK_LOGIN = f"https://{HOST}/login"


class TestUrlSources:
    def test_http_probe_live_urls_are_used(self):
        recon = {"http_probe": {"by_url": {LOGIN: {"url": LOGIN, "status_code": 200}}}}
        findings, posted = _run_checks(recon)
        assert posted == {LOGIN}, "the fallback list was probed instead of the live URL"
        assert [f["url"] for f in findings] == [LOGIN]

    def test_nuclei_url_lists_under_vuln_scan_are_used(self):
        signin = f"https://{HOST}/api/auth/signin"
        recon = {"vuln_scan": {"discovered_urls": {
            "base_urls": [f"https://{HOST}"],
            "all_scanned_urls": [signin, f"https://{HOST}/about"],
            "dast_urls_with_params": [f"https://{HOST}/user/login?next=/home"],
        }}}
        _, posted = _run_checks(recon)
        assert posted == {signin, f"https://{HOST}/user/login"}

    def test_resource_enum_urls_are_still_used(self):
        recon = {"resource_enum": {"discovered_urls": [LOGIN]}}
        _, posted = _run_checks(recon)
        assert posted == {LOGIN}

    def test_without_any_auth_url_the_fallback_list_is_probed(self):
        _, posted = _run_checks({"http_probe": {"by_url": {}}})
        assert FALLBACK_LOGIN in posted and len(posted) == 12

    def test_a_url_with_an_explicit_port_belongs_to_its_host(self):
        ported = f"https://{HOST}:8443/login"
        findings, post = _probe([ported])
        assert {c.args[0] for c in post.call_args_list} == {ported}
        assert [f["url"] for f in findings] == [ported]


class TestWhatCountsAsAProcessedAttempt:
    @pytest.mark.parametrize("status", [200, 302, 401])
    def test_a_login_endpoint_answering_every_attempt_is_reported(self, status):
        findings, post = _probe([LOGIN], post_status=status, post_text="Invalid password")
        assert post.call_count == 10
        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "no_rate_limiting" and f["severity"] == "medium"
        assert f["url"] == LOGIN and f["hostname"] == HOST and f["requests_sent"] == 10

    @pytest.mark.parametrize("status", [400, 403, 404, 405, 410, 422, 500, 501, 502, 503])
    def test_an_answer_that_never_evaluated_credentials_is_not_reported(self, status):
        findings, post = _probe([LOGIN], post_status=status)
        assert findings == []
        assert post.call_count == 1, "kept hammering an endpoint that cannot be reported"

    def test_a_429_is_rate_limiting(self):
        findings, _ = _probe([LOGIN], post_status=429)
        assert findings == []

    @pytest.mark.parametrize("text", [
        "Rate limit exceeded", "rate-limited, slow down", "RATE_LIMIT", "ratelimit hit",
        "429 Too Many Requests", "Too many login attempts. Try again in 60 seconds.",
    ])
    def test_throttling_text_is_rate_limiting(self, text):
        findings, _ = _probe([LOGIN], post_status=200, post_text=text)
        assert findings == []

    @pytest.mark.parametrize("text", [
        "<script>generateToken(); var unlimitedPlan = true;</script>",
        "Please separate the fields. Character limit: 64.",
        "Accurate limits apply to your plan",
    ])
    def test_words_that_merely_contain_rate_and_limit_are_not_throttling(self, text):
        findings, _ = _probe([LOGIN], post_status=200, post_text=text)
        assert len(findings) == 1

    def test_retry_after_and_exhausted_quota_headers_still_count(self):
        assert _probe([LOGIN], post_headers={"Retry-After": "30"})[0] == []
        assert _probe([LOGIN], post_headers={"X-RateLimit-Remaining": "0"})[0] == []

    def test_a_404_on_the_pre_check_still_skips_the_endpoint(self):
        findings, post = _probe([LOGIN], get_status=404)
        assert findings == [] and post.call_count == 0

    def test_a_connection_error_mid_burst_is_not_reported(self):
        get = mock.MagicMock(return_value=_resp(200))
        post = mock.MagicMock(side_effect=[_resp(200)] * 3 + [requests.ConnectionError("x")])
        with mock.patch.object(sc.requests, "get", get), \
             mock.patch.object(sc.requests, "post", post):
            assert sc.check_no_rate_limiting([LOGIN], HOST, timeout=1) == []
