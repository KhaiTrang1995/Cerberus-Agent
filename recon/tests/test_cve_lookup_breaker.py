"""recon/helpers/cve_helpers.py run_cve_lookup through the nvd / vulners breakers.

The loop used to pay 30s plus a fixed 6s sleep per technology even after a
failure, and treated an NVD 403 per technology. `requests.get` and `time.sleep`
are patched; no test waits.
"""
from __future__ import annotations

from unittest import mock

import pytest
import requests

from recon.helpers import cve_helpers
from recon.helpers.cve_helpers import lookup_cves_nvd, run_cve_lookup


def _recon(n: int) -> dict:
    return {"http_probe": {"by_url": {
        f"https://h{i}.example.test": {"technologies": [f"nginx:1.{i}.0"]} for i in range(n)}}}


def _resp(status: int, body=None, headers=None):
    r = mock.MagicMock()
    r.status_code = status
    r.headers = headers if headers is not None else {}
    r.json.return_value = body if body is not None else {}
    r.text = ""
    return r


@pytest.fixture
def http():
    with mock.patch.object(cve_helpers.requests, "get") as get, \
            mock.patch.object(cve_helpers.time, "sleep") as sleep:
        yield get, sleep


def test_a_dead_nvd_is_asked_five_times_and_no_sleep_follows_a_failure(http, capsys):
    get, sleep = http
    get.side_effect = requests.exceptions.ReadTimeout("read timeout=30")
    out = run_cve_lookup(_recon(10), source="nvd", nvd_api_key="")
    assert get.call_count == 5
    # No 6s pacing after a failed lookup.
    assert [c for c in sleep.call_args_list if c.args and c.args[0] >= 6] == []
    printed = capsys.readouterr().out
    assert "[!][DEGRADED][CVE-NVD] nvd skipped for 5 technolog(ies) (ReadTimeout)" in printed
    assert out["technology_cves"]["technologies_checked"] == 10


def test_an_unknown_cpe_404_is_an_answer(http):
    get, _ = http
    get.return_value = _resp(404)
    run_cve_lookup(_recon(8), source="nvd", nvd_api_key="")
    assert get.call_count == 8


def test_an_nvd_key_refusal_is_fatal(http, capsys):
    get, _ = http
    get.return_value = _resp(404, headers={"message": "Invalid apiKey"})
    run_cve_lookup(_recon(6), source="nvd", nvd_api_key="bad-key")
    assert get.call_count == 1
    out = capsys.readouterr().out
    assert "404 key rejected - stopped for the rest of this run" in out
    assert "bad-key" not in out


def test_nvd_403_is_a_rate_limit_not_a_refused_key(http, capsys):
    get, _ = http
    get.return_value = _resp(403)
    run_cve_lookup(_recon(4), source="nvd", nvd_api_key="")
    # First 403 pauses and retries once, the second in a row opens the breaker.
    assert get.call_count == 2
    out = capsys.readouterr().out
    assert "Configure NVD API Key" in out
    assert out.count("Configure NVD API Key") == 1


def test_the_six_second_pacing_applies_only_without_a_key(http):
    get, sleep = http
    get.return_value = _resp(200, {"vulnerabilities": []})
    run_cve_lookup(_recon(3), source="nvd", nvd_api_key="")
    assert [c.args[0] for c in sleep.call_args_list] == [6.0, 6.0]
    sleep.reset_mock()
    from recon.helpers import circuit_breaker as cb
    cb.reset_registry()
    run_cve_lookup(_recon(3), source="nvd", nvd_api_key="key")
    assert [c.args[0] for c in sleep.call_args_list] == [0.6, 0.6]


def test_vulners_warning_is_no_data_and_error_text_never_logged(http, capsys):
    get, _ = http
    get.return_value = _resp(200, {"result": "warning",
                                   "data": {"warning": "Nothing found SECRETISH"}})
    run_cve_lookup(_recon(7), source="vulners", vulners_api_key="vk")
    assert get.call_count == 7
    assert "SECRETISH" not in capsys.readouterr().out


def test_vulners_refused_key_in_body_is_fatal(http):
    get, _ = http
    get.return_value = _resp(200, {"result": "error",
                                   "data": {"error": "Wrong API key", "errorCode": 157}})
    run_cve_lookup(_recon(5), source="vulners", vulners_api_key="vk")
    assert get.call_count == 1


def test_exception_text_with_a_key_is_never_printed(http, capsys):
    get, _ = http
    get.side_effect = requests.exceptions.ConnectionError(
        "HTTPSConnectionPool(host='vulners.com'): url: /api/v3/burp/software/?apiKey=SECRETVK")
    lookup_cves_nvd("nginx", "1.2.3", api_key="")
    run_cve_lookup(_recon(2), source="vulners", vulners_api_key="SECRETVK")
    assert "SECRETVK" not in capsys.readouterr().out


def test_public_lookups_keep_returning_lists(http):
    get, _ = http
    get.return_value = _resp(200, {"vulnerabilities": [
        {"cve": {"id": "CVE-2021-0001", "metrics": {}, "descriptions": []}}]})
    assert [c["id"] for c in lookup_cves_nvd("nginx", "1.2.3")] == ["CVE-2021-0001"]
    get.side_effect = requests.exceptions.ReadTimeout("x")
    assert lookup_cves_nvd("nginx", "1.2.4") == []
