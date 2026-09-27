"""
Unit tests for Censys OSINT enrichment (recon/main_recon_modules/censys_enrich.py).

Mocks requests.get for the Censys Platform API v3.
Censys uses Bearer-token auth (Personal Access Token + Organization ID).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "recon" / "main_recon_modules"))

from censys_enrich import run_censys_enrichment, run_censys_enrichment_isolated


def _combined_result(with_ip: bool = True) -> dict:
    dns = {"domain": {"ips": {"ipv4": ["1.2.3.4"] if with_ip else []}}, "subdomains": {}}
    return {
        "domain": "example.com",
        "metadata": {"ip_mode": False, "modules_executed": []},
        "dns": dns,
    }


def _mock_response(status_code: int = 200, json_data: dict | None = None, text: str = "") -> MagicMock:
    m = MagicMock()
    m.status_code = status_code
    m.text = text or ""
    if json_data is not None:
        m.json.return_value = json_data
    return m


def _censys_host_json() -> dict:
    return {
        "result": {
            "ip": "1.2.3.4",
            "services": [
                {"port": 443, "transport_protocol": "tcp", "service_name": "http"},
            ],
            "location": {"country": "US", "city": "NYC"},
            "autonomous_system": {"asn": 12345, "name": "TestASN"},
            "operating_system": {"product": "Linux"},
            "last_updated_at": "2024-01-01",
        }
    }


class TestCensysEnrich(unittest.TestCase):
    """Censys host enrichment with mocked HTTP."""

    def _settings(self, **overrides) -> dict:
        base = {
            "CENSYS_ENABLED": True,
            "CENSYS_API_TOKEN": "token-test",
            "CENSYS_ORG_ID": "org-test",
        }
        base.update(overrides)
        return base

    @patch("censys_enrich.time.sleep")
    @patch("censys_enrich.requests.get")
    def test_enrichment_success(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _censys_host_json())
        cr = _combined_result()
        out = run_censys_enrichment(cr, self._settings())

        self.assertIn("censys", out)
        hosts = out["censys"]["hosts"]
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["ip"], "1.2.3.4")
        self.assertEqual(hosts[0]["location"]["country"], "US")
        self.assertEqual(hosts[0]["location"]["city"], "NYC")
        self.assertEqual(hosts[0]["autonomous_system"]["asn"], 12345)
        self.assertEqual(hosts[0]["autonomous_system"]["name"], "TestASN")
        self.assertEqual(hosts[0]["os"], "Linux")
        self.assertEqual(len(hosts[0]["services"]), 1)
        self.assertEqual(hosts[0]["services"][0]["port"], 443)

        mock_get.assert_called()
        args, kwargs = mock_get.call_args
        self.assertIn("api.platform.censys.io/v3/global/asset/host/", str(args[0]))
        self.assertIn("Bearer token-test", kwargs.get("headers", {}).get("Authorization", ""))

    @patch("censys_enrich.requests.get")
    def test_missing_api_key(self, mock_get):
        cr = _combined_result()
        for settings in (
            self._settings(CENSYS_API_TOKEN=""),
            self._settings(CENSYS_ORG_ID=""),
        ):
            out = run_censys_enrichment(cr, settings)
            self.assertNotIn("censys", out)
        mock_get.assert_not_called()

    @patch("censys_enrich.time.sleep")
    @patch("censys_enrich.requests.get")
    def test_http_error(self, mock_get, _sleep):
        for code in (500, 502):
            with self.subTest(code=code):
                mock_get.reset_mock()
                mock_get.return_value = _mock_response(code, {}, text="err")
                cr = _combined_result()
                out = run_censys_enrichment(cr, self._settings())
                self.assertEqual(out["censys"]["hosts"], [])

    @patch("censys_enrich.time.sleep")
    @patch("censys_enrich.requests.get")
    def test_auth_error_stops(self, mock_get, _sleep):
        """401/403 should stop all further fetches (treated like rate limit)."""
        mock_get.return_value = _mock_response(401, {}, text="unauthorized")
        cr = _combined_result()
        out = run_censys_enrichment(cr, self._settings())
        self.assertEqual(out["censys"]["hosts"], [])

    @patch("censys_enrich.time.sleep")
    @patch("censys_enrich.requests.get")
    def test_rate_limit(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(429, {}, text="rate limit")
        cr = _combined_result()
        out = run_censys_enrichment(cr, self._settings())
        self.assertEqual(out["censys"]["hosts"], [])

    @patch("censys_enrich.time.sleep")
    @patch("censys_enrich.requests.get")
    def test_empty_results(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, {"result": None})
        cr = _combined_result()
        out = run_censys_enrichment(cr, self._settings())
        self.assertEqual(out["censys"]["hosts"], [])

        mock_get.reset_mock()
        cr_empty = _combined_result(with_ip=False)
        out2 = run_censys_enrichment(cr_empty, self._settings())
        self.assertEqual(out2["censys"]["hosts"], [])
        mock_get.assert_not_called()

    @patch("censys_enrich.time.sleep")
    @patch("censys_enrich.requests.get")
    def test_isolated_returns_subdict(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(200, _censys_host_json())
        combined = _combined_result()
        sub = run_censys_enrichment_isolated(combined, self._settings())
        self.assertIn("hosts", sub)
        self.assertEqual(len(sub["hosts"]), 1)
        self.assertNotIn("censys", combined)


def _ips(n: int) -> dict:
    return {"domain": "", "metadata": {"ip_mode": True,
                                       "expanded_ips": [f"1.2.3.{i}" for i in range(1, n + 1)]},
            "dns": {}}


class TestCensysCircuitBreaker(unittest.TestCase):
    def _settings(self, **overrides) -> dict:
        base = {"CENSYS_ENABLED": True, "CENSYS_API_TOKEN": "token-test",
                "CENSYS_ORG_ID": "org-test", "CENSYS_WORKERS": 1}
        base.update(overrides)
        return base

    @patch("censys_enrich.time.sleep")
    @patch("censys_enrich.requests.get")
    def test_five_timeouts_mean_the_sixth_ip_is_never_requested(self, mock_get, _sleep):
        """Timeouts and 5xx used to cost 30s per IP, for every IP."""
        import requests as req_lib
        mock_get.side_effect = req_lib.exceptions.ReadTimeout("read timeout=30")
        out = run_censys_enrichment(_ips(10), self._settings())
        self.assertEqual(mock_get.call_count, 5)
        (entry,) = out["censys"]["degraded"]
        self.assertEqual((entry["source"], entry["skipped"]), ("censys:host", 5))

    @patch("censys_enrich.time.sleep")
    @patch("censys_enrich.requests.get")
    def test_ten_404s_never_trip_it(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(404, {})
        out = run_censys_enrichment(_ips(10), self._settings())
        self.assertEqual(mock_get.call_count, 10)
        self.assertNotIn("degraded", out["censys"])

    @patch("censys_enrich.time.sleep")
    @patch("censys_enrich.requests.get")
    def test_a_refused_token_means_exactly_one_call(self, mock_get, _sleep):
        mock_get.return_value = _mock_response(401, {}, text="unauthorized")
        with patch("builtins.print") as fake_print:
            out = run_censys_enrichment(_ips(10), self._settings())
        self.assertEqual(mock_get.call_count, 1)
        printed = "\n".join(" ".join(map(str, c.args)) for c in fake_print.call_args_list)
        self.assertIn("401 key rejected - stopped for the rest of this run", printed)
        self.assertNotIn("token-test", printed)
        (entry,) = out["censys"]["degraded"]
        self.assertEqual((entry["source"], entry["outcome"], entry["skipped"]), ("censys", "fatal", 9))


if __name__ == "__main__":
    unittest.main()
