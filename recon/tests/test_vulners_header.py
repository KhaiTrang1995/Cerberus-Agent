"""
Vulners CVE lookup: the API key travels in the X-Api-Key header, never the URL.

Vulners stopped reading the key from query parameters on 2025-10-02. A request
carrying `?apiKey=` gets the Cloudflare challenge page (403 text/html) exactly
like an anonymous one, so every lookup failed and returned no CVEs.

Run with: ./redamon.sh test (recon section) or one file inside the recon image.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

_recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _recon_dir)

from helpers import cve_helpers
from helpers.cve_helpers import lookup_cves_vulners

TEST_KEY = "TESTKEY-0000-vulners-primary"
ROTATED_KEY = "TESTKEY-0000-vulners-rotated"

OK_BODY = {
    "result": "OK",
    "data": {
        "search": [
            {
                "id": "CVE-2021-23017",
                "type": "cve",
                "cvss": {"score": 7.7},
                "description": "A security issue in nginx resolver",
                "published": "2021-06-01T00:00:00",
                "href": "https://vulners.com/cve/CVE-2021-23017",
            }
        ]
    },
}


def _response(body):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = body
    resp.raise_for_status.return_value = None
    return resp


class _Rotator:
    """The two attributes and one method lookup_cves_vulners uses."""

    def __init__(self, key):
        self.current_key = key
        self.has_keys = True
        self.ticks = 0

    def tick(self):
        self.ticks += 1


class TestVulnersKeyHeader(unittest.TestCase):
    @patch.object(cve_helpers.requests, "get")
    def test_key_is_sent_as_header_not_query_param(self, mock_get):
        mock_get.return_value = _response(OK_BODY)

        cves = lookup_cves_vulners("nginx", "1.18.0", api_key=TEST_KEY)

        _, kwargs = mock_get.call_args
        self.assertEqual(kwargs["headers"], {"X-Api-Key": TEST_KEY})
        self.assertNotIn("apiKey", kwargs["params"])
        self.assertNotIn(TEST_KEY, str(kwargs["params"]))
        self.assertEqual(mock_get.call_args[0][0], cve_helpers.VULNERS_API_URL)
        # The parse path still works on the header-authenticated answer.
        self.assertEqual([c["id"] for c in cves], ["CVE-2021-23017"])
        self.assertEqual(cves[0]["source"], "vulners")
        self.assertEqual(cves[0]["severity"], "HIGH")

    @patch.object(cve_helpers.requests, "get")
    def test_rotator_key_wins_and_goes_in_the_header(self, mock_get):
        mock_get.return_value = _response(OK_BODY)
        rotator = _Rotator(ROTATED_KEY)

        lookup_cves_vulners("nginx", "1.18.0", api_key=TEST_KEY, key_rotator=rotator)

        _, kwargs = mock_get.call_args
        self.assertEqual(kwargs["headers"], {"X-Api-Key": ROTATED_KEY})
        self.assertNotIn("apiKey", kwargs["params"])
        self.assertEqual(rotator.ticks, 1)

    @patch.object(cve_helpers.requests, "get")
    def test_no_key_sends_no_auth_header(self, mock_get):
        mock_get.return_value = _response(OK_BODY)

        lookup_cves_vulners("nginx", "1.18.0", api_key=None)

        _, kwargs = mock_get.call_args
        self.assertEqual(kwargs["headers"], {})
        self.assertNotIn("apiKey", kwargs["params"])

    @patch.object(cve_helpers.requests, "get")
    def test_cloudflare_challenge_is_swallowed_as_no_cves(self, mock_get):
        # What an unauthenticated request gets: a 403 HTML challenge page.
        resp = MagicMock()
        resp.raise_for_status.side_effect = cve_helpers.requests.HTTPError("403 Forbidden")
        mock_get.return_value = resp

        self.assertEqual(lookup_cves_vulners("nginx", "1.18.0", api_key=TEST_KEY), [])

    @patch.object(cve_helpers.requests, "get")
    def test_no_version_makes_no_call(self, mock_get):
        self.assertEqual(lookup_cves_vulners("nginx", "", api_key=TEST_KEY), [])
        mock_get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
