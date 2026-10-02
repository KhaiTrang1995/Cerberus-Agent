"""keep_hosts must protect every hostname a skipped target can have.

`keep_host_patterns` drops any name outside a strict character set before it is
regex-escaped. The set had no underscore, so a skipped `my_host.example.com`
built no pattern and the prune deleted its findings; and a fully-qualified
`host.example.com.` kept its trailing dot, so its pattern never matched a
finding, which no writer stores with one.
"""

import re
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.base_mixin import keep_host_patterns  # noqa: E402


def matches(host, value):
    return any(re.fullmatch(p, value) for p in keep_host_patterns([host]))


class TestRegressionKeepHosts(unittest.TestCase):
    def test_regression_keep_hosts_drop_underscore_hostnames(self):
        for value in ("my_host.example.com", "https://my_host.example.com/login",
                      "my_host.example.com:8443", "_dmarc.example.com"):
            host = value.split("://")[-1].split("/")[0].split(":")[0]
            with self.subTest(value=value):
                self.assertTrue(matches(host, value),
                                f"skipped host {host} is not protected from the prune")

    def test_regression_keep_hosts_trailing_dot_never_matches(self):
        for value in ("host.example.com", "https://host.example.com/x", "host.example.com:443"):
            with self.subTest(value=value):
                self.assertTrue(matches("host.example.com.", value))
                self.assertTrue(matches("HOST.Example.COM. ", value))


class TestStrippingTheDot(unittest.TestCase):
    def test_only_one_trailing_dot_is_dropped(self):
        self.assertFalse(matches("host.example.com..", "host.example.com"))

    def test_a_bare_dot_never_becomes_an_empty_alternative(self):
        """Stripped, "." is empty, and an empty alternative would match every
        path-only value (an `endpoint` of "/login"), sparing unrelated findings."""
        self.assertEqual(keep_host_patterns([".", "", None, "  "]), [])


class TestEverythingElseIsUnchanged(unittest.TestCase):
    def test_an_underscore_name_matches_no_other_host(self):
        for value in ("myxhost.example.com", "my_host.example.com.evil.test",
                      "https://evil.test/?h=my_host.example.com"):
            with self.subTest(value=value):
                self.assertFalse(matches("my_host.example.com", value))

    def test_hostile_names_are_still_dropped(self):
        joined = "".join(keep_host_patterns(["a|b", "x*", "evil.com'); DROP", "[::1]",
                                             "a b.example.com", "a/b"]))
        self.assertEqual(joined, "")

    def test_existing_names_build_the_same_patterns(self):
        hosts = ["a.example.com", "198.51.100.7", "::1", "B.EXAMPLE.COM"]
        expected = (r"^(?:[a-z][a-z0-9+.\-]*://(?:[^/@]*@)?)?\[?(?:"
                    + "|".join(re.escape(h) for h in sorted({h.lower() for h in hosts}))
                    + r")\]?(?::[0-9]+)?(?:[/?#].*)?$")
        self.assertEqual(keep_host_patterns(hosts), [expected])


if __name__ == "__main__":
    unittest.main()
