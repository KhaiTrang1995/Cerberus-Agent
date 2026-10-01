"""A GVM run must not delete what it did not scan.

Two ways it did:

* An ABORTED run (three consecutive failed targets) fell through to the graph
  write and then to a project-wide `prune_unseen_findings(["gvm"])` with no
  `keep_hosts`, so every target after the abort point, and every target that
  failed, lost its findings. A run where one target failed did the same to
  that target.
* `clear_gvm_data` ran BEFORE the first target was scanned. It deletes every
  untouched ExploitGvm (a finding, and the one that makes things "proven"),
  the GVM-only Technology/Certificate/Traceroute nodes and GVM's
  USES_TECHNOLOGY edges, so a run that then aborted, could not reach gvmd, or
  found no targets had already destroyed them for targets it never reached.

The flow is driven through the real run_vulnerability_scan with the scanner,
the graph client and the file writes faked.
"""

import re
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scanners"))

from gvm_flow_fake import FakeScanner, GvmFlowTestCase, failed, ok  # noqa: E402
from graph_db.mixins.base_mixin import BaseMixin, keep_host_patterns  # noqa: E402
from gvm_scan import main as gvm_main  # noqa: E402


class TestAnAbortedRunPrunesNothing(GvmFlowTestCase):
    def outcomes(self):
        return {"10.0.0.1": ok("10.0.0.1", 2),
                "10.0.0.2": failed("10.0.0.2"), "10.0.0.3": failed("10.0.0.3"),
                "10.0.0.4": failed("10.0.0.4"),
                "10.0.0.5": ok("10.0.0.5"), "a.example.com": ok("a.example.com")}

    def test_the_abort_still_happens_and_is_recorded(self):
        results, _ = self.scan(self.outcomes())
        self.assertIn("aborted", results)
        scanned = [e[1] for e in self.events("scan")]
        self.assertEqual(scanned, ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])

    def test_an_aborted_run_does_not_prune(self):
        self.scan(self.outcomes())
        self.assertEqual(self.events("prune"), [],
                         "an aborted run pruned the targets it never reached")

    def test_an_aborted_run_does_not_clear(self):
        self.scan(self.outcomes())
        self.assertEqual(self.events("clear"), [],
                         "an aborted run cleared ExploitGvm and GVM assets up front")

    def test_an_aborted_run_still_writes_what_it_found(self):
        self.scan(self.outcomes())
        writes = self.events("write")
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][1], ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])


class TestAFailedTargetKeepsItsFindings(GvmFlowTestCase):
    def test_a_failed_ip_is_kept_out_of_the_prune(self):
        self.scan({"10.0.0.1": ok("10.0.0.1"), "10.0.0.2": failed("10.0.0.2"),
                   "10.0.0.3": ok("10.0.0.3"), "10.0.0.4": ok("10.0.0.4"),
                   "10.0.0.5": ok("10.0.0.5"), "a.example.com": ok("a.example.com")})
        prunes = self.events("prune")
        self.assertEqual(len(prunes), 1)
        self.assertEqual(prunes[0][3], ["10.0.0.2"])

    def test_a_failed_hostname_is_kept_out_of_the_prune(self):
        self.scan({**{ip: ok(ip) for ip in self.IPS},
                   "a.example.com": failed("a.example.com")})
        self.assertEqual(self.events("prune")[0][3], ["a.example.com"])

    def test_a_target_with_no_report_counts_as_failed(self):
        no_report = dict(ok("10.0.0.3", 0), error="No report generated")
        self.scan({**{ip: ok(ip) for ip in self.IPS}, "10.0.0.3": no_report,
                   "a.example.com": ok("a.example.com")})
        self.assertEqual(self.events("prune")[0][3], ["10.0.0.3"])

    def test_a_run_with_a_failed_target_does_not_clear(self):
        """The clear deletes every untouched ExploitGvm, including the failed
        target's; the prune (which spares kept hosts) handles the rest."""
        self.scan({**{ip: ok(ip) for ip in self.IPS}, "10.0.0.2": failed("10.0.0.2"),
                   "a.example.com": ok("a.example.com")})
        self.assertEqual(self.events("clear"), [])


class TestTheUpFrontClearIsGone(GvmFlowTestCase):
    def test_no_clear_when_gvm_is_unreachable(self):
        scanner = FakeScanner({}, self.log)
        scanner.connect = lambda *a, **k: False
        with mock.patch.object(gvm_main, "GVMScanner", scanner):
            results = gvm_main.run_vulnerability_scan(domain="example.com", project_id="p1")
        self.assertIn("error", results)
        self.assertEqual(self.events("clear"), [])

    def test_no_clear_when_there_are_no_targets(self):
        self.IPS, self.HOSTS = [], []
        results, _ = self.scan({})
        self.assertEqual(results.get("error"), "No targets found")
        self.assertEqual(self.events("clear"), [])


class TestACompleteRunIsUnchanged(GvmFlowTestCase):
    """Same clear, same write, same prune; only the clear's moment moved, from
    before the first target to just before the write."""

    def complete(self):
        return {**{ip: ok(ip) for ip in self.IPS}, "a.example.com": ok("a.example.com")}

    def test_it_clears_then_writes_then_prunes(self):
        self.scan(self.complete())
        clear, write, prune = self.index("clear"), self.index("write"), self.index("prune")
        self.assertLess(clear, write)
        self.assertLess(write, prune)
        self.assertEqual(self.events("clear"), [("clear", "u1", "p1")])

    def test_the_prune_is_project_wide_on_gvm_with_nothing_kept(self):
        self.scan(self.complete())
        (_, sources, since, keep), = self.events("prune")
        self.assertEqual(sources, ["gvm"])
        self.assertEqual(keep, [])
        self.assertTrue(since)

    def test_the_run_start_is_taken_before_the_first_target(self):
        self.scan(self.complete())
        first_scan = self.events("scan")[0]
        self.assertIsNotNone(first_scan[2], "the prune timestamp was taken after scanning began")
        self.assertEqual(self.events("prune")[0][2], first_scan[2])

    def test_a_run_that_found_nothing_still_does_not_prune(self):
        self.scan({**{ip: ok(ip, 0) for ip in self.IPS}, "a.example.com": ok("a.example.com", 0)})
        self.assertEqual(self.events("prune"), [])
        self.assertEqual(len(self.events("clear")), 1)

    def test_every_target_is_scanned(self):
        self.scan(self.complete())
        self.assertEqual(sorted(e[1] for e in self.events("scan")),
                         sorted(self.IPS + self.HOSTS))


# ---------------------------------------------------------------------------
# keep_hosts reaches the properties GVM actually writes
# ---------------------------------------------------------------------------

class _Session:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        return mock.Mock(single=mock.Mock(return_value={"pruned": 0, "stale": 0, "revived": 0}))


class _Client(BaseMixin):
    def __init__(self):
        self.calls = []
        self.driver = mock.Mock(session=lambda: _Session(self.calls))


class TestKeepHostsCoversGvmFindings(unittest.TestCase):
    """GVM stores the host on Vulnerability/ExploitGvm as target_ip and
    target_hostname; a keep_hosts that does not check those keeps nothing."""

    def _prune_query(self, keep):
        c = _Client()
        c.prune_unseen_findings("u1", "p1", ["gvm"], "2026-01-01T00:00:00+00:00",
                                keep_hosts=keep)
        return next(q for q, p in c.calls if "DETACH DELETE" in q), c.calls

    def test_the_gvm_host_fields_are_checked(self):
        query, _ = self._prune_query(["10.0.0.2"])
        for field in ("target_ip", "target_hostname"):
            self.assertIn(f"n.{field}", query)

    def test_gvm_values_match_the_patterns(self):
        for host in ("10.0.0.2", "a.example.com", "2001:db8::1"):
            with self.subTest(host=host):
                self.assertTrue(any(re.fullmatch(p, host) for p in keep_host_patterns([host])))

    def test_without_keep_hosts_the_query_is_unchanged(self):
        c = _Client()
        c.prune_unseen_findings("u1", "p1", ["gvm"], "2026-01-01T00:00:00+00:00")
        query = next(q for q, p in c.calls if "DETACH DELETE" in q)
        self.assertNotIn("keep_patterns", query)
        self.assertNotIn("target_ip", query)


if __name__ == "__main__":
    unittest.main()
