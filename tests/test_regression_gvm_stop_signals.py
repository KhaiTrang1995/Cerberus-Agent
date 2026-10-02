"""GVM scan: a stop must never cut a save in half or escape the write.

* The SIGTERM handler raises KeyboardInterrupt while `_STOP_INTERRUPTS_SCAN`
  is set, and it was still set inside the `except ScanAborted` handler. A stop
  arriving during that handler's save escaped run_vulnerability_scan, so
  nothing reached the graph.
* save_vuln_results was open('w') + json.dump: interrupted half-way, it left a
  truncated file, so the orchestrator's stop backstop could not parse it and
  the previous save was gone too.
* The orchestrator re-ingests a stopped run's file unless it can tell the
  scan's own write landed, and the Domain stamp it checks does not exist in IP
  mode. A stopped run now re-saves its results with `graph_update` once its
  write has landed (never on a run nobody stopped).

Driven through the real run_vulnerability_scan with tests/gvm_flow_fake.py.
"""

import copy
import json
import os
import signal
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "scanners"), str(REPO_ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gvm_flow_fake import GvmFlowTestCase, failed, ok  # noqa: E402
from gvm_scan import gvm_scanner as gvm_mod  # noqa: E402
from gvm_scan import main as gvm_main  # noqa: E402


class _Flow(GvmFlowTestCase):
    def setUp(self):
        super().setUp()
        previous = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, previous)
        gvm_main._STOP_REQUESTED = False
        gvm_main._STOP_INTERRUPTS_SCAN = True
        self.saves = []

    def capture_saves(self, on_save=None):
        """Replace the flow fake's save with one that keeps what was saved."""
        def save(results, project_id):
            if on_save:
                on_save(len(self.saves))
            self.saves.append(copy.deepcopy(results))
            self.log.append(("save", len(results["scans"])))
        patcher = mock.patch.object(gvm_main, "save_vuln_results", side_effect=save)
        patcher.start()
        self.addCleanup(patcher.stop)

    def scan(self, outcomes):
        # An escaping KeyboardInterrupt would end the pytest session rather
        # than fail the test.
        try:
            return super().scan(outcomes)
        except KeyboardInterrupt:
            self.fail("the stop escaped run_vulnerability_scan: nothing was written")

    def complete(self):
        return {**{ip: ok(ip) for ip in self.IPS}, "a.example.com": ok("a.example.com")}


class TestRegressionGvmSigtermWindows(_Flow):
    def test_regression_gvm_sigterm_during_abort_save_escapes(self):
        gvm_main._install_sigterm_handler()
        self.capture_saves(on_save=lambda n: n == 0 and os.kill(os.getpid(), signal.SIGTERM))
        outcomes = {ip: failed(ip) for ip in self.IPS}
        outcomes["a.example.com"] = ok("a.example.com")
        results, _ = self.scan(outcomes)
        self.assertIn("aborted", results)
        self.assertTrue(self.saves, "the aborted run's results were never saved")
        self.assertEqual(len(self.events("write")), 1,
                         "a stop during the abort handler skipped the graph write")
        self.assertEqual(self.events("prune"), [])
        self.assertEqual(self.events("clear"), [])
        self.assertTrue(gvm_main._STOP_REQUESTED, "the late stop was not even noted")

    def test_regression_gvm_sigterm_after_scan_loop_is_only_noted(self):
        """Every target scanned, the stop lands in the final save: it is noted
        (no clear, no prune) and must not turn the save into an interrupt."""
        gvm_main._install_sigterm_handler()
        self.capture_saves(on_save=lambda n: n == 0 and os.kill(os.getpid(), signal.SIGTERM))
        results, _ = self.scan(self.complete())
        self.assertNotIn("interrupted", results)
        self.assertEqual(len(self.events("write")), 1)
        self.assertEqual(self.events("prune"), [])
        self.assertEqual(self.events("clear"), [])


class TestRegressionGvmSaveIsAtomic(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.out = Path(self._tmp.name)

    def test_regression_gvm_save_vuln_results_truncates_on_interrupt(self):
        previous = {"metadata": {"scan_timestamp": "t1"}, "scans": [{"targets": ["10.0.0.1"]}]}
        gvm_mod.save_vuln_results(previous, "p1", output_dir=self.out)
        real_dump = json.dump

        def dump_then_stop(obj, fh, **kwargs):
            fh.write('{"metadata": {"scan_timestamp": "t2"}, "scans": [')
            raise KeyboardInterrupt()

        with mock.patch.object(gvm_mod.json, "dump", side_effect=dump_then_stop):
            with self.assertRaises(KeyboardInterrupt):
                gvm_mod.save_vuln_results({"scans": [1, 2]}, "p1", output_dir=self.out)
        self.assertIs(json.dump, real_dump)
        saved = (self.out / "gvm_p1.json").read_text()
        self.assertEqual(json.loads(saved), previous,
                         "an interrupted save destroyed the previous one")
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ["gvm_p1.json"],
                         "the interrupted save left its temp file behind")

    def test_a_save_still_writes_the_same_bytes_with_the_same_mode(self):
        results = {"metadata": {"scan_timestamp": "t1"}, "scans": [{"x": "é"}]}
        path = gvm_mod.save_vuln_results(results, "p1", output_dir=self.out)
        self.assertEqual(path.read_text(), json.dumps(results, indent=2))
        umask = os.umask(0)
        os.umask(umask)
        self.assertEqual(path.stat().st_mode & 0o777, 0o666 & ~umask)


class TestRegressionGvmStoppedRunRecordsItsWrite(_Flow):
    def stopped_at(self, target="10.0.0.3"):
        out = self.complete()
        out[target] = KeyboardInterrupt()
        return out

    def test_regression_gvm_stopped_run_records_its_graph_write(self):
        self.capture_saves()
        self.scan(self.stopped_at())
        self.assertTrue(self.saves)
        self.assertIn("graph_update", self.saves[-1],
                      "the orchestrator cannot tell an IP-mode stopped run was written")
        last_save = max(i for i, e in enumerate(self.log) if e[0] == "save")
        self.assertLess(self.index("write"), last_save,
                        "the marker was saved before the write landed")

    def test_regression_gvm_stopped_run_records_a_write_noted_during_the_write(self):
        gvm_main._install_sigterm_handler()
        self.capture_saves()
        self.on_write = lambda _r: os.kill(os.getpid(), signal.SIGTERM)
        self.scan(self.complete())
        self.assertIn("graph_update", self.saves[-1])

    def test_a_failed_write_records_nothing(self):
        self.capture_saves()
        with mock.patch.object(gvm_main, "update_graph_from_gvm_results",
                               return_value={"error": "Neo4j connection failed"}):
            self.scan(self.stopped_at())
        self.assertFalse(any("graph_update" in s for s in self.saves),
                         "a write that never landed was recorded as landed")

    def test_a_run_nobody_stopped_saves_exactly_as_before(self):
        self.capture_saves()
        self.scan(self.complete())
        self.assertEqual(len(self.saves), 1)
        self.assertNotIn("graph_update", self.saves[0])
        self.assertEqual(len(self.events("prune")), 1)

    def test_an_aborted_run_nobody_stopped_saves_exactly_as_before(self):
        self.capture_saves()
        outcomes = {ip: failed(ip) for ip in self.IPS}
        outcomes["a.example.com"] = ok("a.example.com")
        results, _ = self.scan(outcomes)
        self.assertIn("aborted", results)
        self.assertEqual(len(self.saves), 1)
        self.assertNotIn("graph_update", self.saves[0])


if __name__ == "__main__":
    unittest.main()
