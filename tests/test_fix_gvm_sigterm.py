"""Stopping a GVM scan must keep what it scanned and stop the gvmd task.

The scan container runs `python gvm_scan/main.py` as PID 1 with no init. The
kernel ignores any signal PID 1 has no handler for, and main.py installed none,
so every stop sat out the grace period and was SIGKILLed: the graph is written
once at the very end, so nothing of the run reached it, and the OpenVAS task
it had started kept scanning with nobody left to read the report.

Mirrors tests/test_github_hunt_sigterm.py, plus the flow through
run_vulnerability_scan (tests/gvm_flow_fake.py) and scan_targets' cleanup.
"""

import os
import signal
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scanners"))

from gvm_flow_fake import FakeScanner, GvmFlowTestCase, ok  # noqa: E402
from gvm_scan import gvm_scanner as gvm_mod  # noqa: E402
from gvm_scan import main as gvm_main  # noqa: E402


class _RestoresSigterm(unittest.TestCase):
    def setUp(self):
        super().setUp()
        previous = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, previous)


class TestTheHandler(_RestoresSigterm):
    def setUp(self):
        super().setUp()
        for name in ("_STOP_REQUESTED", "_STOP_INTERRUPTS_SCAN"):
            if hasattr(gvm_main, name):
                self.addCleanup(setattr, gvm_main, name, getattr(gvm_main, name))

    def test_a_handler_is_installed(self):
        gvm_main._install_sigterm_handler()
        self.assertNotIn(signal.getsignal(signal.SIGTERM), (signal.SIG_DFL, signal.SIG_IGN),
                         "PID 1 ignores SIGTERM without a handler; the stop is a SIGKILL")

    def test_during_the_scan_sigterm_ends_it_through_except_exception(self):
        gvm_main._install_sigterm_handler()
        gvm_main._STOP_INTERRUPTS_SCAN = True
        with self.assertRaises(KeyboardInterrupt):
            try:
                os.kill(os.getpid(), signal.SIGTERM)
            except Exception:
                self.fail("SIGTERM was swallowed by scan_targets' `except Exception`")

    def test_during_the_write_sigterm_is_noted_not_raised(self):
        gvm_main._install_sigterm_handler()
        gvm_main._STOP_INTERRUPTS_SCAN = False
        gvm_main._STOP_REQUESTED = False
        os.kill(os.getpid(), signal.SIGTERM)
        self.assertTrue(gvm_main._STOP_REQUESTED)


class TestAStopKeepsTheScannedTargets(_RestoresSigterm, GvmFlowTestCase):
    def scan(self, outcomes):
        # An escaping KeyboardInterrupt would end the whole pytest session
        # rather than fail this test.
        try:
            return super().scan(outcomes)
        except KeyboardInterrupt:
            self.fail("the stop escaped run_vulnerability_scan: nothing was written")

    def outcomes(self, at="10.0.0.3", stop=KeyboardInterrupt()):
        out = {ip: ok(ip) for ip in self.IPS}
        out.update({"a.example.com": ok("a.example.com"), at: stop})
        return out

    def test_the_run_returns_with_what_it_scanned(self):
        results, scanner = self.scan(self.outcomes())
        self.assertEqual(results.get("interrupted"), "Stopped before every target was scanned")
        self.assertEqual([s["targets"][0] for s in results["scans"]], ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(scanner.disconnected, 1)

    def test_the_partial_results_are_saved_and_written(self):
        self.scan(self.outcomes())
        self.assertIn(("save", 2), self.log)
        writes = self.events("write")
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][1], ["10.0.0.1", "10.0.0.2"])

    def test_a_stopped_run_neither_clears_nor_prunes(self):
        self.scan(self.outcomes())
        self.assertEqual(self.events("clear"), [])
        self.assertEqual(self.events("prune"), [])

    def test_a_real_sigterm_mid_scan_does_the_same(self):
        gvm_main._install_sigterm_handler()

        def deliver():
            os.kill(os.getpid(), signal.SIGTERM)
            return ok("never")
        results, _ = self.scan(self.outcomes(stop=deliver))
        self.assertIn("interrupted", results)
        self.assertEqual(len(self.events("write")), 1)
        self.assertEqual(self.events("prune"), [])

    def test_a_stop_during_the_write_lets_it_finish_and_skips_the_prune(self):
        gvm_main._install_sigterm_handler()
        self.on_write = lambda _r: os.kill(os.getpid(), signal.SIGTERM)
        complete = {**{ip: ok(ip) for ip in self.IPS}, "a.example.com": ok("a.example.com")}
        results, _ = self.scan(complete)
        self.assertNotIn("interrupted", results)
        self.assertEqual(len(self.events("write")), 1)
        self.assertEqual(self.events("prune"), [],
                         "a stopped container pruned on its way out")

    def test_main_reports_the_interrupt_after_writing(self):
        scanner = FakeScanner(self.outcomes(), self.log)
        with mock.patch.object(gvm_main, "GVMScanner", scanner), \
                mock.patch.object(gvm_main, "PROJECT_ID", "p1"), \
                mock.patch.object(gvm_main, "load_project_settings"):
            code = gvm_main.main()
        self.assertEqual(code, 130)
        self.assertEqual(len(self.events("write")), 1)

    def test_an_uninterrupted_run_still_exits_zero_and_prunes(self):
        complete = {**{ip: ok(ip) for ip in self.IPS}, "a.example.com": ok("a.example.com")}
        scanner = FakeScanner(complete, self.log)
        with mock.patch.object(gvm_main, "GVMScanner", scanner), \
                mock.patch.object(gvm_main, "PROJECT_ID", "p1"), \
                mock.patch.object(gvm_main, "load_project_settings"):
            code = gvm_main.main()
        self.assertEqual(code, 0)
        self.assertEqual(len(self.events("prune")), 1)


class TestScanTargetsStopsTheGvmdTask(unittest.TestCase):
    def _scanner(self, wait):
        s = gvm_mod.GVMScanner.__new__(gvm_mod.GVMScanner)
        s.gmp = mock.Mock()
        s.create_target = mock.Mock(return_value="tgt-1")
        s.create_task = mock.Mock(return_value="task-1")
        s.start_task = mock.Mock(return_value="rep-1")
        s.wait_for_task = wait
        return s

    def test_an_interrupt_stops_then_deletes_the_task(self):
        s = self._scanner(mock.Mock(side_effect=KeyboardInterrupt()))
        with self.assertRaises(KeyboardInterrupt):
            s.scan_targets(targets=["10.0.0.1"], target_name="IP_10_0_0_1", cleanup=True)
        s.gmp.stop_task.assert_called_once_with("task-1")
        names = [c[0] for c in s.gmp.method_calls]
        self.assertLess(names.index("stop_task"), names.index("delete_task"))
        s.gmp.delete_target.assert_called_once()

    def test_the_task_is_stopped_even_when_cleanup_is_off(self):
        s = self._scanner(mock.Mock(side_effect=KeyboardInterrupt()))
        with self.assertRaises(KeyboardInterrupt):
            s.scan_targets(targets=["10.0.0.1"], target_name="x", cleanup=False)
        s.gmp.stop_task.assert_called_once_with("task-1")
        s.gmp.delete_task.assert_not_called()

    def test_a_failing_stop_does_not_replace_the_interrupt(self):
        s = self._scanner(mock.Mock(side_effect=KeyboardInterrupt()))
        s.gmp.stop_task.side_effect = OSError("socket closed")
        with self.assertRaises(KeyboardInterrupt):
            s.scan_targets(targets=["10.0.0.1"], target_name="x", cleanup=False)

    def test_a_normal_scan_never_stops_its_task(self):
        s = self._scanner(mock.Mock(return_value=("Done", None)))
        result = s.scan_targets(targets=["10.0.0.1"], target_name="x", cleanup=True)
        self.assertEqual(result["error"], "No report generated")
        s.gmp.stop_task.assert_not_called()
        s.gmp.delete_task.assert_called_once_with("task-1", ultimate=True)

    def test_an_ordinary_failure_is_still_an_error_result(self):
        s = self._scanner(mock.Mock(side_effect=RuntimeError("Task failed: Interrupted")))
        result = s.scan_targets(targets=["10.0.0.1"], target_name="x", cleanup=False)
        self.assertEqual(result["status"], "error")
        s.gmp.stop_task.assert_not_called()


if __name__ == "__main__":
    unittest.main()
