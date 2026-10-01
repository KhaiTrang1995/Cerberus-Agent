"""Harness for driving the real gvm_scan.main.run_vulnerability_scan.

The GVM scanner, the Neo4j client and the result files are faked; every call
they receive lands in one ordered log, so a test can assert what happened and
in which order (clear before write, write before prune). Shared by the
abort/prune and the SIGTERM suites.
"""

import copy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
for p in (str(REPO_ROOT), str(REPO_ROOT / "scanners")):
    if p not in sys.path:
        sys.path.insert(0, p)

import graph_db  # noqa: E402
from gvm_scan import main as gvm_main  # noqa: E402


def ok(target, vulns=1):
    return {"status": "Done", "vulnerability_count": vulns, "hosts_scanned": 1,
            "severity_summary": {"high": vulns}, "vulnerabilities": [{"x": 1}] * vulns,
            "targets": [target], "scan_name": target}


def failed(target, error="Task failed: Interrupted"):
    return {"status": "error", "error": error, "vulnerabilities": [],
            "targets": [target], "scan_name": target}


class FakeScanner:
    """Answers scan_targets from a {target: result-or-exception} map."""

    def __init__(self, outcomes, log):
        self.outcomes = outcomes
        self.log = log
        self.disconnected = 0

    def __call__(self, *a, **k):
        return self

    def connect(self, *a, **k):
        return True

    def disconnect(self):
        self.disconnected += 1

    def scan_targets(self, targets, target_name, cleanup=None):
        target = targets[0]
        self.log.append(("scan", target, gvm_main._GVM_RUN_STARTED_AT))
        outcome = self.outcomes[target]
        if isinstance(outcome, BaseException):
            raise outcome
        if callable(outcome):
            return outcome()
        return copy.deepcopy(outcome)


class FakeGraph:
    """Stands in for Neo4jClient(); every call lands in the shared log."""

    def __init__(self, log):
        self.log = log

    def __call__(self, *a, **k):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def verify_connection(self):
        return True

    def clear_gvm_data(self, user_id, project_id):
        self.log.append(("clear", user_id, project_id))
        return {"vulnerabilities_deleted": 0, "technologies_deleted": 0,
                "cves_deleted": 0, "technologies_cleaned": 0}

    def prune_unseen_findings(self, user_id, project_id, sources, since, keep_hosts=()):
        self.log.append(("prune", list(sources), since, sorted(keep_hosts)))
        return {"pruned": 0, "stale": 0, "revived": 0}


class GvmFlowTestCase(unittest.TestCase):
    IPS = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]
    HOSTS = ["a.example.com"]

    #: Called with the results dict when the graph write runs; a test can
    #: replace it to act "during" the write.
    on_write = None

    def setUp(self):
        self.log = []
        gvm_main._GVM_RUN_STARTED_AT = None
        for name in ("_STOP_REQUESTED", "_STOP_INTERRUPTS_SCAN"):
            if hasattr(gvm_main, name):
                self.addCleanup(setattr, gvm_main, name, getattr(gvm_main, name))

        def write(results):
            if self.on_write:
                self.on_write(results)
            created = sum(len(s.get("vulnerabilities") or []) for s in results["scans"])
            self.log.append(("write", [s.get("targets", [None])[0] for s in results["scans"]],
                             dict(results)))
            return {"vulnerabilities_created": created}

        settings = {"SCAN_TARGETS": "both", "CLEANUP_AFTER_SCAN": True}
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patches = [
            mock.patch.object(gvm_main, "GVM_AVAILABLE", True),
            mock.patch.object(gvm_main, "USER_ID", "u1"),
            mock.patch.object(gvm_main, "load_recon_file",
                              return_value={"metadata": {"root_domain": "example.com"}}),
            mock.patch.object(gvm_main, "extract_targets_from_recon",
                              side_effect=lambda _r: (list(self.IPS), list(self.HOSTS))),
            mock.patch.object(gvm_main, "save_vuln_results",
                              side_effect=lambda r, p: self.log.append(("save", len(r["scans"])))),
            mock.patch.object(gvm_main, "update_graph_from_gvm_results", side_effect=write),
            mock.patch.object(gvm_main, "get_setting",
                              side_effect=lambda k, d=None: settings.get(k, d)),
            mock.patch.object(gvm_main.time, "sleep"),
            mock.patch.object(graph_db, "Neo4jClient", FakeGraph(self.log)),
            mock.patch.object(gvm_main, "OUTPUT_DIR", Path(tmp.name)),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def scan(self, outcomes):
        scanner = FakeScanner(outcomes, self.log)
        with mock.patch.object(gvm_main, "GVMScanner", scanner):
            results = gvm_main.run_vulnerability_scan(domain="example.com", project_id="p1")
        return results, scanner

    def events(self, kind):
        return [e for e in self.log if e[0] == kind]

    def index(self, kind):
        return next(i for i, e in enumerate(self.log) if e[0] == kind)
