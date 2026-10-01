"""Stopping a GVM scan must not lose the targets it already scanned.

The scan writes the graph once, at the very end, and saves its JSON after every
target. `stop_gvm_scan` stopped and removed the container and never looked at
that JSON, so whatever the container could not write itself inside the grace
period (all of it, before the scan had a SIGTERM handler) was lost. It now
ingests the saved JSON before removing the container, as stop_github_hunt
does: upsert only, never a clear or a prune, because a stopped run did not
re-check every target.
"""

import asyncio
import json
import os
import sys
import tempfile
import time
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "recon_orchestrator"))
sys.path.insert(0, str(REPO))

import container_manager as cm_mod  # noqa: E402
from models import GvmState, GvmStatus  # noqa: E402

STAMP = "2026-09-30T10:00:00.000001"


def make_manager():
    m = cm_mod.ContainerManager.__new__(cm_mod.ContainerManager)
    m.client = MagicMock()
    m.gvm_states = {}
    m._docker_op_executor = ThreadPoolExecutor(max_workers=2)
    return m


class FakeNeo4j:
    """graph_db.Neo4jClient stand-in; records what the backstop asks of it."""

    def __init__(self, log, stamps=(), fail=None):
        self.log = log
        self.stamps = list(stamps)
        self.fail = fail
        self.driver = MagicMock()
        session = MagicMock()
        session.__enter__.return_value = session
        session.run.return_value.single.return_value = {"stamps": self.stamps}
        self.driver.session.return_value = session

    def __call__(self, *a, **k):
        self.log.append(("connect", k.get("uri")))
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def verify_connection(self):
        return True

    def update_graph_from_gvm_scan(self, gvm_data, user_id, project_id):
        if self.fail:
            raise self.fail
        self.log.append(("ingest", user_id, project_id, len(gvm_data["scans"])))
        return {"vulnerabilities_created": 1}

    def clear_gvm_data(self, *a, **k):
        self.log.append(("clear",))

    def prune_unseen_findings(self, *a, **k):
        self.log.append(("prune",))


class StopBackstopTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.out_dir = Path(self._tmp.name)
        self.log = []
        self.m = make_manager()
        self.m.GVM_OUTPUT_DIR = self.out_dir
        self.state = GvmState(
            project_id="p1", status=GvmStatus.RUNNING, container_id="c1",
            started_at=datetime.now(timezone.utc) - timedelta(minutes=5))
        self.m.gvm_states["p1"] = self.state
        self.container = MagicMock()
        self.container.status = "running"
        self.container.attrs = {"Config": {"Env": ["PROJECT_ID=p1", "USER_ID=u1",
                                                   "NEO4J_PASSWORD=x"]}}
        self.container.stop.side_effect = lambda **k: self.log.append(("stop", k.get("timeout")))
        self.container.remove.side_effect = lambda **k: self.log.append(("remove",))
        self.m.client.containers.get.return_value = self.container

    def write_results(self, scans=1, mtime=None, raw=None):
        path = self.out_dir / "gvm_p1.json"
        if raw is not None:
            path.write_text(raw)
        else:
            path.write_text(json.dumps({
                "metadata": {"scan_timestamp": STAMP, "target_domain": "example.com"},
                "scans": [{"status": "Done", "targets": [f"10.0.0.{i}"],
                           "vulnerabilities": []} for i in range(scans)],
                "summary": {"total_vulnerabilities": 0},
                "interrupted": "Stopped before every target was scanned",
            }))
        if mtime is not None:
            os.utime(path, (mtime, mtime))

    def stop(self, neo4j=None, **kwargs):
        neo4j = neo4j or FakeNeo4j(self.log)
        fake_graph_db = types.ModuleType("graph_db")
        fake_graph_db.Neo4jClient = neo4j
        with mock.patch.dict(sys.modules, {"graph_db": fake_graph_db}):
            return asyncio.run(self.m.stop_gvm_scan("p1", **kwargs))

    def kinds(self):
        return [e[0] for e in self.log]

    def test_the_saved_run_is_ingested_before_the_container_goes(self):
        self.write_results(scans=2)
        state = self.stop()
        self.assertIn(("ingest", "u1", "p1", 2), self.log)
        self.assertLess(self.kinds().index("ingest"), self.kinds().index("remove"))
        self.assertLess(self.kinds().index("stop"), self.kinds().index("ingest"))
        self.assertEqual(state.status, GvmStatus.IDLE)
        self.assertNotIn("p1", self.m.gvm_states)

    def test_a_stopped_run_is_never_cleared_or_pruned(self):
        self.write_results()
        self.stop()
        self.assertNotIn("clear", self.kinds())
        self.assertNotIn("prune", self.kinds())

    def test_a_file_from_an_earlier_run_is_left_alone(self):
        """A run stopped before its first target finished has saved nothing; the
        file on disk is the PREVIOUS run's, already in the graph."""
        self.write_results(mtime=time.time() - 3600)
        self.stop()
        self.assertNotIn("ingest", self.kinds())
        self.assertIn("remove", self.kinds())

    def test_nothing_is_written_twice_when_the_scan_wrote_it_itself(self):
        self.write_results()
        self.stop(neo4j=FakeNeo4j(self.log, stamps=[STAMP]))
        self.assertNotIn("ingest", self.kinds())

    def test_a_run_with_no_tenant_is_refused(self):
        self.container.attrs = {"Config": {"Env": ["PROJECT_ID=p1"]}}
        self.write_results()
        self.stop()
        self.assertNotIn("ingest", self.kinds())

    def test_an_empty_or_unreadable_file_is_skipped(self):
        for raw in ('{"metadata": {}, "scans": []}', '{"scans": [', ""):
            with self.subTest(raw=raw):
                self.log.clear()
                self.m.gvm_states["p1"] = self.state
                self.state.status = GvmStatus.RUNNING
                self.write_results(raw=raw)
                self.stop()
                self.assertNotIn("ingest", self.kinds())
                self.assertIn("remove", self.kinds())

    def test_a_failing_ingest_never_fails_the_stop(self):
        self.write_results()
        state = self.stop(neo4j=FakeNeo4j(self.log, fail=RuntimeError("neo4j down")))
        self.assertEqual(state.status, GvmStatus.IDLE)
        self.assertIn("remove", self.kinds())

    def test_a_run_with_no_known_start_is_skipped(self):
        """An orphan container adopted after an orchestrator restart has no
        start time, so nothing can tell its file from an older one."""
        self.state.started_at = None
        self.write_results()
        self.stop()
        self.assertNotIn("ingest", self.kinds())

    def test_the_grace_period_is_unchanged(self):
        self.write_results()
        self.stop()
        self.assertIn(("stop", 10), self.log)
        self.log.clear()
        self.m.gvm_states["p1"] = self.state
        self.state.status = GvmStatus.RUNNING
        self.stop(timeout=5)
        self.assertIn(("stop", 5), self.log)

    def test_an_idle_project_is_not_touched(self):
        self.state.status = GvmStatus.COMPLETED
        self.container.status = "exited"
        self.container.attrs["State"] = {"ExitCode": 0}
        self.write_results()
        self.stop()
        self.assertNotIn("stop", self.kinds())
        self.assertNotIn("ingest", self.kinds())


if __name__ == "__main__":
    unittest.main()
