"""A TruffleHog run that did not finish must not delete what it did not re-find.

Every stop reaches the orchestrator's ingest with the artifact the container
left behind. The runner saves after each finding with `status: "in_progress"`
and only a finished run rewrites it as `completed`; a run that failed writes
`error` with no findings. The ingest used to ignore the status: it ran the
source-scoped pre-clear (DETACH DELETE of every untouched finding, asset and the
scan node) and then pruned, so stopping a scan two findings in replaced the
source's whole history with those two findings, and a failed run emptied it.

Driven through the shared fake Neo4j (tests/trufflehog_graph_fake.py), plus the
real runner for the artifact a stopped scan actually leaves on disk.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scanners"))

from trufflehog_graph_fake import FakeClient, finding, scan_payload  # noqa: E402


def _seed(client, source="github", kind="repository"):
    """A previous, completed run that found two secrets in two files."""
    client.update_graph_from_trufflehog(
        scan_payload(source, kind, [finding("acme/api", "a.py"),
                                    finding("acme/api", "b.py")]),
        "u1", "p1")


def _locations(client, source="github"):
    return sorted(f["location"] for f in client.findings(source))


class _PruneSpy:
    """Records prune calls; the fake session does not model the prune query."""

    def __init__(self):
        self.calls = []

    def __call__(self, user_id, project_id, sources, run_started_at, keep_hosts=()):
        self.calls.append((user_id, project_id, list(sources), run_started_at))
        return {"pruned": 0, "stale": 0, "revived": 0}


class TestAnUnfinishedRunKeepsWhatItDidNotReFind(unittest.TestCase):
    def test_a_stopped_run_keeps_the_findings_it_never_reached(self):
        c = FakeClient()
        _seed(c)
        c.update_graph_from_trufflehog(
            scan_payload("github", "repository", [finding("acme/api", "a.py")],
                         status="in_progress"),
            "u1", "p1")
        self.assertEqual(_locations(c), ["a.py", "b.py"],
                         "a stopped run deleted a finding it never re-checked")

    def test_an_errored_run_with_no_findings_deletes_nothing(self):
        c = FakeClient()
        _seed(c)
        deletes_before = len(c.store["deletes"])
        nodes_before = set(c.store["nodes"])
        c.update_graph_from_trufflehog(
            scan_payload("github", "repository", [], status="error",
                         error="failed to clone"),
            "u1", "p1")
        self.assertEqual(c.store["deletes"][deletes_before:], [],
                         "an errored run issued a DETACH DELETE")
        self.assertEqual(set(c.store["nodes"]), nodes_before)
        self.assertEqual(_locations(c), ["a.py", "b.py"])

    def test_an_unfinished_run_never_prunes(self):
        for status in ("in_progress", "error", "interrupted", None):
            with self.subTest(status=status):
                c = FakeClient()
                _seed(c)
                spy = _PruneSpy()
                c.prune_unseen_findings = spy
                payload = scan_payload("github", "repository",
                                       [finding("acme/api", "a.py")])
                if status is None:
                    payload.pop("status")
                else:
                    payload["status"] = status
                c.update_graph_from_trufflehog(payload, "u1", "p1")
                self.assertEqual(spy.calls, [], f"a {status!r} run pruned")

    def test_an_unfinished_run_still_writes_what_it_found(self):
        c = FakeClient()
        _seed(c)
        stats = c.update_graph_from_trufflehog(
            scan_payload("github", "repository", [finding("acme/api", "c.py")],
                         status="in_progress"),
            "u1", "p1")
        self.assertEqual(stats["findings_created"], 1)
        self.assertEqual(_locations(c), ["a.py", "b.py", "c.py"])
        scan = c.nodes_of("MultiscannerScan")
        self.assertEqual(len(scan), 1)
        self.assertEqual(scan[0]["status"], "in_progress")

    def test_upserting_without_the_clear_creates_no_duplicates(self):
        """No pre-clear means MERGE alone must keep one node per identity: the
        scan, the asset and the finding all MERGE on deterministic ids."""
        c = FakeClient()
        _seed(c)
        before = {k: v["id"] for k, v in c.store["nodes"].items()}
        merges_before = len(c.store["merge_keys"])
        for _ in range(2):
            c.update_graph_from_trufflehog(
                scan_payload("github", "repository",
                             [finding("acme/api", "a.py"), finding("acme/api", "b.py")],
                             status="in_progress"),
                "u1", "p1")
        after = {k: v["id"] for k, v in c.store["nodes"].items()}
        self.assertEqual(before, after)
        for label in ("MultiscannerScan", "MultiscannerRepository", "MultiscannerFinding"):
            ids = [n["id"] for n in c.nodes_of(label)]
            self.assertEqual(len(ids), len(set(ids)), f"duplicate {label}")
        for label, keys in c.store["merge_keys"][merges_before:]:
            self.assertEqual(keys, ("id", "project_id", "user_id"), label)

    def test_an_unfinished_run_of_one_source_leaves_other_sources_alone(self):
        c = FakeClient()
        _seed(c)
        _seed(c, source="docker", kind="image")
        c.update_graph_from_trufflehog(
            scan_payload("docker", "image", [], status="error"), "u1", "p1")
        self.assertEqual(_locations(c, "github"), ["a.py", "b.py"])
        self.assertEqual(_locations(c, "docker"), ["a.py", "b.py"])


class TestACompletedRunIsUnchanged(unittest.TestCase):
    """The normal path: clear the source, rebuild it, prune what is gone."""

    def test_a_completed_run_still_clears_rebuilds_and_prunes(self):
        c = FakeClient()
        _seed(c)
        spy = _PruneSpy()
        c.prune_unseen_findings = spy
        deletes_before = len(c.store["deletes"])
        c.update_graph_from_trufflehog(
            scan_payload("github", "repository", [finding("acme/api", "b.py")]),
            "u1", "p1")
        self.assertEqual(_locations(c), ["b.py"], "a completed run no longer replaces")
        swept = c.store["deletes"][deletes_before:]
        self.assertIn(("MultiscannerFinding", "github"), swept)
        self.assertIn(("MultiscannerScan", "github"), swept)
        self.assertEqual(len(spy.calls), 1)
        uid, pid, sources, since = spy.calls[0]
        self.assertEqual((uid, pid, sources), ("u1", "p1", ["github"]))
        self.assertTrue(since)

    def test_a_completed_run_that_wrote_nothing_still_does_not_prune(self):
        c = FakeClient()
        _seed(c)
        spy = _PruneSpy()
        c.prune_unseen_findings = spy
        c.update_graph_from_trufflehog(
            scan_payload("github", "repository", []), "u1", "p1")
        self.assertEqual(spy.calls, [])


class TestTheArtifactAStoppedScanLeavesBehind(unittest.TestCase):
    """End to end with the real runner: the container is killed after its first
    finding, so its artifact is the incremental save, never the final one."""

    def test_the_runner_artifact_of_a_stopped_scan_keeps_old_findings(self):
        from trufflehog_scan.job_config import load_job
        from trufflehog_scan.trufflehog_runner import TrufflehogRunner

        line = json.dumps({
            "DetectorName": "AWS", "DetectorDescription": "d", "Verified": False,
            "Redacted": "AKIA****",
            "SourceMetadata": {"Data": {"Github": {
                "repository": "https://github.com/acme/api.git", "file": "a.py",
                "line": 1, "commit": "c0ffee"}}},
        })

        def stopped_after_first_finding():
            yield line
            raise KeyboardInterrupt()   # what a stop looks like from inside

        class _Proc:
            stdout = stopped_after_first_finding()
            returncode = None

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            run_dir.mkdir()
            (run_dir / "job.json").write_text(json.dumps({
                "project_id": "p1", "user_id": "u1", "source": "github",
                "config": {"orgs": ["acme"]}, "run_dir": str(run_dir),
                "output_file": str(run_dir / "out.json"),
            }))
            job = load_job({"TRUFFLEHOG_JOB": str(run_dir / "job.json")})
            runner = TrufflehogRunner(job, env={})
            with patch("subprocess.Popen", return_value=_Proc()):
                with self.assertRaises(KeyboardInterrupt):
                    runner.run()
            artifact = json.loads((run_dir / "out.json").read_text())

        self.assertEqual(artifact["status"], "in_progress")
        self.assertEqual(len(artifact["findings"]), 1)

        c = FakeClient()
        c.update_graph_from_trufflehog(
            scan_payload("github", "repository", [
                finding("https://github.com/acme/api.git", "a.py"),
                finding("https://github.com/acme/api.git", "z.py"),
            ]), "u1", "p1")
        c.update_graph_from_trufflehog(artifact, "u1", "p1")
        self.assertIn("z.py", _locations(c),
                      "the stopped scan's artifact deleted a finding it never reached")


if __name__ == "__main__":
    unittest.main()
