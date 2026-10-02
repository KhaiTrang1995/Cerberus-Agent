"""A TruffleHog run that failed on part of its target must not prune the rest.

Every invocation runs with --fail-on-scan-errors, so a non-zero exit means some
of the target was never scanned. The runner still labels such a run `completed`
as soon as it found anything, and the graph write cleared and pruned the whole
source on `completed`. Scenario: a Docker source with images a and b; pulling b
hits Docker Hub's rate limit, a yields one secret, TruffleHog exits 1, and the
earlier finding in b is deleted although b was never looked at.

The fix keeps the status (`completed` is what the UI and the orchestrator read)
and adds `incomplete` to the artifact, only in that case; the writer clears and
prunes only a run that is completed and not incomplete.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "scanners"), str(REPO_ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from trufflehog_graph_fake import FakeClient, finding, scan_payload  # noqa: E402
from trufflehog_scan.job_config import JobConfig  # noqa: E402
from trufflehog_scan.trufflehog_runner import TrufflehogRunner  # noqa: E402

PULL_ERROR = json.dumps({
    "level": "error", "msg": "error scanning image",
    "error": "docker.io/acme/b:latest: toomanyrequests: You have reached your pull rate limit",
})


def docker_line(image, path="etc/app.env"):
    return json.dumps({
        "DetectorName": "AWS", "DetectorDescription": "d", "Verified": False,
        "Redacted": "AKIA****",
        "SourceMetadata": {"Data": {"Docker": {"image": image, "file": path, "layer": "sha256:1"}}},
    })


class _Stream:
    def __init__(self, text):
        self._text = text

    def read(self):
        return self._text


class _Proc:
    """The TruffleHog subprocess: emits JSONL on stdout, then exits."""

    def __init__(self, lines, returncode, stderr=""):
        self.stdout = iter(lines)
        self.stderr = _Stream(stderr)
        self.returncode = returncode

    def wait(self):
        return self.returncode


class _PruneSpy:
    def __init__(self):
        self.calls = []

    def __call__(self, user_id, project_id, sources, run_started_at, keep_hosts=()):
        self.calls.append(list(sources))
        return {"pruned": 0, "stale": 0, "revived": 0}


class _Harness(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def run_docker(self, lines, returncode, stderr=""):
        job = JobConfig(
            project_id="p1", user_id="u1", source="docker",
            config={"images": ["acme/a:latest", "acme/b:latest"]}, common={},
            run_dir=str(self.tmp / "run"),
            output_file=str(self.tmp / "trufflehog_p1_docker.json"),
        )
        runner = TrufflehogRunner(job, env={})
        with patch("subprocess.Popen", return_value=_Proc(lines, returncode, stderr)):
            runner.run()
        return json.loads(Path(runner.output_file).read_text())

    def seeded_client(self):
        """A previous complete run found one secret in each image."""
        c = FakeClient()
        c.update_graph_from_trufflehog(scan_payload("docker", "image", [
            finding("acme/a:latest", "etc/app.env"),
            finding("acme/b:latest", "etc/app.env"),
        ]), "u1", "p1")
        c.prune_spy = _PruneSpy()
        c.prune_unseen_findings = c.prune_spy
        return c


class TestRegressionTrufflehogPartialRun(_Harness):
    def test_regression_trufflehog_partial_run_prunes_unscanned_image(self):
        """End to end: the artifact the runner writes for the rate-limited pull
        must not delete image b's earlier finding."""
        artifact = self.run_docker([docker_line("acme/a:latest")], returncode=1,
                                   stderr=PULL_ERROR + "\n")
        c = self.seeded_client()
        c.update_graph_from_trufflehog(artifact, "u1", "p1")
        assets = sorted(f["asset"] for f in c.findings("docker"))
        self.assertIn("acme/b:latest", assets,
                      "a run that never pulled image b deleted image b's finding")
        self.assertEqual(c.prune_spy.calls, [], "a partly-failed run pruned its source")

    def test_regression_trufflehog_partial_run_artifact_is_marked_incomplete(self):
        artifact = self.run_docker([docker_line("acme/a:latest")], returncode=1,
                                   stderr=PULL_ERROR + "\n")
        self.assertEqual(artifact["status"], "completed",
                         "the UI/orchestrator vocabulary must not change")
        self.assertIs(artifact.get("incomplete"), True)
        self.assertIn("pull rate limit", artifact.get("incomplete_reason", ""))
        self.assertNotIn("error", artifact, "`error` is the failed-run signal")

    def test_regression_trufflehog_partial_run_writer_honours_the_marker(self):
        c = self.seeded_client()
        deletes_before = len(c.store["deletes"])
        c.update_graph_from_trufflehog(scan_payload(
            "docker", "image", [finding("acme/a:latest", "etc/app.env")],
            incomplete=True, incomplete_reason="pull failed"), "u1", "p1")
        self.assertEqual(c.store["deletes"][deletes_before:], [], "an incomplete run pre-cleared")
        self.assertEqual(c.prune_spy.calls, [])
        self.assertEqual(sorted(f["asset"] for f in c.findings("docker")),
                         ["acme/a:latest", "acme/b:latest"])

    def test_regression_trufflehog_partial_run_reason_without_an_error_record(self):
        artifact = self.run_docker([docker_line("acme/a:latest")], returncode=2)
        self.assertIs(artifact.get("incomplete"), True)
        self.assertIn("exited with code 2", artifact["incomplete_reason"])


class TestTheHealthyPathIsUnchanged(_Harness):
    """The paths the fix must leave exactly as they were."""

    def test_a_clean_run_writes_exactly_the_keys_it_always_did(self):
        artifact = self.run_docker([docker_line("acme/a:latest")], returncode=0)
        self.assertEqual(artifact["status"], "completed")
        self.assertEqual(set(artifact), {
            "source", "source_label", "asset_label", "asset_kind", "run_id", "target",
            "verification_enabled", "scan_start_time", "scan_end_time",
            "duration_seconds", "status", "statistics", "findings"})

    def test_a_failed_run_with_no_findings_is_still_an_error(self):
        artifact = self.run_docker([], returncode=1, stderr=PULL_ERROR + "\n")
        self.assertEqual(artifact["status"], "error")
        self.assertNotIn("incomplete", artifact)
        self.assertIn("pull rate limit", artifact["error"])

    def test_a_clean_completed_run_still_clears_and_prunes(self):
        artifact = self.run_docker([docker_line("acme/a:latest")], returncode=0)
        c = self.seeded_client()
        c.update_graph_from_trufflehog(artifact, "u1", "p1")
        self.assertEqual([f["asset"] for f in c.findings("docker")], ["acme/a:latest"])
        self.assertEqual(c.prune_spy.calls, [["docker"]])


if __name__ == "__main__":
    unittest.main()
