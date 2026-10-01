"""GitHub hunt: a run that did not cover everything must not prune or orphan.

Three defects shared one outcome, a finding deleted that nobody re-checked:

* A stopped, interrupted or errored hunt still pruned `github_hunt`, and its
  pre-clear deleted every GithubPath, which orphaned the findings of repos it
  never reached; the next run's orphan sweep then deleted them.
* Rate-limit and server errors were swallowed per file, per commit and per gist,
  so a throttled run looked complete. `scan_organization` read a rate-limited
  403 as "not an organisation", and `scan_user` dropped its remaining repos on
  any error.
* `repository_public`, which the triage reach factor reads, was never written.

PyGithub is stubbed with exception classes shaped like the real ones
(RateLimitExceededException subclasses GithubException and carries
status/data/headers), and the hunter is built via __new__, so nothing touches
the network.
"""

import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.base_mixin import BaseMixin  # noqa: E402
from graph_db.mixins.secret_mixin import SecretMixin  # noqa: E402


class GithubException(Exception):
    def __init__(self, status=None, data=None, headers=None, message=None):
        super().__init__(status, data)
        self.status = status
        self.data = data
        self.headers = headers
        self.message = message


class RateLimitExceededException(GithubException):
    pass


def _load_hunter_module():
    stub = types.ModuleType("github")
    stub.Github = object
    stub.Auth = types.SimpleNamespace(Token=lambda *a, **k: None)
    exc = types.ModuleType("github.GithubException")
    exc.RateLimitExceededException = RateLimitExceededException
    exc.GithubException = GithubException
    stub.GithubException = exc
    with mock.patch.dict(sys.modules, {"github": stub, "github.GithubException": exc}):
        spec = importlib.util.spec_from_file_location(
            "_ghh_coverage_under_test",
            REPO_ROOT / "scanners" / "github_secret_hunt" / "github_secret_hunt.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


ghh = _load_hunter_module()

_STATS_KEYS = ("repos_scanned", "files_scanned", "commits_scanned", "gists_scanned",
               "secrets_found", "sensitive_files", "high_entropy")


def make_hunter(**settings):
    hunter = ghh.GitHubSecretHunter.__new__(ghh.GitHubSecretHunter)
    hunter.settings = {"GITHUB_OUTPUT_JSON": False, "GITHUB_SCAN_COMMITS": True,
                       "GITHUB_SCAN_GISTS": True, "GITHUB_MAX_COMMITS": 100, **settings}
    hunter.target = "acme"
    hunter.project_id = "p1"
    hunter.target_repos = set()
    hunter.findings = []
    hunter.scanned_repos = set()
    hunter.stats = dict.fromkeys(_STATS_KEYS, 0)
    hunter.rate_limit_hits = 0
    hunter.github = MagicMock()
    hunter._handle_rate_limit = MagicMock()
    hunter._save_incremental = lambda: None
    return hunter


def rate_limited():
    return RateLimitExceededException(
        403, {"message": "API rate limit exceeded for user ID 1."},
        {"x-ratelimit-remaining": "0"})


class _File:
    """A ContentFile whose lazy `decoded_content` fetch raises `error`."""

    type = "file"
    size = 10

    def __init__(self, path, error=None, body=b"nothing to see"):
        self.path = path
        self.name = os.path.basename(path)
        self._error = error
        self._body = body

    @property
    def decoded_content(self):
        if self._error is not None:
            raise self._error
        return self._body


def make_repo(files=(), private=False, commits=None, full_name="acme/api"):
    repo = MagicMock()
    repo.name = full_name.split("/")[-1]
    repo.full_name = full_name
    repo.private = private
    repo.stargazers_count = 0
    repo.forks_count = 0
    repo.get_contents.return_value = list(files)
    repo.get_commits.return_value = commits if commits is not None else []
    return repo


# ---------------------------------------------------------------------------
# B2(b): errors that lose coverage are recorded, benign ones are not
# ---------------------------------------------------------------------------

class TestCoverageGapsAreRecorded(unittest.TestCase):
    def test_a_rate_limited_file_is_a_gap(self):
        h = make_hunter()
        h.scan_repo_contents(make_repo([_File("src/a.py", rate_limited())]))
        self.assertEqual(len(h.coverage_gaps), 1)
        self.assertEqual(h.coverage_gaps[0]["kind"], "file")
        self.assertIn("src/a.py", h.coverage_gaps[0]["where"])

    def test_a_server_error_on_a_file_is_a_gap(self):
        h = make_hunter()
        h.scan_repo_contents(make_repo([_File("src/a.py", GithubException(502))]))
        self.assertEqual([g["kind"] for g in h.coverage_gaps], ["file"])

    def test_a_benign_per_file_error_is_not_a_gap(self):
        """A submodule or symlink entry raises on decode in every healthy run.
        Counting it would stop every such project from ever pruning."""
        h = make_hunter()
        h.scan_repo_contents(make_repo([
            _File("vendor/lib", AssertionError("unsupported encoding: none")),
            _File("gone.py", GithubException(404)),
        ]))
        self.assertEqual(list(h.coverage_gaps), [])

    def test_a_server_error_listing_a_directory_is_a_gap(self):
        h = make_hunter()
        repo = make_repo()
        repo.get_contents.side_effect = GithubException(503)
        h.scan_repo_contents(repo)
        self.assertEqual([g["kind"] for g in h.coverage_gaps], ["directory"])

    def test_a_missing_directory_is_not_a_gap(self):
        h = make_hunter()
        repo = make_repo()
        repo.get_contents.side_effect = GithubException(404)
        h.scan_repo_contents(repo)
        self.assertEqual(list(h.coverage_gaps), [])

    def test_a_rate_limited_commit_is_a_gap(self):
        commit = MagicMock()
        commit.sha = "abcdef1234"
        type(commit).files = mock.PropertyMock(side_effect=rate_limited())
        h = make_hunter()
        h.scan_commit_history(make_repo(commits=[commit]))
        self.assertEqual([g["kind"] for g in h.coverage_gaps], ["commit"])

    def test_a_rate_limit_while_paging_commits_is_a_gap(self):
        def pages():
            raise rate_limited()
            yield  # pragma: no cover

        h = make_hunter()
        h.scan_commit_history(make_repo(commits=pages()))
        self.assertEqual([g["kind"] for g in h.coverage_gaps], ["commits"])
        h._handle_rate_limit.assert_called_once()

    def test_an_empty_repository_history_is_not_a_gap(self):
        """GitHub answers 409 for the commits of an empty repository."""
        def pages():
            raise GithubException(409, {"message": "Git Repository is empty."})
            yield  # pragma: no cover

        h = make_hunter()
        h.scan_commit_history(make_repo(commits=pages()))
        self.assertEqual(list(h.coverage_gaps), [])

    def test_a_rate_limit_while_listing_gists_is_a_gap(self):
        user = MagicMock()
        user.login = "alice"
        user.get_gists.side_effect = rate_limited()
        h = make_hunter()
        h.scan_gists(user)
        self.assertEqual([g["kind"] for g in h.coverage_gaps], ["gists"])

    def test_a_gist_file_without_content_is_not_a_gap(self):
        user = MagicMock()
        user.login = "alice"
        gist = MagicMock()
        gist.id = "g1"
        gist.public = True
        gist.files = {"notes.txt": types.SimpleNamespace(content=None)}
        user.get_gists.return_value = [gist]
        h = make_hunter()
        h.scan_gists(user)
        self.assertEqual(list(h.coverage_gaps), [])

    def test_scan_user_records_the_repos_it_dropped(self):
        h = make_hunter()
        h.github.get_user.side_effect = GithubException(500)
        h.scan_user()
        self.assertEqual([g["kind"] for g in h.coverage_gaps], ["target"])

    def test_scan_user_hands_a_rate_limit_to_the_retry(self):
        h = make_hunter()
        h.github.get_user.side_effect = rate_limited()
        with self.assertRaises(RateLimitExceededException):
            h.scan_user()


class TestRateLimitIsNotNotAnOrganisation(unittest.TestCase):
    def test_a_rate_limited_org_lookup_does_not_fall_back_to_user(self):
        h = make_hunter()
        h.github.get_organization.side_effect = rate_limited()
        h.scan_user = MagicMock()
        with self.assertRaises(RateLimitExceededException):
            h.scan_organization()
        h.scan_user.assert_not_called()

    def test_a_403_flagged_by_its_headers_is_a_rate_limit_too(self):
        h = make_hunter()
        h.github.get_organization.side_effect = GithubException(
            403, {"message": "Forbidden"}, {"X-RateLimit-Remaining": "0"})
        h.scan_user = MagicMock()
        with self.assertRaises(GithubException):
            h.scan_organization()
        h.scan_user.assert_not_called()

    def test_a_secondary_rate_limit_message_is_a_rate_limit(self):
        h = make_hunter()
        h.github.get_organization.side_effect = GithubException(
            403, {"message": "You have exceeded a secondary rate limit."}, {})
        h.scan_user = MagicMock()
        with self.assertRaises(GithubException):
            h.scan_organization()
        h.scan_user.assert_not_called()

    def test_not_found_still_falls_back_to_user(self):
        h = make_hunter()
        h.github.get_organization.side_effect = GithubException(404, {"message": "Not Found"}, {})
        h.scan_user = MagicMock()
        h.scan_organization()
        h.scan_user.assert_called_once_with()

    def test_a_plain_forbidden_still_falls_back_to_user(self):
        h = make_hunter()
        h.github.get_organization.side_effect = GithubException(
            403, {"message": "Resource not accessible by personal access token"},
            {"X-RateLimit-Remaining": "4999"})
        h.scan_user = MagicMock()
        h.scan_organization()
        h.scan_user.assert_called_once_with()

    def test_a_rate_limit_part_way_through_an_org_is_a_gap_not_a_restart(self):
        # run()'s retry restarts every repo from the top; once the org resolved
        # the throttle ends this target as an incomplete run instead.
        h = make_hunter()
        org = MagicMock()
        org.get_repos.side_effect = rate_limited()
        h.github.get_organization.return_value = org
        h.scan_user = MagicMock()
        h.scan_organization()
        h.scan_user.assert_not_called()
        self.assertEqual([g["kind"] for g in h.coverage_gaps], ["organization"])

    def test_a_rate_limit_part_way_through_a_user_is_a_gap_not_a_restart(self):
        h = make_hunter()
        user = MagicMock()
        user.get_repos.side_effect = rate_limited()
        h.github.get_user.return_value = user
        h.scan_user()
        self.assertEqual([g["kind"] for g in h.coverage_gaps], ["target"])

    def test_run_retries_after_a_rate_limited_org_lookup(self):
        """The retry run() already owns, rather than a user scan of an org."""
        h = make_hunter()
        calls = []

        def org():
            calls.append(1)
            if len(calls) == 1:
                raise rate_limited()
        h.scan_organization = org
        h.save_results = MagicMock()
        h.print_summary = MagicMock()
        h.run()
        self.assertEqual(len(calls), 2)
        h.save_results.assert_called_once_with("completed")


class TestAgainstTheRealPyGithub(unittest.TestCase):
    """The stubs above mirror PyGithub; this checks the classifier against the
    exceptions the real library builds from a GitHub response."""

    @classmethod
    def setUpClass(cls):
        try:
            from github.Requester import Requester
        except Exception:
            raise unittest.SkipTest("PyGithub is not installed in this image")
        factory = getattr(Requester, "createException", None)
        if factory is None:
            raise unittest.SkipTest("this PyGithub has no public createException")
        spec = importlib.util.spec_from_file_location(
            "_ghh_real_pygithub",
            REPO_ROOT / "scanners" / "github_secret_hunt" / "github_secret_hunt.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.mod = module
        cls.factory = staticmethod(factory)

    def _exc(self, status, message, headers=None):
        return self.factory(status, headers or {}, {"message": message})

    def _hunter(self):
        h = self.mod.GitHubSecretHunter.__new__(self.mod.GitHubSecretHunter)
        return h

    def test_rate_limits_are_recognised(self):
        for status, message in ((403, "API rate limit exceeded for user ID 1."),
                                (403, "You have exceeded a secondary rate limit. Please wait."),
                                (429, "Too many requests")):
            with self.subTest(message=message):
                self.assertTrue(self.mod.GitHubSecretHunter._is_rate_limit(
                    self._exc(status, message)))

    def test_not_found_and_plain_forbidden_are_not(self):
        for status, message in ((404, "Not Found"),
                                (403, "Resource not accessible by personal access token")):
            with self.subTest(message=message):
                exc = self._exc(status, message)
                self.assertFalse(self.mod.GitHubSecretHunter._is_rate_limit(exc))
                self.assertFalse(self._hunter()._loses_coverage(exc))

    def test_a_server_error_loses_coverage(self):
        self.assertTrue(self._hunter()._loses_coverage(self._exc(502, "Bad Gateway")))


class TestTheArtifactCarriesTheGaps(unittest.TestCase):
    def _save(self, hunter, status="completed"):
        with tempfile.TemporaryDirectory() as tmp:
            hunter.settings["GITHUB_OUTPUT_JSON"] = True
            hunter.output_file = Path(tmp) / "out.json"
            from datetime import datetime
            hunter.scan_start_time = datetime(2026, 1, 1)
            hunter.save_results(status)
            return json.loads(hunter.output_file.read_text())

    def test_a_clean_run_writes_exactly_the_keys_it_always_did(self):
        out = self._save(make_hunter())
        self.assertEqual(set(out), {"target", "scan_start_time", "scan_end_time",
                                    "duration_seconds", "status", "last_update",
                                    "statistics", "findings"})
        self.assertEqual(set(out["statistics"]), set(_STATS_KEYS))

    def test_a_run_with_gaps_says_so(self):
        h = make_hunter()
        h.scan_repo_contents(make_repo([_File("src/a.py", rate_limited())]))
        out = self._save(h)
        self.assertEqual(out["coverage_gap_count"], 1)
        self.assertEqual(out["coverage_gaps"][0]["kind"], "file")
        self.assertEqual(set(out["statistics"]), set(_STATS_KEYS))

    def test_the_incremental_save_carries_them_too(self):
        h = make_hunter()
        h.scan_repo_contents(make_repo([_File("src/a.py", rate_limited())]))
        with tempfile.TemporaryDirectory() as tmp:
            h.settings["GITHUB_OUTPUT_JSON"] = True
            h.output_file = Path(tmp) / "out.json"
            from datetime import datetime
            h.scan_start_time = datetime(2026, 1, 1)
            del h._save_incremental            # back to the real method
            h._save_incremental()
            out = json.loads(h.output_file.read_text())
        self.assertEqual(out["coverage_gap_count"], 1)


# ---------------------------------------------------------------------------
# B3: repository visibility rides on each finding, only when known
# ---------------------------------------------------------------------------

AWS = "AKIAABCDEFGHIJKLMNOP"


class TestRepositoryVisibility(unittest.TestCase):
    def _scan(self, private):
        h = make_hunter(GITHUB_SCAN_COMMITS=False)
        repo = make_repo([_File("config/.env", body=f"KEY={AWS}".encode())], private=private)
        h.scan_repo(repo)
        return h.findings

    def test_a_public_repository_marks_its_findings_public(self):
        findings = self._scan(private=False)
        self.assertTrue(findings)
        self.assertTrue(all(f["repository_public"] is True for f in findings))

    def test_a_private_repository_marks_its_findings_private(self):
        findings = self._scan(private=True)
        self.assertTrue(findings)
        self.assertTrue(all(f["repository_public"] is False for f in findings))

    def test_unknown_visibility_writes_no_key(self):
        findings = self._scan(private=None)
        self.assertTrue(findings)
        self.assertTrue(all("repository_public" not in f for f in findings))

    def test_a_public_gist_is_public(self):
        user = MagicMock()
        user.login = "alice"
        gist = MagicMock()
        gist.id = "g1"
        gist.public = True
        gist.files = {"creds.txt": types.SimpleNamespace(content=f"key={AWS}")}
        user.get_gists.return_value = [gist]
        h = make_hunter()
        h.scan_gists(user)
        self.assertTrue(h.findings)
        self.assertTrue(all(f["repository_public"] is True for f in h.findings))

    def test_reading_visibility_costs_no_api_call(self):
        """`private` comes with the listing payload; the scan must not ask for
        anything a normal run did not already ask for."""
        h = make_hunter(GITHUB_SCAN_COMMITS=True)
        repo = make_repo([_File("a.py")])
        h.scan_repo(repo)
        called = sorted({c[0].split(".")[0] for c in repo.method_calls})
        self.assertEqual(called, ["get_commits", "get_contents"])
        self.assertEqual(repo.get_contents.call_count, 1)
        self.assertEqual(repo.get_commits.call_count, 1)


# ---------------------------------------------------------------------------
# Graph side: B2(a), B2(c), B3
# ---------------------------------------------------------------------------

class FakeResult:
    def __init__(self, single=None):
        self._single = single

    def single(self):
        return self._single


class FakeSession:
    def __init__(self):
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **kwargs):
        self.queries.append((query, kwargs))
        if "HAS_GITHUB_HUNT" in query:
            return FakeResult({"linked": 1})
        for key in ("deleted", "kept"):
            if f"as {key}" in query or f"AS {key}" in query:
                return FakeResult({key: 0})
        return FakeResult()


class FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class Client(SecretMixin, BaseMixin):
    def __init__(self, session):
        self.driver = FakeDriver(session)


def hunt_payload(status="completed", **extra):
    payload = {
        "target": "acme",
        "status": status,
        "scan_start_time": "2026-01-01T00:00:00",
        "scan_end_time": "2026-01-01T01:00:00",
        "statistics": {"repos_scanned": 1},
        "findings": [
            {"type": "SECRET", "repository": "acme/api", "path": "src/.env",
             "secret_type": "AWS Access Key ID", "details": {"matches": 1, "sample": "AKIA..."}},
            {"type": "SENSITIVE_FILE", "repository": "acme/api", "path": "src/.env",
             "secret_type": "Sensitive Filename", "details": {}},
        ],
    }
    payload.update(extra)
    return payload


def ingest(payload):
    session = FakeSession()
    client = Client(session)
    client.prune_unseen_findings = MagicMock(return_value={"pruned": 0})
    stats = client.update_graph_from_github_hunt(payload, "u1", "p1")
    return session, client, stats


def deletes(session):
    return [q for q, _ in session.queries if "DELETE" in q]


def finding_props(session, label):
    return [p["props"] for q, p in session.queries
            if f"MERGE (" in q and f":{label} " in q and "props" in p]


class TestAnIncompleteHuntNeitherClearsNorPrunes(unittest.TestCase):
    def test_an_interrupted_hunt_does_not_prune(self):
        _, client, stats = ingest(hunt_payload("interrupted"))
        self.assertEqual(stats["secrets_created"], 1)
        client.prune_unseen_findings.assert_not_called()

    def test_an_errored_or_killed_hunt_does_not_prune(self):
        for status in ("error", "in_progress", None):
            with self.subTest(status=status):
                payload = hunt_payload(status or "completed")
                if status is None:
                    payload.pop("status")
                _, client, _ = ingest(payload)
                client.prune_unseen_findings.assert_not_called()

    def test_an_incomplete_hunt_deletes_no_path_so_orphans_nothing(self):
        """Deleting every GithubPath orphaned the findings of repos the run
        never reached, and the next run's orphan sweep deleted them."""
        for status in ("interrupted", "error", "in_progress"):
            with self.subTest(status=status):
                session, _, _ = ingest(hunt_payload(status))
                self.assertEqual(deletes(session), [])

    def test_a_completed_hunt_with_gaps_is_incomplete(self):
        session, client, stats = ingest(hunt_payload(
            "completed", coverage_gap_count=3,
            coverage_gaps=[{"kind": "file", "where": "acme/api:src/a.py", "reason": "rate limit"}]))
        self.assertEqual(deletes(session), [])
        client.prune_unseen_findings.assert_not_called()
        self.assertEqual(stats["secrets_created"], 1)
        hunt = next(p["props"] for q, p in session.queries
                    if "MERGE (gh:GithubHunt" in q)
        self.assertEqual(hunt["coverage_gap_count"], 3)

    def test_an_incomplete_hunt_upserts_on_the_same_ids(self):
        complete, _, _ = ingest(hunt_payload("completed"))
        partial, _, _ = ingest(hunt_payload("interrupted"))
        ids = lambda s: sorted(p["id"] for q, p in s.queries if "MERGE (" in q and "id" in p)  # noqa: E731
        self.assertEqual(ids(complete), ids(partial))
        for q, _ in partial.queries:
            if "MERGE (" in q and "{id: $id" in q:
                self.assertIn("user_id: $props.user_id", q)
                self.assertIn("project_id: $props.project_id", q)


class TestACompletedHuntIsUnchanged(unittest.TestCase):
    def test_a_completed_hunt_clears_and_prunes(self):
        session, client, _ = ingest(hunt_payload("completed"))
        self.assertTrue(any("GithubPath" in q and "DETACH DELETE" in q for q in deletes(session)))
        self.assertTrue(any("GithubHunt" in q and "DETACH DELETE" in q for q in deletes(session)))
        client.prune_unseen_findings.assert_called_once()
        args = client.prune_unseen_findings.call_args[0]
        self.assertEqual(args[:3], ("u1", "p1", ["github_hunt"]))

    def test_a_completed_hunt_writes_no_gap_property(self):
        session, _, _ = ingest(hunt_payload("completed"))
        hunt = next(p["props"] for q, p in session.queries if "MERGE (gh:GithubHunt" in q)
        self.assertNotIn("coverage_gap_count", hunt)


class TestVisibilityReachesTheGraph(unittest.TestCase):
    def _props(self, visibility):
        payload = hunt_payload("completed")
        for f in payload["findings"]:
            if visibility is not None:
                f["repository_public"] = visibility
        session, _, _ = ingest(payload)
        return (finding_props(session, "GithubSecret")
                + finding_props(session, "GithubSensitiveFile"))

    def test_public_is_written(self):
        props = self._props(True)
        self.assertEqual(len(props), 2)
        self.assertTrue(all(p["repository_public"] is True for p in props))

    def test_private_is_written_as_false(self):
        props = self._props(False)
        self.assertTrue(all(p["repository_public"] is False for p in props))

    def test_unknown_is_never_written_as_false(self):
        props = self._props(None)
        self.assertEqual(len(props), 2)
        self.assertTrue(all("repository_public" not in p for p in props))

    def test_validation_status_is_left_unset(self):
        """The hunt validates nothing, and the evidence bundle prints a missing
        value as "never tested": writing one would change every review hash."""
        for p in self._props(True):
            self.assertNotIn("validation_status", p)


if __name__ == "__main__":
    unittest.main()
