"""GitHub hunt: transport failures are coverage gaps, and a 429 is retried.

Two ways a hunt that did not read everything still ended as a clean,
prunable run, or as a failed one:

* PyGithub 2.x retries 5xx and rate-limited 403s itself (GithubRetry). When the
  retries run out, requests raises RetryError; a body cut off mid-read raises
  ChunkedEncodingError. Neither is a GithubException nor a ConnectionError or
  Timeout, so `_loses_coverage` returned False, the per-file / per-commit /
  per-gist `except Exception` swallowed them with no gap, the run ended
  `completed` with 0 gaps, and the graph write cleared and pruned findings in
  files it never fetched.
* PyGithub 2.x raises a 429 as a plain GithubException. Before the target
  resolved, scan_organization re-raises a rate limit for run() to wait and
  retry, but run() only caught RateLimitExceededException, so the 429 ended
  the hunt as "error".

PyGithub is stubbed (exception classes shaped like the real ones); requests is
the real library, so the exceptions are exactly the ones the hunter will see.
"""

import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent

try:
    import requests.exceptions as rexc
    import urllib3.exceptions as u3exc
except ImportError:  # pragma: no cover - both ship in every section image
    rexc = u3exc = None


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
            "_ghh_regression_under_test",
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


class _File:
    """A ContentFile whose lazy `decoded_content` fetch raises `error`."""

    type = "file"
    size = 10

    def __init__(self, path, error=None):
        self.path = path
        self.name = os.path.basename(path)
        self._error = error

    @property
    def decoded_content(self):
        if self._error is not None:
            raise self._error
        return b"nothing to see"


def make_repo(files=(), commits=None, full_name="acme/api"):
    repo = MagicMock()
    repo.name = full_name.split("/")[-1]
    repo.full_name = full_name
    repo.private = False
    repo.stargazers_count = 0
    repo.forks_count = 0
    repo.get_contents.return_value = list(files)
    repo.get_commits.return_value = commits if commits is not None else []
    return repo


def retries_exhausted():
    """What requests raises once GithubRetry gives up on a 5xx or a throttle."""
    return rexc.RetryError("Max retries exceeded with url: /repos/acme/api/contents/a.py "
                           "(Caused by ResponseError('too many 502 error responses'))")


def body_cut_off():
    return rexc.ChunkedEncodingError("Connection broken: IncompleteRead(12 bytes read)")


@unittest.skipIf(rexc is None, "requests is not installed in this image")
class TestRegressionGithubHuntTransportGaps(unittest.TestCase):
    def test_regression_github_hunt_retry_error_is_a_coverage_gap(self):
        for error in (retries_exhausted(), body_cut_off(),
                      u3exc.ProtocolError("Connection aborted.")):
            with self.subTest(error=type(error).__name__):
                h = make_hunter()
                h.scan_repo_contents(make_repo([_File("src/a.py", error)]))
                self.assertEqual([g["kind"] for g in h.coverage_gaps], ["file"],
                                 f"an unread file ({type(error).__name__}) left no gap")

    def test_regression_github_hunt_retry_error_on_a_commit_is_a_gap(self):
        commit = MagicMock()
        commit.sha = "abcdef1234"
        type(commit).files = mock.PropertyMock(side_effect=retries_exhausted())
        h = make_hunter()
        h.scan_commit_history(make_repo(commits=[commit]))
        self.assertEqual([g["kind"] for g in h.coverage_gaps], ["commit"])

    def test_regression_github_hunt_retry_error_paging_commits_is_a_gap(self):
        def pages():
            raise body_cut_off()
            yield  # pragma: no cover

        h = make_hunter()
        h.scan_commit_history(make_repo(commits=pages()))
        self.assertEqual([g["kind"] for g in h.coverage_gaps], ["commits"])

    def test_regression_github_hunt_retry_error_on_a_gist_is_a_gap(self):
        user = MagicMock()
        user.login = "alice"
        gist = MagicMock()
        gist.id = "g1"
        gist.public = True
        content = mock.PropertyMock(side_effect=retries_exhausted())
        gist_file = MagicMock()
        type(gist_file).content = content
        gist.files = {"notes.txt": gist_file}
        user.get_gists.return_value = [gist]
        h = make_hunter()
        h.scan_gists(user)
        self.assertEqual([g["kind"] for g in h.coverage_gaps], ["gist"])

    def test_regression_github_hunt_retry_error_run_is_not_prunable(self):
        """The artifact of such a run must carry the gap, which is what stops
        the graph write from clearing and pruning."""
        h = make_hunter()
        h.scan_repo_contents(make_repo([_File("src/a.py", retries_exhausted())]))
        self.assertEqual(h._coverage_fields().get("coverage_gap_count"), 1)


@unittest.skipIf(rexc is None, "requests is not installed in this image")
class TestBenignFailuresAreStillNotGaps(unittest.TestCase):
    """Failures that repeat on every healthy run must stay gap-free, or every
    such project's hunts would be incomplete for ever and never prune."""

    def test_submodule_and_missing_file(self):
        h = make_hunter()
        h.scan_repo_contents(make_repo([
            _File("vendor/lib", AssertionError("unsupported encoding: none")),
            _File("gone.py", GithubException(404)),
            _File("link", TypeError("argument should be a bytes-like object, not 'NoneType'")),
        ]))
        self.assertEqual(list(h.coverage_gaps), [])

    def test_empty_repository_history(self):
        def pages():
            raise GithubException(409, {"message": "Git Repository is empty."})
            yield  # pragma: no cover

        h = make_hunter()
        h.scan_commit_history(make_repo(commits=pages()))
        self.assertEqual(list(h.coverage_gaps), [])

    def test_gist_file_without_content(self):
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

    def test_server_errors_and_rate_limits_are_still_gaps(self):
        for error in (GithubException(502), RateLimitExceededException(
                403, {"message": "API rate limit exceeded"}, {"x-ratelimit-remaining": "0"})):
            with self.subTest(error=error):
                h = make_hunter()
                h.scan_repo_contents(make_repo([_File("src/a.py", error)]))
                self.assertEqual(len(h.coverage_gaps), 1)


class TestRegressionGithubHunt429BeforeTheTargetResolves(unittest.TestCase):
    def _run(self, h):
        h.save_results = MagicMock()
        h.print_summary = MagicMock()
        h.run()
        return h.save_results.call_args_list

    def test_regression_github_hunt_429_before_target_resolves_is_retried(self):
        """Through the real scan_organization: the 429 on the org lookup is
        re-raised (nothing scanned yet) and must reach run()'s wait-and-retry."""
        h = make_hunter(GITHUB_SCAN_GISTS=False)
        org = MagicMock()
        org.login = "acme"
        org.get_repos.return_value = []
        h.github.get_organization.side_effect = [
            GithubException(429, {"message": "Too many requests"}, {}), org]
        saves = self._run(h)
        h._handle_rate_limit.assert_called_once_with()
        self.assertEqual(h.github.get_organization.call_count, 2)
        self.assertEqual(saves, [mock.call("completed")],
                         "a 429 before the target resolved ended the hunt as an error")

    def test_regression_github_hunt_429_on_user_lookup_is_retried(self):
        h = make_hunter(GITHUB_SCAN_GISTS=False)
        user = MagicMock()
        user.login = "alice"
        user.get_repos.return_value = []
        h.github.get_organization.side_effect = GithubException(404, {"message": "Not Found"}, {})
        h.github.get_user.side_effect = [
            GithubException(429, {"message": "Too many requests"}, {}), user]
        saves = self._run(h)
        self.assertEqual(saves, [mock.call("completed")])
        self.assertEqual(h.github.get_user.call_count, 2)

    def test_a_rate_limit_exception_is_still_retried(self):
        h = make_hunter(GITHUB_SCAN_GISTS=False)
        org = MagicMock()
        org.get_repos.return_value = []
        h.github.get_organization.side_effect = [
            RateLimitExceededException(403, {"message": "API rate limit exceeded"},
                                       {"x-ratelimit-remaining": "0"}), org]
        self.assertEqual(self._run(h), [mock.call("completed")])

    def test_an_ordinary_error_still_ends_the_hunt_as_error(self):
        h = make_hunter()
        h.github.get_organization.side_effect = GithubException(500, {"message": "boom"}, {})
        saves = self._run(h)
        h._handle_rate_limit.assert_not_called()
        self.assertEqual(saves, [mock.call("error")])

    def test_a_stop_is_still_interrupted(self):
        h = make_hunter()
        h.github.get_organization.side_effect = KeyboardInterrupt()
        self.assertEqual(self._run(h), [mock.call("interrupted")])


if __name__ == "__main__":
    unittest.main()
