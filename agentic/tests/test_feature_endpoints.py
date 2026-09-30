"""The three "Models by feature" agent endpoints: /roe/parse,
/api/report/summarize and /command-whisperer.

Each runs the CALLER's saved model on the CALLER's keys, so each must:
- refuse the scanner token (it would spend any user's keys) - master key only;
- refuse an empty model instead of inventing one;
- never touch `orchestrator.llm`, the last-loaded project's LLM;
- answer `model_used` (the webapp's "this agent knows the feature" marker);
- turn a refused key into `model_unavailable` with a FIXED message, never the
  provider's text (a 401 body can quote part of the key).
"""
from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

MASTER = "m" * 40
SCANNER = "s" * 40
LEAK = "sk-live-LEAKED-FRAGMENT"


@pytest.fixture(scope="module")
def api():
    @asynccontextmanager
    async def fake_lifespan(_app):
        yield

    with patch("api.lifespan", fake_lifespan):
        import api as api_module
    return api_module


@pytest.fixture(autouse=True)
def keys(monkeypatch):
    import llm_guard
    monkeypatch.setenv("INTERNAL_API_KEY", MASTER)
    monkeypatch.setenv("SCANNER_API_KEY", SCANNER)
    llm_guard.reset_state()
    yield
    llm_guard.reset_state()


class _Tripwire:
    """Stands in for the orchestrator: touching its LLM fails the test."""

    _initialized = True

    @property
    def llm(self):
        raise AssertionError("orchestrator.llm must never be used by a feature endpoint")


class _Answer:
    def __init__(self, content):
        self.content = content


class _Llm:
    def __init__(self, content="", error=None):
        self._content = content
        self._error = error

    async def ainvoke(self, _messages):
        if self._error:
            raise self._error
        return _Answer(self._content)


class _Refused(Exception):
    status_code = 401


REPORT_JSON = ('{"executiveSummary": "s", "scopeNarrative": "", "riskNarrative": "", '
               '"findingsNarrative": "", "attackSurfaceNarrative": "", '
               '"recommendationsNarrative": ""}')

ENDPOINTS = [
    ("/roe/parse", {"text": "scope example.com"}, '{"projectName": "p"}'),
    ("/api/report/summarize", {"data": {"metrics": {}}}, REPORT_JSON),
    ("/command-whisperer", {"prompt": "list files", "session_type": "shell",
                            "project_id": "p1"}, "ls -la"),
]


def _post(api, path, body, *, key=MASTER, llm=None, providers=None, fetch_error=None):
    from fastapi.testclient import TestClient

    def fetch(_user_id):
        if fetch_error:
            raise fetch_error
        return providers if providers is not None else [
            {"providerType": "openai", "apiKey": "sk-test"}]

    with patch.object(api, "orchestrator", _Tripwire()), \
         patch.object(api, "fetch_user_providers", fetch), \
         patch.object(api, "build_llm_from_providers",
                      return_value=llm if llm is not None else _Llm()), \
         patch.object(api, "_prompt_skew", return_value=None):
        return TestClient(api.app).post(path, json=body, headers={"x-internal-key": key})


@pytest.mark.parametrize("path,body,content", ENDPOINTS)
def test_the_scanner_key_is_refused(api, path, body, content):
    res = _post(api, path, {**body, "model": "gpt-5", "user_id": "u1"},
                key=SCANNER, llm=_Llm(content))
    assert res.status_code == 401


@pytest.mark.parametrize("path,body,content", ENDPOINTS)
def test_no_key_is_refused(api, path, body, content):
    res = _post(api, path, {**body, "model": "gpt-5", "user_id": "u1"},
                key="", llm=_Llm(content))
    assert res.status_code == 401


@pytest.mark.parametrize("path,body,content", ENDPOINTS)
def test_an_empty_model_is_a_400(api, path, body, content):
    res = _post(api, path, {**body, "model": "", "user_id": "u1"}, llm=_Llm(content))
    assert res.status_code == 400


@pytest.mark.parametrize("path,body,content", ENDPOINTS)
def test_a_missing_user_is_a_400(api, path, body, content):
    res = _post(api, path, {**body, "model": "gpt-5"}, llm=_Llm(content))
    assert res.status_code == 400


@pytest.mark.parametrize("path,body,content", ENDPOINTS)
def test_success_carries_model_used_and_never_touches_the_shared_llm(api, path, body, content):
    res = _post(api, path, {**body, "model": "gpt-5", "user_id": "u1"}, llm=_Llm(content))
    assert res.status_code == 200, res.text
    assert res.json()["model_used"] == "gpt-5"


@pytest.mark.parametrize("path,body,content", ENDPOINTS)
def test_a_refused_key_at_call_time_is_model_unavailable_with_a_fixed_message(
        api, path, body, content):
    res = _post(api, path, {**body, "model": "gpt-5", "user_id": "u1"},
                llm=_Llm(error=_Refused(f"invalid api key {LEAK}")))
    assert res.status_code == 503
    payload = res.json()
    assert payload["code"] == "model_unavailable"
    assert payload["error"] == "Your model gpt-5 could not be used"
    assert payload["model_used"] == "gpt-5"
    assert LEAK not in res.text


@pytest.mark.parametrize("path,body,content", ENDPOINTS)
def test_a_build_failure_is_model_unavailable(api, path, body, content):
    from fastapi.testclient import TestClient

    with patch.object(api, "orchestrator", _Tripwire()), \
         patch.object(api, "fetch_user_providers", return_value=[]), \
         patch.object(api, "build_llm_from_providers",
                      side_effect=ValueError(f"missing key {LEAK}")), \
         patch.object(api, "_prompt_skew", return_value=None):
        res = TestClient(api.app).post(
            path, json={**body, "model": "custom/gone", "user_id": "u1"},
            headers={"x-internal-key": MASTER})
    assert res.status_code == 503
    assert res.json()["code"] == "model_unavailable"
    assert LEAK not in res.text


@pytest.mark.parametrize("path,body,content", ENDPOINTS)
def test_unloadable_providers_are_not_a_model_problem(api, path, body, content):
    import llm_builder
    res = _post(api, path, {**body, "model": "gpt-5", "user_id": "u1"},
                fetch_error=llm_builder.ProvidersUnreachable("down"))
    assert res.status_code == 503
    assert res.json()["code"] == "providers_unreachable"


@pytest.mark.parametrize("path,body,content", ENDPOINTS)
def test_a_transient_failure_keeps_the_model(api, path, body, content):
    """A 5xx from the provider must not open the model picker."""
    class _Busy(Exception):
        status_code = 529

    res = _post(api, path, {**body, "model": "gpt-5", "user_id": "u1"},
                llm=_Llm(error=_Busy("overloaded")))
    if path == "/api/report/summarize":
        # The summarizer degrades to empty narratives on a transient error.
        assert res.status_code == 200
    else:
        assert res.status_code == 502
        assert "code" not in res.json()
    assert res.json()["model_used"] == "gpt-5"


def test_the_providers_are_fetched_for_the_callers_user(api):
    seen = []
    from fastapi.testclient import TestClient

    def fetch(user_id):
        seen.append(user_id)
        return []

    with patch.object(api, "orchestrator", _Tripwire()), \
         patch.object(api, "fetch_user_providers", fetch), \
         patch.object(api, "build_llm_from_providers", return_value=_Llm("pwd")):
        TestClient(api.app).post("/command-whisperer", json={
            "prompt": "where am i", "session_type": "shell", "project_id": "p1",
            "user_id": "alice", "model": "gpt-5"}, headers={"x-internal-key": MASTER})
    assert seen == ["alice"]
