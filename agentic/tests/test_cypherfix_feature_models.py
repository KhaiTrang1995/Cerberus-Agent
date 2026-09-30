"""The triage and CodeFix loaders read the project OWNER's per-feature models.

Before Models by feature both read `cypherfixLlmModel || agentOpenaiModel`, and
CodeFix fell back to a hardcoded "gpt-4o" when the settings could not be read,
which named a provider the owner may have no key for.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PROJECT = {
    "userId": "owner-1",
    "cypherfixLlmModel": "claude-opus-legacy",
    "agentOpenaiModel": "gpt-agent",
    "cypherfixDefaultRepo": "acme/app",
    "triageReviewBudget": 25,
}
CUSTOM = {"id": "prov-x", "providerType": "openai_compatible", "apiKey": "k"}


class _Resp:
    def __init__(self, body, status=200):
        self._body = body
        self.status_code = status

    def json(self):
        return self._body

    def raise_for_status(self):
        pass


def _client_for(feature_models, failing=()):
    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, **_kwargs):
            for suffix, failure in failing:
                if url.endswith(suffix):
                    if isinstance(failure, Exception):
                        raise failure
                    return _Resp({"error": "boom"}, status=failure)
            if url.endswith("/llm-providers"):
                return _Resp([CUSTOM, {"providerType": "openai", "apiKey": "sk"}])
            if url.endswith("/settings"):
                return _Resp({"featureModels": feature_models})
            return _Resp(PROJECT)

    return _Client


def _load(module, feature_models, failing=()):
    with mock.patch.object(module.httpx, "AsyncClient", _client_for(feature_models, failing)):
        return asyncio.run(module.load_cypherfix_settings("p1"))


def test_triage_reads_the_owners_triage_model():
    from cypherfix_triage import project_settings as module
    settings = _load(module, {"triage": "gpt-5-mini", "codefix": "other"})
    assert settings["llm_model"] == "gpt-5-mini"
    assert settings["triageReviewBudget"] == 25


def test_triage_with_no_model_never_borrows_the_project_models():
    from cypherfix_triage import project_settings as module
    assert _load(module, {})["llm_model"] == ""


def test_codefix_reads_the_owners_codefix_model():
    from cypherfix_codefix import project_settings as module
    assert _load(module, {"codefix": "claude-sonnet-x", "triage": "t"})["model"] == "claude-sonnet-x"


def test_codefix_with_no_model_never_borrows_the_project_models():
    from cypherfix_codefix import project_settings as module
    assert _load(module, {})["model"] == ""


def test_a_custom_model_resolves_to_its_exact_provider_only():
    from cypherfix_codefix import project_settings as module
    assert _load(module, {"codefix": "custom/prov-x"})["custom_llm_config"] == CUSTOM
    assert "custom_llm_config" not in _load(module, {"codefix": "custom/prov-gone"})


def test_codefix_settings_have_no_model_default():
    from cypherfix_codefix.state import CodeFixSettings
    assert CodeFixSettings().model == ""


def test_codefix_refuses_to_start_without_a_model():
    """Before the remediation is read, the repo cloned or an LLM built."""
    from cypherfix_codefix import orchestrator as module

    errors = []

    class _Callback:
        async def on_error(self, message, recoverable=True, code=""):
            errors.append(code)

        async def on_phase(self, *a, **k):
            raise AssertionError("no phase may start without a model")

    async def settings(_project_id):
        return {"github_repo": "acme/app", "model": ""}

    orch = module.CodeFixOrchestrator.__new__(module.CodeFixOrchestrator)
    orch.state = module.CodeFixState()
    orch.state.project_id = "p1"
    orch.callback = _Callback()

    async def no_remediation(_rid):
        raise AssertionError("the remediation must not be loaded")

    orch._load_remediation = no_remediation
    with mock.patch.object(module, "load_cypherfix_settings", settings):
        asyncio.run(orch.run("rem-1"))
    assert errors == ["model_required"]


class TestAFailedSettingsFetchIsNotModelRequired:
    """Review finding: a failed settings fetch was reported as `model_required`.

    The loaders swallowed the failure and `feature_model(None)` gave "", so a
    webapp hiccup sent the owner to pick a model they already had.
    """

    FAILURES = [("/settings", 500), ("/settings", ConnectionError("down")),
                ("/llm-providers", 503), ("/llm-providers", ConnectionError("down"))]

    def test_the_loaders_flag_a_failed_fetch(self):
        from cypherfix_codefix import project_settings as codefix
        from cypherfix_triage import project_settings as triage
        for module in (triage, codefix):
            assert _load(module, {"triage": "t", "codefix": "c"})["settings_unavailable"] is False
            for failure in self.FAILURES:
                loaded = _load(module, {"triage": "t", "codefix": "c"}, failing=[failure])
                assert loaded["settings_unavailable"] is True, (module.__name__, failure)

    def _codefix_errors(self, loaded):
        from cypherfix_codefix import orchestrator as module
        errors = []

        class _Callback:
            async def on_error(self, message, recoverable=True, code=""):
                errors.append((code, message))

            async def on_phase(self, *a, **k):
                raise AssertionError("nothing may start without settings")

        async def settings(_project_id):
            return loaded

        orch = module.CodeFixOrchestrator.__new__(module.CodeFixOrchestrator)
        orch.state = module.CodeFixState()
        orch.state.project_id = "p1"
        orch.callback = _Callback()
        with mock.patch.object(module, "load_cypherfix_settings", settings):
            asyncio.run(orch.run("rem-1"))
        return errors

    def test_codefix_says_settings_unavailable_not_model_required(self):
        from cypherfix_errors import CODEFIX_ERROR_MESSAGES
        loaded = {"github_repo": "acme/app", "model": "", "settings_unavailable": True}
        assert self._codefix_errors(loaded) == [
            ("settings_unavailable", CODEFIX_ERROR_MESSAGES["settings_unavailable"])]

    def test_a_failed_project_read_is_settings_unavailable_too(self):
        assert [code for code, _ in self._codefix_errors({})] == ["settings_unavailable"]
