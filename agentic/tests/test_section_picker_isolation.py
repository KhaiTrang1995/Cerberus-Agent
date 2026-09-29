"""The tradecraft section picker is per session, and per user.

It used to be one attribute on the manager every session shares, set to a Haiku
client built from the last-loaded project's Anthropic key, falling back to that
project's agent LLM. Two concurrent sessions of two users therefore picked
pages with one user's key. Now the picker lives in a ContextVar set per task
from that task's own USER_SETTINGS ("Tradecraft section picker" in Models by
feature), and an unset model means None: the picker uses the text match.
"""
from __future__ import annotations

import asyncio
import contextvars
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator_helpers.tradecraft_lookup import TradecraftLookupManager  # noqa: E402


def test_two_tasks_keep_their_own_picker():
    manager = TradecraftLookupManager(cache_root="/tmp/tc-picker-test")
    seen = {}

    async def session(name, picker, gate):
        manager.section_picker_llm = picker
        await gate.wait()
        seen[name] = manager.section_picker_llm

    async def main():
        gate = asyncio.Event()
        tasks = [asyncio.create_task(session("alice", "picker-alice", gate)),
                 asyncio.create_task(session("bob", "picker-bob", gate))]
        await asyncio.sleep(0)
        gate.set()
        await asyncio.gather(*tasks)

    asyncio.run(main())
    assert seen == {"alice": "picker-alice", "bob": "picker-bob"}


def test_a_task_that_never_set_one_gets_none_not_another_users():
    manager = TradecraftLookupManager(cache_root="/tmp/tc-picker-test")

    async def other_user():
        manager.section_picker_llm = "someone-elses-picker"

    async def fresh_session():
        return manager.section_picker_llm

    async def main():
        await asyncio.create_task(other_user())
        return await asyncio.create_task(fresh_session())

    assert contextvars.copy_context().run(asyncio.run, main()) is None


def test_the_agent_llm_is_never_the_fallback():
    manager = TradecraftLookupManager(llm="the-agents-shared-llm",
                                      cache_root="/tmp/tc-picker-test")
    assert manager.section_picker_llm is None


def _bare_orchestrator():
    from orchestrator import AgentOrchestrator
    orch = AgentOrchestrator.__new__(AgentOrchestrator)
    orch.llm = "the-agents-shared-llm"
    return orch


def _settings(values):
    return lambda key, default=None: values.get(key, default)


def test_the_picker_model_comes_from_the_tasks_user_settings():
    import orchestrator as module
    values = {
        "USER_SETTINGS": {"featureModels": {"tradecraft_section_picker": "gpt-5-nano"}},
        "USER_LLM_PROVIDERS": [{"providerType": "openai", "apiKey": "sk-alice"}],
    }
    with mock.patch.object(module, "get_setting", _settings(values)), \
         mock.patch("llm_builder.build_llm_from_providers",
                    side_effect=lambda model, providers: (model, providers)) as build:
        picker = _bare_orchestrator()._build_section_picker_llm()
    assert picker == ("gpt-5-nano", values["USER_LLM_PROVIDERS"])
    build.assert_called_once()


def test_unset_gives_none_so_the_text_match_is_used():
    import orchestrator as module
    with mock.patch.object(module, "get_setting", _settings({"USER_SETTINGS": {}})), \
         mock.patch("llm_builder.build_llm_from_providers") as build:
        assert _bare_orchestrator()._build_section_picker_llm() is None
    build.assert_not_called()


def test_a_model_that_cannot_be_built_gives_none():
    import orchestrator as module
    values = {"USER_SETTINGS": {"featureModels": {"tradecraft_section_picker": "custom/gone"}}}
    with mock.patch.object(module, "get_setting", _settings(values)), \
         mock.patch("llm_builder.build_llm_from_providers", side_effect=ValueError("no provider")):
        assert _bare_orchestrator()._build_section_picker_llm() is None


def test_the_hidden_default_constant_is_gone():
    from project_settings import DEFAULT_AGENT_SETTINGS
    assert "TRADECRAFT_SECTION_PICKER_MODEL" not in DEFAULT_AGENT_SETTINGS


import pytest  # noqa: E402


@pytest.mark.xfail(strict=True, reason=(
    "Review finding, accepted: the picker is rebuilt on every turn, on the event "
    "loop, and a custom/ model's base-URL guard resolves its host each time. Caching "
    "the built client would also skip that SSRF re-check for the cache's lifetime, "
    "so it needs a TTL design, not a plain cache."))
def test_the_picker_is_not_rebuilt_on_every_turn():
    import orchestrator as module
    values = {
        "USER_SETTINGS": {"featureModels": {"tradecraft_section_picker": "gpt-5-nano"}},
        "USER_LLM_PROVIDERS": [{"providerType": "openai", "apiKey": "sk-alice"}],
    }
    orch = _bare_orchestrator()
    with mock.patch.object(module, "get_setting", _settings(values)), \
         mock.patch("llm_builder.build_llm_from_providers",
                    side_effect=lambda model, providers: object()) as build:
        orch._build_section_picker_llm()
        orch._build_section_picker_llm()
    assert build.call_count == 1
