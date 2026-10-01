"""`jev_hooks`: questions and the mapping back to the /llm/* shapes.

Each hook maps Jev answers onto the response shape recon already validates, with
code-enforced floors so a Jev answer can only rank/tune, never drop coverage
below the static fallback:
- ffuf always keeps .bak/.old; nuclei always keeps the universal tags present;
- waf/takeover confidence is derived from the noul, answer sets are closed;
- a set larger than JEV_MAX_QUESTIONS_PER_CALL splits into sequential calls;
- any failing request fails the whole hook (never a partial answer set).

Runs inside the agent container.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import jev_hooks  # noqa: E402
from jev_client import JevError  # noqa: E402

KEY = "apikey_" + "a" * 36 + "_" + "b" * 64


def _noul_answers(values: dict) -> dict:
    return {name: {"type": "noul", "noul": v} for name, v in values.items()}


def _patch_system_one(side):
    return patch("jev_client.system_one", side)


# ---------------------------------------------------------------------------
# ffuf extensions
# ---------------------------------------------------------------------------

def _run(coro):
    import asyncio
    return asyncio.run(coro)


def test_ffuf_keeps_the_floor_even_when_jev_rejects_everything():
    answers = _noul_answers({f"ext_{i}": 0.0 for i in range(len(jev_hooks.FFUF_JEV_CATALOG))})
    with _patch_system_one(AsyncMock(return_value={"model": "jev-1.13.0", "answers": answers})):
        out = _run(jev_hooks.ffuf_extensions(KEY, "http://t/", {"Server": "nginx"}, 6))
    assert out["extensions"][:2] == [".bak", ".old"]
    assert set(out["extensions"]) == {".bak", ".old"}


def test_ffuf_ranks_by_noul_and_caps():
    vals = {f"ext_{i}": 0.0 for i in range(len(jev_hooks.FFUF_JEV_CATALOG))}
    # .php is index 0, .zip index 18; give .php 0.9, .zip 0.6.
    vals["ext_0"] = 0.9
    vals["ext_18"] = 0.6
    with _patch_system_one(AsyncMock(return_value={"model": "x", "answers": _noul_answers(vals)})):
        out = _run(jev_hooks.ffuf_extensions(KEY, "http://t/", {}, 3))
    assert out["extensions"] == [".bak", ".old", ".php"]
    assert len(out["extensions"]) == 3


def test_ffuf_floor_is_never_duplicated_when_jev_also_picks_it():
    vals = {f"ext_{i}": 0.0 for i in range(len(jev_hooks.FFUF_JEV_CATALOG))}
    bak = jev_hooks.FFUF_JEV_CATALOG.index(".bak")
    vals[f"ext_{bak}"] = 0.95
    with _patch_system_one(AsyncMock(return_value={"model": "x", "answers": _noul_answers(vals)})):
        out = _run(jev_hooks.ffuf_extensions(KEY, "http://t/", {}, 10))
    assert out["extensions"].count(".bak") == 1


def test_ffuf_only_asks_about_catalog_entries():
    captured = {}

    async def fake(key, model, state, questions):
        captured["questions"] = questions
        captured["state"] = state
        return {"model": "x", "answers": _noul_answers({n: 0.0 for n in questions})}

    with _patch_system_one(fake):
        _run(jev_hooks.ffuf_extensions(KEY, "http://t/", {"Server": "nginx"}, 6))
    assert len(captured["questions"]) == len(jev_hooks.FFUF_JEV_CATALOG)
    assert all(q["type"] == "noul" for q in captured["questions"].values())
    # Target headers go into the state, wrapped, never into an instruction.
    assert "UNTRUSTED_TARGET_HEADERS" in captured["state"]["headers"]
    assert all("nginx" not in q["instructions"] for q in captured["questions"].values())


# ---------------------------------------------------------------------------
# nuclei tags
# ---------------------------------------------------------------------------

def test_nuclei_always_keeps_universal_tags_present_in_candidates():
    candidates = ["cve", "kev", "exposure", "wordpress", "apache"]
    answers = _noul_answers({f"tag_{i}": 0.0 for i in range(len(candidates))})
    with _patch_system_one(AsyncMock(return_value={"model": "x", "answers": answers})):
        out = _run(jev_hooks.nuclei_tags(KEY, [], [], candidates, 15))
    assert set(out["tags"]) == {"cve", "kev", "exposure"}


def test_nuclei_universal_floor_only_includes_tags_in_candidates():
    candidates = ["wordpress", "apache"]  # no universal tags offered
    answers = _noul_answers({"tag_0": 0.9, "tag_1": 0.0})
    with _patch_system_one(AsyncMock(return_value={"model": "x", "answers": answers})):
        out = _run(jev_hooks.nuclei_tags(KEY, ["wordpress"], [], candidates, 15))
    assert out["tags"] == ["wordpress"]


def test_nuclei_keeps_floor_then_adds_ranked_picks_capped():
    candidates = ["cve", "wordpress", "apache", "php"]
    vals = {"tag_0": 0.0, "tag_1": 0.95, "tag_2": 0.9, "tag_3": 0.6}
    with _patch_system_one(AsyncMock(return_value={"model": "x", "answers": _noul_answers(vals)})):
        out = _run(jev_hooks.nuclei_tags(KEY, [], [], candidates, 3))
    assert out["tags"][0] == "cve"            # floor first
    assert "wordpress" in out["tags"]
    assert len(out["tags"]) == 3


def test_nuclei_no_candidates_makes_no_call():
    s1 = AsyncMock()
    with _patch_system_one(s1):
        out = _run(jev_hooks.nuclei_tags(KEY, [], [], [], 15))
    assert out == {"tags": []}
    s1.assert_not_called()


# ---------------------------------------------------------------------------
# splitting + all-or-nothing
# ---------------------------------------------------------------------------

def test_a_large_set_splits_into_sequential_calls_same_state(monkeypatch):
    monkeypatch.setattr(jev_hooks, "JEV_MAX_QUESTIONS_PER_CALL", 10)
    candidates = [f"tag{i}" for i in range(25)]
    calls = []

    async def fake(key, model, state, questions):
        calls.append((state, list(questions)))
        return {"model": "x", "answers": _noul_answers({n: 0.9 for n in questions})}

    with _patch_system_one(fake):
        out = _run(jev_hooks.nuclei_tags(KEY, ["php"], ["nginx"], candidates, 100))
    assert [len(names) for _, names in calls] == [10, 10, 5]
    assert all(state == calls[0][0] for state, _ in calls)   # same state across the split
    assert len(out["tags"]) == 25


def test_a_failed_request_in_a_split_fails_the_whole_hook(monkeypatch):
    monkeypatch.setattr(jev_hooks, "JEV_MAX_QUESTIONS_PER_CALL", 10)
    candidates = [f"tag{i}" for i in range(25)]
    n = {"i": 0}

    async def fake(key, model, state, questions):
        n["i"] += 1
        if n["i"] == 2:
            raise JevError("jev_rate_limited", retry_after=3)
        return {"model": "x", "answers": _noul_answers({q: 0.9 for q in questions})}

    with _patch_system_one(fake):
        with pytest.raises(JevError) as err:
            _run(jev_hooks.nuclei_tags(KEY, [], [], candidates, 100))
    assert err.value.error_type == "jev_rate_limited"


# ---------------------------------------------------------------------------
# waf + takeover mapping
# ---------------------------------------------------------------------------

def test_waf_detected_maps_vendor_and_confidence():
    answers = {
        "edge": {"type": "noul", "noul": 0.82},
        "vendor": {"type": "choice", "choice": "cloudflare", "confidence": 0.9,
                   "probabilities": {"cloudflare": 0.9}},
    }
    with _patch_system_one(AsyncMock(return_value={"model": "x", "answers": answers})):
        out = _run(jev_hooks.waf_classify(KEY, "http://t/", 403, {"cf-ray": "x"}, "blocked", 120))
    assert out == {"waf_detected": True, "waf_type": "cloudflare", "confidence": 82,
                   "reasoning": "", "source": "jev_classifier"}


def test_waf_not_detected_drops_the_vendor():
    answers = {
        "edge": {"type": "noul", "noul": 0.1},
        "vendor": {"type": "choice", "choice": "cloudflare", "confidence": 0.3,
                   "probabilities": {"cloudflare": 0.3}},
    }
    with _patch_system_one(AsyncMock(return_value={"model": "x", "answers": answers})):
        out = _run(jev_hooks.waf_classify(KEY, "http://t/", 200, {}, "", 10))
    assert out["waf_detected"] is False
    assert out["waf_type"] is None
    assert out["confidence"] == 10
    assert out["source"] == "jev_classifier"


def test_waf_vendor_choice_is_the_closed_14_set():
    captured = {}

    async def fake(key, model, state, questions):
        captured["vendors"] = list(questions["vendor"]["criteria"])
        return {"model": "x", "answers": {
            "edge": {"type": "noul", "noul": 0.9},
            "vendor": {"type": "choice", "choice": "custom", "confidence": 0.5,
                       "probabilities": {"custom": 1.0}},
        }}

    with _patch_system_one(fake):
        _run(jev_hooks.waf_classify(KEY, "http://t/", 403, {}, "", 0))
    assert set(captured["vendors"]) == set(jev_hooks._WAF_VENDORS)
    assert len(captured["vendors"]) == 14


def test_takeover_confidence_is_in_the_verdict_taken():
    for noul, is_block, conf in [(0.9, True, 90), (0.1, False, 90), (0.5, True, 50)]:
        answers = {"waf_block": {"type": "noul", "noul": noul}}
        with _patch_system_one(AsyncMock(return_value={"model": "x", "answers": answers})):
            out = _run(jev_hooks.takeover_classify(KEY, "h", "heroku", 404, {}, "nope"))
        assert out["is_waf_block"] is is_block
        assert out["confidence"] == conf
        assert out["source"] == "jev_classifier"
        assert out["reason"] == ""
