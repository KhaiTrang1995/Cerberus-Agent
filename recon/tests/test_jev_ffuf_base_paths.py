"""R6: FFuf smart-fuzz base paths ranked by Jev.

What it locks in:
- `select_base_paths` stays the single seam and keeps exactly `cap` paths whatever a
  ranker does: it only changes which survive. A ranker that raises, returns None,
  invents paths or returns too few leaves the random pick (or tops it up from it);
- the ranker is consulted only when the cap actually cuts;
- in SHADOW the ranker records Jev's pick against the sorted baseline and returns
  None, so the scan fuzzes today's random pick; in ACT it returns Jev's order;
- a malformed agent answer is a fallback, never a crash;
- both call sites (full pipeline and partial recon) pass the ranker, gated by
  AI_IN_PIPELINE and FFUF_JEV_BASE_PATHS.

The six random-pick tests in test_ffuf.py keep pinning the no-ranker behaviour.
"""
from __future__ import annotations

import random
from pathlib import Path
from unittest import mock

import pytest

from recon.helpers.ai_planner import ffuf_base_paths as fbp
from recon.helpers.ai_planner import jev_shadow
from recon.helpers.resource_enum.ffuf_helpers import select_base_paths

REPO = Path(__file__).resolve().parents[2]
PATHS = [f"d{i:02d}" for i in range(30)] + ["admin", "api", "api/v1", "static", "index.php"]


def _resp(status=200, body=None):
    r = mock.MagicMock(status_code=status, text="")
    r.json.return_value = body if body is not None else {}
    return r


def _jev_answer(asked, ranked, score=0.5):
    return {"ranked": ranked, "scores": [score] * len(asked), "model": "jev-1.13.0"}


# ---------------------------------------------------------------------------
# The seam with a ranker
# ---------------------------------------------------------------------------

def test_a_ranker_decides_which_survive_and_never_how_many():
    out = select_base_paths(PATHS, 5, ranker=lambda items, cap: ["admin", "api", "api/v1"])
    assert out[:3] == ["admin", "api", "api/v1"]
    assert len(out) == 5 and len(set(out)) == 5
    assert set(out) <= set(PATHS)


def test_a_full_ranking_is_taken_as_is():
    out = select_base_paths(PATHS, 3, ranker=lambda items, cap: ["static", "admin", "api", "d01"])
    assert out == ["static", "admin", "api"]


def test_invented_and_duplicate_paths_are_dropped_and_the_slots_refilled():
    ranker = lambda items, cap: ["admin", "admin", "/admin", "../etc", 7, None, "api"]  # noqa: E731
    out = select_base_paths(PATHS, 4, ranker=ranker, rng=random.Random(1))
    assert out[:2] == ["admin", "api"]
    assert len(out) == 4 and set(out) <= set(PATHS)


@pytest.mark.parametrize("answer", [None, [], ["nope"]])
def test_a_ranker_with_nothing_usable_leaves_the_random_pick(answer):
    seeded = select_base_paths(PATHS, 6, rng=random.Random(42))
    out = select_base_paths(PATHS, 6, rng=random.Random(42), ranker=lambda items, cap: answer)
    assert out == seeded


def test_a_ranker_that_raises_leaves_the_random_pick(capsys):
    def boom(items, cap):
        raise RuntimeError("agent down")

    seeded = select_base_paths(PATHS, 6, rng=random.Random(3))
    assert select_base_paths(PATHS, 6, rng=random.Random(3), ranker=boom) == seeded
    assert "Base-path ranker failed (RuntimeError) - using the random pick" in capsys.readouterr().out


def test_the_ranker_is_not_consulted_when_the_cap_does_not_cut():
    ranker = mock.Mock()
    assert select_base_paths(["b", "a"], 5, ranker=ranker) == ["a", "b"]
    ranker.assert_not_called()


@pytest.mark.parametrize("cap", [0, -1])
def test_a_non_positive_cap_is_empty_and_never_raises(cap):
    ranker = mock.Mock()
    assert select_base_paths(PATHS, cap, ranker=ranker) == []
    ranker.assert_not_called()


def test_the_ranker_gets_the_sorted_candidates():
    seen = {}

    def ranker(items, cap):
        seen["items"], seen["cap"] = items, cap
        return None

    select_base_paths(set(PATHS), 4, ranker=ranker)
    assert seen == {"items": sorted(PATHS), "cap": 4}


# ---------------------------------------------------------------------------
# The Jev ranker
# ---------------------------------------------------------------------------

def _run_ranker(answer_body, *, status=200, items=None, cap=4, recon_data=None, rollout=None,
                monkeypatch=None):
    items = sorted(items or PATHS)
    if rollout is not None:
        monkeypatch.setattr(fbp, "ROLLOUT", rollout)
    with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(status, answer_body)) as post:
        out = fbp.make_jev_ranker("u1", "p1", recon_data=recon_data)(items, cap)
    return out, post


def test_the_shipped_rollout_returns_jev_pick_and_records_it(capsys):
    items = sorted(PATHS)
    data = {}
    out, post = _run_ranker(_jev_answer(items, ["admin", "api", "static", "d05"], 0.9), recon_data=data)
    assert out == ["admin", "api", "static", "d05"]       # the seam fuzzes Jev's pick
    body = post.call_args.kwargs["json"]
    assert post.call_args.args[0].endswith("/jev/ffuf-base-paths")
    assert body == {"candidates": items, "cap": 4, "user_id": "u1", "project_id": "p1"}
    stored = data["jev_shadow"]["ffuf_base_paths"]
    assert stored["rollout"] == "act" and stored["model"] == "jev-1.13.0"
    by_path = {r["path"]: r for r in stored["records"]}
    # The baseline is the sorted order's first 4: admin, api, api/v1, d00.
    assert by_path["static"]["jev"] == "keep" and by_path["static"]["baseline"] == "cut"
    assert by_path["d00"]["jev"] == "cut" and by_path["d00"]["baseline"] == "keep"
    assert by_path["admin"]["agreed"] is True and by_path["admin"]["conf"] == 90
    printed = capsys.readouterr().out
    assert "jev-shadow ffuf_base_paths: summary decisions=35" in printed
    assert "admin" not in printed and "index.php" not in printed     # items never reach stdout


def test_act_returns_jev_order(monkeypatch):
    items = sorted(PATHS)
    out, _ = _run_ranker(_jev_answer(items, ["admin", "api"]), rollout=jev_shadow.ACT,
                         monkeypatch=monkeypatch)
    assert out == ["admin", "api"]


def test_a_shadow_rollout_returns_none_so_the_random_pick_stands(monkeypatch):
    """The gate itself: a hook switched back to SHADOW records but changes nothing."""
    items = sorted(PATHS)
    data = {}
    out, _ = _run_ranker(_jev_answer(items, ["admin", "api"]), rollout=jev_shadow.SHADOW,
                         recon_data=data, monkeypatch=monkeypatch)
    assert out is None
    assert data["jev_shadow"]["ffuf_base_paths"]["rollout"] == "shadow"


def test_the_shipped_rollout_is_act():
    assert fbp.ROLLOUT == jev_shadow.ACT


@pytest.mark.parametrize("bad", [
    None, [], {"ranked": ["admin"]},                                  # missing scores
    {"ranked": ["not-a-candidate"], "scores": "x"},
    {"ranked": ["not-a-candidate"], "scores": [0.5] * 35},             # invented path
    {"ranked": ["admin", "admin"], "scores": [0.5] * 35},             # duplicate
    {"ranked": ["admin", "api", "d01", "d02", "d03"], "scores": [0.5] * 35},   # over the cap
    {"ranked": ["admin"], "scores": [0.5] * 34},                      # wrong length
    {"ranked": ["admin"], "scores": [float("nan")] * 35},
    {"ranked": ["admin"], "scores": [1.5] * 35},
    {"ranked": ["admin"], "scores": [True] * 35},
    {"ranked": [["admin"]], "scores": [0.5] * 35},                    # unhashable
])
def test_a_malformed_answer_is_a_fallback(bad, monkeypatch):
    data = {}
    out, _ = _run_ranker(bad, recon_data=data, rollout=jev_shadow.ACT, monkeypatch=monkeypatch)
    assert out is None
    assert data["jev_shadow"]["ffuf_base_paths"]["summary"]["fallbacks"] == 1
    assert data["jev_shadow"]["ffuf_base_paths"]["records"] == []


def test_an_agent_failure_is_a_fallback_and_never_raises(monkeypatch):
    data = {}
    out, _ = _run_ranker({"error_type": "jev_not_configured"}, status=503, recon_data=data,
                         rollout=jev_shadow.ACT, monkeypatch=monkeypatch)
    assert out is None
    assert data["jev_shadow"]["ffuf_base_paths"]["summary"]["fallbacks"] == 1


def test_an_unexpected_error_inside_the_ranker_is_a_fallback(monkeypatch):
    monkeypatch.setattr(fbp, "jev_post", mock.Mock(side_effect=KeyError("x")))
    assert fbp.make_jev_ranker("u", "p")(sorted(PATHS), 4) is None


def test_more_candidates_than_the_bound_ask_about_a_sample_of_the_bound():
    items = sorted(f"p{i:04d}" for i in range(fbp.MAX_CANDIDATES + 100))
    with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(503, {})) as post:
        fbp.make_jev_ranker("u", "p", rng=random.Random(0))(items, 10)
    asked = post.call_args.kwargs["json"]["candidates"]
    assert len(asked) == fbp.MAX_CANDIDATES
    assert asked == sorted(asked) and set(asked) <= set(items)
    assert asked != items[:fbp.MAX_CANDIDATES]                 # not the alphabetical cut


def test_overlong_candidates_are_never_sent_but_stay_drawable():
    long = "x" * (fbp.MAX_PATH_CHARS + 1)
    with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(503, {})) as post:
        fbp.make_jev_ranker("u", "p")(sorted(PATHS + [long]), 4)
    assert long not in post.call_args.kwargs["json"]["candidates"]


def test_the_breaker_open_means_no_post():
    with mock.patch.object(jev_shadow, "agent_jev_gate", return_value=mock.Mock(allowed=False)), \
            mock.patch.object(jev_shadow.requests, "post") as post:
        assert fbp.make_jev_ranker("u", "p")(sorted(PATHS), 4) is None
    post.assert_not_called()


# ---------------------------------------------------------------------------
# Gating and wiring
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ai,flag,on", [(True, True, True), (True, False, False),
                                        (False, True, False), (None, None, False)])
def test_the_hook_needs_both_the_master_switch_and_its_own_flag(ai, flag, on):
    settings = {"AI_IN_PIPELINE": ai, "FFUF_JEV_BASE_PATHS": flag}
    assert fbp.jev_base_paths_enabled(settings) is on
    assert (fbp.ranker_for(settings) is not None) is on


def test_an_absent_flag_is_off():
    assert fbp.ranker_for({"AI_IN_PIPELINE": True}) is None


def test_the_ranker_reads_the_owner_from_the_environment(monkeypatch):
    monkeypatch.setenv("USER_ID", "owner-1")
    monkeypatch.setenv("PROJECT_ID", "proj-1")
    with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(503, {})) as post:
        fbp.ranker_for({"AI_IN_PIPELINE": True, "FFUF_JEV_BASE_PATHS": True})(sorted(PATHS), 4)
    body = post.call_args.kwargs["json"]
    assert (body["user_id"], body["project_id"]) == ("owner-1", "proj-1")


@pytest.mark.parametrize("path,call", [
    ("recon/main_recon_modules/resource_enum.py", "ranker=ranker_for(settings, recon_data))"),
    ("recon/partial_recon_modules/web_crawling.py", "ranker=ranker_for(settings))"),
])
def test_both_call_sites_pass_the_ranker_to_the_seam(path, call):
    source = (REPO / path).read_text()
    assert source.count("= select_base_paths(") == 1
    assert call in source
    assert "from recon.helpers.ai_planner.ffuf_base_paths import ranker_for" in source
