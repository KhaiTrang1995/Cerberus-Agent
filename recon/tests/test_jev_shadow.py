"""The shared plumbing of the kind B Jev hooks: `jev_post` and shadow mode.

What it locks in:
- jev_post goes through the `agent_jev` breaker (never `agent_llm`), skips the POST
  while it is open, records every outcome, and never raises;
- a failure prints at most a fixed error_type, never a response body (a 422 echoes
  the target strings the payload carried);
- shadow lines are capped per hook per run, a summary line always closes the hook,
  and the full records go into the recon JSON when there is one;
- no line a kind B hook prints can move the recon drawer to another phase.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from unittest import mock

import pytest
import requests

from recon.helpers import circuit_breaker as cb
from recon.helpers.ai_planner import jev_shadow
from recon.helpers.ai_planner.jev_shadow import ShadowRecorder, jev_model, jev_post

REPO = Path(__file__).resolve().parents[2]


def _resp(status=200, body=None):
    r = mock.MagicMock(status_code=status, text="")
    r.json.return_value = body if body is not None else {}
    return r


# ---------------------------------------------------------------------------
# jev_post
# ---------------------------------------------------------------------------

def test_posts_to_the_jev_route_with_the_internal_key(monkeypatch):
    monkeypatch.setenv("AGENT_API_URL", "http://agent:8090/")
    monkeypatch.setenv("INTERNAL_API_KEY", "k1")
    with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(200, {"ok": 1})) as post:
        out = jev_post("page-type", {"pages": []}, "T", 7)
    assert out == {"ok": 1}
    assert post.call_args.args[0] == "http://agent:8090/jev/page-type"
    assert post.call_args.kwargs["headers"] == {"X-Internal-Key": "k1"}
    assert post.call_args.kwargs["timeout"] == 7


def test_a_jev_fatal_opens_the_jev_breaker_and_never_the_llm_one():
    with mock.patch.object(jev_shadow.requests, "post",
                           return_value=_resp(503, {"error_type": "jev_not_configured"})) as post:
        assert jev_post("x", {}, "T", 1) is None
        assert jev_post("x", {}, "T", 1) is None
    assert post.call_count == 1                        # the second call never left recon
    assert cb.is_open("agent_jev")
    assert not cb.is_open("agent_llm")


def test_an_open_breaker_skips_the_post_and_says_so(capsys):
    with mock.patch.object(jev_shadow, "agent_jev_gate", return_value=mock.Mock(allowed=False)), \
            mock.patch.object(jev_shadow.requests, "post") as post:
        assert jev_post("x", {}, "PageType-Jev", 1) is None
    post.assert_not_called()
    assert "[!][PageType-Jev] Agent Jev paused (breaker open) - using the fallback." in capsys.readouterr().out


def test_a_transport_error_is_recorded_and_never_raises(capsys):
    gate = mock.Mock(allowed=True)
    err = requests.ConnectionError("http://agent:8090/jev/x secret-ish detail")
    with mock.patch.object(jev_shadow, "agent_jev_gate", return_value=gate), \
            mock.patch.object(jev_shadow.requests, "post", side_effect=err):
        assert jev_post("x", {}, "T", 1) is None
    gate.record.assert_called_once_with(exc=err)
    out = capsys.readouterr().out
    assert "ConnectionError" in out and "secret-ish" not in out


def test_a_non_200_prints_only_the_error_type_never_the_body(capsys):
    body = {"detail": [{"input": "http://portal.example.test/scan"}], "error_type": "jev_bad_request"}
    with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(422, body)):
        assert jev_post("x", {}, "T", 1) is None
    out = capsys.readouterr().out
    assert "HTTP 422 jev_bad_request" in out
    assert "portal" not in out


def test_an_odd_error_type_is_not_printed(capsys):
    with mock.patch.object(jev_shadow.requests, "post",
                           return_value=_resp(503, {"error_type": "portal scan <script>"})):
        jev_post("x", {}, "T", 1)
    out = capsys.readouterr().out
    assert "HTTP 503 - using the fallback" in out and "portal" not in out


def test_a_non_json_200_is_a_fallback():
    r = _resp(200)
    r.json.side_effect = ValueError("no json")
    with mock.patch.object(jev_shadow.requests, "post", return_value=r):
        assert jev_post("x", {}, "T", 1) is None


@pytest.mark.parametrize("data,expected", [
    ({"model": "jev-1.13.0"}, "jev-1.13.0"),
    ({"model": "jev-latest"}, "unknown"),
    ({"model": "port scan"}, "unknown"),
    ({}, "unknown"), (None, "unknown"), ([1], "unknown"),
])
def test_only_a_pinned_model_name_is_kept(data, expected):
    assert jev_model(data) == expected


# ---------------------------------------------------------------------------
# ShadowRecorder
# ---------------------------------------------------------------------------

def test_shadow_lines_are_capped_and_summarised(capsys, monkeypatch):
    monkeypatch.setenv("PROJECT_ID", "cmabc123")
    rec = ShadowRecorder("page_type", cap=3)
    rec.model = "jev-1.13.0"
    for i in range(5):
        rec.decision(f"page_{i}", "parked" if i % 2 else "app", 80, "app", url=f"http://h{i}.example.test/")
    rec.fallback()
    data = {}
    rec.finish(data)
    lines = capsys.readouterr().out.strip().splitlines()
    assert lines[0] == ("jev-shadow page_type: project=cmabc123 item=page_0 jev=app conf=80 "
                        "baseline=app agreed=true model=jev-1.13.0")
    assert len([ln for ln in lines if " item=" in ln]) == 3
    assert lines[3] == "jev-shadow page_type: 2 more decisions not printed"
    assert lines[4] == ("jev-shadow page_type: summary decisions=5 agreed=60% mean_conf=80 "
                        "fallbacks=1 model=jev-1.13.0")
    stored = data["jev_shadow"]["page_type"]
    assert stored["rollout"] == "shadow" and stored["summary"]["decisions"] == 5
    assert stored["records"][1] == {"item": "page_1", "jev": "parked", "conf": 80, "baseline": "app",
                                    "agreed": False, "url": "http://h1.example.test/"}


def test_the_item_itself_reaches_the_records_but_never_stdout(capsys):
    rec = ShadowRecorder("ffuf_base_paths")
    rec.decision("path_0", "keep", 90, "cut", path="portal/scan")
    rec.finish(None)                                  # partial run: no recon JSON
    assert "portal" not in capsys.readouterr().out


def test_an_empty_run_still_prints_one_summary(capsys):
    ShadowRecorder("tool_health").finish({})
    assert capsys.readouterr().out.strip() == (
        "jev-shadow tool_health: summary decisions=0 agreed=0% mean_conf=0 fallbacks=0 model=unknown")


def test_the_default_stdout_cap_is_fifty():
    assert jev_shadow.STDOUT_CAP == 50


# ---------------------------------------------------------------------------
# Phase safety of every line a kind B hook prints
# ---------------------------------------------------------------------------

def _orchestrator_phase_patterns() -> list:
    source = (REPO / "recon_orchestrator" / "container_manager.py").read_text()
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "PHASE_PATTERNS" for t in node.targets):
            return [entry[0] for entry in ast.literal_eval(node.value)]
    raise AssertionError("PHASE_PATTERNS not found in container_manager.py")


#: Each kind B hook's stdout lines, rendered with realistic values. The items are
#: indexes and the numbers are ours, so these are the only bytes that can match.
_HOOK_LINES = {
    "ffuf_base_paths": [
        "[*][FFuf-BasePaths-Jev] Ranking 400 of 523 candidate directories for 20 slots",
        "[+][FFuf-BasePaths-Jev] Jev keeps 20; 6 of them are in the deterministic first 20",
        "[!][FFuf-BasePaths-Jev] Agent answer failed validation - using the fallback.",
        "[!][FFuf-BasePaths-Jev] Ranking failed (KeyError) - using the fallback.",
        "[!][FFuf] Base-path ranker failed (KeyError) - using the random pick",
    ],
    # Runs inside the HTTP probe, so a "port...scan" match would move the drawer back.
    "page_type": [
        "[*][PageType-Jev] 1200 pages, 340 placed by the pre-filter, 300 distinct to ask",
        "[!][PageType-Jev] Time budget of 60s reached - 44 distinct pages left unlabelled",
        "[!][PageType-Jev] 512 pages not asked (cap 300 distinct pages per scan, or the time budget)",
        "[+][PageType-Jev] 688 pages labelled, 1 batches fell back",
        "[!][PageType-Jev] Agent answer failed validation - using the fallback.",
        "[!][PageType-Jev] Pass failed (KeyError) - pages left unlabelled.",
        "[!][PageType-Jev] Skipped (KeyError).",
    ],
    "tool_health": [
        "[*][ToolHealth-Jev] 4 empty result(s) with unexplained error output; asking about 4",
        "[!][ToolHealth-Jev] 2 more not asked (cap 20 per run)",
        "[!][ToolHealth-Jev] Pass failed (KeyError) - the gaps stand as recorded.",
        "[!][ToolHealth-Jev] Skipped (KeyError).",
        "[!][ToolHealth-Jev] Agent answer failed validation - using the fallback.",
        "[!][ToolHealth] paramspider: 12 empty result(s) look like a failure, recorded as a coverage gap",
        "[!][Hakrawler] 3 seed(s) came back empty with an error or no clean exit",
    ],
    "crawl_seed_order": [
        "[*][CrawlOrder-Jev] Scoring 120 of 140 hosts for the Hakrawler order",
        "[+][CrawlOrder-Jev] Jev would move 12 host(s) from the second half of the list into the first",
        "[*][CrawlOrder-Jev] Partial recon has no per-host probe signal - keeping the alphabetical order",
        "[!][CrawlOrder-Jev] Ordering failed (KeyError) - using the fallback.",
        "[!][CrawlOrder-Jev] Agent answer failed validation - using the fallback.",
    ],
}


def _shadow_lines(hook: str) -> list:
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rec = ShadowRecorder(hook, cap=1)
        rec.model = "jev-1.13.0"
        rec.decision("item_12", "keep", 73, "cut")
        rec.decision("item_13", "cut", 41, "cut")
        rec.finish({})
    return buf.getvalue().splitlines()


def _common_lines(tag: str) -> list:
    return [
        f"[!][{tag}] Agent Jev paused (breaker open) - using the fallback.",
        f"[!][{tag}] Agent request failed (ReadTimeout) - using the fallback.",
        f"[!][{tag}] Agent returned HTTP 503 jev_not_configured - using the fallback.",
        f"[!][{tag}] Agent returned a non-JSON answer - using the fallback.",
    ]


@pytest.mark.parametrize("hook", sorted(_HOOK_LINES))
def test_no_kind_b_line_moves_the_drawer_to_another_phase(hook):
    tag = _HOOK_LINES[hook][0].split("][", 1)[1].split("]", 1)[0]
    lines = _HOOK_LINES[hook] + _shadow_lines(hook) + _common_lines(tag)
    for line in lines:
        for pattern in _orchestrator_phase_patterns():
            assert not re.search(pattern, line, re.IGNORECASE), (line, pattern)
