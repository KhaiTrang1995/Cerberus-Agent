"""run_resource_enum, end to end with fake tools: the R7 jsluice protection and the
shadow records' trip to the saved recon JSON.

The unit tests prove each piece; these prove the wiring inside the real function:
- a Hakrawler that reports failed seeds keeps the previous run's jsluice secrets out
  of the prune, even when the crawl still found URLs (that case has no other trigger);
- the Jev-only hooks' shadow records survive into the file the run saves, which is
  what a person reads to decide whether a hook may act.
Only the tool binaries and the agent call are faked; the function under test is real.
"""
from __future__ import annotations

import json
from unittest import mock

import pytest

from recon.helpers import circuit_breaker as cb
from recon.helpers.ai_planner import jev_shadow
from recon.main_recon_modules import resource_enum

SEEDS = ["https://a.example.test/", "https://b.example.test/"]
CRAWLED = ["https://a.example.test/admin/users", "https://a.example.test/api/v1/orders",
           "https://a.example.test/static/app.js", "https://b.example.test/blog/post-1",
           "https://b.example.test/assets/logo.png"]

BASE = {
    "KATANA_ENABLED": False, "HAKRAWLER_ENABLED": True, "HAKRAWLER_TIMEOUT": 30,
    "HAKRAWLER_PARALLELISM": 2, "GAU_ENABLED": False, "PARAMSPIDER_ENABLED": False,
    "KITERUNNER_ENABLED": False, "JSLUICE_ENABLED": False, "FFUF_ENABLED": False,
    "ARJUN_ENABLED": False, "ZAP_AJAX_SPIDER_ENABLED": False,
    "RESOURCE_ENUM_AI_CLASSIFIER_ENABLED": False,
}


def _hakrawler(failed: bool):
    def fake(*args, **kwargs):
        return list(CRAWLED), {"external_domains": [], "failed": failed,
                               "failed_seeds": 1 if failed else 0}
    return fake


def _run(settings: dict, *, failed: bool = False, recon_data=None, output_file=None, post=None):
    hosts = {s.split("//", 1)[1].rstrip("/") for s in SEEDS}
    patches = [
        mock.patch.object(resource_enum, "run_hakrawler_crawler", _hakrawler(failed)),
        mock.patch.object(resource_enum, "pull_hakrawler_docker_image", return_value=True),
        mock.patch.object(resource_enum, "is_docker_installed", return_value=True),
        mock.patch.object(resource_enum, "is_docker_running", return_value=True),
        mock.patch.object(resource_enum, "extract_targets_from_recon", return_value=(set(), hosts, {})),
        mock.patch.object(resource_enum, "build_target_urls", return_value=list(SEEDS)),
        mock.patch.object(resource_enum, "run_jsluice_analysis",
                          return_value={"urls": [], "secrets": [], "external_domains": []}),
        mock.patch.object(resource_enum, "pull_ffuf_binary_check", return_value=True),
        mock.patch.object(resource_enum, "run_ffuf_discovery", return_value=([], {})),
        mock.patch.object(jev_shadow.requests, "post", side_effect=post or _agent_down),
    ]
    for p in patches:
        p.start()
    try:
        return resource_enum.run_resource_enum(
            recon_data if recon_data is not None else {"domain": "example.test"},
            output_file=output_file, settings={**BASE, **settings})
    finally:
        for p in patches:
            p.stop()


def _agent_down(*a, **k):
    raise AssertionError("no Jev call expected in this test")


# ---------------------------------------------------------------------------
# Row 3: a failed Hakrawler protects jsluice
# ---------------------------------------------------------------------------

JSLUICE_ON = {"JSLUICE_ENABLED": True, "JSLUICE_EXTRACT_SECRETS": True, "JSLUICE_EXTRACT_URLS": True}


def test_a_failed_hakrawler_that_still_found_urls_marks_jsluice_degraded():
    _run(JSLUICE_ON, failed=True)
    assert "jsluice" in cb.coverage_report().degraded_sources


def test_a_healthy_hakrawler_crawl_does_not_protect_jsluice():
    """The control: the same crawl without failed seeds re-checked the secrets."""
    _run(JSLUICE_ON, failed=False)
    assert "jsluice" not in cb.coverage_report().degraded_sources


# ---------------------------------------------------------------------------
# Row 4: the shadow records reach the saved recon JSON
# ---------------------------------------------------------------------------

def _jev_agent(url, json=None, headers=None, timeout=None):
    resp = mock.MagicMock(status_code=200, text="")
    if url.endswith("/jev/ffuf-base-paths"):
        cands = json["candidates"]
        resp.json.return_value = {"ranked": cands[:json["cap"]], "scores": [0.6] * len(cands),
                                  "model": "jev-1.13.0"}
    elif url.endswith("/jev/crawl-seed-order"):
        resp.json.return_value = {"scores": [0.2, 0.9][:len(json["hosts"])], "model": "jev-1.13.0"}
    else:
        raise AssertionError(f"unexpected Jev route {url}")
    return resp


def test_the_shadow_records_are_in_the_saved_recon_json(tmp_path):
    out = tmp_path / "recon_p1.json"
    probe = {"by_url": {s: {"url": s, "host": s.split("//")[1].rstrip("/"), "status_code": 200,
                            "content_length": 900, "word_count": 80, "title": "T", "server": "nginx"}
                        for s in SEEDS}}
    settings = {"AI_IN_PIPELINE": True, "FFUF_ENABLED": True, "FFUF_SMART_FUZZ": True,
                "FFUF_SMART_FUZZ_MAX_BASE_PATHS": 2, "FFUF_JEV_BASE_PATHS": True,
                "HAKRAWLER_JEV_SEED_ORDER": True}
    _run(settings, recon_data={"domain": "example.test", "http_probe": probe},
         output_file=out, post=_jev_agent)
    saved = json.loads(out.read_text())
    shadow = saved["jev_shadow"]
    assert set(shadow) >= {"ffuf_base_paths", "crawl_seed_order"}
    assert shadow["ffuf_base_paths"]["records"] and shadow["crawl_seed_order"]["records"]
    assert shadow["ffuf_base_paths"]["model"] == "jev-1.13.0"


# ---------------------------------------------------------------------------
# Regression
# ---------------------------------------------------------------------------

def test_a_previous_runs_leftover_empty_results_are_not_charged_to_this_run():
    """REGRESSION: a run that raised before its drain (another domain group in the same
    process) left its reports queued, and the next run recorded them as its own gaps."""
    from recon.helpers.resource_enum import tool_health as th
    th.report_empty("gau", th.FAILURE, return_code=None, seeds=1, elapsed_s=1)
    _run({})
    assert "gau" not in {g["source"] for g in cb.coverage_report().gaps}
