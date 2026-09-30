"""Live: the Multi mute prompt against a real model, on SYNTHETIC findings.

Records how often the model's verdict lands where a reviewer put it, per
`MULTI_MUTE_PROMPT_VERSION`, so a prompt or model change that quietly makes
suggestions worse shows up as a number rather than as operators muting the
wrong things. The graph is replaced by fixture rows (example.com, RFC 5737);
everything from the pool rules to the validation runs for real.

Self-skips unless both are set, and the webapp is reachable for the providers:
    MULTI_MUTE_LIVE_MODEL     e.g. deepseek/deepseek-v4-flash
    MULTI_MUTE_LIVE_USER_ID   the user whose provider keys to use
Optional: MULTI_MUTE_LIVE_RECORD=<path> appends one JSON line per run.

    ./agentic/run_tests.sh live
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parents[2]
for p in (str(REPO), str(REPO / "agentic")):
    if p not in sys.path:
        sys.path.insert(0, p)

pytestmark = pytest.mark.live

MODEL = os.environ.get("MULTI_MUTE_LIVE_MODEL", "")
USER = os.environ.get("MULTI_MUTE_LIVE_USER_ID", "")
MIN_ACCURACY = 0.6


def _row(key, name, template, body, host="a.example.com", severity="info", **extra):
    row = {
        "key": key, "id": key, "label": "Vulnerability", "node_id": str(100 + len(key)),
        "source": "nuclei", "name": name, "severity": severity, "template_id": template,
        "matcher_name": template, "type": "http", "raw_response": body, "evidence": None,
        "triage_host": host, "matched_at": f"https://{host}/", "tags": [],
        "proven": False, "validation_status": None, "verdict": None, "confidence_tier": None,
        "triage_tier": None, "triage_factors": None, "triage_ai_verdict": None,
        "triage_group_key": None, "finding_type": None, "stale_since": None, "muted": False,
        "cve_ids": [],
    }
    row.update(extra)
    return row


NGINX = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html>Welcome</html>"
SEED = _row("seed", "Nginx version disclosure", "nginx-version", NGINX)

#: key -> the verdicts a reviewer accepts for a seed muted as "not worth fixing".
EXPECTED = {
    "same-banner-b": {"match"},
    "same-banner-c": {"match"},
    "apache-banner": {"match", "maybe"},
    "waf-block": {"maybe", "no"},
    "git-config": {"no"},
    "debug-page": {"no", "maybe"},
}
POOL = [SEED,
        _row("same-banner-b", "Nginx version disclosure", "nginx-version", NGINX, host="b.example.com"),
        _row("same-banner-c", "Nginx version disclosure", "nginx-version", NGINX, host="c.example.com"),
        _row("apache-banner", "Apache version disclosure", "apache-version",
             "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57 (Debian)\r\n\r\n<html>It works!</html>"),
        _row("waf-block", "Possible SQL error", "sql-error-generic",
             "HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\n\r\n<title>Attention Required! | "
             "Cloudflare</title> Sorry, you have been blocked"),
        _row("git-config", "Exposed .git/config", "git-config",
             "HTTP/1.1 200 OK\r\n\r\n[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n"
             "\turl = https://git.example.com/acme/internal.git"),
        _row("debug-page", "Framework debug page", "debug-mode",
             "HTTP/1.1 500 Internal Server Error\r\n\r\nTraceback (most recent call last):\n"
             "  File \"/srv/app/views.py\", line 42, in handler\nSECRET_KEY = '<redacted>'")]


def _skip_reason():
    if not MODEL or not USER:
        return "set MULTI_MUTE_LIVE_MODEL and MULTI_MUTE_LIVE_USER_ID to run"
    try:
        from llm_builder import fetch_user_providers
        if not fetch_user_providers(USER):
            return "the user has no LLM providers"
    except Exception as exc:  # noqa: BLE001
        return f"providers unreachable: {exc.__class__.__name__}"
    return None


def test_verdict_accuracy_on_the_synthetic_pool():
    reason = _skip_reason()
    if reason:
        pytest.skip(reason)
    from llm_builder import build_llm_from_providers, fetch_user_providers
    from multi_mute import batches, prompt, queries, service

    service.reset_state()
    batches.STORE.clear()
    patches = [
        mock.patch.object(queries, "locate_seed", return_value={
            "label": "Vulnerability", "muted": False, "props": {"source": "nuclei"}}),
        mock.patch.object(queries, "read_seed", return_value={
            **SEED, "_mm_source": "nuclei", "_mm_detector": "nginx-version"}),
        mock.patch.object(queries, "read_pool", return_value=[dict(r) for r in POOL]),
        mock.patch.object(queries, "read_counts", return_value={
            "live": len(POOL), "stale": 0, "js_file": 0}),
    ]
    for p in patches:
        p.start()
    try:
        started = time.time()
        payload = asyncio.run(service.suggest(
            user_id=USER, project_id="live-fixture", seed_key="seed", model=MODEL,
            exempt_pairs=[], driver=object(),
            build_llm=lambda m: build_llm_from_providers(m, fetch_user_providers(USER))))
        seconds = time.time() - started
    finally:
        for p in patches:
            p.stop()
        batches.STORE.clear()

    verdicts = {}
    checked = set()
    for group in payload["groups"]:
        for member in group["members"] + group["probably_not"]:
            verdicts.setdefault(member["key"], member["verdict"])
            if member["checked"]:
                checked.add(member["key"])
    hits = sum(1 for key, ok in EXPECTED.items() if verdicts.get(key) in ok)
    accuracy = hits / len(EXPECTED)
    record = {
        "prompt_version": prompt.MULTI_MUTE_PROMPT_VERSION, "model": MODEL,
        "status": payload["status"], "reason": (payload.get("read") or {}).get("reason"),
        "accuracy": round(accuracy, 3), "seconds": round(seconds, 1),
        "verdicts": verdicts, "checked": sorted(checked),
    }
    print("MULTI_MUTE_LIVE", json.dumps(record))
    if os.environ.get("MULTI_MUTE_LIVE_RECORD"):
        with open(os.environ["MULTI_MUTE_LIVE_RECORD"], "a", encoding="utf-8") as fh:
            fh.write(json.dumps({**record, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}) + "\n")

    assert payload["status"] == "ok", payload["status"]
    # A finding that could matter more than the seed must never be pre-ticked,
    # whatever the model said: that is the code's guarantee, not the model's.
    assert "git-config" not in checked
    assert "debug-page" not in checked
    assert accuracy >= MIN_ACCURACY, record
