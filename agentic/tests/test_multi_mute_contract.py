"""Contract: the suggest payload the agent produces is the one the modal renders.

The agent (`multi_mute.service.suggest`) and the webapp modal
(`MuteNode/multiMuteModel.ts`) agree on one JSON shape, and nothing else checks
it: each side's own tests build their payloads by hand, so a key renamed on one
side passes both suites and the modal silently shows nothing.

The shared fixture `webapp/src/app/graph/components/MuteNode/multiMuteSuggest.contract.json`
is a real payload, produced here from synthetic findings and a canned model
answer. This test fails when the producer's shape or enums drift from it; the
webapp's `MultiMuteModal.contract.test.tsx` renders the same file. After an
intended change, regenerate it and let the webapp test say whether the modal
still reads it:

    MULTI_MUTE_CONTRACT_WRITE=1 ./agentic/run_tests.sh tests/test_multi_mute_contract.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
for p in (str(REPO), str(REPO / "agentic")):
    if p not in sys.path:
        sys.path.insert(0, p)

FIXTURE = (REPO / "webapp" / "src" / "app" / "graph" / "components" / "MuteNode"
           / "multiMuteSuggest.contract.json")
BATCH = "mm-00000000"
NGINX = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n<html>Welcome</html>"


def _row(key, host, severity="low", body=NGINX, template="nginx-version", name=None):
    return {
        "key": key, "id": key, "label": "Vulnerability", "node_id": str(1000 + len(key) * 7),
        "source": "nuclei", "name": name or "Nginx version disclosure", "severity": severity,
        "template_id": template, "matcher_name": template, "type": "http",
        "raw_response": body, "evidence": None, "triage_host": host,
        "matched_at": f"https://{host}/", "tags": [], "proven": False,
        "validation_status": None, "verdict": None, "confidence_tier": None,
        "triage_tier": None, "triage_factors": None, "triage_ai_verdict": None,
        "triage_group_key": None, "finding_type": None, "stale_since": None,
        "muted": False, "cve_ids": [],
    }


SEED = _row("v-seed", "a.example.com")
ROWS = [SEED,
        _row("v-b", "b.example.com"),
        _row("v-c", "c.example.com"),
        _row("v-apache", "a.example.com", template="apache-version", name="Apache version disclosure",
             body="HTTP/1.1 200 OK\r\nServer: Apache/2.4.57\r\n\r\n<html>It works</html>"),
        _row("v-git", "a.example.com", template="git-config", name="Exposed .git/config",
             body="[core]\n\trepositoryformatversion = 0")]


def _answer(clusters):
    """A model answer naming every cluster it was sent, one verdict of each kind."""
    by_template = {c.representative.get("template_id"): c.id for c in clusters}
    verdicts = [
        {"cluster": by_template["nginx-version"], "verdict": "match",
         "quote": "<html>Welcome</html>", "why": "the same default page"},
        {"cluster": by_template["apache-version"], "verdict": "maybe",
         "quote": "", "why": "a banner, but another server"},
        {"cluster": by_template["git-config"], "verdict": "no",
         "quote": "", "why": "exposed source matters more"},
    ]
    return json.dumps({
        "seed": {"reason": "not_worth_fixing", "why": "an informational banner", "quote": ""},
        "verdicts": verdicts,
        "groups": [{"concept": "same_low_risk", "title": "Version banners",
                    "why": "informational fingerprints",
                    "clusters": [by_template["nginx-version"], by_template["apache-version"]]}],
    })


def _payload():
    from multi_mute import batches, queries, service

    class _Llm:
        async def ainvoke(self, messages):
            class _R:
                content = _answer(_Llm.clusters)
            return _R()

    real_rank = service.clusters.rank_clusters

    def capture(*a, **k):
        ranked = real_rank(*a, **k)
        _Llm.clusters = ranked
        return ranked

    patches = [
        mock.patch.object(queries, "locate_seed", return_value={
            "label": "Vulnerability", "muted": False, "props": {"source": "nuclei"}}),
        mock.patch.object(queries, "read_seed", return_value={
            **SEED, "_mm_source": "nuclei", "_mm_detector": "nginx-version"}),
        mock.patch.object(queries, "read_pool", return_value=[dict(r) for r in ROWS]),
        mock.patch.object(queries, "read_counts", return_value={
            "live": len(ROWS), "stale": 1, "js_file": 0}),
        mock.patch.object(service.clusters, "rank_clusters", capture),
    ]
    for p in patches:
        p.start()
    service.reset_state()
    try:
        payload = asyncio.run(service.suggest(
            user_id="u1", project_id="p1", seed_key="v-seed", model="provider/model-x",
            exempt_pairs=[], driver=object(), build_llm=lambda _m: _Llm()))
    finally:
        for p in patches:
            p.stop()
        batches.STORE.clear()
        service.reset_state()
    # What the webapp route strips before the browser sees it.
    for key in ("model_used", "multi_mute"):
        payload.pop(key, None)
    payload["batch_id"] = BATCH
    return payload


def _shape(value):
    """Keys all the way down, and the JSON type of every leaf."""
    if isinstance(value, dict):
        return {k: _shape(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        merged: dict = {}
        leaves = set()
        for item in value:
            s = _shape(item)
            if isinstance(s, dict):
                for k, v in s.items():
                    merged.setdefault(k, set()).add(json.dumps(v, sort_keys=True))
            else:
                leaves.add(json.dumps(s))
        return {"[]": {k: sorted(v) for k, v in sorted(merged.items())} if merged else sorted(leaves)}
    return "null" if value is None else type(value).__name__


def _enums(payload):
    members = [m for g in payload["groups"] for m in g["members"] + g["probably_not"]]
    return {
        "status": {payload["status"]},
        "reason": {payload["read"]["reason"]},
        "verdict": {m["verdict"] for m in members},
        "concepts": {c for g in payload["groups"] for c in g["concepts"]},
        "excluded": set(payload["pool"]["excluded"]),
    }


def test_the_producer_matches_the_shared_fixture():
    payload = _payload()
    if os.environ.get("MULTI_MUTE_CONTRACT_WRITE"):
        FIXTURE.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert _shape(payload) == _shape(fixture), (
        "the suggest payload's shape drifted from the fixture the modal renders: "
        "regenerate it (see the module docstring) and run MultiMuteModal.contract.test.tsx")
    assert _enums(payload) == _enums(fixture)


def test_the_fixture_exercises_every_state_the_modal_draws():
    """A fixture missing a verdict or a group kind would let that path drift unseen."""
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    enums = _enums(fixture)
    assert enums["verdict"] >= {"match", "maybe", "no"}
    assert any(g["ai"] for g in fixture["groups"]) and any(not g["ai"] for g in fixture["groups"])
    assert any(g["probably_not"] for g in fixture["groups"])
    members = [m for g in fixture["groups"] for m in g["members"]]
    assert any(m["checked"] for m in members) and any(not m["checked"] for m in members)
    assert any(m["quote_verified"] for m in members) and any(not m["quote_verified"] for m in members)


def test_the_fixture_values_are_ones_the_agent_can_emit():
    from multi_mute import pool, validate

    enums = _enums(json.loads(FIXTURE.read_text(encoding="utf-8")))
    assert enums["status"] <= {"ok", "model_unreadable", "empty_pool"}
    assert enums["reason"] <= set(validate.REASONS)
    assert enums["verdict"] <= set(validate.VERDICTS) | {None}
    assert enums["concepts"] <= set(validate.CONCEPT_LABELS)
    assert enums["excluded"] <= set(pool.EXCLUSION_REASONS)
