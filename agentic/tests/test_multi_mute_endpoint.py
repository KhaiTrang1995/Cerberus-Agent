"""POST /graph/multi-mute/suggest and `multi_mute.service`.

The graph reads are replaced by synthetic rows (example.com / RFC 5737 only);
everything between them and the model - pool rules, clusters, the prompt, the
validation and the batch store - runs for real.
"""
from __future__ import annotations

import asyncio
import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parents[2]
for p in (str(REPO), str(REPO / "agentic")):
    if p not in sys.path:
        sys.path.insert(0, p)

MASTER = "m" * 40
SCANNER = "s" * 40


def _row(key, host="a.example.com", severity="low", body="Server: nginx/1.18.0", **extra):
    row = {
        "key": key, "id": key, "label": "Vulnerability", "node_id": str(abs(hash(key)) % 10000),
        "source": "nuclei", "name": "Nginx version disclosure", "severity": severity,
        "template_id": "tech-detect", "matcher_name": "nginx", "type": "info",
        "raw_response": f"HTTP/1.1 200 OK\r\n{body}\r\n", "evidence": None,
        "triage_host": host, "matched_at": f"https://{host}/", "tags": ["tech"],
        "proven": False, "validation_status": None, "verdict": None,
        "confidence_tier": None, "triage_tier": None, "triage_factors": None,
        "triage_ai_verdict": None, "triage_group_key": None, "finding_type": None,
        "stale_since": None, "muted": False, "cve_ids": [],
    }
    row.update(extra)
    return row


SEED = _row("seed-1")
POOL = [SEED] + [_row(f"k{i}", host=f"h{i}.example.com") for i in range(1, 6)] + [
    _row("hi-1", severity="high"),
]


class _Answer:
    def __init__(self, content):
        self.content = content


class _Llm:
    def __init__(self, content="", error=None, delay=0.0):
        self.content, self.error, self.delay = content, error, delay
        self.calls = 0

    async def ainvoke(self, messages):
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise self.error
        return _Answer(self.content)


GOOD = ('```json\n{"seed": {"reason": "not_worth_fixing", "why": "banner", "quote": ""},'
        ' "verdicts": [{"cluster": "c1", "verdict": "match", "quote": "", "why": "same banner"}],'
        ' "groups": []}\n```')


@pytest.fixture(autouse=True)
def fresh():
    from multi_mute import batches, service
    service.reset_state()
    batches.STORE.clear()
    yield
    service.reset_state()
    batches.STORE.clear()


def _patched_graph(rows=POOL, counts=None, seed=SEED):
    from multi_mute import queries
    counts = counts or {"live": len(rows), "stale": 2, "js_file": 0}
    return [
        mock.patch.object(queries, "locate_seed", return_value={
            "label": "Vulnerability", "muted": False, "props": {"source": "nuclei"}}),
        mock.patch.object(queries, "read_seed", return_value={**seed, "_mm_source": "nuclei",
                                                              "_mm_detector": "tech-detect"}),
        mock.patch.object(queries, "read_pool", return_value=[dict(r) for r in rows]),
        mock.patch.object(queries, "read_counts", return_value=counts),
    ]


def _run_service(llm=None, build_error=None, rows=POOL, user="u1", **kw):
    from multi_mute import service

    def build(model):
        if build_error:
            raise build_error
        return llm or _Llm(GOOD)

    patches = _patched_graph(rows)
    for p in patches:
        p.start()
    try:
        return asyncio.run(service.suggest(
            user_id=user, project_id="p1", seed_key="seed-1", model="gpt-5-mini",
            exempt_pairs=[], driver=object(), build_llm=build, **kw))
    finally:
        for p in patches:
            p.stop()


# -- the service ------------------------------------------------------------

def test_a_suggestion_is_stored_as_a_batch():
    from multi_mute import batches
    out = _run_service()
    assert out["multi_mute"] == 1
    assert out["status"] == "ok"
    batch = batches.STORE.get("u1", "p1", out["batch_id"])
    assert batch is not None
    assert batch.seed_key == "seed-1" and batch.label == "Vulnerability"
    assert batch.model == "gpt-5-mini" and batch.prompt_version == out["prompt_version"]
    assert {"k1", "k2"} <= set(batch.members)
    assert "hi-1" not in batch.members, "a higher-severity finding is never proposed"
    assert "seed-1" not in batch.members


def test_the_pool_reports_its_exclusions():
    out = _run_service()
    assert out["pool"]["total"] == len(POOL) - 1
    assert out["pool"]["excluded"]["above_seed"] == 1
    assert out["pool"]["excluded"]["stale"] == 2


def test_an_empty_pool_makes_no_llm_call():
    llm = _Llm(GOOD)
    out = _run_service(llm=llm, rows=[SEED])
    assert out["status"] == "empty_pool"
    assert llm.calls == 0
    assert out["groups"] == []


def test_an_empty_pool_never_even_builds_the_model():
    from llm_builder import ProvidersUnreachable
    out = _run_service(build_error=ProvidersUnreachable("down"), rows=[SEED])
    assert out["status"] == "empty_pool"


def test_providers_unreachable():
    from llm_builder import ProvidersUnreachable
    from multi_mute import service
    with pytest.raises(service.SuggestError) as err:
        _run_service(build_error=ProvidersUnreachable("down"))
    assert (err.value.code, err.value.status) == ("providers_unreachable", 503)


def test_a_model_that_cannot_be_built_is_model_unavailable():
    from multi_mute import service
    with pytest.raises(service.SuggestError) as err:
        _run_service(build_error=ValueError("no key sk-LEAK"))
    assert err.value.code == "model_unavailable"
    assert "sk-LEAK" not in err.value.message


def test_a_refused_key_at_call_time_is_model_unavailable():
    from multi_mute import service

    class _Refused(Exception):
        status_code = 401

    with pytest.raises(service.SuggestError) as err:
        _run_service(llm=_Llm(error=_Refused("bad key")))
    assert err.value.code == "model_unavailable"


def test_a_slow_model_is_agent_timeout():
    from multi_mute import service
    with mock.patch.object(service, "LLM_TIMEOUT_S", 0.05):
        with pytest.raises(service.SuggestError) as err:
            _run_service(llm=_Llm(GOOD, delay=1))
    assert (err.value.code, err.value.status) == ("agent_timeout", 504)


def test_an_unreadable_answer_still_gives_the_exact_groups_unchecked():
    out = _run_service(llm=_Llm("I think they are all fine"))
    assert out["status"] == "model_unreadable"
    members = [m for g in out["groups"] for m in g["members"]]
    assert members and not any(m["checked"] for m in members)


def test_a_transient_model_failure_degrades_to_the_exact_groups():
    class _Busy(Exception):
        status_code = 529

    out = _run_service(llm=_Llm(error=_Busy("overloaded")))
    assert out["status"] == "model_unreadable"


def test_a_muted_or_missing_seed_is_seed_changed():
    from multi_mute import queries, service
    with mock.patch.object(queries, "locate_seed", side_effect=queries.SeedMissing("x")):
        with pytest.raises(service.SuggestError) as err:
            asyncio.run(service.suggest(user_id="u1", project_id="p1", seed_key="x",
                                        model="m", exempt_pairs=[], driver=object(),
                                        build_llm=lambda m: _Llm(GOOD)))
    assert (err.value.code, err.value.status) == ("seed_changed", 409)
    with mock.patch.object(queries, "locate_seed", return_value={
            "label": "Vulnerability", "muted": True, "props": {}}):
        with pytest.raises(service.SuggestError) as err:
            asyncio.run(service.suggest(user_id="u1", project_id="p1", seed_key="x",
                                        model="m", exempt_pairs=[], driver=object(),
                                        build_llm=lambda m: _Llm(GOOD)))
    assert err.value.code == "seed_changed"


@pytest.mark.parametrize("located", [
    {"label": "ExploitGvm", "muted": False, "props": {}},
    {"label": "JsReconFinding", "muted": False, "props": {"finding_type": "js_file"}},
])
def test_an_unmuteable_seed_is_refused(located):
    from multi_mute import queries, service
    with mock.patch.object(queries, "locate_seed", return_value=located):
        with pytest.raises(service.SuggestError) as err:
            asyncio.run(service.suggest(user_id="u1", project_id="p1", seed_key="x",
                                        model="m", exempt_pairs=[], driver=object(),
                                        build_llm=lambda m: _Llm(GOOD)))
    assert (err.value.code, err.value.status) == ("seed_not_muteable", 400)


def test_a_new_request_from_the_same_user_supersedes_the_first():
    from multi_mute import service
    slow, fast = _Llm(GOOD, delay=5), _Llm(GOOD)
    patches = _patched_graph()
    for p in patches:
        p.start()

    async def main():
        first = asyncio.create_task(service.suggest(
            user_id="u1", project_id="p1", seed_key="seed-1", model="m",
            exempt_pairs=[], driver=object(), build_llm=lambda m: slow))
        await asyncio.sleep(0.2)
        second = await service.suggest(
            user_id="u1", project_id="p1", seed_key="seed-1", model="m",
            exempt_pairs=[], driver=object(), build_llm=lambda m: fast)
        with pytest.raises(service.Superseded):
            await first
        return second

    try:
        second = asyncio.run(main())
    finally:
        for p in patches:
            p.stop()
    assert second["status"] == "ok"
    assert fast.calls == 1


def test_the_global_ceiling_answers_busy():
    from multi_mute import service
    patches = _patched_graph()
    for p in patches:
        p.start()

    async def main():
        blockers = [asyncio.create_task(service.suggest(
            user_id=f"u{i}", project_id="p1", seed_key="seed-1", model="m",
            exempt_pairs=[], driver=object(), build_llm=lambda m: _Llm(GOOD, delay=2)))
            for i in range(service.SUGGEST_MAX_CONCURRENT)]
        await asyncio.sleep(0.2)
        with pytest.raises(service.SuggestError) as err:
            await service.suggest(user_id="late", project_id="p1", seed_key="seed-1",
                                  model="m", exempt_pairs=[], driver=object(),
                                  build_llm=lambda m: _Llm(GOOD))
        for b in blockers:
            b.cancel()
        await asyncio.gather(*blockers, return_exceptions=True)
        return err.value

    try:
        with mock.patch.object(service, "SUGGEST_WAIT_S", 0.1):
            err = asyncio.run(main())
    finally:
        for p in patches:
            p.stop()
    assert (err.code, err.status) == ("busy", 429)


def test_the_suggestion_is_logged_as_an_event():
    """Found exercising the live flow: `kind=` collided with log_event's own
    first parameter, and the TypeError was swallowed, so no suggestion was
    ever logged. autospec keeps the real signature, which a plain mock would
    not."""
    import session_log
    with mock.patch.object(session_log, "log_event", autospec=True) as logged:
        payload = _run_service()
    logged.assert_called_once()
    args, fields = logged.call_args
    assert args == ("multi_mute_suggested",)
    assert fields["finding_kind"] and fields["batch_id"] == payload["batch_id"]
    assert fields["prompt_version"] == payload["prompt_version"]
    assert {"status", "pool", "clusters_sent", "groups", "model", "seed_key"} <= fields.keys()


def test_a_superseded_search_keeps_its_slot_until_its_thread_ends():
    """Review finding: the concurrency cap did not limit real work.

    A cancelled `to_thread` returns while its thread runs on, so each re-run
    freed its slot at once: twelve quick re-runs from one user were twelve
    concurrent graph reads.
    """
    import threading
    import time

    from multi_mute import service
    real_read = service._read_graph
    lock, reads = threading.Lock(), {"now": 0, "max": 0}

    def slow_read(*args):
        with lock:
            reads["now"] += 1
            reads["max"] = max(reads["max"], reads["now"])
        try:
            time.sleep(0.4)
            return real_read(*args)
        finally:
            with lock:
                reads["now"] -= 1

    patches = _patched_graph() + [mock.patch.object(service, "_read_graph", slow_read)]
    for p in patches:
        p.start()

    async def main():
        runs = []
        for _ in range(12):
            runs.append(asyncio.create_task(service.suggest(
                user_id="u1", project_id="p1", seed_key="seed-1", model="m",
                exempt_pairs=[], driver=object(), build_llm=lambda m: _Llm(GOOD))))
            await asyncio.sleep(0.02)
        return await asyncio.gather(*runs, return_exceptions=True)

    try:
        outcomes = asyncio.run(main())
    finally:
        for p in patches:
            p.stop()
    assert reads["max"] <= service.SUGGEST_MAX_CONCURRENT, reads
    assert all(isinstance(o, service.Superseded) for o in outcomes[:-1])
    assert outcomes[-1]["status"] == "ok"


@pytest.mark.xfail(strict=True, reason=(
    "Review finding, accepted: one search per USER (plan §11), so the same person's "
    "search in another project, or an admin acting as them, supersedes this one. The "
    "cost is a 409 superseded and a Retry."))
def test_a_search_in_another_project_does_not_cancel_this_one():
    from multi_mute import service
    patches = _patched_graph()
    for p in patches:
        p.start()

    async def main():
        first = asyncio.create_task(service.suggest(
            user_id="u1", project_id="p1", seed_key="seed-1", model="m",
            exempt_pairs=[], driver=object(), build_llm=lambda m: _Llm(GOOD, delay=0.5)))
        await asyncio.sleep(0.2)
        await service.suggest(user_id="u1", project_id="p2", seed_key="seed-1", model="m",
                              exempt_pairs=[], driver=object(), build_llm=lambda m: _Llm(GOOD))
        return await first

    try:
        result = asyncio.run(main())
    finally:
        for p in patches:
            p.stop()
    assert result["status"] == "ok"


# -- the endpoint -------------------------------------------------------------

@pytest.fixture(scope="module")
def api():
    @asynccontextmanager
    async def fake_lifespan(_app):
        yield

    with mock.patch("api.lifespan", fake_lifespan):
        import api as api_module
    return api_module


def _post(api, body, key=MASTER, env=None):
    from fastapi.testclient import TestClient
    import llm_guard
    llm_guard.reset_state()
    env = env if env is not None else {"INTERNAL_API_KEY": MASTER, "SCANNER_API_KEY": SCANNER}
    client = mock.MagicMock()
    with mock.patch.dict("os.environ", env, clear=False), \
         mock.patch.object(api, "_triage_graph_client", lambda: client):
        for name in ("INTERNAL_API_KEY", "SCANNER_API_KEY"):
            if name not in env:
                import os
                os.environ.pop(name, None)
        return TestClient(api.app).post("/graph/multi-mute/suggest", json=body,
                                        headers={"x-internal-key": key})


BODY = {"user_id": "u1", "project_id": "p1", "seed_key": "seed-1", "model": "gpt-5-mini",
        "exempt_pairs": []}


def test_the_scanner_key_is_refused(api):
    assert _post(api, BODY, key=SCANNER).status_code == 401


def test_a_weak_master_key_is_refused(api):
    res = _post(api, BODY, key="", env={"INTERNAL_API_KEY": "changeme"})
    assert res.status_code == 503
    assert res.json()["multi_mute"] == 1


def test_an_empty_model_is_a_400(api):
    res = _post(api, {**BODY, "model": ""})
    assert res.status_code == 400
    assert res.json()["multi_mute"] == 1


def test_a_success_carries_the_markers(api):
    patches = _patched_graph()
    for p in patches:
        p.start()
    try:
        with mock.patch.object(api, "build_llm_from_providers", return_value=_Llm(GOOD)), \
             mock.patch.object(api, "fetch_user_providers", return_value=[]):
            res = _post(api, BODY)
    finally:
        for p in patches:
            p.stop()
    assert res.status_code == 200, res.text
    payload = res.json()
    assert payload["multi_mute"] == 1 and payload["model_used"] == "gpt-5-mini"
    assert payload["batch_id"].startswith("mm-")


def test_an_unreadable_answer_is_a_502_that_still_carries_groups(api):
    patches = _patched_graph()
    for p in patches:
        p.start()
    try:
        with mock.patch.object(api, "build_llm_from_providers", return_value=_Llm("no json")), \
             mock.patch.object(api, "fetch_user_providers", return_value=[]):
            res = _post(api, BODY)
    finally:
        for p in patches:
            p.stop()
    assert res.status_code == 502
    assert res.json()["status"] == "model_unreadable"
    assert res.json()["groups"]


def test_a_coded_error_keeps_its_code_and_marker(api):
    from multi_mute import queries
    with mock.patch.object(queries, "locate_seed", side_effect=queries.SeedMissing("x")):
        res = _post(api, BODY)
    assert res.status_code == 409
    assert res.json() == {"error": mock.ANY, "code": "seed_changed", "multi_mute": 1,
                          "model_used": "gpt-5-mini"}


def test_the_payload_never_carries_a_secret_value(api):
    rows = [_row("seed-1", body="Authorization: Bearer ghp_FAKEFAKEFAKEFAKEFAKE0123")] + [
        _row(f"k{i}", body="Authorization: Bearer ghp_FAKEFAKEFAKEFAKEFAKE0123") for i in range(3)]
    seen = {}

    class _Spy(_Llm):
        async def ainvoke(self, messages):
            seen["text"] = json.dumps([m.content for m in messages])
            return _Answer(GOOD)

    patches = _patched_graph(rows=rows, seed=rows[0])
    for p in patches:
        p.start()
    try:
        with mock.patch.object(api, "build_llm_from_providers", return_value=_Spy()), \
             mock.patch.object(api, "fetch_user_providers", return_value=[]):
            _post(api, BODY)
    finally:
        for p in patches:
            p.stop()
    assert "ghp_FAKEFAKEFAKEFAKEFAKE0123" not in seen["text"]
