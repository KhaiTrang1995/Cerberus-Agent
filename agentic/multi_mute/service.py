"""Multi mute suggest: one read-only suggestion, stored as a batch (plan §7.7).

Nothing here writes the graph. The suggestion is kept server-side as a batch
(`batches.STORE`) and the later `mute_batch` write accepts only its keys, so a
tampered client cannot turn a suggestion into an arbitrary bulk mute.

Concurrency:
- one suggestion per user: a new request CANCELS that user's running one, so
  closing and reopening the modal never waits on a stale model call;
- at most `SUGGEST_MAX_CONCURRENT` overall, waiting `SUGGEST_WAIT_S` for a slot
  before answering `busy`;
- the graph reads and the provider fetch run in threads, and the model call
  under `LLM_TIMEOUT_S`. A cancelled search keeps its slot until its thread
  ends (`_in_thread`), so the cap bounds the work, not just the requests.
"""
from __future__ import annotations

import asyncio
import logging

from . import batches, clusters, pool, prompt, queries, validate
from .kind import SeedNotMuteable, resolve_kind

logger = logging.getLogger(__name__)

SUGGEST_MAX_CONCURRENT = 3
SUGGEST_WAIT_S = 10
#: Reasoning models think before they answer: a live run of a small one spent
#: 16k reasoning tokens (80 s) on a 3k-token prompt. The webapp route waits 30 s
#: longer than this, so it always sees the agent's own timeout answer.
LLM_TIMEOUT_S = 150

_running: dict = {}
_semaphore: asyncio.Semaphore | None = None


class SuggestError(Exception):
    """A suggestion that cannot be made. `code` is the modal's error code."""

    def __init__(self, code: str, status: int, message: str):
        super().__init__(message)
        self.code = code
        self.status = status
        self.message = message


class Superseded(Exception):
    """The same user started a newer suggestion; this one was cancelled."""


def _slots() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(SUGGEST_MAX_CONCURRENT)
    return _semaphore


def reset_state() -> None:
    """Test hook."""
    global _semaphore
    for task in list(_running.values()):
        task.cancel()
    _running.clear()
    _semaphore = None


async def suggest(*, user_id: str, project_id: str, seed_key: str, model: str,
                  exempt_pairs: list, driver, build_llm) -> dict:
    """The modal's payload. Raises SuggestError or Superseded.

    `driver` is a neo4j driver; `build_llm(model) -> llm` is blocking and may
    raise the builder's errors (the endpoint maps them to codes).
    """
    previous = _running.get(user_id)
    if previous is not None and not previous.done():
        previous.cancel()
    task = asyncio.create_task(_suggest(
        user_id=user_id, project_id=project_id, seed_key=seed_key, model=model,
        exempt_pairs=exempt_pairs, driver=driver, build_llm=build_llm))
    _running[user_id] = task
    try:
        return await task
    except asyncio.CancelledError:
        current = asyncio.current_task()
        if current is not None and current.cancelling():
            task.cancel()
            raise
        raise Superseded() from None
    finally:
        if _running.get(user_id) is task:
            del _running[user_id]


async def _suggest(*, user_id, project_id, seed_key, model, exempt_pairs, driver, build_llm):
    slots = _slots()
    try:
        await asyncio.wait_for(slots.acquire(), SUGGEST_WAIT_S)
    except asyncio.TimeoutError:
        raise SuggestError("busy", 429,
                           "Too many Multi mute searches right now; try again in a moment") from None
    try:
        return await _run(user_id, project_id, seed_key, model, exempt_pairs, driver, build_llm)
    finally:
        slots.release()


async def _in_thread(fn, *args):
    """`asyncio.to_thread`, except that a cancel returns only once the thread ends.

    A thread cannot be stopped, and a cancelled `to_thread` returns at once
    while its thread runs on. `_suggest` releases the slot when `_run` returns,
    so without this a superseded search's graph read or fingerprinting kept
    running outside the cap: twelve quick re-runs from one user were twelve
    concurrent reads on the executor every other request shares.
    """
    work = asyncio.ensure_future(asyncio.to_thread(fn, *args))
    try:
        return await asyncio.shield(work)
    except asyncio.CancelledError:
        while not work.done():
            try:
                await asyncio.shield(work)
            except asyncio.CancelledError:
                continue
            except Exception:                                     # noqa: BLE001
                break
        raise


def _read_graph(driver, user_id, project_id, seed_key):
    """Everything the suggestion reads, in one thread hop."""
    located = queries.locate_seed(driver, user_id, project_id, seed_key)
    if located.get("muted"):
        raise queries.SeedMissing(seed_key)
    label = str(located.get("label") or "")
    kind = resolve_kind(label, located.get("props") or {})
    seed = queries.read_seed(driver, user_id, project_id, seed_key, kind)
    seed_rank = pool.severity_rank(seed)
    rows = queries.read_pool(driver, user_id, project_id, kind, seed, seed_rank)
    counts = queries.read_counts(driver, user_id, project_id, kind)
    for key in ("_mm_source", "_mm_detector"):
        seed.pop(key, None)
    return kind, seed, rows, counts


def _prepare(seed, kind, rows, exempt_pairs, compared):
    """Pool rules, exact lenses and the ranked clusters sent to the model."""
    result = pool.apply_pool_rules(seed, kind, rows, exempt_pairs, total=compared)
    lenses = clusters.exact_lenses(seed, result.candidates)
    ranked = (clusters.rank_clusters(seed, clusters.build_clusters(seed, result.candidates), lenses)
              if result.candidates else [])
    return result, lenses, ranked


def _seed_view(seed: dict, kind) -> dict:
    return {
        "key": seed.get("key"),
        "node_id": seed.get("node_id"),
        "label": kind.label,
        "kind": kind.display,
        "name": validate.clean_text(seed.get("name") or "", validate.NAME_MAX),
        "host": validate.clean_text(clusters.resolved_host(seed), validate.HOST_MAX),
        "severity": pool.normalised_severity(seed) or "",
        "source": str(seed.get("source") or ""),
        # P4: without a triage run the suggestion reads raw scanner fields only.
        "triaged": bool(seed.get("triage_tier") or seed.get("triage_group_key")),
    }


def _member_keys(groups: list) -> set:
    keys = set()
    for group in groups or []:
        for member in (group.get("members") or []) + (group.get("probably_not") or []):
            if member.get("key"):
                keys.add(str(member["key"]))
    return keys


async def _run(user_id, project_id, seed_key, model, exempt_pairs, driver, build_llm):
    try:
        kind, seed, rows, counts = await _in_thread(
            _read_graph, driver, user_id, project_id, seed_key)
    except queries.SeedMissing:
        raise SuggestError("seed_changed", 409,
                           "This finding changed or was muted; reload and try again") from None
    except SeedNotMuteable as exc:
        raise SuggestError("seed_not_muteable", 400, str(exc)) from None

    seed_live = seed.get("stale_since") in (None, "")
    compared = max(0, counts["live"] - (1 if seed_live else 0))
    # Fingerprinting a full 2,000-row pool is about a second of CPU: a thread,
    # not the event loop every other request shares.
    result, lenses, ranked = await _in_thread(
        _prepare, seed, kind, rows, exempt_pairs, compared)
    excluded = dict(result.excluded)
    excluded["stale"] = excluded.get("stale", 0) + counts["stale"]
    excluded["js_file"] = excluded.get("js_file", 0) + counts["js_file"]
    candidates = result.candidates

    status = "ok"
    raw_text = None
    if not candidates:
        status = "empty_pool"
        assembled = {"status": "empty_pool", "read": None, "groups": []}
    else:
        from llm_builder import (MODEL_UNAVAILABLE_MESSAGE, ProvidersUnreachable,
                                 is_model_unavailable_error, log_provider_error)
        try:
            llm = await _in_thread(build_llm, model)
        except ProvidersUnreachable:
            raise SuggestError("providers_unreachable", 503,
                               "Couldn't load your LLM providers, try again") from None
        except Exception as exc:                                  # noqa: BLE001
            log_provider_error("Multi mute", model, exc)
            raise SuggestError("model_unavailable", 503,
                               MODEL_UNAVAILABLE_MESSAGE.format(model=model)) from None
        from langchain_core.messages import HumanMessage, SystemMessage
        messages = [SystemMessage(content=text) if role == "system" else HumanMessage(content=text)
                    for role, text in prompt.build_messages(seed, kind, ranked, compared, lenses)]
        try:
            answer = await asyncio.wait_for(llm.ainvoke(messages), LLM_TIMEOUT_S)
            from orchestrator_helpers import normalize_content
            raw_text = normalize_content(answer.content)
        except asyncio.TimeoutError:
            raise SuggestError("agent_timeout", 504,
                               "The model took too long, try again") from None
        except Exception as exc:                                  # noqa: BLE001
            log_provider_error("Multi mute", model, exc)
            if is_model_unavailable_error(exc):
                raise SuggestError("model_unavailable", 503,
                                   MODEL_UNAVAILABLE_MESSAGE.format(model=model)) from None
            raw_text = None
        assembled = await _in_thread(
            validate.assemble, raw_text, seed, ranked, lenses, candidates)
        status = assembled.get("status") or "ok"

    groups = assembled.get("groups") or []
    batch = batches.STORE.put(
        user_id, project_id, label=kind.label, seed_key=str(seed.get("key") or seed_key),
        seed_name=str(seed.get("name") or ""), ceiling=pool.ceiling_for(seed),
        members=_member_keys(groups), model=model,
        prompt_version=prompt.MULTI_MUTE_PROMPT_VERSION)

    payload = {
        "multi_mute": 1,
        "status": status,
        "batch_id": batch.batch_id,
        "prompt_version": prompt.MULTI_MUTE_PROMPT_VERSION,
        "model": model,
        "model_used": model,
        "seed": _seed_view(seed, kind),
        "read": assembled.get("read"),
        "pool": {
            "total": compared,
            "candidates": len(candidates),
            "excluded": {k: v for k, v in excluded.items() if v},
            "truncated": result.truncated,
            "clusters_sent": len(ranked),
        },
        "groups": groups,
    }
    from session_log import log_event
    # `kind` is log_event's own first parameter (the event's name), so the
    # finding kind goes under another key.
    log_event("multi_mute_suggested", user_id=user_id, project_id=project_id,
              batch_id=batch.batch_id, seed_key=str(seed.get("key") or seed_key),
              finding_kind=kind.id, model=model, prompt_version=prompt.MULTI_MUTE_PROMPT_VERSION,
              status=status, pool=compared, clusters_sent=len(ranked), groups=len(groups))
    return payload
