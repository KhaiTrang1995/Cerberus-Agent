"""The only code that talks to TypeSafe AI (Jev).

Recon never sees the Jev token: it calls the agent's `/jev/*` endpoints, which
load the project owner's token and call TypeSafe through this module.

- The base URL is a constant, never user-configurable, so there is no SSRF
  surface and the token can only ever be sent to api.typesafe.ai. Redirects are
  not followed.
- Every failure raises `JevError` with a fixed message. The httpx exception
  text, the key and the state never appear in it: recon prints agent error
  bodies into the recon drawer.
- One attempt, 5 s, no retries. The recon breaker owns retry policy.
"""
from __future__ import annotations

import asyncio
import logging
import math
import os
import re
import time
import urllib.parse

import httpx

logger = logging.getLogger(__name__)

BASE_URL = "https://api.typesafe.ai"

#: Pinned, not the `jev-latest` alias: the recon thresholds are calibrated
#: against this version, so moving to a newer one is a deliberate edit.
JEV_MODEL = "jev-1.13.0"

TIMEOUT_S = 5.0
OWNER_CACHE_TTL_S = 300
_WEBAPP_TIMEOUT_S = 10.0

_MODEL_RE = re.compile(r"^jev-\d+\.\d+\.\d+$")
#: Printable ASCII with no whitespace. A CR/LF in a header value makes httpx
#: raise an error that quotes the value, which would put the key in a log.
_KEY_RE = re.compile(r"^[\x21-\x7e]{8,512}$")

ERROR_MESSAGES = {
    "jev_auth": "TypeSafe rejected the Jev API key",
    "jev_no_credit": "The TypeSafe account has no credit left",
    "jev_bad_request": "TypeSafe refused the request",
    "jev_rate_limited": "TypeSafe rate limit reached",
    "jev_overloaded": "TypeSafe is unavailable",
    "jev_timeout": "TypeSafe did not answer in time",
    "jev_bad_response": "TypeSafe returned an unexpected answer",
    "jev_not_configured": "No Jev token on the project owner's account",
    "jev_unavailable": "The Jev token could not be loaded",
    "jev_forbidden": "The project does not belong to this user",
}


class JevError(Exception):
    """A Jev call failed. `error_type` is a key of ERROR_MESSAGES."""

    def __init__(self, error_type: str, retry_after: float | None = None):
        if error_type not in ERROR_MESSAGES:
            error_type = "jev_bad_response"
        super().__init__(ERROR_MESSAGES[error_type])
        self.error_type = error_type
        self.message = ERROR_MESSAGES[error_type]
        self.retry_after = retry_after


def _retry_after(headers) -> float | None:
    try:
        value = float(headers.get("retry-after", ""))
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) and value >= 0 else None


def _error_for_status(status: int, headers) -> JevError:
    if status in (401, 403):
        return JevError("jev_auth")
    if status == 402:
        return JevError("jev_no_credit")
    if status in (400, 422):
        # The live API answers a malformed body with 400; the docs say 422.
        return JevError("jev_bad_request")
    if status == 429:
        return JevError("jev_rate_limited", retry_after=_retry_after(headers))
    if status >= 500:
        return JevError("jev_overloaded")
    return JevError("jev_bad_response")


def _auth_headers(key: str) -> dict:
    if not isinstance(key, str) or not _KEY_RE.match(key):
        raise JevError("jev_auth")
    return {"Authorization": f"Bearer {key}"}


async def _request(method: str, path: str, key: str, payload: dict | None = None):
    headers = _auth_headers(key)
    try:
        async with httpx.AsyncClient(headers=headers, timeout=TIMEOUT_S,
                                     follow_redirects=False) as client:
            resp = await client.request(method, f"{BASE_URL}{path}", json=payload)
    except httpx.HTTPError:
        # Timeouts and connection errors alike; the exception text is dropped.
        raise JevError("jev_timeout") from None
    except (TypeError, ValueError):
        # A state that does not serialise to JSON.
        raise JevError("jev_bad_request") from None
    if not 200 <= resp.status_code < 300:
        raise _error_for_status(resp.status_code, resp.headers)
    try:
        return resp.json()
    except ValueError:
        raise JevError("jev_bad_response") from None


async def list_models(key: str) -> list[str]:
    """The model names the key can use. Free: spends no credit."""
    data = await _request("GET", "/v1/models", key)
    models = data.get("models") if isinstance(data, dict) else None
    if not isinstance(models, list):
        raise JevError("jev_bad_response")
    return [m["name"] for m in models if isinstance(m, dict) and isinstance(m.get("name"), str)]


def _is_unit(value) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value) and 0.0 <= value <= 1.0)


def _valid_answer(question: dict, answer) -> bool:
    if not isinstance(answer, dict) or answer.get("type") != question.get("type"):
        return False
    qtype = question["type"]
    if qtype == "noul":
        return _is_unit(answer.get("noul"))
    if qtype == "choice":
        return (answer.get("choice") in (question.get("criteria") or {})
                and _is_unit(answer.get("confidence")))
    if qtype == "score":
        score = answer.get("score")
        return (isinstance(score, (int, float)) and not isinstance(score, bool)
                and math.isfinite(score) and _is_unit(answer.get("confidence")))
    return False


async def system_one(key: str, model: str, state, questions: dict) -> dict:
    """Ask `questions` about `state`. Returns `{"model", "answers"}`.

    Every question must come back with an answer of its own type and in range
    (a Choice must name one of its own options), or the whole call fails with
    `jev_bad_response`: callers never see a partial answer set.
    """
    if not isinstance(model, str) or not _MODEL_RE.match(model):
        raise JevError("jev_bad_request")
    if not isinstance(questions, dict) or not questions:
        raise JevError("jev_bad_request")
    data = await _request("POST", "/v1/systemone", key,
                          {"model": model, "state": state, "questions": questions})
    answers = data.get("answers") if isinstance(data, dict) else None
    if not isinstance(answers, dict):
        raise JevError("jev_bad_response")
    for name, question in questions.items():
        if not _valid_answer(question, answers.get(name)):
            raise JevError("jev_bad_response")
    returned_model = data.get("model")
    return {
        "model": returned_model if isinstance(returned_model, str) else "",
        "answers": {name: answers[name] for name in questions},
    }


# ---------------------------------------------------------------------------
# Owner binding: a /jev/* caller names a project and a user; both must match.
# ---------------------------------------------------------------------------

_OWNER_CACHE_MAX = 1024
_owner_cache: dict[tuple[str, str], float] = {}


def _fetch_project_owner(project_id: str) -> str | None:
    """The project's userId, None when it does not exist. Raises on any other failure."""
    import requests

    webapp_url = os.environ.get("WEBAPP_API_URL", "http://webapp:3000").rstrip("/")
    url = f"{webapp_url}/api/projects/{urllib.parse.quote(project_id, safe='')}"
    resp = requests.get(url, headers={"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")},
                        timeout=_WEBAPP_TIMEOUT_S)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    owner = resp.json().get("userId")
    return owner if isinstance(owner, str) else None


async def verify_owner(project_id: str, user_id: str) -> None:
    """Raise unless `project_id` belongs to `user_id`. Fails closed.

    A mismatch (or a project that does not exist) is `jev_forbidden`; a webapp
    that cannot answer is `jev_unavailable`. Only a match is cached.
    """
    cache_key = (project_id, user_id)
    now = time.monotonic()
    if _owner_cache.get(cache_key, 0.0) > now:
        return
    try:
        owner = await asyncio.to_thread(_fetch_project_owner, project_id)
    except Exception:                                             # noqa: BLE001
        raise JevError("jev_unavailable") from None
    if owner is None or owner != user_id:
        raise JevError("jev_forbidden")
    if len(_owner_cache) >= _OWNER_CACHE_MAX:
        for stale in [k for k, expiry in _owner_cache.items() if expiry <= now]:
            del _owner_cache[stale]
        if len(_owner_cache) >= _OWNER_CACHE_MAX:
            _owner_cache.clear()
    _owner_cache[cache_key] = now + OWNER_CACHE_TTL_S


def pick_jev_key(providers: list) -> str | None:
    """The key on the user's Jev provider row (the oldest, if there are two)."""
    for row in providers or []:
        if isinstance(row, dict) and row.get("providerType") == "jev":
            key = row.get("apiKey")
            return key if isinstance(key, str) and key else None
    return None
