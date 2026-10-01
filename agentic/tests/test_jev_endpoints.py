"""The agent's /jev/* endpoints.

They take the same request bodies as /llm/* and return the same response shapes,
answered by TypeSafe Jev. This locks in:
- user_id and project_id are required (422), so no call lands in the shared
  "anonymous" rate bucket;
- the project is bound to its owner and fails closed (403 mismatch, 503 when the
  webapp is unreachable);
- no Jev row -> 503 jev_not_configured; providers unreachable -> 503 jev_unavailable;
- every Jev-side failure is a 503 with a fixed body, never exception text;
- the Jev token never appears in a response body (asserted on a canary key).

Runs inside the agent container.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

CANARY = "apikey_" + "c" * 36 + "_" + "d" * 64
JEV_ROW = {"id": "p-jev", "providerType": "jev", "apiKey": CANARY, "modelIdentifier": "jev-1.13.0"}

FFUF_BODY = {"url": "http://t/", "headers": {"Server": "nginx"}, "model": "ignored",
             "max_extensions": 6, "user_id": "u1", "project_id": "p1"}
NUCLEI_BODY = {"technologies": ["php"], "servers": ["nginx"], "current_tags": ["cve"],
               "candidates": ["cve", "php", "wordpress"], "model": "ignored", "max_tags": 15,
               "user_id": "u1", "project_id": "p1"}
WAF_BODY = {"url": "http://t/", "status_code": 403, "headers": {"cf-ray": "x"},
            "body_sample": "blocked", "response_time_ms": 100, "model": "ignored",
            "user_id": "u1", "project_id": "p1"}
TAKEOVER_BODY = {"hostname": "h.t", "expected_provider": "heroku", "status_code": 404,
                 "headers": {}, "response_sample": "nope", "model": "ignored",
                 "user_id": "u1", "project_id": "p1"}


@pytest.fixture(scope="module")
def client():
    with patch.dict(os.environ, {"INTERNAL_API_KEY": "s3cret"}):
        import api
        from fastapi.testclient import TestClient
        yield TestClient(api.app), api


def _post(client, path, body):
    cl, _ = client
    with patch.dict(os.environ, {"INTERNAL_API_KEY": "s3cret"}):
        return cl.post(path, headers={"X-Internal-Key": "s3cret"}, json=body)


@pytest.fixture(autouse=True)
def _clear_owner_cache():
    import jev_client
    jev_client._owner_cache.clear()
    yield
    jev_client._owner_cache.clear()


def _owner_ok():
    return patch("jev_client.verify_owner", AsyncMock(return_value=None))


def _providers(rows):
    # fetch_user_providers is sync, called via asyncio.to_thread.
    return patch("llm_builder.fetch_user_providers", return_value=rows)


PATHS = {
    "/jev/ffuf-extensions": FFUF_BODY,
    "/jev/nuclei-tags": NUCLEI_BODY,
    "/jev/waf-classify": WAF_BODY,
    "/jev/takeover-classify": TAKEOVER_BODY,
}


# ---------------------------------------------------------------------------
# request validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path,body", list(PATHS.items()))
def test_empty_user_or_project_is_422(client, path, body):
    for missing in ("user_id", "project_id"):
        resp = _post(client, path, {**body, missing: ""})
        assert resp.status_code == 422, resp.text
        assert resp.json()["error_type"] == "jev_bad_request"


# ---------------------------------------------------------------------------
# owner binding
# ---------------------------------------------------------------------------

def test_owner_mismatch_is_403_and_no_token_is_fetched(client):
    import jev_client
    with patch("jev_client.verify_owner", AsyncMock(side_effect=jev_client.JevError("jev_forbidden"))), \
            _providers([JEV_ROW]) as fetch:
        resp = _post(client, "/jev/nuclei-tags", NUCLEI_BODY)
    assert resp.status_code == 403
    assert resp.json()["error_type"] == "jev_forbidden"
    fetch.assert_not_called()


def test_webapp_unreachable_in_owner_check_is_503(client):
    import jev_client
    with patch("jev_client.verify_owner", AsyncMock(side_effect=jev_client.JevError("jev_unavailable"))):
        resp = _post(client, "/jev/nuclei-tags", NUCLEI_BODY)
    assert resp.status_code == 503
    assert resp.json()["error_type"] == "jev_unavailable"


# ---------------------------------------------------------------------------
# token resolution
# ---------------------------------------------------------------------------

def test_no_jev_row_is_503_not_configured(client):
    with _owner_ok(), _providers([{"providerType": "anthropic", "apiKey": "sk"}]):
        resp = _post(client, "/jev/nuclei-tags", NUCLEI_BODY)
    assert resp.status_code == 503
    assert resp.json()["error_type"] == "jev_not_configured"


def test_providers_unreachable_is_503_unavailable(client):
    from llm_builder import ProvidersUnreachable
    with _owner_ok(), patch("llm_builder.fetch_user_providers", side_effect=ProvidersUnreachable("down")):
        resp = _post(client, "/jev/nuclei-tags", NUCLEI_BODY)
    assert resp.status_code == 503
    assert resp.json()["error_type"] == "jev_unavailable"


# ---------------------------------------------------------------------------
# success + failure mapping, and the key never leaks
# ---------------------------------------------------------------------------

def test_nuclei_success_returns_tags_and_never_leaks_the_key(client):
    answers = {"tag_0": {"type": "noul", "noul": 0.9}, "tag_1": {"type": "noul", "noul": 0.9},
               "tag_2": {"type": "noul", "noul": 0.1}}
    with _owner_ok(), _providers([JEV_ROW]), \
            patch("jev_client.system_one", AsyncMock(return_value={"model": "jev-1.13.0", "answers": answers})) as s1:
        resp = _post(client, "/jev/nuclei-tags", NUCLEI_BODY)
    assert resp.status_code == 200
    assert "cve" in resp.json()["tags"]
    # The token is the one passed to the client, and never appears in the body.
    assert s1.await_args.args[0] == CANARY
    assert CANARY not in resp.text


@pytest.mark.parametrize("path,body", list(PATHS.items()))
def test_a_jev_failure_is_503_with_a_fixed_body_no_key(client, path, body):
    import jev_client
    with _owner_ok(), _providers([JEV_ROW]), \
            patch("jev_client.system_one", AsyncMock(side_effect=jev_client.JevError("jev_rate_limited", retry_after=5))):
        resp = _post(client, path, body)
    assert resp.status_code == 503
    data = resp.json()
    assert data["error_type"] == "jev_rate_limited"
    assert data["retry_after"] == 5
    assert data["error"] == jev_client.ERROR_MESSAGES["jev_rate_limited"]
    assert CANARY not in resp.text


def test_waf_success_shape(client):
    answers = {"edge": {"type": "noul", "noul": 0.9},
               "vendor": {"type": "choice", "choice": "cloudflare", "confidence": 0.9,
                          "probabilities": {"cloudflare": 1.0}}}
    with _owner_ok(), _providers([JEV_ROW]), \
            patch("jev_client.system_one", AsyncMock(return_value={"model": "jev-1.13.0", "answers": answers})):
        resp = _post(client, "/jev/waf-classify", WAF_BODY)
    assert resp.status_code == 200
    assert resp.json() == {"waf_detected": True, "waf_type": "cloudflare", "confidence": 90,
                           "reasoning": "", "source": "jev_classifier"}


def test_owner_binding_runs_before_the_token_fetch(client):
    """verify_owner is awaited before any provider is read."""
    order = []
    import jev_client

    async def owner(*a, **k):
        order.append("owner")

    def providers(*a, **k):
        order.append("providers")
        return [JEV_ROW]

    with patch("jev_client.verify_owner", owner), patch("llm_builder.fetch_user_providers", providers), \
            patch("jev_client.system_one", AsyncMock(return_value={"model": "x", "answers": {
                "tag_0": {"type": "noul", "noul": 0.1}, "tag_1": {"type": "noul", "noul": 0.1},
                "tag_2": {"type": "noul", "noul": 0.1}}})):
        _post(client, "/jev/nuclei-tags", NUCLEI_BODY)
    assert order == ["owner", "providers"]


# ---------------------------------------------------------------------------
# The token never reaches a log, on any path
# ---------------------------------------------------------------------------
#
# Driven through the REAL jev_client over a mock HTTP transport, not through a
# patched system_one: the realistic leak is TypeSafe or httpx echoing the
# Authorization header back in an error body or an exception message, and a
# logger that prints either.

import json as _json
import logging

import httpx

_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _mock_typesafe(handler):
    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return _REAL_ASYNC_CLIENT(*args, **kwargs)
    return patch("jev_client.httpx.AsyncClient", side_effect=factory)


def _valid_answers(req):
    body = _json.loads(req.content)
    answers = {}
    for name, q in body["questions"].items():
        if q["type"] == "choice":
            answers[name] = {"type": "choice", "choice": next(iter(q["criteria"])),
                             "confidence": 0.9, "probabilities": {}}
        else:
            answers[name] = {"type": "noul", "noul": 0.9}
    return httpx.Response(200, json={"model": "jev-1.13.0", "answers": answers, "usage": {}})


def _bare_key(req) -> str:
    """The key exactly as sent, without the "Bearer " scheme. The agent's log redaction filter
    also scrubs `Bearer <token>`, so echoing the scheme would let the filter, not the code, pass."""
    return req.headers["authorization"].split(" ", 1)[1]


def _echo_401(req):
    return httpx.Response(401, json={"detail": {"error_type": "authentication_error",
                                                 "message": f"rejected {_bare_key(req)}"}})


def _echo_500_html(req):
    return httpx.Response(500, text=f"<html>upstream error for {_bare_key(req)}</html>")


def _echo_exception(req):
    raise httpx.ConnectError(f"cannot reach host with {_bare_key(req)}")


#: Two keys. The first has the shape of a real TypeSafe key, so the agent's RedactingFilter would
#: scrub it from a log line: that is defence in depth, and it is not what this test is for. The
#: second has no shape any redaction pattern knows, so only the code's own discipline (never log
#: a body, a header or an exception message) can keep it out. A leak that the filter happens to
#: hide today would surface the day TypeSafe changes its key format.
RAW_KEY = "zzq-Plain_Looking_Key_0123456789"
LEAK_KEYS = [("known_shape", CANARY), ("shape_the_filter_cannot_know", RAW_KEY)]

LEAK_SCENARIOS = [
    ("success", _valid_answers, 200),
    ("typesafe_401_echoes_the_header", _echo_401, 503),
    ("typesafe_500_echoes_the_header", _echo_500_html, 503),
    ("connect_error_echoes_the_header", _echo_exception, 503),
]


@pytest.mark.parametrize("key_name,key", LEAK_KEYS, ids=[k[0] for k in LEAK_KEYS])
@pytest.mark.parametrize("name,handler,status", LEAK_SCENARIOS, ids=[s[0] for s in LEAK_SCENARIOS])
@pytest.mark.parametrize("path,body", list(PATHS.items()))
def test_the_token_is_never_logged_or_returned(client, caplog, path, body, name, handler, status, key_name, key):
    caplog.set_level(logging.DEBUG)
    with _owner_ok(), _providers([dict(JEV_ROW, apiKey=key)]), _mock_typesafe(handler):
        resp = _post(client, path, body)
    assert resp.status_code == status, resp.text
    assert key not in resp.text
    assert key not in caplog.text
    assert not any(key in r.getMessage() or key in str(r.args) or key in str(r.exc_info)
                   for r in caplog.records)
    # Not vacuous: the endpoint did log this call, so a leak here would have shown.
    assert any(r.getMessage().startswith("jev ") for r in caplog.records), caplog.text


@pytest.mark.parametrize("path,body", list(PATHS.items()))
def test_the_token_is_never_logged_on_the_owner_mismatch_path(client, caplog, path, body):
    import jev_client
    caplog.set_level(logging.DEBUG)
    with patch("jev_client.verify_owner", AsyncMock(side_effect=jev_client.JevError("jev_forbidden"))), \
            _providers([JEV_ROW]) as fetch:
        resp = _post(client, path, body)
    assert resp.status_code == 403
    assert CANARY not in resp.text and CANARY not in caplog.text
    fetch.assert_not_called()                      # the token was never even loaded
    assert any(r.getMessage().startswith("jev ") for r in caplog.records), caplog.text


def test_an_unexpected_error_inside_a_hook_is_a_fixed_503_logged_by_class_only(client, caplog):
    """REGRESSION (a non-JevError became a 500 with a traceback): only JevError was handled, so
    any other exception escaped as an unhandled 500 and skipped the per-call log line. Recon
    reads an error_type from a 503, so an unclassified 500 was also the one failure the Jev
    breaker could not name. The exception text is never returned or logged: it can carry
    state."""
    caplog.set_level(logging.DEBUG)
    boom = RuntimeError(f"unexpected {CANARY}")
    with _owner_ok(), _providers([JEV_ROW]), patch("jev_hooks.nuclei_tags", AsyncMock(side_effect=boom)):
        resp = _post(client, "/jev/nuclei-tags", NUCLEI_BODY)
    assert resp.status_code == 503
    assert resp.json()["error_type"] == "jev_bad_response"
    assert CANARY not in resp.text and CANARY not in caplog.text
    assert any("RuntimeError" in r.getMessage() and r.getMessage().startswith("jev ") for r in caplog.records), caplog.text
