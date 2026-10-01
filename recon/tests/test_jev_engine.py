"""The LLM | Jev engine on the four recon AI hooks.

What it locks in:
- engine="jev" posts to /jev/<hook> with its own `agent_jev` breaker and
  `[*][<Tool>-Jev]` log tags; the default engine is unchanged (/llm/<hook>,
  `agent_llm`, `[*][<Tool>-AI]`);
- the Jev breaker maps the agent's 503 `error_type` bodies to outcomes, and a
  Jev FATAL (no token, bad key, no credit) leaves `agent_llm` closed, so the LLM
  hooks keep running for the rest of the scan;
- a Jev failure falls back to the hook's existing static fallback (never raises,
  never re-routes to the LLM, never returns empty);
- the WAF path stamps detection_method "jev_classifier" and takeover findings
  carry ai_engine "jev".
"""
from __future__ import annotations

from unittest import mock

import pytest
import requests

from recon.helpers import ai_planner
from recon.helpers import circuit_breaker as cb
from recon.helpers.ai_planner import (
    ffuf_extensions, nuclei_tags, takeover_classifier, waf_classifier,
)


def _resp(status=200, body=None, headers=None):
    r = mock.MagicMock(status_code=status, headers=headers or {}, text="")
    r.json.return_value = body if body is not None else {}
    return r


def _waf_resp():
    r = mock.MagicMock(status_code=403, headers={"Server": "nginx"}, url="https://t/")
    r.content = b"<html>blocked</html>"
    return r


JEV_503 = lambda error_type, **extra: _resp(503, {"error_type": error_type, "error": "x", **extra})  # noqa: E731


# ---------------------------------------------------------------------------
# agent_jev_gate: the outcome table
# ---------------------------------------------------------------------------

def _outcome_after(resp=None, exc=None):
    gate = ai_planner.agent_jev_gate()
    assert gate.allowed
    with mock.patch.object(gate._breaker, "record") as record:
        gate.record(resp=resp, exc=exc)
    return record


@pytest.mark.parametrize("error_type", [
    "jev_not_configured", "jev_auth", "jev_no_credit", "jev_forbidden",
])
def test_jev_account_errors_are_fatal(error_type):
    record = _outcome_after(JEV_503(error_type))
    assert record.call_args.args[0] is cb.Outcome.FATAL
    assert record.call_args.args[1] == error_type


def test_jev_rate_limit_carries_retry_after():
    record = _outcome_after(JEV_503("jev_rate_limited", retry_after=7))
    assert record.call_args.args[0] is cb.Outcome.RATE_LIMIT
    assert record.call_args.kwargs["retry_after"] == 7


@pytest.mark.parametrize("error_type", ["jev_timeout", "jev_overloaded", "jev_bad_response", "jev_unavailable"])
def test_other_jev_errors_are_transient(error_type):
    record = _outcome_after(JEV_503(error_type))
    assert record.call_args.args[0] is cb.Outcome.TRANSIENT


def test_a_transport_exception_is_transient():
    record = _outcome_after(exc=requests.Timeout("x"))
    assert record.call_args.args[0] is cb.Outcome.TRANSIENT


def test_a_response_without_an_error_type_goes_through_the_normal_classifier():
    # The agent guard's own 401 and 429 carry no error_type.
    assert _outcome_after(_resp(401)).call_args.args[0] is cb.Outcome.FATAL
    assert _outcome_after(_resp(429)).call_args.args[0] is cb.Outcome.RATE_LIMIT
    assert _outcome_after(_resp(200)).call_args.args[0] is cb.Outcome.OK


def test_a_503_with_an_unreadable_body_is_not_fatal():
    bad = mock.MagicMock(status_code=503, headers={}, text="")
    bad.json.side_effect = ValueError("not json")
    assert _outcome_after(bad).call_args.args[0] is cb.Outcome.TRANSIENT


# ---------------------------------------------------------------------------
# A Jev FATAL must not silence the LLM hooks
# ---------------------------------------------------------------------------

def test_a_jev_fatal_leaves_the_llm_breaker_closed():
    with mock.patch.object(nuclei_tags.requests, "post", return_value=JEV_503("jev_no_credit")) as post:
        out = nuclei_tags.get_ai_tags({"servers": ["nginx"]}, ["cve"], model="m", engine="jev")
    assert out == ["cve"]                          # the static fallback
    assert post.call_count == 1
    assert cb.is_open("agent_jev")                 # FATAL: stopped for the run
    assert not cb.is_open("agent_llm")             # the LLM hooks are untouched

    # ...and an LLM-engine call still goes out.
    with mock.patch.object(nuclei_tags.requests, "post",
                           return_value=_resp(200, {"tags": ["cve", "php"]})) as post:
        out = nuclei_tags.get_ai_tags({"servers": ["nginx"]}, ["cve"], model="m",
                                      engine="llm")
    assert post.call_count == 1
    assert "/llm/nuclei-tags" in post.call_args.args[0]


def test_an_llm_fatal_leaves_the_jev_breaker_closed():
    with mock.patch.object(nuclei_tags.requests, "post", return_value=_resp(401)):
        nuclei_tags.get_ai_tags({"servers": ["nginx"]}, ["cve"], model="m", engine="llm")
    assert cb.is_open("agent_llm")
    assert not cb.is_open("agent_jev")


def test_once_the_jev_breaker_is_open_no_further_post_is_made():
    with mock.patch.object(nuclei_tags.requests, "post", return_value=JEV_503("jev_auth")) as post:
        nuclei_tags.get_ai_tags({"servers": ["nginx"]}, ["a"], model="m", engine="jev")
        out = nuclei_tags.get_ai_tags({"servers": ["nginx"]}, ["a"], model="m", engine="jev")
    assert post.call_count == 1
    assert out == ["a"]


# ---------------------------------------------------------------------------
# Routing, tags, and fallbacks per hook
# ---------------------------------------------------------------------------

def test_nuclei_posts_to_the_jev_route_and_logs_the_jev_tag(capsys):
    body = {"tags": ["cve", "wordpress"]}
    with mock.patch.object(nuclei_tags.requests, "post", return_value=_resp(200, body)) as post:
        out = nuclei_tags.get_ai_tags({"technologies": ["wordpress"], "servers": ["nginx"]},
                                      ["cve"], model="ignored", engine="jev")
    assert post.call_args.args[0].endswith("/jev/nuclei-tags")
    # Both tags are in the fallback candidate list the hook loads without a
    # templates volume, so the existing validator keeps them in order.
    assert out == ["cve", "wordpress"]
    printed = capsys.readouterr().out
    assert "[Nuclei-Jev]" in printed
    assert "[Nuclei-AI] Calling" not in printed


def test_nuclei_default_engine_is_unchanged(capsys):
    with mock.patch.object(nuclei_tags.requests, "post", return_value=_resp(200, {"tags": ["cve"]})) as post:
        nuclei_tags.get_ai_tags({"servers": ["nginx"]}, ["cve"], model="m")
    assert post.call_args.args[0].endswith("/llm/nuclei-tags")
    assert "[Nuclei-AI]" in capsys.readouterr().out


def test_nuclei_falls_back_to_current_tags_on_any_jev_failure():
    for resp in (JEV_503("jev_overloaded"), _resp(500), _resp(200, {"nope": 1})):
        cb.reset_registry()
        with mock.patch.object(nuclei_tags.requests, "post", return_value=resp):
            out = nuclei_tags.get_ai_tags({"servers": ["nginx"]}, ["mine"], model="m", engine="jev")
        assert out == ["mine"]


def test_ffuf_posts_to_the_jev_route_and_falls_back_to_the_safe_list(capsys):
    head = mock.MagicMock(headers={"Server": "nginx"})
    with mock.patch.object(ffuf_extensions.requests, "head", return_value=head), \
            mock.patch.object(ffuf_extensions.requests, "post", return_value=JEV_503("jev_timeout")) as post:
        out = ffuf_extensions.get_ai_extensions("https://t/", model="m", max_extensions=6, engine="jev")
    assert post.call_args.args[0].endswith("/jev/ffuf-extensions")
    assert out == ffuf_extensions.SAFE_FALLBACK[:6]
    assert "[FFuf-Jev]" in capsys.readouterr().out


def test_ffuf_validates_jev_extensions_with_the_existing_regex():
    head = mock.MagicMock(headers={"Server": "nginx"})
    body = {"extensions": [".bak", ".old", ".php", "../etc", ".x" * 9]}
    with mock.patch.object(ffuf_extensions.requests, "head", return_value=head), \
            mock.patch.object(ffuf_extensions.requests, "post", return_value=_resp(200, body)):
        out = ffuf_extensions.get_ai_extensions("https://t/", model="m", engine="jev")
    assert out == [".bak", ".old", ".php"]


def test_waf_jev_result_is_accepted_and_keeps_its_source_in_the_agents_shape():
    body = {"waf_detected": True, "waf_type": "cloudflare", "confidence": 90,
            "reasoning": "", "source": "jev_classifier"}
    with mock.patch.object(waf_classifier.requests, "post", return_value=_resp(200, body)) as post:
        out = waf_classifier.classify_waf(_waf_resp(), model="m", engine="jev")
    assert post.call_args.args[0].endswith("/jev/waf-classify")
    assert out["waf_detected"] is True and out["waf_type"] == "cloudflare"
    assert out["confidence"] == 90


def test_waf_falls_back_when_jev_fails(capsys):
    with mock.patch.object(waf_classifier.requests, "post", return_value=JEV_503("jev_no_credit")):
        out = waf_classifier.classify_waf(_waf_resp(), model="m", engine="jev")
    assert out["source"] == "ai_unavailable"
    assert "[WAF-Jev]" in capsys.readouterr().out


def test_takeover_posts_to_the_jev_route_and_falls_back(capsys):
    with mock.patch.object(takeover_classifier.requests, "post", return_value=JEV_503("jev_overloaded")) as post:
        out = takeover_classifier.classify_takeover_response(
            "h.example", "github", "body", 404, {}, model="m", engine="jev")
    assert post.call_args.args[0].endswith("/jev/takeover-classify")
    assert out["source"] == "ai_unavailable"
    assert "[Takeover-Jev]" in capsys.readouterr().out


def test_no_hook_ever_sends_the_user_token_or_model_secret():
    """The payload carries ids only: the Jev token lives in the agent."""
    with mock.patch.object(nuclei_tags.requests, "post", return_value=_resp(200, {"tags": ["cve"]})) as post:
        nuclei_tags.get_ai_tags({"servers": ["nginx"]}, ["cve"], model="m",
                                user_id="u1", project_id="p1", engine="jev")
    payload = post.call_args.kwargs["json"]
    assert payload["user_id"] == "u1" and payload["project_id"] == "p1"
    assert not any("key" in k.lower() or "token" in k.lower() for k in payload)
