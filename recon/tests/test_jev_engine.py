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


@pytest.mark.parametrize("error_type", ["jev_not_configured", "jev_auth", "jev_no_credit"])
def test_jev_account_errors_are_fatal(error_type):
    record = _outcome_after(JEV_503(error_type))
    assert record.call_args.args[0] is cb.Outcome.FATAL
    assert record.call_args.args[1] == error_type


def test_a_wrong_owner_403_is_fatal_and_named_for_what_it_is():
    """The agent answers jev_forbidden with 403 (not 503). It must be read by its
    error_type, or the breaker message says "403 key rejected" for a project that
    simply is not this user's."""
    resp = _resp(403, {"error_type": "jev_forbidden", "error": "The project does not belong to this user"})
    record = _outcome_after(resp)
    assert record.call_args.args[0] is cb.Outcome.FATAL
    assert record.call_args.args[1] == "jev_forbidden"


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


def test_waf_jev_result_is_stamped_as_jev_provenance():
    body = {"waf_detected": True, "waf_type": "cloudflare", "confidence": 90, "reasoning": ""}
    with mock.patch.object(waf_classifier.requests, "post", return_value=_resp(200, body)) as post:
        out = waf_classifier.classify_waf(_waf_resp(), model="m", engine="jev")
    assert post.call_args.args[0].endswith("/jev/waf-classify")
    assert out["waf_detected"] is True and out["waf_type"] == "cloudflare"
    assert out["confidence"] == 90
    assert out["source"] == "jev_classifier"


def test_waf_llm_result_keeps_the_llm_provenance():
    body = {"waf_detected": True, "waf_type": "cloudflare", "confidence": 90, "reasoning": "x"}
    with mock.patch.object(waf_classifier.requests, "post", return_value=_resp(200, body)):
        out = waf_classifier.classify_waf(_waf_resp(), model="m", engine="llm")
    assert out["source"] == "ai_classifier"


@pytest.mark.parametrize("engine,expected", [("jev", "jev_classifier"), ("llm", "ai_classifier")])
def test_provenance_comes_from_the_engine_asked_for_never_from_the_response_body(engine, expected):
    """A body claiming any source cannot change what detection_method says."""
    waf = {"waf_detected": True, "waf_type": "cloudflare", "confidence": 90,
           "reasoning": "", "source": "something_else"}
    with mock.patch.object(waf_classifier.requests, "post", return_value=_resp(200, waf)):
        assert waf_classifier.classify_waf(_waf_resp(), model="m", engine=engine)["source"] == expected
    tk = {"is_waf_block": True, "confidence": 90, "reason": "", "source": "something_else"}
    with mock.patch.object(takeover_classifier.requests, "post", return_value=_resp(200, tk)):
        out = takeover_classifier.classify_takeover_response(
            "h.example", "github", "body", 404, {}, model="m", engine=engine)
    assert out["source"] == expected


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


# ---------------------------------------------------------------------------
# The engine reaches the call sites and the findings carry it
# ---------------------------------------------------------------------------

from recon.helpers import security_checks as sc  # noqa: E402


def _http_resp(status=200, headers=None, body=b"", url="https://target.com/"):
    r = mock.MagicMock(status_code=status, headers=headers or {}, url=url)
    r.content = body
    r.text = body.decode("utf-8", "replace")
    return r


@pytest.fixture
def ai_ctx_reset():
    yield
    sc._set_ai_ctx(False, "", "", "")


def test_set_ai_ctx_carries_the_engine_into_classify_waf(ai_ctx_reset):
    sc._set_ai_ctx(True, "m", "u", "p", "jev")
    with mock.patch("recon.helpers.ai_planner.waf_classifier.classify_waf",
                    return_value={"source": "jev_classifier", "waf_detected": False}) as classify:
        sc._classify_waf_ai(_http_resp(403, {"Server": "nginx"}))
    assert classify.call_args.kwargs["engine"] == "jev"


def test_engine_defaults_to_llm_in_the_ai_context(ai_ctx_reset):
    sc._set_ai_ctx(True, "m", "u", "p")
    with mock.patch("recon.helpers.ai_planner.waf_classifier.classify_waf",
                    return_value={"source": "ai_classifier", "waf_detected": False}) as classify:
        sc._classify_waf_ai(_http_resp(403, {"Server": "nginx"}))
    assert classify.call_args.kwargs["engine"] == "llm"


@pytest.mark.parametrize("source,expected", [("jev_classifier", "jev_classifier"), ("ai_classifier", "ai_classifier")])
def test_a_waf_bypass_finding_records_which_engine_found_the_waf(source, expected, ai_ctx_reset):
    sc._set_ai_ctx(True, "m", "u", "p", "jev" if source == "jev_classifier" else "llm")
    sub = _http_resp(403, {"Server": "nginx"}, b"<html>Attention Required</html>")
    ip = _http_resp(200, {"Server": "nginx"}, b"<html>origin</html>")

    def fake_classify(response, response_time_ms=0):
        if response is sub:
            return {"waf_detected": True, "waf_type": "cloudflare", "confidence": 92,
                    "reasoning": "", "source": source}
        return {"waf_detected": False, "waf_type": None, "confidence": 80,
                "reasoning": "", "source": source}

    with mock.patch("recon.helpers.security_checks.requests.get", side_effect=[sub, ip]), \
            mock.patch.object(sc, "_waf_payload_differential", return_value=None), \
            mock.patch.object(sc, "_classify_waf_ai", side_effect=fake_classify):
        result = sc.check_waf_bypass("api.target.com", "1.2.3.4")
    assert result is not None
    assert result["detection_method"] == expected


@pytest.mark.parametrize("engine", ["jev", "llm"])
def test_a_takeover_finding_records_the_engine_that_flagged_the_collision(engine):
    from recon.main_recon_modules import subdomain_takeover as st
    finding = {"hostname": "x.example.com", "takeover_provider": "heroku"}
    verdict = {"is_waf_block": True, "confidence": 90, "reason": "r",
               "source": "jev_classifier" if engine == "jev" else "ai_classifier"}
    with mock.patch.object(st, "_probe_for_ai_disambiguation", return_value=(403, {}, "blocked")), \
            mock.patch("recon.helpers.ai_planner.takeover_classifier.has_third_party_vendor_token",
                       return_value=False), \
            mock.patch("recon.helpers.ai_planner.takeover_classifier.classify_takeover_response",
                       return_value=verdict) as classify:
        st._apply_ai_waf_disambiguation([finding], "m", "u", "p", engine=engine)
    assert classify.call_args.kwargs["engine"] == engine
    assert finding["ai_waf_likely"] is True
    assert finding["ai_engine"] == engine


def test_a_takeover_below_the_threshold_is_not_annotated_at_all():
    from recon.main_recon_modules import subdomain_takeover as st
    finding = {"hostname": "x.example.com", "takeover_provider": "heroku"}
    verdict = {"is_waf_block": True, "confidence": 50, "reason": "", "source": "jev_classifier"}
    with mock.patch.object(st, "_probe_for_ai_disambiguation", return_value=(403, {}, "blocked")), \
            mock.patch("recon.helpers.ai_planner.takeover_classifier.has_third_party_vendor_token",
                       return_value=False), \
            mock.patch("recon.helpers.ai_planner.takeover_classifier.classify_takeover_response",
                       return_value=verdict):
        st._apply_ai_waf_disambiguation([finding], "m", "u", "p", engine="jev")
    assert "ai_waf_likely" not in finding and "ai_engine" not in finding


@pytest.mark.parametrize("engine,source", [("jev", "jev_classifier"), ("llm", "ai_classifier")])
def test_an_ai_waf_bypass_finding_keeps_the_waf_type_confidence_and_evidence_whatever_the_engine(
        engine, source, ai_ctx_reset):
    """REGRESSION (Jev WAF bypass finding lost its AI fields): only the assignment of
    detection_method learned about "jev_classifier"; three later checks still compared
    it to "ai_classifier", so a Jev-detected bypass fell into the static-header branch:
    waf_label came from the (empty) Server header and the type, confidence and reasoning
    were never attached. The evidence/description are what the graph persists."""
    sc._set_ai_ctx(True, "m", "u", "p", engine)
    sub = _http_resp(403, {"Server": "nginx"}, b"<html>Attention Required</html>")
    ip = _http_resp(200, {"Server": "nginx"}, b"<html>origin</html>")

    def fake_classify(response, response_time_ms=0):
        if response is sub:
            return {"waf_detected": True, "waf_type": "cloudflare", "confidence": 92,
                    "reasoning": "challenge page", "source": source}
        return {"waf_detected": False, "waf_type": None, "confidence": 80, "reasoning": "", "source": source}

    with mock.patch("recon.helpers.security_checks.requests.get", side_effect=[sub, ip]), \
            mock.patch.object(sc, "_waf_payload_differential", return_value=None), \
            mock.patch.object(sc, "_classify_waf_ai", side_effect=fake_classify):
        result = sc.check_waf_bypass("api.target.com", "1.2.3.4")

    assert result["detection_method"] == source
    assert result["waf_type"] == "cloudflare"
    assert result["waf_confidence"] == 92
    assert result["ai_reasoning"] == "challenge page"
    assert "cloudflare" in result["description"]
    assert "AI classifier flagged subdomain as cloudflare" in result["evidence"]
    assert "(unknown)" not in result["description"] and "()" not in result["evidence"]
