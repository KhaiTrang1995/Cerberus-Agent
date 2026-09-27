"""The shared agent_llm breaker across the five /llm/* hooks (recon/helpers/ai_planner/).

Each hook times out at 20-30s per item; a dead agent must stop being called
after 3 failures. The breaker sits AFTER the cache check (a cache hit still
answers) and, when open, each hook returns its own existing fallback.
"""
from __future__ import annotations

from unittest import mock

import pytest
import requests

from recon.helpers import ai_planner
from recon.helpers import circuit_breaker as cb
from recon.helpers.ai_planner import (
    ffuf_extensions, nuclei_response_filter, nuclei_tags, takeover_classifier,
    waf_classifier,
)


def _post(status=200, body=None, exc=None):
    if exc is not None:
        return mock.MagicMock(side_effect=exc)
    resp = mock.MagicMock(status_code=status, headers={}, text="")
    resp.json.return_value = body if body is not None else {}
    return resp


def _waf_resp():
    r = mock.MagicMock(status_code=403, headers={"Server": "nginx"}, url="https://t/")
    r.content = b"<html>blocked</html>"
    return r


def test_the_breaker_is_shared_across_hooks_and_opens_after_three_failures():
    """Two WAF failures + one FFuf failure = 3 in a row: the fourth hook, of any
    kind, skips without a POST."""
    # The hooks share one `requests` module, so a single patch covers them all.
    with mock.patch.object(requests, "post", side_effect=requests.Timeout("x")) as post:
        waf_classifier.classify_waf(_waf_resp(), model="m")
        waf_classifier.classify_waf(_waf_resp(), model="m", cache={})
        nuclei_tags.get_ai_tags({"servers": ["iis"]}, ["cve"], model="m")
        assert post.call_count == 3 and cb.is_open("agent_llm")
        # A fourth call, on a third hook type, never reaches the network.
        out = nuclei_response_filter.classify_nuclei_response("body", "tid", ["cve"], model="m")
        assert out["source"] == "ai_unavailable"
        assert post.call_count == 3


def test_a_cache_hit_answers_even_while_the_breaker_is_open():
    cb.get_breaker("agent_llm", label="Agent-LLM", threshold=cb.INTERNAL_THRESHOLD)
    for _ in range(3):
        cb.peek_breaker("agent_llm").record(cb.Outcome.TRANSIENT, "Timeout")
    assert cb.is_open("agent_llm")
    resp = _waf_resp()
    cached = {"waf_detected": True, "waf_type": "cloudflare", "confidence": 92,
              "reasoning": "cached", "source": "ai_classifier"}
    cache = {waf_classifier._fingerprint(resp): cached}
    with mock.patch.object(waf_classifier.requests, "post") as post:
        out = waf_classifier.classify_waf(resp, model="m", cache=cache)
    assert out == cached
    post.assert_not_called()


@pytest.mark.parametrize("fallback_source", ["ai_unavailable"])
def test_each_hook_returns_its_own_fallback_when_open(fallback_source):
    for _ in range(3):
        cb.get_breaker("agent_llm", label="Agent-LLM",
                       threshold=cb.INTERNAL_THRESHOLD).record(cb.Outcome.TRANSIENT, "Timeout")
    assert cb.is_open("agent_llm")
    head = mock.MagicMock(headers={"Server": "nginx"})
    with mock.patch.object(waf_classifier.requests, "post") as p1, \
            mock.patch.object(nuclei_response_filter.requests, "post") as p2, \
            mock.patch.object(takeover_classifier.requests, "post") as p3, \
            mock.patch.object(ffuf_extensions.requests, "post") as p4, \
            mock.patch.object(ffuf_extensions.requests, "head", return_value=head), \
            mock.patch.object(nuclei_tags.requests, "post") as p5:
        assert waf_classifier.classify_waf(_waf_resp(), model="m")["source"] == fallback_source
        assert nuclei_response_filter.classify_nuclei_response(
            "body", "tid", ["cve"], model="m")["source"] == fallback_source
        assert takeover_classifier.classify_takeover_response(
            "h.example", "github", "body", 404, {}, model="m")["source"] == fallback_source
        assert ffuf_extensions.get_ai_extensions("https://t/", model="m") == \
            ffuf_extensions.SAFE_FALLBACK[:6]
        assert nuclei_tags.get_ai_tags({"Server": ["x"]}, ["myfallback"], model="m") == ["myfallback"]
    for p in (p1, p2, p3, p4, p5):
        p.assert_not_called()


def test_a_200_keeps_the_breaker_closed_even_if_the_body_is_rejected():
    """A 200 means the agent LLM is alive; a body the validator rejects is not
    an "agent down" signal, so it must not count toward opening the breaker."""
    with mock.patch.object(waf_classifier.requests, "post",
                           return_value=_post(200, {"garbage": True})) as post:
        for _ in range(10):
            waf_classifier.classify_waf(_waf_resp(), model="m", cache={})
    assert post.call_count == 10
    assert not cb.is_open("agent_llm")


def test_a_recovery_probe_closes_it(clock=None):
    c = mock.MagicMock()
    t = {"v": 1000.0}
    cb.set_clock(lambda: t["v"], lambda s: t.__setitem__("v", t["v"] + s))
    try:
        for _ in range(3):
            cb.get_breaker("agent_llm", label="Agent-LLM",
                           threshold=cb.INTERNAL_THRESHOLD).record(cb.Outcome.TRANSIENT, "x")
        assert cb.is_open("agent_llm")
        t["v"] += cb.COOLDOWN_S
        ok = {"waf_detected": False, "waf_type": None, "confidence": 10, "reasoning": "ok"}
        with mock.patch.object(waf_classifier.requests, "post", return_value=_post(200, ok)):
            out = waf_classifier.classify_waf(_waf_resp(), model="m", cache={})
        assert out["source"] == "ai_classifier"
        assert not cb.is_open("agent_llm")
    finally:
        cb.set_clock()
