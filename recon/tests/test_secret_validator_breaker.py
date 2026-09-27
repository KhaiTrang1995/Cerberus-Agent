"""The per-service breaker on the JS secret validators (recon/helpers/js_recon/validators.py).

A validator serialises at 1 req/s and waits up to 5s, so a dead service must
stop being called. A skipped call keeps the {'valid': False, ...} shape, and an
invalid-but-answering key never trips the breaker.
"""
from __future__ import annotations

from unittest import mock

import pytest
import requests

from recon.helpers import circuit_breaker as cb
from recon.helpers.js_recon import validators


@pytest.fixture(autouse=True)
def _no_pacing():
    # The real validator sleeps 1s after each call; drop it so the test is quick.
    with mock.patch.object(validators.time, "sleep"):
        yield


def _github(token="ghp_" + "a" * 36):
    return f"token={token}"


def test_three_timeouts_stop_the_service_and_the_shape_is_kept():
    with mock.patch.object(validators.requests, "get",
                           side_effect=requests.Timeout("slow")) as get:
        for _ in range(3):
            r = validators.validate_github(_github())
            assert r == {"valid": False, "scope": "", "info": "", "error": "timeout"}
        skipped = validators.validate_github(_github())
    assert get.call_count == 3
    assert skipped["valid"] is False
    assert skipped["error"].startswith("skipped")


def test_an_invalid_key_answering_401_never_trips_the_breaker():
    resp = mock.MagicMock(status_code=401)
    resp.json.return_value = {}
    with mock.patch.object(validators.requests, "get", return_value=resp) as get:
        for _ in range(10):
            r = validators.validate_github(_github())
            assert r["valid"] is False and not r["error"]
    assert get.call_count == 10


def test_each_service_has_its_own_breaker():
    with mock.patch.object(validators.requests, "get", side_effect=requests.Timeout("x")), \
            mock.patch.object(validators.requests, "post", side_effect=requests.Timeout("x")):
        for _ in range(3):
            validators.validate_github(_github())
        # GitHub is now stopped, but GitLab (a different service) still tries.
        assert validators.validate_github(_github())["error"].startswith("skipped")
        gl = validators.validate_gitlab("glpat-" + "a" * 20)
        assert gl["error"] == "timeout"


def test_a_valid_answer_resets_the_streak():
    ok = mock.MagicMock(status_code=200)
    ok.json.return_value = {"login": "octocat"}
    ok.headers = {"X-OAuth-Scopes": "repo"}
    seq = [requests.Timeout("x"), requests.Timeout("x"), ok,
           requests.Timeout("x"), requests.Timeout("x")]
    with mock.patch.object(validators.requests, "get", side_effect=seq):
        results = [validators.validate_github(_github()) for _ in range(5)]
    # The success in the middle resets the count, so no call is skipped.
    assert all(not r["error"].startswith("skipped") for r in results)
    assert results[2]["valid"] is True


def test_the_off_switch_keeps_calling(monkeypatch):
    monkeypatch.setenv("RECON_CIRCUIT_BREAKERS", "off")
    with mock.patch.object(validators.requests, "get",
                           side_effect=requests.Timeout("x")) as get:
        for _ in range(10):
            validators.validate_github(_github())
    assert get.call_count == 10
