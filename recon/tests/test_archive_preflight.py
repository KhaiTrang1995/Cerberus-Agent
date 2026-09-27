"""The archive preflight GAU and ParamSpider share (recon/main_recon_modules/resource_enum.py).

One hung archive used to stall every domain for its full per-domain timeout.
`requests.head` is patched; the breaker clock is injected.
"""
from __future__ import annotations

from unittest import mock

import pytest
import requests

from recon.helpers import circuit_breaker as cb
from recon.main_recon_modules import resource_enum as re_mod


class _Clock:
    def __init__(self):
        self.t = 5000.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s


@pytest.fixture
def clock():
    c = _Clock()
    cb.set_clock(c.now, c.sleep)
    yield c
    cb.set_clock()


def _resp(status):
    r = mock.MagicMock()
    r.status_code = status
    return r


def test_both_tries_failing_pauses_the_archive(clock, capsys):
    with mock.patch("requests.head", side_effect=requests.exceptions.ConnectTimeout("x")) as head:
        re_mod._archive_preflight("example.test", ["wayback"])
        assert head.call_count == 2
        assert cb.is_open("wayback") and not cb.is_fatal("wayback")
        # Within the cooldown nothing is asked again, by any later group.
        re_mod._archive_preflight("example.test", ["wayback"])
        assert head.call_count == 2
    assert "[!][Archive] wayback: archive unreachable (preflight) - pausing it" in capsys.readouterr().out


def test_a_4xx_is_an_archive_that_answered(clock):
    with mock.patch("requests.head", return_value=_resp(405)) as head:
        re_mod._archive_preflight("example.test", ["wayback", "commoncrawl"])
    assert head.call_count == 2  # one try per archive
    assert not cb.is_open("wayback") and not cb.is_open("commoncrawl")


def test_two_5xx_pause_it_one_does_not(clock):
    with mock.patch("requests.head", side_effect=[_resp(503), _resp(200)]):
        re_mod._archive_preflight("example.test", ["commoncrawl"])
    assert not cb.is_open("commoncrawl")
    with mock.patch("requests.head", side_effect=[_resp(502), _resp(504)]):
        re_mod._archive_preflight("example.test", ["commoncrawl"])
    assert cb.is_open("commoncrawl")


def test_a_later_group_rechecks_after_the_cooldown(clock):
    with mock.patch("requests.head", side_effect=requests.exceptions.ConnectionError("x")):
        re_mod._archive_preflight("example.test", ["wayback"])
    clock.t += cb.COOLDOWN_S
    with mock.patch("requests.head", return_value=_resp(200)) as head:
        re_mod._archive_preflight("example.test", ["wayback"])
    assert head.call_count == 1 and not cb.is_open("wayback")


def test_a_failed_recheck_doubles_the_cooldown(clock):
    with mock.patch("requests.head", side_effect=requests.exceptions.ConnectionError("x")):
        re_mod._archive_preflight("example.test", ["wayback"])
        clock.t += cb.COOLDOWN_S
        re_mod._archive_preflight("example.test", ["wayback"])
    clock.t += cb.COOLDOWN_S
    assert cb.peek_breaker("wayback").allow() is False
    clock.t += cb.COOLDOWN_S
    assert cb.peek_breaker("wayback").allow() is True


def test_the_domain_is_the_only_target_detail_sent(clock):
    with mock.patch("requests.head", return_value=_resp(200)) as head:
        re_mod._archive_preflight("example.test", ["wayback"])
    (url,), kwargs = head.call_args
    assert url == "https://web.archive.org/cdx/search/cdx?url=example.test&limit=1"
    assert kwargs["timeout"] == 10


@pytest.mark.parametrize("provider,breaker_key", [
    ("wayback", "wayback"), ("commoncrawl", "commoncrawl"),
    ("otx", "otx"), ("otx", "otx:url_list"), ("urlscan", "urlscan"), ("urlscan", "urlscan:search"),
])
def test_a_gau_provider_is_paused_by_its_breaker(provider, breaker_key):
    assert not re_mod._gau_provider_paused(provider)
    cb.get_breaker(breaker_key, label="X").force_open("down")
    assert re_mod._gau_provider_paused(provider)


def test_the_off_switch_never_pauses_an_archive(clock, monkeypatch):
    monkeypatch.setenv("RECON_CIRCUIT_BREAKERS", "off")
    with mock.patch("requests.head", side_effect=requests.exceptions.ConnectionError("x")):
        re_mod._archive_preflight("example.test", ["wayback"])
    assert not re_mod._gau_provider_paused("wayback")
