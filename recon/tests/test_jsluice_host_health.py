"""HostHealth gate + parallel download on jsluice (jsluice_helpers.py, #19).

The downloader was sequential urllib at 10s each, so one dead host stalled the
whole file list. It now runs on a thread pool and skips a host HostHealth
already found down, recording what each fetch saw.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from unittest import mock

import requests

from recon.helpers import circuit_breaker as cb
from recon.helpers.resource_enum import jsluice_helpers as jl


def _mark_down(host):
    for _ in range(3):
        cb.host_health.record_failure(f"https://{host}", requests.ConnectionError("x"))


class _FakeResp:
    def __init__(self, status=200, body=b"var x=1;", ctype="application/javascript"):
        self.status = status
        self._body = body
        self.headers = {"Content-Type": ctype}

    def read(self):
        return self._body


class _FakeOpener:
    def __init__(self, on_open):
        self._on_open = on_open

    def open(self, request, timeout=10):
        return self._on_open(request.full_url)


def test_a_down_host_is_skipped_and_the_live_one_downloads():
    _mark_down("dead.example.test")
    opened = []

    def on_open(url):
        opened.append(url)
        return _FakeResp()

    with tempfile.TemporaryDirectory() as d, \
         mock.patch.object(jl.urllib.request, "build_opener",
                           return_value=_FakeOpener(on_open)):
        out = jl._download_js_files(
            ["https://dead.example.test/a.js", "https://live.example.test/b.js"],
            Path(d))
    assert opened == ["https://live.example.test/b.js"]
    assert list(out) == ["https://live.example.test/b.js"]


def test_a_200_keeps_the_host_alive():
    def on_open(url):
        return _FakeResp(status=200)

    with tempfile.TemporaryDirectory() as d, \
         mock.patch.object(jl.urllib.request, "build_opener",
                           return_value=_FakeOpener(on_open)):
        jl._download_js_files(["https://web.example.test/a.js"], Path(d))
    assert not cb.host_health.is_down("https://web.example.test/a.js")


def test_connection_failures_mark_the_host_down():
    def on_open(url):
        raise requests.ConnectionError("refused")

    with tempfile.TemporaryDirectory() as d, \
         mock.patch.object(jl.urllib.request, "build_opener",
                           return_value=_FakeOpener(on_open)):
        jl._download_js_files(
            [f"https://boom.example.test/{i}.js" for i in range(3)], Path(d))
    assert cb.host_health.is_down("https://boom.example.test/x.js")
