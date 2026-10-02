"""R5: the page-type classifier on Jev.

What it locks in:
- the deterministic pre-filter places the easy pages with no call, and leaves a
  real app alone;
- pages that share title, body, status, size bucket and Server collapse to one
  question set; a different title is a different page;
- the agent sees bounded, typed items (body clipped at 4096, headers bounded);
- per-scan cap and wall-clock budget: past either, the rest get no label and one
  line says so; a failed batch is a fallback, never a crash, never re-asked;
- SHADOW changes nothing on the URL entries and records Jev's label next to the
  pre-filter's; ACT writes page_class, its confidence and its source;
- the pass sits in run_http_probe between the traffic capture and the body drop,
  under its own guard, and partial Httpx inherits it.
"""
from __future__ import annotations

import re
from pathlib import Path
from unittest import mock

import pytest

from recon.helpers.ai_planner import jev_shadow
from recon.helpers.ai_planner import page_type as pt

REPO = Path(__file__).resolve().parents[2]


def _resp(status=200, body=None):
    r = mock.MagicMock(status_code=status, text="")
    r.json.return_value = body if body is not None else {}
    return r


def _entry(url="http://app.example.test/", **over):
    entry = {"url": url, "host": "app.example.test", "status_code": 200, "content_length": 5120,
             "word_count": 400, "line_count": 90, "title": "Dashboard", "server": "nginx",
             "headers": {"Server": "nginx"}, "body": "<html>real app</html>",
             "response_time_ms": "123.4ms", "cname": ["edge.example.test"], "is_cdn": False}
    entry.update(over)
    return entry


def _labels_for(json_body):
    return {"labels": [{"page_class": "app", "confidence": 90}] * len(json_body["pages"]),
            "model": "jev-1.13.0"}


def _echo_post(label=("app", 90), status=200):
    calls = []

    def post(url, json=None, headers=None, timeout=None):
        calls.append(json)
        if status != 200:
            return _resp(status, {"error_type": "jev_timeout"})
        return _resp(200, {"labels": [{"page_class": label[0], "confidence": label[1]}] * len(json["pages"]),
                           "model": "jev-1.13.0"})

    return calls, post


# ---------------------------------------------------------------------------
# Pre-filter
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("over,label", [
    ({"status_code": 503}, "error"),
    ({"status_code": 404}, "error"),
    ({"status_code": 403}, "error"),
    ({"title": "Welcome to nginx!"}, "default"),
    ({"title": "IIS Windows Server"}, "default"),
    ({"title": "It works!"}, "default"),
    ({"title": "This domain is for sale"}, "parked"),
    ({"cname": ["x.sedoparking.com"]}, "parked"),
    ({"cname": "pk.parkingcrew.net"}, "parked"),
    ({"title": "Coming Soon"}, "placeholder"),
    ({"title": "Page Not Found"}, "error"),                    # a soft 404 answering 200
    ({"url": "http://app.example.test/login"}, "login_only"),
    ({"url": "http://app.example.test/wp-login.php"}, "login_only"),
    ({"word_count": 1, "content_length": 10}, "placeholder"),
    ({}, None),                                                # a real app is not placed
    ({"url": "http://app.example.test/login/history"}, None),  # only the login path itself
    ({"status_code": 401}, None),                              # left to Jev, not assumed
])
def test_the_prefilter_places_only_the_easy_pages(over, label):
    assert pt.prefilter(_entry(**over)) == label


@pytest.mark.parametrize("entry,ok", [
    ({"status_code": None, "title": "x"}, False),
    ({"status_code": 200}, False),                             # no body, title or size
    ({"status_code": 200, "title": "x"}, True),                # metadata only
    ({"status_code": 200, "content_length": 10}, True),
    ({"status_code": 200, "body": "<p>"}, True),
])
def test_a_page_without_any_signal_is_never_asked_about(entry, ok):
    assert pt._classifiable(entry) is ok


# ---------------------------------------------------------------------------
# Cache key and request item
# ---------------------------------------------------------------------------

def test_identical_pages_share_a_key_and_a_different_title_does_not():
    a = _entry("http://a.example.test/")
    b = _entry("http://b.example.test/")
    assert pt.cache_key(a) == pt.cache_key(b)
    assert pt.cache_key(a) != pt.cache_key(_entry(title="Sign in"))
    assert pt.cache_key(a) != pt.cache_key(_entry(status_code=302))
    assert pt.cache_key(a) != pt.cache_key(_entry(content_length=9000))
    assert pt.cache_key(a) != pt.cache_key(_entry(server="Apache"))


def test_the_key_ignores_body_bytes_past_what_is_sent():
    head = "x" * pt.BODY_CHARS
    assert pt.cache_key(_entry(body=head + "A")) == pt.cache_key(_entry(body=head + "B"))


def test_the_request_item_is_bounded_and_typed():
    big = _entry(body="b" * 100_000, headers={f"H{i}": "v" * 5000 for i in range(100)},
                 response_time_ms="1.5s", cname=["a.example.test", "b.example.test"],
                 word_count="lots", status_code=200)
    item = pt._page(big)
    assert len(item["body"]) == pt.BODY_CHARS
    assert len(item["headers"]) == 40 and all(len(v) == 500 for v in item["headers"].values())
    assert item["response_time_ms"] == 1500
    assert item["cname"] == "a.example.test b.example.test"
    assert item["word_count"] == 0                             # a non-number becomes 0
    assert set(item) == {"url", "host", "status_code", "content_length", "word_count", "line_count",
                         "response_time_ms", "is_cdn", "title", "server", "cname", "headers", "body"}


@pytest.mark.parametrize("raw,ms", [("123.4ms", 123), ("2s", 2000), ("900µs", 0), (42, 42),
                                    ("", 0), (None, 0), ("fast", 0), (True, 0)])
def test_response_time_parsing(raw, ms):
    assert pt._ms(raw) == ms


# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------

def _by_url(n=3, **over):
    return {f"http://h{i}.example.test/": _entry(f"http://h{i}.example.test/", title=f"T{i}", **over)
            for i in range(n)}


def test_shadow_records_and_leaves_the_entries_alone(capsys):
    by_url = _by_url(3)
    by_url["http://h9.example.test/"] = _entry("http://h9.example.test/", title="Welcome to nginx!")
    data = {}
    calls, post = _echo_post(("parked", 88))
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        stats = pt.run_page_type_pass(by_url, user_id="u1", project_id="p1", recon_data=data)
    assert stats["prefiltered"] == 1 and stats["asked"] == 4 and stats["labelled"] == 4
    assert all("page_class" not in e for e in by_url.values())
    assert calls[0]["user_id"] == "u1" and calls[0]["project_id"] == "p1"
    records = data["jev_shadow"]["page_type"]["records"]
    nginx = next(r for r in records if r["url"] == "http://h9.example.test/")
    assert nginx["baseline"] == "default" and nginx["jev"] == "parked" and nginx["prefiltered"] is True
    app = next(r for r in records if r["url"] == "http://h0.example.test/")
    assert app["baseline"] == "app" and app["agreed"] is False and app["conf"] == 88
    out = capsys.readouterr().out
    assert "example.test" not in out and "Welcome to nginx" not in out
    assert "jev-shadow page_type: summary decisions=4" in out


def test_act_writes_the_label_and_the_prefilter_label(monkeypatch):
    monkeypatch.setattr(pt, "ROLLOUT", jev_shadow.ACT)
    by_url = _by_url(2)
    by_url["http://h9.example.test/"] = _entry("http://h9.example.test/", status_code=404)
    calls, post = _echo_post(("login_only", 91))
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        pt.run_page_type_pass(by_url, user_id="u", project_id="p")
    assert by_url["http://h0.example.test/"]["page_class"] == "login_only"
    assert by_url["http://h0.example.test/"]["page_class_confidence"] == 91
    assert by_url["http://h0.example.test/"]["page_class_source"] == "jev_classifier"
    assert by_url["http://h9.example.test/"]["page_class"] == "error"
    assert by_url["http://h9.example.test/"]["page_class_source"] == "prefilter"
    assert sum(len(c["pages"]) for c in calls) == 2              # the pre-filtered page is not asked


def test_the_shipped_rollout_is_shadow():
    assert pt.ROLLOUT == jev_shadow.SHADOW


def test_identical_pages_are_asked_once_and_all_get_the_answer():
    by_url = {f"http://h{i}.example.test/": _entry(f"http://h{i}.example.test/") for i in range(40)}
    data = {}
    calls, post = _echo_post()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        stats = pt.run_page_type_pass(by_url, user_id="u", project_id="p", recon_data=data)
    assert sum(len(c["pages"]) for c in calls) == 1
    assert stats["labelled"] == 40
    assert len(data["jev_shadow"]["page_type"]["records"]) == 40


def test_batches_are_bounded():
    by_url = _by_url(40)
    calls, post = _echo_post()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        pt.run_page_type_pass(by_url, user_id="u", project_id="p")
    assert [len(c["pages"]) for c in calls] == [4] * 10


def test_the_per_scan_cap_bounds_the_pages_asked(monkeypatch, capsys):
    monkeypatch.setattr(pt, "MAX_PAGES_PER_SCAN", 20)
    calls, post = _echo_post()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        stats = pt.run_page_type_pass(_by_url(50), user_id="u", project_id="p")
    assert sum(len(c["pages"]) for c in calls) == 20
    assert stats["not_asked"] == 30
    assert "30 pages not asked (cap 20 distinct pages per scan" in capsys.readouterr().out


def test_the_shipped_bounds():
    assert pt.MAX_PAGES_PER_SCAN == 300 and pt.TIME_BUDGET_S == 60
    # Each page is its own TypeSafe request (up to 5 s): a call of BATCH_SIZE pages
    # must fit inside the agent call's timeout.
    assert pt.BATCH_SIZE * 5 <= pt.TIMEOUT


def test_the_time_budget_stops_the_pass(capsys):
    ticks = iter([0, 0, 61, 61, 61])
    calls, post = _echo_post()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        stats = pt.run_page_type_pass(_by_url(40), user_id="u", project_id="p",
                                      clock=lambda: next(ticks))
    assert len(calls) == 1
    assert stats["not_asked"] == 36
    assert "Time budget of 60s reached - 36 distinct pages left unlabelled" in capsys.readouterr().out


def test_a_failed_batch_falls_back_and_is_never_re_asked():
    data = {}
    calls, post = _echo_post(status=503)
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        stats = pt.run_page_type_pass(_by_url(20), user_id="u", project_id="p", recon_data=data)
    # One call per batch, never per URL; after three failures in a row the Jev
    # breaker pauses and the remaining batches fall back without a request.
    assert len(calls) == 3
    assert stats["failed_batches"] == 5 and stats["labelled"] == 0
    assert data["jev_shadow"]["page_type"]["summary"]["fallbacks"] == 5


@pytest.mark.parametrize("bad", [
    {"labels": []},                                              # wrong length
    {"labels": [{"page_class": "spam", "confidence": 90}]},
    {"labels": [{"page_class": "app", "confidence": 101}]},
    {"labels": [{"page_class": "app", "confidence": True}]},
    {"labels": [{"page_class": "app", "confidence": 90.5}]},
    {"labels": [{"page_class": ["app"], "confidence": 90}]},
    {"labels": "app"}, [], None,
])
def test_a_malformed_answer_is_a_fallback(bad):
    by_url = _by_url(1)
    with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(200, bad)):
        stats = pt.run_page_type_pass(by_url, user_id="u", project_id="p")
    assert stats["labelled"] == 0 and stats["failed_batches"] == 1


def test_an_unexpected_error_never_escapes_the_pass(capsys):
    with mock.patch.object(pt, "jev_post", side_effect=KeyError("boom")):
        stats = pt.run_page_type_pass(_by_url(2), user_id="u", project_id="p")
    assert stats["labelled"] == 0
    assert "Pass failed (KeyError) - pages left unlabelled." in capsys.readouterr().out


def test_pages_without_any_signal_are_skipped():
    by_url = {"http://x.example.test/": {"url": "http://x.example.test/", "status_code": 200}}
    with mock.patch.object(jev_shadow.requests, "post") as post:
        stats = pt.run_page_type_pass(by_url, user_id="u", project_id="p")
    post.assert_not_called()
    assert stats["skipped_no_signal"] == 1


def test_a_bodyless_page_is_classified_on_its_metadata():
    by_url = {"http://x.example.test/": _entry("http://x.example.test/", body=None)}
    calls, post = _echo_post()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        pt.run_page_type_pass(by_url, user_id="u", project_id="p")
    assert calls[0]["pages"][0]["body"] == "" and calls[0]["pages"][0]["title"] == "Dashboard"


# ---------------------------------------------------------------------------
# Gating and wiring
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ai,flag,on", [(True, True, True), (True, False, False), (False, True, False)])
def test_the_hook_needs_both_switches(ai, flag, on):
    assert pt.jev_page_type_enabled({"AI_IN_PIPELINE": ai, "HTTPX_JEV_PAGE_TYPE": flag}) is on


def test_run_for_probe_does_nothing_when_off():
    with mock.patch.object(pt, "run_page_type_pass") as run:
        pt.run_for_probe({"by_url": _by_url(1)}, {"AI_IN_PIPELINE": True}, {})
    run.assert_not_called()


def test_run_for_probe_reads_the_owner_from_the_environment(monkeypatch):
    monkeypatch.setenv("USER_ID", "owner-1")
    monkeypatch.setenv("PROJECT_ID", "proj-1")
    with mock.patch.object(pt, "run_page_type_pass") as run:
        pt.run_for_probe({"by_url": {}}, {"AI_IN_PIPELINE": True, "HTTPX_JEV_PAGE_TYPE": True}, {})
    assert run.call_args.kwargs["user_id"] == "owner-1"
    assert run.call_args.kwargs["project_id"] == "proj-1"


def test_run_for_probe_never_raises():
    with mock.patch.object(pt, "run_page_type_pass", side_effect=RuntimeError("x")):
        pt.run_for_probe({"by_url": {}}, {"AI_IN_PIPELINE": True, "HTTPX_JEV_PAGE_TYPE": True}, {})


def test_the_pass_runs_after_the_capture_and_before_the_bodies_are_dropped():
    source = (REPO / "recon/main_recon_modules/http_probe.py").read_text()
    capture = source.index("capture_httpx_transactions(httpx_results, settings)")
    call = source.index("run_for_probe(httpx_results, settings, recon_data)")
    drop = source.index('url_data.pop("body", None)')
    assert capture < call < drop
    assert "settings.get('AI_IN_PIPELINE') and settings.get('HTTPX_JEV_PAGE_TYPE')" in \
        source[capture:call]
    # Its own catch-all: an exception reaching the except at the end of run_http_probe
    # would discard the whole probe result.
    assert re.search(
        r"try:\s+from recon\.helpers\.ai_planner\.page_type import run_for_probe\s+"
        r"run_for_probe\(httpx_results, settings, recon_data\)\s+except Exception as \w+:",
        source[capture:drop])


def test_partial_httpx_runs_the_same_probe_with_its_settings():
    source = (REPO / "recon/partial_recon_modules/http_probing.py").read_text()
    assert "_run_http_probe(recon_data, output_file=None, settings=settings)" in source
