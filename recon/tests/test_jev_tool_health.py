"""R7: telling a collector's empty result from a failure, and the Jev layer on top.

Phase 1 (deterministic, ungated) locks in:
- the verdict table: no input, a timeout/kill/exception/non-zero exit, stderr that
  names a failure, other stderr, a clean exit; the tools' routine lines (Katana and
  ParamSpider info lines, logrus/zerolog info, GAU's missing-config warning) are not
  a failure;
- every collector reports its empty results: Katana, Hakrawler, GAU, ParamSpider,
  Kiterunner, FFuf, Arjun; a Hakrawler seed that failed protects jsluice through
  meta["failed"], as Katana's already does;
- the run records one coverage-gap entry per tool, entries only (their own output
  is Endpoints and Parameters, which the prune never touches);
- full and partial runs both drain the queue on the main thread.

Phase 2 (Jev, shadow) locks in:
- only UNDECIDED results with stderr are asked about, at most MAX_CALLS_PER_SCAN;
- configured header values and credential-shaped tokens never leave recon;
- the deterministic verdict always stands; any failure is a fallback, never a crash.
"""
from __future__ import annotations

import json
import subprocess
import threading
from pathlib import Path
from unittest import mock

import pytest

from recon.helpers import circuit_breaker as cb
from recon.helpers.ai_planner import jev_shadow
from recon.helpers.ai_planner import tool_health as jev_th
from recon.helpers.resource_enum import tool_health as th

REPO = Path(__file__).resolve().parents[2]
ANSI_INFO = "\x1b[93m[INFO]\x1b[0m Fetching URLs for \x1b[36mexample.test\x1b[0m"


@pytest.fixture(autouse=True)
def _empty_queue():
    th.drain()
    yield
    th.drain()


def _resp(status=200, body=None):
    r = mock.MagicMock(status_code=status, text="")
    r.json.return_value = body if body is not None else {}
    return r


# ---------------------------------------------------------------------------
# The verdict table
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kw,verdict", [
    (dict(seeds=0, return_code=1, stderr="boom"), th.NO_INPUT),
    (dict(seeds=3, return_code=None), th.FAILURE),
    (dict(seeds=3, return_code=0, timed_out=True), th.FAILURE),
    (dict(seeds=3, return_code=0, raised=True), th.FAILURE),
    (dict(seeds=3, return_code=1), th.FAILURE),
    (dict(seeds=3, return_code=125), th.FAILURE),
    (dict(seeds=3, return_code=-9), th.FAILURE),
    (dict(seeds=3, return_code=0, stderr=""), th.GENUINE),
    (dict(seeds=3, return_code=0, stderr="\n  \n"), th.GENUINE),
    (dict(seeds=3, return_code=0, stderr="[INF] Current katana version v1.1.0"), th.GENUINE),
    (dict(seeds=1, return_code=0, stderr=ANSI_INFO + "\n\x1b[93m[INFO]\x1b[0m Found 0 URLs"), th.GENUINE),
    (dict(seeds=1, return_code=0, stderr='time="x" level=warning msg="error reading config: '
                                         'Config file /home/gau/.gau.toml not found, using default config"'),
     th.GENUINE),
    (dict(seeds=1, return_code=0, stderr='{"level":"info","message":"scan started"}'), th.GENUINE),
    (dict(seeds=1, return_code=0, stderr="10:42PM INF loaded 12 routes"), th.GENUINE),
    # ParamSpider gives up with exit 0: its stderr is the only sign.
    (dict(seeds=1, return_code=0, stderr=ANSI_INFO + "\nFailed to fetch URL http://x after 3 retries."),
     th.FAILURE),
    (dict(seeds=1, return_code=0, stderr="dial tcp: connection refused"), th.FAILURE),
    (dict(seeds=1, return_code=0, stderr="HTTP 429 too many requests"), th.FAILURE),
    (dict(seeds=1, return_code=0, stderr="context deadline exceeded"), th.UNDECIDED),
    (dict(seeds=1, return_code=0, stderr='level=warning msg="partial page"'), th.UNDECIDED),
])
def test_the_verdict_table(kw, verdict):
    assert th.classify_empty(**kw) == verdict


def test_only_failures_and_undecided_results_are_queued():
    for verdict in (th.GENUINE, th.NO_INPUT, th.FAILURE, th.UNDECIDED):
        th.report_empty("gau", verdict, return_code=0, seeds=1, elapsed_s=1.234, stderr="x")
    out = th.drain()
    assert [r.verdict for r in out] == [th.FAILURE, th.UNDECIDED]
    assert out[0].elapsed_s == 1.2
    assert th.drain() == []                                       # drained


def test_the_queue_keeps_only_unplaced_stderr_and_bounds_it():
    th.check_empty("paramspider", seeds=1, return_code=0,
                   stderr=ANSI_INFO + "\n" + "odd " * 5000, elapsed_s=1)
    (r,) = th.drain()
    assert "[INFO]" not in r.stderr and "\x1b" not in r.stderr
    assert len(r.stderr) == th.STDERR_KEEP


def test_reporting_is_thread_safe():
    def worker():
        for _ in range(200):
            th.report_empty("hakrawler", th.FAILURE, return_code=1, seeds=1, elapsed_s=0)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(th.drain()) == 1600


def test_report_never_raises_on_odd_input():
    th.report_empty("gau", th.FAILURE, return_code=None, seeds="x", elapsed_s=None)
    assert th.drain() == []


def test_gaps_are_one_entry_per_tool_and_never_a_source_cut(capsys):
    results = [th.EmptyResult("gau", th.FAILURE, None, 1, 1.0),
               th.EmptyResult("gau", th.UNDECIDED, 0, 1, 1.0, "odd"),
               th.EmptyResult("ffuf", th.FAILURE, 1, 1, 1.0)]
    with mock.patch.object(cb, "note_degraded") as note:
        counts = th.note_gaps(results)
    assert counts == {"ffuf": 1, "gau": 2}
    (args, kwargs), = [(c.args, c.kwargs) for c in note.call_args_list]
    assert args == ("resource_enum",)
    assert "sources" not in kwargs and "hosts" not in kwargs
    assert [(e["source"], e["skipped"]) for e in kwargs["entries"]] == [("ffuf", 1), ("gau", 2)]
    assert "[!][ToolHealth] gau: 2 empty result(s) look like a failure" in capsys.readouterr().out


def test_no_empty_results_means_no_gap():
    with mock.patch.object(cb, "note_degraded") as note:
        assert th.note_gaps([]) == {}
    note.assert_not_called()


# ---------------------------------------------------------------------------
# Each collector reports its empty results
# ---------------------------------------------------------------------------

def _hakrawler(returncode=0, stderr="", lines=(), max_urls=500, prefill=0):
    from recon.helpers.resource_enum import hakrawler_helpers as hk
    seen = {}

    def fake_popen(cmd, **kwargs):
        seen["stderr"] = kwargs.get("stderr")
        if stderr:
            kwargs["stderr"].write(stderr)
            kwargs["stderr"].flush()
        proc = mock.MagicMock()
        proc.stdout.readline.side_effect = [f"{u}\n" for u in lines] + [""]
        proc.poll.return_value = returncode
        proc.returncode = returncode
        return proc

    with mock.patch.object(hk.subprocess, "Popen", side_effect=fake_popen):
        urls, meta = hk.run_hakrawler_crawler(
            target_urls=["https://a.example.test"], docker_image="img", depth=1, threads=1,
            timeout=5, max_urls=max_urls, include_subs=False, insecure=True,
            allowed_hosts={"a.example.test"}, custom_headers=[], exclude_patterns=[],
            parallelism=1)
    return urls, meta, seen


def test_a_hakrawler_seed_that_exits_non_zero_protects_jsluice():
    _, meta, seen = _hakrawler(returncode=1)
    assert meta["failed"] is True and meta["failed_seeds"] == 1
    assert seen["stderr"] is not subprocess.PIPE                 # a file: it cannot fill and block
    (r,) = th.drain()
    assert (r.tool, r.verdict, r.return_code) == ("hakrawler", th.FAILURE, 1)


def test_a_hakrawler_seed_with_error_output_is_read_from_its_file():
    _, meta, _ = _hakrawler(returncode=0, stderr="dial tcp: lookup a.example.test: no such host")
    assert meta["failed"] is True
    (r,) = th.drain()
    assert "no such host" in r.stderr


def test_a_clean_empty_hakrawler_seed_is_genuine():
    _, meta, _ = _hakrawler(returncode=0)
    assert meta["failed"] is False and th.drain() == []


def test_a_hakrawler_seed_that_printed_urls_is_not_an_empty_result():
    urls, meta, _ = _hakrawler(returncode=1, lines=["https://a.example.test/x"])
    assert urls == ["https://a.example.test/x"]
    assert meta["failed"] is False and th.drain() == []


def test_a_katana_failure_reaches_the_queue_and_keeps_its_flag():
    from recon.helpers.resource_enum import katana_helpers

    def fake_popen(cmd, *a, **k):
        proc = mock.MagicMock()
        proc.stdout.readline.return_value = ""
        proc.stderr.read.return_value = "context deadline exceeded"
        proc.poll.return_value = 0
        proc.returncode = 0
        return proc

    with mock.patch.object(katana_helpers.subprocess, "Popen", side_effect=fake_popen), \
            mock.patch.object(katana_helpers.select, "select", side_effect=lambda r, *a: (r, [], [])):
        _, meta = katana_helpers.run_katana_crawler(
            target_urls=["https://example.test"], docker_image="img", depth=1, max_urls=10,
            rate_limit=10, timeout=5, js_crawl=False, params_only=False,
            allowed_hosts={"example.test"}, custom_headers=[], exclude_patterns=[])
    assert meta["failed"] is True
    (r,) = th.drain()
    assert (r.tool, r.verdict) == ("katana", th.UNDECIDED)


@pytest.mark.parametrize("rc,stderr,verdict", [
    (0, 'level=warning msg="error reading config: Config file /home/gau/.gau.toml not found, '
        'using default config"', None),
    (0, "error: cannot reach web.archive.org", th.FAILURE),
    (2, "", th.FAILURE),
])
def test_gau_reports_by_exit_code_and_stderr(rc, stderr, verdict):
    from recon.helpers.resource_enum import gau_helpers
    done = subprocess.CompletedProcess([], rc, stdout="", stderr=stderr)
    with mock.patch.object(gau_helpers.subprocess, "run", return_value=done):
        gau_helpers._run_gau_docker("example.test", "img", ["wayback"], 1, 5, [], 0, None, False, None)
    out = th.drain()
    assert [r.verdict for r in out] == ([verdict] if verdict else [])


def test_a_gau_timeout_is_a_failure():
    from recon.helpers.resource_enum import gau_helpers
    with mock.patch.object(gau_helpers.subprocess, "run", side_effect=subprocess.TimeoutExpired("gau", 5)):
        gau_helpers._run_gau_docker("example.test", "img", ["wayback"], 1, 5, [], 0, None, False, None)
    assert [r.verdict for r in th.drain()] == [th.FAILURE]


@pytest.mark.parametrize("stderr,verdict", [
    (ANSI_INFO + "\n\x1b[93m[INFO]\x1b[0m Found 0 URLs for example.test", None),
    (ANSI_INFO + "\nError fetching URL https://web.archive.org/x. Retrying in 5 seconds...\n"
                 "Failed to fetch URL https://web.archive.org/x after 3 retries.", th.FAILURE),
])
def test_paramspider_exit_zero_is_judged_by_its_stderr(stderr, verdict):
    from recon.helpers.resource_enum import paramspider_helpers as ps
    done = subprocess.CompletedProcess([], 0, stdout="", stderr=stderr)
    with mock.patch.object(ps.subprocess, "run", return_value=done):
        assert ps.run_paramspider_for_domain("example.test", "FUZZ", 30) == []
    assert [r.verdict for r in th.drain()] == ([verdict] if verdict else [])


@pytest.mark.parametrize("exc", [subprocess.TimeoutExpired("p", 1), FileNotFoundError(), RuntimeError()])
def test_paramspider_exceptions_are_failures(exc):
    from recon.helpers.resource_enum import paramspider_helpers as ps
    with mock.patch.object(ps.subprocess, "run", side_effect=exc):
        ps.run_paramspider_for_domain("example.test", "FUZZ", 30)
    assert [r.verdict for r in th.drain()] == [th.FAILURE]


def test_kiterunner_exit_code_on_an_empty_run_is_a_failure(tmp_path):
    from recon.helpers.resource_enum import kiterunner_helpers as kr
    binary = tmp_path / "kr"
    binary.write_text("")
    done = subprocess.CompletedProcess([], 2, stdout="", stderr="")
    with mock.patch.object(kr, "run_with_heartbeat", return_value=done):
        kr.run_kiterunner_discovery(["https://example.test"], str(binary), "ASSETNOTE:apiroutes-210228",
                                    "w", 10, 1, 1, 5, 1, [], [], 0, [])
    (r,) = th.drain()
    assert (r.tool, r.verdict, r.seeds) == ("kiterunner", th.FAILURE, 1)


def _ffuf(tmp_path, rc=0, write=None, stderr=""):
    from recon.helpers.resource_enum import ffuf_helpers as ff

    def fake_run(cmd, **kwargs):
        out = cmd[cmd.index("-o") + 1]
        if write is not None:
            Path(out).write_text(write)
        return subprocess.CompletedProcess(cmd, rc, stdout="", stderr=stderr)

    with mock.patch.object(ff, "run_with_heartbeat", side_effect=fake_run):
        return ff._fuzz_single_target(0, "https://example.test/FUZZ", str(tmp_path), "/w.txt", 1, 5, 5, 1,
                                      [200], [], "", [], False, 1, False, [], False, {"example.test"})


def test_an_ffuf_run_that_wrote_no_file_is_a_failure(tmp_path):
    _ffuf(tmp_path, rc=0, write=None)
    assert [r.verdict for r in th.drain()] == [th.FAILURE]


def test_an_ffuf_run_with_an_empty_result_file_is_genuine(tmp_path):
    _ffuf(tmp_path, rc=0, write=json.dumps({"results": []}))
    assert th.drain() == []


def test_an_ffuf_result_file_that_does_not_parse_is_a_failure(tmp_path):
    _ffuf(tmp_path, rc=0, write="{nope")
    assert [r.verdict for r in th.drain()] == [th.FAILURE]


def _arjun(rc, stderr="", timeout=False):
    from recon.helpers.resource_enum import arjun_helpers as aj
    proc = mock.MagicMock(returncode=rc)
    if timeout:
        proc.communicate.side_effect = [subprocess.TimeoutExpired("arjun", 1), ("", ""), ("", "")]
    else:
        proc.communicate.return_value = ("", stderr)
    with mock.patch.object(aj.subprocess, "Popen", return_value=proc):
        return aj._run_arjun_single_method(["https://example.test/a"], "GET", 1, 5, 5, 10, 10,
                                           False, False, False, [], {"example.test"})


@pytest.mark.parametrize("rc,stderr,timeout,verdict", [
    (1, "Traceback (most recent call last):\nKeyError: 'x'", False, th.FAILURE),
    (0, "", False, None),
    (0, "", True, th.FAILURE),
])
def test_arjun_tells_a_crash_from_no_parameters(rc, stderr, timeout, verdict):
    _arjun(rc, stderr, timeout)
    assert [r.verdict for r in th.drain()] == ([verdict] if verdict else [])


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------

def test_resource_enum_protects_jsluice_when_hakrawler_failed():
    source = (REPO / "recon/main_recon_modules/resource_enum.py").read_text()
    block = source[source.index("hakrawler_urls, hakrawler_meta = future.result("):][:400]
    assert 'if hakrawler_meta.get("failed"):' in block
    assert 'jsluice_feed_cut.append("hakrawler")' in block


def test_resource_enum_drains_before_it_saves():
    source = (REPO / "recon/main_recon_modules/resource_enum.py").read_text()
    drain = source.index("finish_tool_health(")
    assert drain < source.index("recon_data['resource_enum'] = resource_enum_result")
    assert "jev=bool(settings.get('AI_IN_PIPELINE') and settings.get('RESOURCE_ENUM_JEV_TOOL_HEALTH'))" \
        in source[drain:drain + 300]


def test_partial_recon_drains_after_the_tool():
    source = (REPO / "recon/partial_recon.py").read_text()
    assert source.index("statuses, completed = _run_tool(tool_id, config)") < source.index("finish_tool_health(")
    assert "jev=bool(settings.get('AI_IN_PIPELINE') and settings.get('RESOURCE_ENUM_JEV_TOOL_HEALTH'))" in source


# ---------------------------------------------------------------------------
# The Jev layer
# ---------------------------------------------------------------------------

def _undecided(tool="katana", stderr="context deadline exceeded"):
    return th.EmptyResult(tool, th.UNDECIDED, 0, 4, 12.5, stderr)


def test_only_undecided_results_with_stderr_are_asked(monkeypatch):
    monkeypatch.setenv("USER_ID", "u1")
    monkeypatch.setenv("PROJECT_ID", "p1")
    results = [_undecided(), th.EmptyResult("gau", th.FAILURE, 1, 1, 1.0, "error"),
               th.EmptyResult("ffuf", th.UNDECIDED, 0, 1, 1.0, "  ")]
    data = {}
    body = {"transient": True, "confidence": 81, "model": "jev-1.13.0"}
    with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(200, body)) as post:
        transient = jev_th.run_tool_health_pass(results, {}, recon_data=data)
    assert post.call_count == 1
    sent = post.call_args.kwargs["json"]
    assert post.call_args.args[0].endswith("/jev/tool-health")
    assert sent == {"tool": "katana", "return_code": 0, "elapsed_s": 12.5, "seed_count": 4,
                    "stderr": "context deadline exceeded", "user_id": "u1", "project_id": "p1"}
    assert transient == [results[0]]
    (rec,) = data["jev_shadow"]["tool_health"]["records"]
    assert (rec["item"], rec["jev"], rec["baseline"], rec["conf"]) == ("katana_0", "retry", "no_retry", 81)


def test_the_shipped_rollout_is_shadow():
    assert jev_th.ROLLOUT == jev_shadow.SHADOW


def test_header_values_and_credentials_never_leave_recon():
    stderr = ("GET https://a.example.test with -H 'Authorization: Bearer abc.def.ghi' "
              "Cookie: session=s3cr3t-value; X-Redamon-Ctx: tag.sig.xyz custom=MyApiKey123")
    settings = {"KATANA_CUSTOM_HEADERS": ["X-Custom: MyApiKey123"],
                "ZAP_AJAX_SPIDER_CUSTOM_HEADERS": [{"name": "X-Z", "value": "zap-secret-9"}]}
    out = jev_th.redact(stderr + " zap-secret-9 merged-auth-777", settings,
                        extra_headers=["Authorization: merged-auth-777"])
    for secret in ("abc.def.ghi", "s3cr3t-value", "tag.sig.xyz", "MyApiKey123", "zap-secret-9", "merged-auth-777"):
        assert secret not in out, secret
    assert "https://a.example.test" in out                       # target text stays (it is wrapped later)


def test_the_redaction_is_applied_to_what_is_sent():
    r = _undecided(stderr="odd failure with Authorization: Bearer tok3n-value-xyz")
    with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(503, {})) as post:
        jev_th.run_tool_health_pass([r], {})
    assert "tok3n-value-xyz" not in post.call_args.kwargs["json"]["stderr"]


def test_the_per_run_cap(monkeypatch, capsys):
    monkeypatch.setattr(jev_th, "MAX_CALLS_PER_SCAN", 3)
    body = {"transient": False, "confidence": 70, "model": "jev-1.13.0"}
    with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(200, body)) as post:
        jev_th.run_tool_health_pass([_undecided() for _ in range(5)], {})
    assert post.call_count == 3
    assert "2 more not asked (cap 3 per run)" in capsys.readouterr().out


def test_the_shipped_cap_is_twenty():
    assert jev_th.MAX_CALLS_PER_SCAN == 20


@pytest.mark.parametrize("bad", [None, [], {"transient": "yes", "confidence": 80},
                                 {"transient": True, "confidence": 101},
                                 {"transient": True, "confidence": True},
                                 {"transient": True}])
def test_a_malformed_answer_is_a_fallback(bad):
    data = {}
    with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(200, bad)):
        assert jev_th.run_tool_health_pass([_undecided()], {}, recon_data=data) == []
    assert data["jev_shadow"]["tool_health"]["summary"]["fallbacks"] == 1


def test_the_pass_never_raises(capsys):
    with mock.patch.object(jev_th, "jev_post", side_effect=RuntimeError("x")):
        assert jev_th.run_tool_health_pass([_undecided()], {}) == []
    assert "Pass failed (RuntimeError) - the gaps stand as recorded." in capsys.readouterr().out


def test_finish_records_the_gaps_even_with_jev_off():
    th.report_empty("gau", th.UNDECIDED, return_code=0, seeds=1, elapsed_s=1, stderr="odd")
    with mock.patch.object(cb, "note_degraded") as note, \
            mock.patch.object(jev_th, "run_tool_health_pass") as run:
        jev_th.finish_tool_health({}, jev=False)
    note.assert_called_once()
    run.assert_not_called()
    assert th.drain() == []


@pytest.mark.parametrize("jev,settings,called", [
    (True, {"AI_IN_PIPELINE": True, "RESOURCE_ENUM_JEV_TOOL_HEALTH": True}, True),
    (True, {"AI_IN_PIPELINE": True}, False),
    (False, {"AI_IN_PIPELINE": True, "RESOURCE_ENUM_JEV_TOOL_HEALTH": True}, False),
])
def test_finish_runs_the_jev_pass_only_when_both_switches_are_on(jev, settings, called):
    with mock.patch.object(jev_th, "run_tool_health_pass") as run:
        jev_th.finish_tool_health(settings, jev=jev)
    assert run.called is called


def test_finish_never_raises():
    with mock.patch.object(th, "drain", side_effect=RuntimeError("x")):
        jev_th.finish_tool_health({}, jev=True)
