"""recon/helpers/circuit_breaker.py: outcomes, breakers, HostHealth, coverage.

Driven through an injected clock, so no test sleeps. The conftest autouse
fixture resets the registry around every test.
"""
from __future__ import annotations

import ast
import errno
import re
import socket
import threading
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import pytest
import requests

from recon.helpers import circuit_breaker as cb
from recon.helpers.circuit_breaker import Outcome
from recon.helpers.key_rotation import KeyRotator

REPO = Path(__file__).resolve().parents[2]

# A pinned copy of recon_orchestrator/container_manager.py PHASE_PATTERNS.
# test_pinned_phase_patterns_match_the_orchestrator keeps it honest.
PINNED_PHASE_PATTERNS = [
    r"\[Phase 1\]|\[PHASE 1\]|Phase 1:|WHOIS Lookup|domain.*discovery|Domain Reconnaissance",
    r"\[Phase 2\]|\[PHASE 2\]|Phase 2:|NAABU PORT SCANNER|port.*scan",
    r"\[Phase 3\]|\[PHASE 3\]|Phase 3:|HTTPX HTTP PROBER|http.*prob",
    r"\[Phase 4\]|\[PHASE 4\]|Phase 4:|Resource Enumeration|Katana.*GAU|resource.*enum",
    r"\[Phase 4\.5\]|\[PHASE 4\.5\]|Phase 4\.5:|AI Surface Recon|ai_surface_recon",
    r"\[Phase 5\]|\[PHASE 5\]|Phase 5:|NUCLEI|Vulnerability Scan|vuln.*scan",
    r"\[Phase 6\]|\[PHASE 6\]|Phase 6:|CVE LOOKUP|MITRE|CWE|CAPEC",
]


class FakeClock:
    def __init__(self):
        self.t = 1000.0
        self.slept: list[float] = []

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.t += seconds

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock():
    c = FakeClock()
    cb.set_clock(c.now, c.sleep)
    yield c
    cb.set_clock()


@pytest.fixture(autouse=True)
def _switch_on(monkeypatch):
    monkeypatch.delenv("RECON_CIRCUIT_BREAKERS", raising=False)


def _resp(status=200, body=None, headers=None, text=""):
    r = mock.MagicMock()
    r.status_code = status
    r.headers = headers if headers is not None else {}
    r.text = text
    if isinstance(body, Exception):
        r.json.side_effect = body
    else:
        r.json.return_value = body
    return r


def _fail(b, n, outcome=Outcome.TRANSIENT, detail="ReadTimeout"):
    for _ in range(n):
        b.record(outcome, detail)


# ---------------------------------------------------------------------------
# Breaker state machine
# ---------------------------------------------------------------------------

class TestStreaks:
    def test_threshold_consecutive_failures_open_it(self, clock, capsys):
        b = cb.get_breaker("svc:x", label="Svc")
        _fail(b, 4)
        assert b.allow() and not b.is_open
        _fail(b, 1)
        assert b.is_open
        assert b.allow() is False
        assert b.skipped == 1
        out = capsys.readouterr().out
        assert "[!][Svc] x: 5 consecutive failures (ReadTimeout) - pausing it, next try in 120s" in out
        assert out.count("consecutive failures") == 1

    def test_no_data_is_an_answer_and_resets_the_streak(self, clock):
        b = cb.get_breaker("svc:x", label="Svc")
        _fail(b, 4)
        b.record(Outcome.NO_DATA)
        _fail(b, 4)
        assert not b.is_open
        for _ in range(100):
            b.record(Outcome.NO_DATA)
        assert not b.is_open and b.allow()

    def test_ten_404s_never_trip_it(self, clock):
        b = cb.get_breaker("svc:x", label="Svc")
        for _ in range(10):
            res = cb.guarded_call(b, lambda: _resp(404), lambda r: cb.json_result(r, keyed=True))
            assert res.outcome is Outcome.NO_DATA
        assert not b.is_open

    def test_fatal_opens_on_the_first_failure_and_never_probes(self, clock, capsys):
        b = cb.get_breaker("svc:x", label="Svc")
        b.record(Outcome.FATAL, "401 key rejected")
        assert b.is_open and b.is_fatal
        clock.advance(100_000)
        assert b.allow() is False
        b.record(Outcome.OK)  # a late success does not revive a refused key
        assert b.is_fatal and b.allow() is False
        assert "[!][Svc] x: 401 key rejected - stopped for the rest of this run" in capsys.readouterr().out

    def test_internal_threshold_is_three(self, clock):
        b = cb.get_breaker("agent_llm", label="AI", threshold=cb.INTERNAL_THRESHOLD)
        _fail(b, 3)
        assert b.is_open

    def test_first_creation_fixes_the_parameters(self):
        a = cb.get_breaker("svc:x", label="Svc", threshold=2)
        b = cb.get_breaker("svc:x", label="Other", threshold=9)
        assert a is b and b.threshold == 2 and b.label == "Svc"


class TestRateLimit:
    def test_first_429_sets_a_shared_pause_second_opens(self, clock):
        b = cb.get_breaker("svc:x", label="Svc")
        b.record(Outcome.RATE_LIMIT, "HTTP 429", retry_after=5, epoch=b.epoch())
        assert not b.is_open
        assert b.allow() is True
        assert clock.slept == [5]
        b.record(Outcome.RATE_LIMIT, "HTTP 429", retry_after=5, epoch=b.epoch())
        assert b.is_open and b.open_outcome is Outcome.RATE_LIMIT

    def test_every_thread_honours_the_pause(self, clock):
        b = cb.get_breaker("svc:x", label="Svc")
        b.record(Outcome.RATE_LIMIT, "HTTP 429", retry_after=4, epoch=b.epoch())
        # A second worker admitted during the pause sleeps out what is left.
        clock.advance(1)
        assert b.allow() is True
        assert clock.slept == [3]

    def test_429s_already_in_flight_are_one_strike(self, clock):
        b = cb.get_breaker("svc:x", label="Svc")
        before = b.epoch()
        for _ in range(10):  # ten workers admitted before the limit hit
            b.record(Outcome.RATE_LIMIT, "HTTP 429", retry_after=2, epoch=before)
        assert not b.is_open
        b.record(Outcome.RATE_LIMIT, "HTTP 429", retry_after=2, epoch=b.epoch())
        assert b.is_open

    def test_a_success_between_limits_resets_the_count(self, clock):
        b = cb.get_breaker("svc:x", label="Svc")
        b.record(Outcome.RATE_LIMIT, "HTTP 429", epoch=b.epoch())
        b.record(Outcome.OK, epoch=b.epoch())
        b.record(Outcome.RATE_LIMIT, "HTTP 429", epoch=b.epoch())
        assert not b.is_open

    def test_guarded_call_waits_and_retries_once(self, clock):
        b = cb.get_breaker("svc:x", label="Svc")
        responses = iter([_resp(429, headers={"Retry-After": "3"}), _resp(200, {"a": 1})])
        res = cb.guarded_call(b, lambda: next(responses), lambda r: cb.json_result(r, keyed=True))
        assert res.outcome is Outcome.OK and res.data == {"a": 1}
        assert clock.slept == [3]

    def test_two_429s_in_a_row_open_it_through_guarded_call(self, clock):
        b = cb.get_breaker("svc:x", label="Svc")
        calls = []

        def send():
            calls.append(1)
            return _resp(429)

        res = cb.guarded_call(b, send, lambda r: cb.json_result(r, keyed=True))
        assert res.outcome is Outcome.RATE_LIMIT
        assert len(calls) == 2 and b.is_open
        again = cb.guarded_call(b, send, lambda r: cb.json_result(r, keyed=True))
        assert again.outcome is Outcome.SKIPPED and len(calls) == 2


class TestRetryAfter:
    @pytest.mark.parametrize("raw,expected", [
        ("7.5", 7.5), ("0", 0.0), ("120", 60.0), ("60", 60.0),
        ("-5", 2.0), ("nan", 2.0), ("inf", 2.0), ("", 2.0), ("soon", 2.0),
        ("Wed, 21 Oct 2015 07:28:00 GMT", 2.0),
    ])
    def test_clamped_and_garbage_falls_back(self, raw, expected):
        assert cb.retry_after_seconds(_resp(429, headers={"Retry-After": raw})) == expected

    def test_missing_header_uses_the_default(self):
        assert cb.retry_after_seconds(_resp(429, headers={})) == 2.0

    def test_bare_magicmock_header_is_tolerated(self):
        assert cb.retry_after_seconds(mock.MagicMock()) == 1.0


class TestCooldown:
    def test_probe_after_cooldown_closes_it(self, clock, capsys):
        b = cb.get_breaker("svc:x", label="Svc")
        _fail(b, 5)
        clock.advance(119)
        assert b.allow() is False
        clock.advance(1)
        assert b.allow() is True          # the probe
        assert b.allow() is False         # only one probe at a time
        b.record(Outcome.OK)
        assert not b.is_open and b.allow()
        assert "[+][Svc] x responding again - resumed" in capsys.readouterr().out

    def test_failed_probe_reopens_with_a_doubled_capped_cooldown(self, clock):
        b = cb.get_breaker("svc:x", label="Svc")
        _fail(b, 5)
        expected = 120
        for _ in range(8):
            clock.advance(expected)
            assert b.allow() is True
            b.record(Outcome.TRANSIENT, "HTTP 502")
            expected = min(expected * 2, 1800)
            clock.advance(expected - 1)
            assert b.allow() is False
            clock.advance(1)
            assert b.allow() is True
            b.record(Outcome.TRANSIENT, "HTTP 502")
            expected = min(expected * 2, 1800)
        assert b.is_open and expected == 1800

    def test_recovery_resets_the_cooldown(self, clock):
        b = cb.get_breaker("svc:x", label="Svc")
        _fail(b, 5)
        clock.advance(120)
        assert b.allow()
        b.record(Outcome.TRANSIENT)       # cooldown -> 240
        clock.advance(240)
        assert b.allow()
        b.record(Outcome.OK)
        _fail(b, 5)
        clock.advance(120)
        assert b.allow() is True

    def test_an_unanswered_probe_is_reissued_after_the_grace(self, clock):
        b = cb.get_breaker("svc:x", label="Svc")
        _fail(b, 5)
        clock.advance(120)
        assert b.allow() is True          # probe taken, never recorded
        assert b.allow() is False
        clock.advance(cb.PROBE_GRACE_S)
        assert b.allow() is True

    def test_a_late_success_closes_an_open_breaker(self, clock):
        b = cb.get_breaker("svc:x", label="Svc")
        _fail(b, 5)
        b.record(Outcome.OK)  # from a call already in flight when it opened
        assert not b.is_open

    def test_force_open_is_non_fatal(self, clock, capsys):
        b = cb.get_breaker("wayback", label="Archive")
        b.force_open("preflight failed")
        assert b.is_open and not b.is_fatal
        clock.advance(120)
        assert b.allow() is True
        assert "[!][Archive] wayback: preflight failed - pausing it, next try in 120s" in capsys.readouterr().out


class TestParent:
    def test_rate_limit_on_one_endpoint_stops_the_provider(self, clock):
        a = cb.get_breaker("p:a", label="P", parent="p")
        other = cb.get_breaker("p:b", label="P", parent="p")
        a.record(Outcome.RATE_LIMIT, "HTTP 429", epoch=a.epoch())
        a.record(Outcome.RATE_LIMIT, "HTTP 429", epoch=a.epoch())
        assert other.allow() is False
        assert other.is_open and "429" in other.detail
        assert cb.peek_breaker("p").skipped == 1

    def test_a_rejected_key_stops_every_endpoint(self, clock):
        a = cb.get_breaker("p:a", label="P", parent="p")
        other = cb.get_breaker("p:b", label="P", parent="p")
        a.record(Outcome.FATAL, "401 key rejected")
        assert other.is_fatal and other.allow() is False

    def test_timeouts_stay_endpoint_local(self, clock):
        a = cb.get_breaker("p:a", label="P", parent="p")
        other = cb.get_breaker("p:b", label="P", parent="p")
        _fail(a, 5)
        assert a.is_open and not other.is_open and other.allow()

    def test_a_success_anywhere_revives_the_provider(self, clock):
        a = cb.get_breaker("p:a", label="P", parent="p")
        other = cb.get_breaker("p:b", label="P", parent="p")
        a.record(Outcome.RATE_LIMIT, epoch=a.epoch())
        a.record(Outcome.RATE_LIMIT, epoch=a.epoch())
        other.record(Outcome.OK)  # an in-flight call on another endpoint
        assert not cb.peek_breaker("p").is_open and a.allow()

    def test_parent_pause_is_shared(self, clock):
        a = cb.get_breaker("p:a", label="P", parent="p")
        other = cb.get_breaker("p:b", label="P", parent="p")
        a.record(Outcome.RATE_LIMIT, retry_after=6, epoch=a.epoch())
        assert other.allow() is True and clock.slept == [6]


class TestThreadSafety:
    def test_holds_up_under_a_thread_pool(self, clock):
        # A real clock would do too; the fake keeps the cooldown from expiring.
        b = cb.get_breaker("svc:x", label="Svc")
        sent = []
        lock = threading.Lock()

        def send():
            with lock:
                sent.append(1)
            raise requests.exceptions.ReadTimeout("slow")

        def work(_):
            return cb.guarded_call(b, send, lambda r: cb.json_result(r, keyed=True)).outcome

        with ThreadPoolExecutor(max_workers=16) as pool:
            outcomes = list(pool.map(work, range(400)))
        assert b.is_open and b.opens == 1
        assert outcomes.count(Outcome.SKIPPED) == b.skipped
        assert len(sent) + b.skipped == 400
        # At most one wave of in-flight calls gets past the threshold.
        assert len(sent) <= b.threshold + 16


# ---------------------------------------------------------------------------
# Classification, secrets, never-raise
# ---------------------------------------------------------------------------

class TestClassification:
    @pytest.mark.parametrize("status,keyed,expected", [
        (200, True, Outcome.OK), (204, False, Outcome.OK),
        (404, True, Outcome.NO_DATA), (429, False, Outcome.RATE_LIMIT),
        (401, True, Outcome.FATAL), (403, True, Outcome.FATAL),
        (401, False, Outcome.TRANSIENT), (403, False, Outcome.TRANSIENT),
        (402, False, Outcome.FATAL), (500, True, Outcome.TRANSIENT),
        (502, True, Outcome.TRANSIENT), (418, True, Outcome.TRANSIENT),
        (302, True, Outcome.TRANSIENT),
    ])
    def test_classify_http(self, status, keyed, expected):
        assert cb.classify_http(_resp(status), keyed=keyed) is expected

    def test_explicit_sets_win(self):
        assert cb.classify_http(_resp(403), keyed=True, no_data=(403,)) is Outcome.NO_DATA
        assert cb.classify_http(_resp(503), keyed=True, rate=(503,)) is Outcome.RATE_LIMIT
        assert cb.classify_http(_resp(400), keyed=True, fatal=(400,)) is Outcome.FATAL

    def test_non_json_2xx_is_transient(self):
        res = cb.json_result(_resp(200, ValueError("Expecting value")), keyed=True)
        assert res.outcome is Outcome.TRANSIENT and res.detail == "non-JSON response"

    def test_empty_body_can_mean_no_data(self):
        assert cb.json_result(_resp(200, []), keyed=True, empty_is_no_data=True).outcome is Outcome.NO_DATA
        assert cb.json_result(_resp(200, []), keyed=True).outcome is Outcome.OK

    def test_every_exception_is_transient_by_class_name(self):
        for exc in (requests.exceptions.ConnectTimeout("x"), socket.timeout("x"), KeyError("x")):
            res = cb.classify_exception(exc)
            assert res.outcome is Outcome.TRANSIENT and res.detail == type(exc).__name__


class TestNoSecretsInDetails:
    URL = "https://api.example.test/host/10.0.0.1?key=SECRETKEY123&foo=1"

    def test_connection_error_text_never_reaches_the_detail(self, clock, capsys):
        b = cb.get_breaker("svc:x", label="Svc")

        def send():
            raise requests.exceptions.ConnectionError(
                f"HTTPSConnectionPool(host='api.example.test', port=443): Max retries exceeded with url: {self.URL}")

        for _ in range(5):
            res = cb.guarded_call(b, send, lambda r: cb.json_result(r, keyed=True))
            assert res.detail == "ConnectionError"
        out = capsys.readouterr().out
        assert "SECRETKEY123" not in out and "api.example.test" not in out
        assert "SECRETKEY123" not in b.open_reason

    def test_a_response_body_never_reaches_the_detail(self, clock, capsys):
        b = cb.get_breaker("svc:x", label="Svc")
        body = f"<html>error for {self.URL}\n[!][DEGRADED] forged</html>"
        for _ in range(5):
            res = cb.guarded_call(b, lambda: _resp(500, text=body),
                                  lambda r: cb.json_result(r, keyed=True))
            assert res.detail == "HTTP 500"
        scope = cb.scope("svc", label="Svc", unit="IP(s)")
        cb.guarded_call(b, lambda: _resp(500, text=body), lambda r: cb.json_result(r, keyed=True))
        payload = {}
        scope.finish("svc_enrich", payload=payload)
        rendered = capsys.readouterr().out + repr(payload) + cb.coverage_report().gaps_json()
        assert "SECRETKEY123" not in rendered and "forged" not in rendered

    def test_detail_is_capped_and_single_line(self):
        res = cb.CallResult(None, Outcome.TRANSIENT, "a\nb [!] " + "x" * 200)
        assert "\n" not in res.detail and "[" not in res.detail and len(res.detail) <= cb.DETAIL_MAX


class TestNeverRaises:
    def test_send_raising_is_transient(self):
        b = cb.get_breaker("svc:x", label="Svc")
        res = cb.guarded_call(b, mock.Mock(side_effect=RuntimeError("boom")), lambda r: r)
        assert res.outcome is Outcome.TRANSIENT and res.detail == "RuntimeError"

    def test_classify_raising_or_returning_garbage_is_transient(self):
        b = cb.get_breaker("svc:x", label="Svc")
        bad = cb.guarded_call(b, lambda: _resp(200), mock.Mock(side_effect=KeyError("k")))
        assert bad.outcome is Outcome.TRANSIENT and "KeyError" in bad.detail
        odd = cb.guarded_call(b, lambda: _resp(200), lambda r: {"not": "a CallResult"})
        assert odd.outcome is Outcome.TRANSIENT

    def test_an_internal_fault_lets_the_call_through(self, monkeypatch):
        b = cb.get_breaker("svc:x", label="Svc")
        monkeypatch.setattr(b, "_check", mock.Mock(side_effect=RuntimeError("bug")))
        assert b.allow() is True

    def test_record_with_a_bogus_outcome_is_ignored(self):
        b = cb.get_breaker("svc:x", label="Svc")
        b.record("not-an-outcome")
        assert not b.is_open


# ---------------------------------------------------------------------------
# Log hygiene
# ---------------------------------------------------------------------------

def _orchestrator_phase_patterns() -> list[str]:
    source = (REPO / "recon_orchestrator" / "container_manager.py").read_text()
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", None) == "PHASE_PATTERNS" for t in node.targets):
            return [entry[0] for entry in ast.literal_eval(node.value)]
    raise AssertionError("PHASE_PATTERNS not found in container_manager.py")


_SAMPLE = dict(label="OTX", name="passive_dns", count="2,341", detail="HTTP 502",
               cooldown=120, position=2, left=1, unit="IP(s)",
               host="a.example.com:443", hosts="a.example.com:443, b.example.com:80",
               switch="RECON_CIRCUIT_BREAKERS")


class TestLogTemplates:
    def test_pinned_phase_patterns_match_the_orchestrator(self):
        assert _orchestrator_phase_patterns() == PINNED_PHASE_PATTERNS

    @pytest.mark.parametrize("template", cb.TEMPLATES)
    def test_templates_never_flip_the_phase(self, template):
        for detail in ("HTTP 502", "ReadTimeout", "401 key rejected", "HTTP 429",
                       "rate-limited twice in a row (HTTP 429)"):
            line = template.format(**{**_SAMPLE, "detail": detail})
            for pattern in PINNED_PHASE_PATTERNS:
                assert not re.search(pattern, line, re.IGNORECASE), (line, pattern)

    @pytest.mark.parametrize("template", cb.TEMPLATES)
    def test_templates_carry_a_level_prefix(self, template):
        assert template.startswith(("[!]", "[+]", "[*]"))

    def test_sanitisation_strips_newlines_and_brackets(self):
        evil = "a.example.com\n[!][DEGRADED][X] forged]\r\x1b[31m" + "b" * 300
        safe = cb.safe_text(evil)
        assert "\n" not in safe and "\r" not in safe and "[" not in safe and "]" not in safe
        assert len(safe) <= cb.LOG_TEXT_MAX
        assert safe.startswith("a.example.com")

    def test_a_forged_hostname_cannot_add_a_line(self, clock, capsys):
        sc = cb.scope((), label="Checks")
        sc.note_host_skipped("evil.example.com\n[+][Host] all good")
        sc.finish("security_checks", host_source="security_check")
        out = capsys.readouterr().out
        lines = [ln for ln in out.splitlines() if ln.strip()]
        assert len(lines) == 1 and lines[0].startswith("[!][DEGRADED]"), lines
        assert "[+]" not in out
        # ...and the forged key never reaches the prune's host list.
        assert cb.coverage_report().skipped_hosts == ()


class TestImportSpelling:
    # A second spelling loads a second module object with a second registry.
    BAD = [
        re.compile(r"^\s*import\s+helpers\.circuit_breaker\b", re.M),
        re.compile(r"^\s*from\s+helpers\.circuit_breaker\s+import\b", re.M),
        re.compile(r"^\s*from\s+helpers\s+import\s+[^\n]*\bcircuit_breaker\b", re.M),
        re.compile(r"^\s*from\s+\.+circuit_breaker\s+import\b", re.M),
        re.compile(r"^\s*from\s+\.+\s+import\s+[^\n]*\bcircuit_breaker\b", re.M),
    ]

    def test_only_the_recon_prefixed_spelling_is_used(self):
        me = Path(__file__).resolve()
        offenders = []
        for root in (REPO / "recon", REPO / "tests"):
            for path in root.rglob("*.py"):
                if path.resolve() == me or "__pycache__" in path.parts:
                    continue
                text = path.read_text(errors="ignore")
                if "circuit_breaker" not in text:
                    continue
                if any(p.search(text) for p in self.BAD):
                    offenders.append(str(path.relative_to(REPO)))
        assert offenders == []


# ---------------------------------------------------------------------------
# HostHealth
# ---------------------------------------------------------------------------

class TestHostKey:
    @pytest.mark.parametrize("target,key", [
        ("https://A.example.com/x", "a.example.com:443"),
        ("http://a.example.com", "a.example.com:80"),
        ("http://a.example.com:8080/p?q=1", "a.example.com:8080"),
        ("a.example.com:8443", "a.example.com:8443"),
        ("a.example.com", "a.example.com"),
        ("https://[::1]:8443/", "[::1]:8443"),
        ("https://a.example.com./", "a.example.com:443"),
        ("", ""), (None, ""), ("http://", ""),
    ])
    def test_host_key(self, target, key):
        assert cb.host_key(target) == key

    def test_hostname_of(self):
        assert cb.hostname_of("a.example.com:443") == "a.example.com"
        assert cb.hostname_of("[::1]:8443") == "::1"
        assert cb.hostname_of("a.example.com") == "a.example.com"


class TestHostHealth:
    URL = "https://a.example.com/login"

    @pytest.mark.parametrize("exc", [
        requests.exceptions.ConnectTimeout("x"),
        requests.exceptions.ConnectionError("x"),
        requests.exceptions.SSLError("x"),
        urllib.error.URLError(ConnectionRefusedError()),
        urllib.error.URLError(socket.gaierror("x")),
        urllib.error.URLError(socket.timeout("x")),
        ConnectionRefusedError(),
        socket.gaierror("x"),
        OSError(errno.EHOSTUNREACH, "no route"),
    ])
    def test_connection_failures_count(self, clock, exc):
        hh = cb.host_health
        assert cb.is_connection_failure(exc)
        for _ in range(3):
            assert hh.record_failure(self.URL, exc) is True
        assert hh.allow(self.URL) is False
        assert hh.unreachable() == ["a.example.com:443"]

    @pytest.mark.parametrize("exc", [
        requests.exceptions.ProxyError("capture proxy down"),
        requests.exceptions.HTTPError("500"),
        requests.exceptions.TooManyRedirects("x"),
        requests.exceptions.ChunkedEncodingError("x"),
        OSError(errno.EMFILE, "too many open files"),
        ValueError("x"),
    ])
    def test_other_failures_never_count(self, clock, exc):
        hh = cb.host_health
        for _ in range(10):
            assert hh.record_failure(self.URL, exc) is False
        assert hh.allow(self.URL) is True and hh.unreachable() == []

    def test_urllib_http_error_is_a_response(self, clock):
        hh = cb.host_health
        hh.record_failure(self.URL, requests.exceptions.ConnectionError("x"))
        hh.record_failure(self.URL, requests.exceptions.ConnectionError("x"))
        err = urllib.error.HTTPError(self.URL, 403, "Forbidden", {}, None)
        assert hh.record_failure(self.URL, err) is False
        hh.record_failure(self.URL, requests.exceptions.ConnectionError("x"))
        assert hh.allow(self.URL) is True  # the streak was reset by the 403

    def test_read_timeout_counts_only_before_the_first_response(self, clock):
        hh = cb.host_health
        slow = "https://slow.example.com/"
        hh.record_alive(slow)
        for _ in range(10):
            assert hh.record_failure(slow, requests.exceptions.ReadTimeout("x")) is False
        assert hh.allow(slow) is True
        silent = "https://silent.example.com/"
        for _ in range(3):
            assert hh.record_failure(silent, requests.exceptions.ReadTimeout("x")) is True
        assert hh.allow(silent) is False

    def test_any_response_resets_and_revives(self, clock, capsys):
        hh = cb.host_health
        for _ in range(3):
            hh.record_failure(self.URL, requests.exceptions.ConnectionError("x"))
        assert hh.allow(self.URL) is False
        hh.record_alive(self.URL)  # a late response from an in-flight request
        assert hh.allow(self.URL) is True
        out = capsys.readouterr().out
        assert "[!][Host] a.example.com:443 unreachable (3 connection failures)" in out
        assert "[+][Host] a.example.com:443 responding again - resumed" in out

    def test_other_ports_and_hosts_are_independent(self, clock):
        hh = cb.host_health
        for _ in range(3):
            hh.record_failure(self.URL, requests.exceptions.ConnectionError("x"))
        assert hh.allow("http://a.example.com/") is True
        assert hh.allow("https://b.example.com/") is True

    def test_cooldown_probe(self, clock):
        hh = cb.host_health
        for _ in range(3):
            hh.record_failure(self.URL, requests.exceptions.ConnectionError("x"))
        clock.advance(cb.HOST_COOLDOWN_S)
        assert hh.allow(self.URL) is True       # one probe
        assert hh.allow(self.URL) is False
        hh.record_failure(self.URL, requests.exceptions.ConnectionError("x"))
        clock.advance(cb.HOST_COOLDOWN_S)
        assert hh.allow(self.URL) is False      # cooldown doubled
        clock.advance(cb.HOST_COOLDOWN_S)
        assert hh.allow(self.URL) is True

    def test_is_down_never_takes_a_probe(self, clock):
        hh = cb.host_health
        for _ in range(3):
            hh.record_failure(self.URL, requests.exceptions.ConnectionError("x"))
        clock.advance(10_000)
        assert hh.is_down(self.URL) is True
        assert hh.is_down(self.URL) is True


# ---------------------------------------------------------------------------
# Key pools
# ---------------------------------------------------------------------------

class TestKeyPool:
    def _call(self, b, pool, statuses, used):
        it = iter(statuses)

        def send(key):
            used.append(key)
            return _resp(next(it), {"ok": True})

        return cb.guarded_call(b, send, lambda r: cb.json_result(r, keyed=True), keys=pool)

    def test_a_refused_key_is_dropped_and_the_next_one_used(self, clock, capsys):
        b = cb.get_breaker("svc:x", label="Svc", parent="svc")
        rot = KeyRotator(["MAINKEY", "EXTRAKEY"], rotate_every_n=100)
        pool = cb.KeyPool(rot, "MAINKEY", label="Svc")
        used = []
        res = self._call(b, pool, [401, 200], used)
        assert res.outcome is Outcome.OK and used == ["MAINKEY", "EXTRAKEY"]
        assert not b.is_open and rot.keys == ["EXTRAKEY"]
        out = capsys.readouterr().out
        assert "[!][Svc] API key #1 rejected (401 key rejected) - removed from rotation (1 left)" in out
        assert "MAINKEY" not in out and "EXTRAKEY" not in out

    def test_the_breaker_opens_only_when_the_pool_is_empty(self, clock):
        b = cb.get_breaker("svc:x", label="Svc", parent="svc")
        rot = KeyRotator(["K1", "K2"], rotate_every_n=100)
        pool = cb.KeyPool(rot, "K1", label="Svc")
        used = []
        res = self._call(b, pool, [401, 403], used)
        assert res.outcome is Outcome.FATAL and b.is_fatal
        # The main key was the pool's first member: never resurrect it.
        assert rot.exhausted and pool.current() == ""

    def test_a_single_key_without_a_rotator_opens_on_fatal(self, clock):
        b = cb.get_breaker("svc:x", label="Svc")
        pool = cb.KeyPool(None, "ONLYKEY", label="Svc")
        used = []
        assert self._call(b, pool, [401], used).outcome is Outcome.FATAL
        assert b.is_fatal and used == ["ONLYKEY"]

    def test_a_magicmock_rotator_never_loops(self, clock):
        b = cb.get_breaker("svc:x", label="Svc")
        pool = cb.KeyPool(mock.MagicMock(), "K", label="Svc")
        used = []
        assert self._call(b, pool, [401] * 20, used).outcome is Outcome.FATAL
        assert len(used) == 1

    def test_ticks_after_each_request(self, clock):
        b = cb.get_breaker("svc:x", label="Svc")
        rot = KeyRotator(["A", "B"], rotate_every_n=1)
        pool = cb.KeyPool(rot, "A", label="Svc")
        used = []
        self._call(b, pool, [200], used)
        self._call(b, pool, [200], used)
        assert used == ["A", "B"]


class TestKeyRotator:
    def test_mark_bad_by_value_and_by_index(self):
        rot = KeyRotator(["", "A", "B", "C"], rotate_every_n=1)
        assert rot.mark_bad("B") == (3, 2)   # positions count the configured slots
        assert rot.mark_bad(0) == (2, 1)
        assert rot.mark_bad("zzz") == (0, 1)
        assert rot.current_key == "C" and not rot.exhausted
        assert rot.mark_bad("C") == (4, 0)
        assert rot.exhausted and rot.current_key == "" and not rot.has_keys

    def test_dropping_the_current_key_moves_to_the_next(self):
        rot = KeyRotator(["A", "B", "C"], rotate_every_n=1)
        rot.tick()
        assert rot.current_key == "B"
        rot.mark_bad("B")
        assert rot.current_key == "C"

    def test_concurrent_ticks_are_counted_exactly(self):
        rot = KeyRotator(["A", "B"], rotate_every_n=1000)
        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(lambda _: rot.tick(), range(999)))
        assert rot.current_key == "A"
        rot.tick()
        assert rot.current_key == "B"


# ---------------------------------------------------------------------------
# Off switch
# ---------------------------------------------------------------------------

class TestOffSwitch:
    def test_only_the_exact_value_off_disables(self, monkeypatch):
        for value, on in (("off", False), (" off \r", False), ("OFF", True), ("0", True),
                          ("false", True), ("on", True), ("", True)):
            monkeypatch.setenv("RECON_CIRCUIT_BREAKERS", value)
            assert cb.enabled() is on, value

    def test_off_admits_everything_but_still_records_coverage(self, clock, monkeypatch, capsys):
        monkeypatch.setenv("RECON_CIRCUIT_BREAKERS", "off")
        assert cb.announce_mode() == "off"
        assert "[*][Breakers] circuit breakers are off" in capsys.readouterr().out
        b = cb.get_breaker("svc:x", label="Svc")
        b.record(Outcome.FATAL, "401 key rejected")
        _fail(b, 50)
        assert b.allow() is True and not b.is_open
        for _ in range(5):
            cb.host_health.record_failure("https://a.example.com/", requests.exceptions.ConnectionError())
        assert cb.host_health.allow("https://a.example.com/") is True
        cb.note_degraded("vuln_scan", sources=["nuclei"], nuclei_truncated=True,
                         reason="NUCLEI_MAX_RUNTIME reached")
        report = cb.coverage_report()
        assert report.nuclei_truncated and "nuclei" in report.degraded_sources

    def test_off_still_waits_out_a_429_before_the_retry(self, clock, monkeypatch):
        monkeypatch.setenv("RECON_CIRCUIT_BREAKERS", "off")
        b = cb.get_breaker("svc:x", label="Svc")
        responses = iter([_resp(429, headers={"Retry-After": "4"}), _resp(200, {"a": 1})])
        res = cb.guarded_call(b, lambda: next(responses), lambda r: cb.json_result(r, keyed=True))
        assert res.outcome is Outcome.OK and clock.slept == [4]

    def test_on_prints_nothing(self, capsys):
        assert cb.announce_mode() == "on"
        assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# Report scope and the coverage accumulator
# ---------------------------------------------------------------------------

class TestReportScope:
    def test_a_clean_module_keeps_todays_payload_shape(self, clock, capsys):
        sc = cb.scope("otx", label="OTX", unit="IP(s)")
        b = cb.get_breaker("otx:general", label="OTX", parent="otx")
        b.record(Outcome.OK)
        payload = {"ip_reports": []}
        assert sc.finish("otx_enrich", payload=payload) == []
        assert payload == {"ip_reports": []}
        assert capsys.readouterr().out == ""
        assert not cb.coverage_report().degraded

    def test_reports_only_this_invocations_deltas(self, clock, capsys):
        b = cb.get_breaker("otx:passive_dns", label="OTX", parent="otx")
        first = cb.scope("otx", label="OTX", unit="IP(s)")
        _fail(b, 5)
        for _ in range(3):
            b.allow()
        payload = {}
        entries = first.finish("otx_enrich", payload=payload)
        assert entries == [{"source": "otx:passive_dns", "outcome": "transient",
                            "reason": "5 consecutive failures (ReadTimeout)",
                            "skipped": 3, "recovered": False}]
        assert payload["degraded"] == entries and "unreachable_hosts" not in payload
        assert "[!][DEGRADED][OTX] passive_dns skipped for 3 IP(s) (ReadTimeout)" in capsys.readouterr().out
        second = cb.scope("otx", label="OTX", unit="IP(s)")
        b.allow()
        assert second.report()[0]["skipped"] == 1

    def test_a_breaker_that_opened_on_the_last_item_is_reported(self, clock):
        sc = cb.scope("svc", label="Svc")
        _fail(cb.get_breaker("svc:x", label="Svc"), 5)
        assert sc.report()[0]["skipped"] == 0

    def test_a_breaker_that_recovered_without_skipping_is_not(self, clock):
        sc = cb.scope("svc", label="Svc")
        b = cb.get_breaker("svc:x", label="Svc")
        _fail(b, 5)
        b.record(Outcome.OK)
        assert sc.report() == []

    def test_findings_module_degrades_its_sources(self, clock):
        sc = cb.scope(("shodan", "otx"), label="Origin", unit="domain(s)")
        _fail(cb.get_breaker("shodan:host", label="Shodan", parent="shodan"), 5)
        cb.get_breaker("shodan:host", label="Shodan").allow()
        sc.finish("origin_discovery", sources=["origin_discovery"])
        report = cb.coverage_report()
        assert report.degraded_sources == frozenset({"origin_discovery"})
        assert report.gaps[0]["source"] == "origin_discovery"

    def test_host_skips_are_host_level(self, clock, capsys):
        sc = cb.scope((), label="Checks")
        for _ in range(3):
            sc.host_failed("https://a.example.com/", requests.exceptions.ConnectTimeout())
        assert sc.allow_host("https://a.example.com/admin") is False
        payload = {}
        sc.finish("security_checks", host_source="security_check", payload=payload)
        assert payload == {"unreachable_hosts": ["a.example.com:443"]}
        report = cb.coverage_report()
        assert report.degraded_sources == frozenset()
        assert report.skipped_hosts == ("a.example.com:443",)
        assert report.skipped_hostnames() == ("a.example.com",)
        assert report.gaps == ({"source": "security_check", "module": "security_checks",
                                "reason": "unreachable host(s) skipped", "skipped": 0, "hosts": 1},)
        assert "[!][DEGRADED][Checks] 1 unreachable host(s) skipped: a.example.com:443" in capsys.readouterr().out

    def test_host_skips_without_a_host_field_are_source_level(self, clock):
        sc = cb.scope((), label="AI Surface")
        for _ in range(3):
            sc.host_failed("https://a.example.com/", requests.exceptions.ConnectTimeout())
        sc.finish("ai_surface_recon", host_source="ai_surface_recon", host_field=False)
        assert cb.coverage_report().degraded_sources == frozenset({"ai_surface_recon"})

    def test_docker_tools_only_skip_hosts_already_down(self, clock):
        sc = cb.scope((), label="ffuf")
        assert sc.skip_if_down("https://a.example.com/") is False
        for _ in range(3):
            cb.host_health.record_failure("https://a.example.com/", requests.exceptions.ConnectTimeout())
        assert sc.skip_if_down("https://a.example.com/") is True
        assert sc.hosts() == ["a.example.com:443"]

    def test_the_log_lists_at_most_ten_hosts(self, clock, capsys):
        sc = cb.scope((), label="Checks")
        for i in range(15):
            sc.note_host_skipped(f"h{i}.example.com:443")
        sc.finish("security_checks", host_source="security_check")
        out = capsys.readouterr().out
        assert "(+5 more)" in out and out.count("example.com") == 10


class TestAccumulator:
    def test_group_scope_sees_only_its_own_notes(self):
        cb.note_degraded("vuln_scan", sources=["nuclei"], nuclei_truncated=True)
        grp = cb.group_scope()
        cb.note_degraded("security_checks", hosts=["b.example.com:443"], host_source="security_check")
        mine = grp.report()
        assert mine.degraded_sources == frozenset() and not mine.nuclei_truncated
        assert mine.skipped_hosts == ("b.example.com:443",)
        whole = cb.coverage_report()
        assert whole.nuclei_truncated and whole.degraded_sources == frozenset({"nuclei"})

    def test_clean_run_gaps_json_is_an_empty_array(self):
        report = cb.coverage_report()
        assert report.gaps_json() == "[]" and not report.degraded

    def test_a_faulted_accumulator_fails_closed(self, monkeypatch):
        monkeypatch.setattr(cb, "_token", mock.Mock(side_effect=RuntimeError("bug")))
        cb.note_degraded("x", sources=["nuclei"])
        with pytest.raises(cb.CoverageUnknown):
            cb.coverage_report()
        with pytest.raises(cb.CoverageUnknown):
            cb.group_scope().report()

    def test_stored_hosts_are_capped(self):
        cb.note_degraded("m", hosts=[f"h{i:04d}.example.com:443" for i in range(700)])
        report = cb.coverage_report()
        assert len(report.skipped_hosts) == 700
        assert len(report.stored_skipped_hosts()) == cb.STORED_HOSTS_MAX

    def test_unsafe_hosts_never_reach_the_prune_list(self):
        cb.note_degraded("m", hosts=["a.example.com:443", "evil.com'); DROP", "[::1]:8443"])
        assert cb.coverage_report().skipped_hostnames() == ("::1", "a.example.com")

    def test_gaps_merge_by_source_and_module(self):
        for _ in range(2):
            cb.note_degraded("otx_enrich", entries=[{"source": "otx:general", "reason": "r", "skipped": 5}])
        (gap,) = cb.coverage_report().gaps
        assert gap["skipped"] == 10 and gap["source"] == "otx:general"
