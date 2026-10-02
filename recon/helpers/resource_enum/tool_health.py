"""Tell a collection tool's empty result from a failure.

When a crawler or collector returns nothing, the run used to record a genuine
zero: no coverage gap on the Domain node, and for the crawlers that feed jsluice,
no protection for last run's secrets. `classify_empty` reads only what code can
read, in this order:

- no input (no seeds)                         -> not a tool zero
- a timeout, a kill, an exception, or a
  non-zero exit (docker's own 125-127 too)    -> failure
- exit 0, and stderr that still names a
  failure once the tool's routine lines are
  set aside (an error, a timeout, a refusal,
  a rate limit)                               -> failure
- exit 0 and any other stderr text            -> undecided
- exit 0 and nothing on stderr                -> genuine

A failure and an undecided result are both recorded: one coverage-gap entry per
tool per run (`note_gaps`), and for Katana and Hakrawler a jsluice cut through
their `failed` flag, so the prune keeps the secrets their crawl did not re-check.
An undecided result is not proven genuine, so it is treated like a failure; it is
also the only case the Jev layer (`ai_planner.tool_health`) is asked about.

Some failures leave no trace at all: GAU exits 0 with an empty stderr when it
cannot reach any archive. Nothing here, or in a model, can tell that from a
domain with no history.

Helpers report from worker threads into a locked queue; the run drains it on
the main thread, so no Jev call ever runs in a worker.
"""

import re
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional

NO_INPUT = "no_input"
GENUINE = "genuine"
FAILURE = "failure"
UNDECIDED = "undecided"

#: Exit codes docker run uses for its own failures: the tool never ran.
DOCKER_EXIT_CODES = frozenset({125, 126, 127})

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
#: Lines a tool prints on a healthy run: projectdiscovery and ParamSpider info
#: lines, logrus and zerolog info/debug (text and JSON), GAU's warning that it
#: runs without a config file, and the notice Hakrawler prints whenever a crawl
#: finds nothing (seen running the real binary on a page with no links).
_ROUTINE_RE = re.compile(
    r"^\s*(\[(INF|INFO|DBG|DEBUG)\]|(\d{1,2}:\d{2}(:\d{2})?\s*(AM|PM)?\s+)?(INF|DBG)\b|"
    r".*\blevel=(info|debug)\b|.*\"level\"\s*:\s*\"(info|debug)\"|"
    r".*error reading config: .*not found, using default config|"
    r"No URLs were found\. This usually happens when)", re.I)
_FAILURE_RE = re.compile(
    r"(error|fail(ed|ure|s)?\b|timed? ?out|timeout|refused|unreachable|no such host|"
    r"denied|panic|fatal|killed|too many requests|rate.?limit|\b429\b|\b50[234]\b|"
    r"cannot|could not|unable to)", re.I)

#: How much stderr a record keeps for the Jev layer (the agent clips at 4000).
STDERR_KEEP = 8_000


def unplaced_stderr(stderr: Optional[str]) -> str:
    """stderr without colour codes, blank lines and the tool's routine lines."""
    lines = []
    for line in _ANSI_RE.sub("", stderr or "").splitlines():
        if line.strip() and not _ROUTINE_RE.match(line):
            lines.append(line.rstrip())
    return "\n".join(lines)


def classify_empty(*, seeds: int, return_code: Optional[int], stderr: Optional[str] = "",
                   timed_out: bool = False, raised: bool = False) -> str:
    """The verdict on a run that produced nothing. `return_code` None means it never
    reported one (it raised, or was killed before exiting)."""
    if seeds <= 0:
        return NO_INPUT
    if timed_out or raised or return_code is None or return_code != 0:
        return FAILURE
    rest = unplaced_stderr(stderr)
    if not rest:
        return GENUINE
    return FAILURE if _FAILURE_RE.search(rest) else UNDECIDED


@dataclass
class EmptyResult:
    tool: str
    verdict: str
    return_code: Optional[int]
    seeds: int
    elapsed_s: float
    stderr: str = field(default="", repr=False)


_lock = threading.Lock()
_pending: List[EmptyResult] = []


def report_empty(tool: str, verdict: str, *, return_code: Optional[int], seeds: int,
                 elapsed_s: float, stderr: Optional[str] = "") -> None:
    """Queue a classified empty result. Never raises; genuine and no-input zeros are dropped."""
    try:
        if verdict not in (FAILURE, UNDECIDED):
            return
        with _lock:
            _pending.append(EmptyResult(tool, verdict, return_code, int(seeds),
                                        round(float(elapsed_s), 1),
                                        unplaced_stderr(stderr)[:STDERR_KEEP]))
    except Exception:  # noqa: BLE001 - bookkeeping must never break a crawl
        pass


def check_empty(tool: str, *, seeds: int, return_code: Optional[int], elapsed_s: float,
                stderr: Optional[str] = "", timed_out: bool = False, raised: bool = False) -> str:
    """classify_empty, then report_empty. Returns the verdict."""
    verdict = classify_empty(seeds=seeds, return_code=return_code, stderr=stderr,
                             timed_out=timed_out, raised=raised)
    report_empty(tool, verdict, return_code=return_code, seeds=seeds,
                 elapsed_s=elapsed_s, stderr=stderr)
    return verdict


def drain() -> List[EmptyResult]:
    """Everything reported since the last drain."""
    with _lock:
        out = list(_pending)
        _pending.clear()
    return out


def note_gaps(results: List[EmptyResult]) -> Dict[str, int]:
    """One coverage-gap entry per tool for its unconfirmed empty results. Never raises.

    Entries only: the prune is unaffected for these tools' own output (Endpoints
    and Parameters are assets, which it never touches). The jsluice protection for
    the crawlers goes through their `failed` flag instead, before jsluice runs.
    """
    counts: Dict[str, int] = {}
    for r in results:
        counts[r.tool] = counts.get(r.tool, 0) + 1
    if not counts:
        return counts
    try:
        from recon.helpers import circuit_breaker as cb
        cb.note_degraded("resource_enum", entries=[
            {"source": tool, "reason": f"{n} empty result(s) not confirmed genuine "
                                       f"(exit code or error output)", "skipped": n}
            for tool, n in sorted(counts.items())])
        for tool, n in sorted(counts.items()):
            print(f"[!][ToolHealth] {tool}: {n} empty result(s) look like a failure, "
                  f"recorded as a coverage gap")
    except Exception:  # noqa: BLE001
        pass
    return counts
