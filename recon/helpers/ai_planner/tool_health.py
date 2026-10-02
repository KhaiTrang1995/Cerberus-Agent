"""
Silent tool-failure detector: the Jev layer
===========================================
`recon.helpers.resource_enum.tool_health` classifies every empty collector result
from what code can read (exit code, timeout, stderr). A result whose stderr says
something that is neither a routine line nor a named failure is UNDECIDED: it is
already recorded as a coverage gap, like a failure. This layer asks Jev about
those results only, one question each: does the error output describe a
transient failure (a run again could succeed) or a permanent one?

The deterministic verdict always stands. Jev never turns a gap back into a
genuine zero, and on any Jev failure nothing changes, so the answer can only add.
What it would add is a single retry of a transient failure, which is not built:
ROLLOUT is SHADOW, and the verdict is recorded as "would retry" or not next to the
deterministic baseline (no retry). The retry ships with the switch to act.

stderr is not trusted: crawlers echo target URLs into it, and a custom header can
appear in a command echo. Header values the project configured, and anything
shaped like a credential, are redacted here before it leaves recon; the agent
then clips and wraps it like any target bytes.

Kind B, gated by AI_IN_PIPELINE and RESOURCE_ENUM_JEV_TOOL_HEALTH at each call
site. At most MAX_CALLS_PER_SCAN calls per run; the run's own drain on the main
thread calls it, never a worker.
"""

import os
import re
from typing import Iterable, List, Optional

from recon.helpers.ai_planner.jev_shadow import SHADOW, ShadowRecorder, jev_model, jev_post
from recon.helpers.resource_enum import tool_health as th

ROLLOUT = SHADOW

HOOK = "tool_health"
_TAG = "ToolHealth-Jev"

#: Undecided results asked about per run. Undecided is rare (a failure keyword
#: or a routine line settles most stderr), so this only bounds a pathological run.
MAX_CALLS_PER_SCAN = 20
TIMEOUT = 15

_CREDENTIAL_RE = re.compile(
    r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|apikey|"
    r"x-auth-token|x-redamon-ctx)(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s;,]+(\s+[^\s;,]+)?)")
_BEARER_RE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")


def _header_values(settings: dict, extra: Iterable = ()) -> List[str]:
    values = []
    lists = [v for k, v in (settings or {}).items() if k.endswith("_HEADERS") and isinstance(v, list)]
    for headers in lists + [list(extra)]:
        for h in headers:
            if isinstance(h, dict):
                values.append(str(h.get("value", "")))
            elif isinstance(h, str) and ":" in h:
                values.append(h.split(":", 1)[1].strip())
    return [v for v in values if len(v) >= 4]


def redact(stderr: str, settings: dict, extra_headers: Iterable = ()) -> str:
    """stderr with configured header values and credential-shaped tokens removed."""
    text = stderr or ""
    for value in sorted(set(_header_values(settings, extra_headers)), key=len, reverse=True):
        text = text.replace(value, "[REDACTED]")
    text = _CREDENTIAL_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
    return _BEARER_RE.sub(lambda m: f"{m.group(1)} [REDACTED]", text)


def _validate(data) -> Optional[tuple]:
    if not isinstance(data, dict):
        return None
    transient, conf = data.get("transient"), data.get("confidence")
    if not isinstance(transient, bool):
        return None
    if not isinstance(conf, int) or isinstance(conf, bool) or not 0 <= conf <= 100:
        return None
    return transient, conf


def jev_tool_health_enabled(settings: dict) -> bool:
    """Kind B gating: nothing upstream folds this flag into AI_IN_PIPELINE."""
    return bool(settings.get('AI_IN_PIPELINE') and settings.get('RESOURCE_ENUM_JEV_TOOL_HEALTH'))


def run_tool_health_pass(results: List[th.EmptyResult], settings: dict, *,
                         recon_data: Optional[dict] = None, extra_headers: Iterable = ()) -> List[th.EmptyResult]:
    """Ask Jev about the undecided results. Never raises.

    Returns the results Jev reads as transient (the retry candidates once this acts).
    In SHADOW the caller ignores them.
    """
    undecided = [r for r in results if r.verdict == th.UNDECIDED and (r.stderr or "").strip()]
    transient: List[th.EmptyResult] = []
    if not undecided:
        return transient
    recorder = ShadowRecorder(HOOK)
    try:
        user_id, project_id = os.environ.get('USER_ID', ''), os.environ.get('PROJECT_ID', '')
        asked = undecided[:MAX_CALLS_PER_SCAN]
        print(f"[*][{_TAG}] {len(undecided)} empty result(s) with unexplained error output; "
              f"asking about {len(asked)}")
        for i, r in enumerate(asked):
            data = jev_post("tool-health", {
                "tool": r.tool, "return_code": r.return_code if r.return_code is not None else 0,
                "elapsed_s": max(float(r.elapsed_s), 0.0), "seed_count": max(int(r.seeds), 0),
                "stderr": redact(r.stderr, settings, extra_headers),
                "user_id": user_id, "project_id": project_id,
            }, _TAG, TIMEOUT)
            verdict = _validate(data) if data is not None else None
            if verdict is None:
                if data is not None:
                    print(f"[!][{_TAG}] Agent answer failed validation - using the fallback.")
                recorder.fallback()
                continue
            recorder.model = jev_model(data)
            is_transient, conf = verdict
            if is_transient:
                transient.append(r)
            recorder.decision(f"{r.tool}_{i}", "retry" if is_transient else "no_retry", conf,
                              "no_retry", tool=r.tool, elapsed_s=r.elapsed_s, seeds=r.seeds)
        if len(undecided) > len(asked):
            print(f"[!][{_TAG}] {len(undecided) - len(asked)} more not asked "
                  f"(cap {MAX_CALLS_PER_SCAN} per run)")
    except Exception as e:  # noqa: BLE001
        print(f"[!][{_TAG}] Pass failed ({type(e).__name__}) - the gaps stand as recorded.")
        recorder.fallback()
    finally:
        recorder.finish(recon_data)
    return transient


def finish_tool_health(settings: dict, *, jev: bool, recon_data: Optional[dict] = None,
                       extra_headers: Iterable = ()) -> None:
    """The call-site entry: drain the queue, record the gaps (always: that part is a
    correctness fix, not a Jev feature), then the Jev pass when the call site's own
    AI_IN_PIPELINE and RESOURCE_ENUM_JEV_TOOL_HEALTH test says so. Never raises.
    """
    try:
        results = th.drain()
        th.note_gaps(results)
        if jev and jev_tool_health_enabled(settings):
            run_tool_health_pass(results, settings, recon_data=recon_data, extra_headers=extra_headers)
    except Exception as e:  # noqa: BLE001
        print(f"[!][{_TAG}] Skipped ({type(e).__name__}).")
