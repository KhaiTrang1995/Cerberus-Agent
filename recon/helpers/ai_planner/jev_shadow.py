"""Shared plumbing for the Jev hooks that have no LLM twin: the agent call and shadow mode.

A hook in SHADOW asks Jev, ACTS on the deterministic path, and records how Jev's
answer compares with it, so a person can decide from real runs whether to let it
act. Each hook module holds its own `ROLLOUT` constant; flipping one to ACT is a
separate change, made after reviewing the agreement data.

Where the shadow lines go. Recon stdout streams into the recon drawer and the run
log, so a per-item hook would flood both: per-decision lines are capped per hook
per run (STDOUT_CAP), one line says how many more were not printed, and one
summary line always closes the hook. The full records go into the recon JSON
under `jev_shadow.<hook>`, which is deleted and exported with the project's recon
output; a sidecar file would outlive the project, because nothing deletes it. A
partial run writes no recon JSON, so it keeps the capped lines and the summary.

Every line is phase-safe. The orchestrator matches PHASE_PATTERNS against each
recon stdout line and moves the drawer to the phase it names, so nothing here
prints a URL, a hostname, a path or stderr: a target called
`portal.example.test/scan` would move the drawer to Port Scanning. Items are named
by a stable index; the records keep the item itself.
"""

import os
import re
from typing import Any, Dict, List, Optional

import requests

from recon.helpers.ai_planner import agent_jev_gate, internal_key_headers

SHADOW = "shadow"
ACT = "act"

#: Per-decision stdout lines per hook per run.
STDOUT_CAP = 50

_MODEL_RE = re.compile(r"^jev-\d+\.\d+\.\d+$")


def jev_post(route: str, payload: dict, tag: str, timeout: float) -> Optional[Any]:
    """POST one agent `/jev/<route>` call through the agent_jev breaker.

    Returns the decoded JSON body, or None on any failure (breaker open, network,
    non-200, non-JSON). Never raises. The caller validates the shape and owns the
    fallback. Only an error_type is printed, never a response body: a 422 from
    request validation can echo the target strings the payload carried.
    """
    gate = agent_jev_gate()
    if not gate.allowed:
        print(f"[!][{tag}] Agent Jev paused (breaker open) - using the fallback.")
        return None
    endpoint = f"{os.environ.get('AGENT_API_URL', 'http://localhost:8090').rstrip('/')}/jev/{route}"
    try:
        resp = requests.post(endpoint, json=payload, headers=internal_key_headers(), timeout=timeout)
    except requests.RequestException as e:
        gate.record(exc=e)
        print(f"[!][{tag}] Agent request failed ({type(e).__name__}) - using the fallback.")
        return None
    gate.record(resp=resp)
    if resp.status_code != 200:
        error_type = None
        try:
            body = resp.json()
            error_type = body.get("error_type") if isinstance(body, dict) else None
        except ValueError:
            pass
        detail = f" {error_type}" if isinstance(error_type, str) and re.fullmatch(r"[a-z_]{1,40}", error_type) else ""
        print(f"[!][{tag}] Agent returned HTTP {resp.status_code}{detail} - using the fallback.")
        return None
    try:
        return resp.json()
    except ValueError:
        print(f"[!][{tag}] Agent returned a non-JSON answer - using the fallback.")
        return None


def jev_model(data: Any) -> str:
    """The model an answer names, or "unknown". Only a pinned-version shape is kept."""
    model = data.get("model") if isinstance(data, dict) else None
    return model if isinstance(model, str) and _MODEL_RE.match(model) else "unknown"


class ShadowRecorder:
    """Collects one hook's shadow decisions for one run and prints them, capped."""

    def __init__(self, hook: str, cap: int = STDOUT_CAP, rollout: str = SHADOW):
        self.hook = hook
        self.cap = cap
        self.rollout = rollout
        self.model = "unknown"
        self.project = os.environ.get("PROJECT_ID", "")
        self.records: List[Dict[str, Any]] = []
        self.fallbacks = 0
        self._printed = 0

    def decision(self, item: str, jev: str, conf: int, baseline: str, **detail) -> None:
        """Record one decision. `item` is a stable index, never target text; `detail`
        goes to the records only, so it may carry the item itself."""
        agreed = jev == baseline
        self.records.append({"item": item, "jev": jev, "conf": int(conf), "baseline": baseline,
                             "agreed": agreed, **detail})
        if self._printed < self.cap:
            self._printed += 1
            print(f"jev-shadow {self.hook}: project={self.project} item={item} jev={jev} "
                  f"conf={int(conf)} baseline={baseline} agreed={'true' if agreed else 'false'} "
                  f"model={self.model}")

    def fallback(self) -> None:
        """A call that fell back: no Jev verdict for these items, the run unchanged."""
        self.fallbacks += 1

    def summary(self) -> Dict[str, Any]:
        n = len(self.records)
        agreed = sum(1 for r in self.records if r["agreed"])
        stats = {
            "decisions": n,
            "agreed_pct": round(100 * agreed / n) if n else 0,
            "mean_conf": round(sum(r["conf"] for r in self.records) / n) if n else 0,
            "fallbacks": self.fallbacks,
        }
        if n > self._printed:
            print(f"jev-shadow {self.hook}: {n - self._printed} more decisions not printed")
        print(f"jev-shadow {self.hook}: summary decisions={stats['decisions']} "
              f"agreed={stats['agreed_pct']}% mean_conf={stats['mean_conf']} "
              f"fallbacks={stats['fallbacks']} model={self.model}")
        return {"hook": self.hook, "rollout": self.rollout, "model": self.model,
                "summary": stats, "records": self.records}

    def finish(self, recon_data: Optional[dict]) -> None:
        """Print the summary and keep the records in the recon JSON when there is one."""
        result = self.summary()
        if isinstance(recon_data, dict):
            recon_data.setdefault("jev_shadow", {})[self.hook] = result
