"""
FFuf smart-fuzz base paths, ranked by TypeSafe Jev
==================================================
Smart fuzz runs a full wordlist under each discovered base directory, so when
there are more candidates than FFUF_SMART_FUZZ_MAX_BASE_PATHS the cap decides
what gets fuzzed. Without AI the cap is filled by a random pick. This hook asks
Jev, per candidate, whether the directory is likely to hold sensitive,
administrative or application content, and orders the candidates by that answer.

Coverage-neutral: `select_base_paths` (the single seam) keeps exactly `cap`
paths either way and fills any slot Jev leaves from the random pick, so Jev
changes which directories survive the cap, never how many.

The candidates come from the target's own links, so the agent puts them in the
state and asks about them by index. The ranker is built per call site and passed
to the seam; it never raises and returns None on any failure, which leaves the
random pick in place.

Kind B (no LLM twin), gated by AI_IN_PIPELINE and FFUF_JEV_BASE_PATHS at each
call site. ROLLOUT is ACT: smart fuzz runs on Jev's pick (the random pick is the
fallback when Jev is unavailable), and the pick is still recorded next to the
deterministic one so agreement stays visible.
"""

import os
import random
from typing import Callable, List, Optional

from recon.helpers.ai_planner.jev_shadow import ACT, SHADOW, ShadowRecorder, jev_model, jev_post

ROLLOUT = ACT

HOOK = "ffuf_base_paths"
_TAG = "FFuf-BasePaths-Jev"

#: Must equal the agent's FFUF_BASE_PATHS_MAX and the request model's bound
#: (test_jev_item_contract.py holds that line). Above it, a random sample of this
#: many is asked about; the rest can still be drawn for any slot left over.
MAX_CANDIDATES = 400
MAX_PATH_CHARS = 200

#: One agent call; the agent splits it into two sequential TypeSafe requests.
TIMEOUT = 30


def _validate(data, asked: List[str], cap: int) -> Optional[dict]:
    """The agent's answer as {"ranked", "scores"}, or None when its shape is wrong.

    `ranked` must be distinct candidates that were asked about, at most `cap`;
    `scores` one finite number in [0, 1] per asked candidate.
    """
    if not isinstance(data, dict):
        return None
    ranked, scores = data.get("ranked"), data.get("scores")
    if not isinstance(ranked, list) or not isinstance(scores, list) or len(scores) != len(asked):
        return None
    asked_set = set(asked)
    if len(ranked) > cap or len(set(map(str, ranked))) != len(ranked):
        return None
    if not all(isinstance(p, str) and p in asked_set for p in ranked):
        return None
    if not all(isinstance(s, (int, float)) and not isinstance(s, bool) and 0.0 <= s <= 1.0
               for s in scores):
        return None
    return {"ranked": ranked, "scores": [float(s) for s in scores]}


def make_jev_ranker(
    user_id: str,
    project_id: str,
    *,
    recon_data: Optional[dict] = None,
    rng: Optional[random.Random] = None,
) -> Callable[[List[str], int], Optional[List[str]]]:
    """A ranker for `select_base_paths`. Never raises.

    The seam calls it only when the candidates exceed the cap. In SHADOW it
    records Jev's pick against the deterministic baseline (the sorted order's
    first `cap`; a fresh random draw would make the overlap meaningless) and
    returns None, so the seam keeps its random pick. The records go into
    `recon_data["jev_shadow"]` when a recon JSON exists.
    """
    def ranker(items: List[str], cap: int) -> Optional[List[str]]:
        recorder = ShadowRecorder(HOOK, rollout=ROLLOUT)
        try:
            askable = [p for p in items if 0 < len(p) <= MAX_PATH_CHARS]
            if len(askable) > MAX_CANDIDATES:
                askable = sorted((rng or random).sample(askable, MAX_CANDIDATES))
            if not askable:
                return None
            print(f"[*][{_TAG}] Ranking {len(askable)} of {len(items)} candidate directories "
                  f"for {cap} slots")
            data = jev_post("ffuf-base-paths",
                            {"candidates": askable, "cap": cap,
                             "user_id": user_id, "project_id": project_id},
                            _TAG, TIMEOUT)
            answer = _validate(data, askable, cap) if data is not None else None
            if answer is None:
                if data is not None:
                    print(f"[!][{_TAG}] Agent answer failed validation - using the fallback.")
                recorder.fallback()
                return None
            recorder.model = jev_model(data)
            baseline = set(items[:cap])
            jev_pick = set(answer["ranked"])
            for i, path in enumerate(askable):
                recorder.decision(
                    f"path_{i}",
                    "keep" if path in jev_pick else "cut",
                    round(answer["scores"][i] * 100),
                    "keep" if path in baseline else "cut",
                    path=path,
                )
            overlap = len(jev_pick & baseline)
            print(f"[+][{_TAG}] Jev keeps {len(jev_pick)}; {overlap} of them are in the "
                  f"deterministic first {cap}")
            if ROLLOUT == SHADOW:
                return None
            return list(answer["ranked"])
        except Exception as e:  # noqa: BLE001 - never break smart fuzz
            print(f"[!][{_TAG}] Ranking failed ({type(e).__name__}) - using the fallback.")
            recorder.fallback()
            return None
        finally:
            recorder.finish(recon_data)

    return ranker


def jev_base_paths_enabled(settings: dict) -> bool:
    """Kind B gating: nothing upstream folds this flag into AI_IN_PIPELINE."""
    return bool(settings.get('AI_IN_PIPELINE') and settings.get('FFUF_JEV_BASE_PATHS'))


def ranker_for(settings: dict, recon_data: Optional[dict] = None):
    """The ranker to pass to `select_base_paths`, or None when the hook is off."""
    if not jev_base_paths_enabled(settings):
        return None
    return make_jev_ranker(os.environ.get('USER_ID', ''), os.environ.get('PROJECT_ID', ''),
                           recon_data=recon_data)
