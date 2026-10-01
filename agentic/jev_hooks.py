"""Jev questions for the four recon AI hooks, and the mapping back to the
existing `/llm/*` response shapes.

Containment here is code-enforced floors and closed answer sets, not prompt
wording: a Jev answer can only rank, tune or annotate, never drop coverage
below the static fallback. Target-derived bytes go into the `state` as data
(wrapped), never concatenated into an instruction.

Question wording is versioned with the pinned model: a prompt change is a
deliberate edit alongside JEV_MODEL.
"""
from __future__ import annotations

import json
from typing import Any

from prompt_safety import wrap_untrusted
import jev_client
from jev_client import JEV_MODEL, JevError

#: At most this many questions per request. The live API answers 1000 in under
#: a second (checked 2026-10-01), but a smaller cap keeps one scan well under
#: the per-account rate and bounds the request size; larger sets split.
JEV_MAX_QUESTIONS_PER_CALL = 200

#: Caps on target-derived text placed in the state. TypeSafe takes about 64k tokens
#: per request, and the endpoint accepts the same unbounded bodies as /llm/*, so one
#: oversized header or body would fail the call. Clipping keeps the verdict
#: available, and the tail of a header dump or body sample is the least useful part.
_HEADERS_CHARS = 16_000
_SAMPLE_CHARS = 8_000
_FINGERPRINT_CHARS = 8_000
_SHORT_CHARS = 2_000
#: More candidate tags than any real template set has; only bounds a pathological caller.
_MAX_CANDIDATES = 500

#: Noul answers at or above this read as "yes". The recon thresholds (70/100)
#: are calibrated against this, so it moves with the pinned model.
_YES = 0.5


def _clip(value, limit: int) -> str:
    return str(value if value is not None else "")[:limit]


def _noul(instructions: str, *, true: str = "", false: str = "") -> dict:
    q: dict[str, Any] = {"type": "noul", "instructions": instructions}
    if true or false:
        q["criteria"] = {"true": true, "false": false}
    return q


async def _ask(key: str, state, questions: dict) -> dict:
    """One or more sequential requests, same state, all-or-nothing.

    Splitting is sequential (never concurrent) so one scan cannot burst the
    per-account rate. If any request fails the whole hook fails: a partial
    answer set would silently narrow coverage.
    """
    names = list(questions)
    answers: dict[str, Any] = {}
    for i in range(0, len(names), JEV_MAX_QUESTIONS_PER_CALL):
        chunk = {n: questions[n] for n in names[i:i + JEV_MAX_QUESTIONS_PER_CALL]}
        result = await jev_client.system_one(key, JEV_MODEL, state, chunk)
        answers.update(result["answers"])
    return answers


# ---------------------------------------------------------------------------
# FFuf extensions
# ---------------------------------------------------------------------------

#: The fixed catalog Jev ranks over. Jev never invents an extension: it only
#: scores these, so the FFuf validator's regex can never reject its output.
FFUF_JEV_CATALOG: tuple[str, ...] = (
    ".php", ".asp", ".aspx", ".jsp", ".do", ".action", ".html", ".htm", ".js",
    ".json", ".xml", ".txt", ".bak", ".old", ".orig", ".save", ".swp", ".tmp",
    ".zip", ".tar", ".gz", ".7z", ".rar", ".sql", ".db", ".sqlite", ".log",
    ".conf", ".config", ".ini", ".env", ".yml", ".yaml", ".properties", ".inc",
    ".cgi", ".pl", ".py", ".rb", ".map",
)

#: Always kept, whatever Jev says: these lead the FFuf static SAFE_FALLBACK, so
#: the Jev engine never discovers fewer backup files than no AI at all.
_FFUF_FLOOR = (".bak", ".old")


async def ffuf_extensions(key: str, url: str, headers: dict, max_extensions: int) -> dict:
    """`{"extensions": [...]}` — the same shape as `/llm/ffuf-extensions`."""
    questions = {
        f"ext_{i}": _noul(
            f"Is the file extension `{ext}` likely to find real files on this server, "
            f"given its response headers and URL?")
        for i, ext in enumerate(FFUF_JEV_CATALOG)
    }
    state = {
        "url": _clip(url, _SHORT_CHARS),
        "headers": wrap_untrusted(_clip(json.dumps(headers), _HEADERS_CHARS), label="TARGET_HEADERS"),
    }
    answers = await _ask(key, state, questions)

    scored = sorted(
        ((answers[f"ext_{i}"]["noul"], ext) for i, ext in enumerate(FFUF_JEV_CATALOG)
         if answers[f"ext_{i}"]["noul"] >= _YES),
        reverse=True,
    )
    chosen: list[str] = []
    for ext in _FFUF_FLOOR:
        if ext not in chosen:
            chosen.append(ext)
    for _, ext in scored:
        if ext not in chosen:
            chosen.append(ext)
    return {"extensions": chosen[:max_extensions]}


# ---------------------------------------------------------------------------
# Nuclei tags
# ---------------------------------------------------------------------------

#: Kept whenever present in the candidates, whatever Jev says. The same
#: universal high-impact set the LLM prompt asks for (api.py:707-708), now
#: enforced in code so an injected fingerprint cannot strip them.
_NUCLEI_UNIVERSAL = ("cve", "exposure", "misconfig", "default-login", "kev", "oast", "takeover")


async def nuclei_tags(key: str, technologies: list, servers: list,
                      candidates: list, max_tags: int) -> dict:
    """`{"tags": [...]}` — the same shape as `/llm/nuclei-tags`.

    Every candidate is a plain tag string the tool chose, so the question text
    is tool-controlled; the fingerprint is the only target-derived input and
    goes into the state.
    """
    all_candidates = [c for c in candidates if isinstance(c, str)]
    # The floor is computed over the FULL list; only the questions are bounded.
    universal = {t for t in _NUCLEI_UNIVERSAL if t in all_candidates}
    valid_candidates = all_candidates[:_MAX_CANDIDATES]
    questions = {
        f"tag_{i}": _noul(
            f"Should the Nuclei template tag `{tag}` be included for a scan of a host "
            f"with the detected technology stack?")
        for i, tag in enumerate(valid_candidates)
    }
    state = {
        "technologies": wrap_untrusted(_clip(json.dumps(technologies), _FINGERPRINT_CHARS), label="TARGET_FINGERPRINT"),
        "servers": wrap_untrusted(_clip(json.dumps(servers), _FINGERPRINT_CHARS), label="TARGET_FINGERPRINT"),
    }
    answers = await _ask(key, state, questions) if questions else {}

    scored = sorted(
        ((answers[f"tag_{i}"]["noul"], tag) for i, tag in enumerate(valid_candidates)
         if answers[f"tag_{i}"]["noul"] >= _YES),
        reverse=True,
    )
    chosen = sorted(universal)
    for _, tag in scored:
        if tag not in chosen:
            chosen.append(tag)
    return {"tags": chosen[:max_tags]}


# ---------------------------------------------------------------------------
# WAF classify
# ---------------------------------------------------------------------------

#: The 14 vendors the LLM prompt offers (api.py WAF prompt). Jev picks one when
#: it decides a WAF is present; the recon WAF_TYPE_REGEX accepts all of them.
_WAF_VENDORS = (
    "cloudflare", "akamai", "aws_waf", "imperva", "sucuri", "fastly",
    "azure_frontdoor", "cloudfront", "modsecurity", "f5", "fortinet",
    "barracuda", "stackpath", "custom",
)


async def waf_classify(key: str, url: str, status_code: int, headers: dict,
                       body_sample: str, response_time_ms: int) -> dict:
    """The `/llm/waf-classify` shape: waf_detected, waf_type, confidence, reasoning, source."""
    questions = {
        "edge": _noul("A WAF or CDN edge produced this HTTP response."),
        "vendor": {
            "type": "choice",
            "instructions": "If a WAF or CDN edge produced this response, which vendor is it?",
            "criteria": {v: None for v in _WAF_VENDORS},
        },
    }
    state = {
        "url": _clip(url, _SHORT_CHARS),
        "status_code": status_code,
        "response_time_ms": response_time_ms,
        "headers": wrap_untrusted(_clip(json.dumps(headers), _HEADERS_CHARS), label="TARGET_HEADERS"),
        "body_sample": wrap_untrusted(_clip(body_sample, _SAMPLE_CHARS), label="TARGET_BODY"),
    }
    answers = await _ask(key, state, questions)

    noul = answers["edge"]["noul"]
    detected = noul >= _YES
    return {
        "waf_detected": detected,
        "waf_type": answers["vendor"]["choice"] if detected else None,
        "confidence": round(noul * 100),
        "reasoning": "",
        "source": "jev_classifier",
    }


# ---------------------------------------------------------------------------
# Takeover classify
# ---------------------------------------------------------------------------

async def takeover_classify(key: str, hostname: str, expected_provider: str,
                            status_code: int, headers: dict, response_sample: str) -> dict:
    """The `/llm/takeover-classify` shape: is_waf_block, confidence, reason, source."""
    questions = {
        "waf_block": _noul(
            "This response is a WAF or edge block page, not the unclaimed-site page of the "
            "claimed third-party provider.",
            true="A WAF/edge block page (likely a fingerprint collision)",
            false="A genuine provider unclaimed-site page"),
    }
    state = {
        "hostname": _clip(hostname, _SHORT_CHARS),
        "claimed_provider": _clip(expected_provider, _SHORT_CHARS),
        "status_code": status_code,
        "headers": wrap_untrusted(_clip(json.dumps(headers), _HEADERS_CHARS), label="TARGET_HEADERS"),
        "response_sample": wrap_untrusted(_clip(response_sample, _SAMPLE_CHARS), label="TARGET_BODY"),
    }
    answers = await _ask(key, state, questions)

    noul = answers["waf_block"]["noul"]
    is_block = noul >= _YES
    # Confidence in the verdict actually taken, so a 0.5 reads as low either way.
    confidence = round(max(noul, 1 - noul) * 100)
    return {
        "is_waf_block": is_block,
        "confidence": confidence,
        "reason": "",
        "source": "jev_classifier",
    }


__all__ = [
    "JevError", "JEV_MAX_QUESTIONS_PER_CALL", "FFUF_JEV_CATALOG",
    "ffuf_extensions", "nuclei_tags", "waf_classify", "takeover_classify",
]
