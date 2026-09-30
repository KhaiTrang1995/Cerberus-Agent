"""Check the model's answer and assemble the groups (plan §4, §7.6).

This is the defence, not the prompt. The model's input is scanner output and
target response bodies, so an injected instruction is the expected case. What
code enforces here, whatever the model says:

- only cluster ids that were sent count, and each is judged once;
- a quote counts only when it is really in that cluster's own evidence as
  sent, never in a label the code added around it nor in the HTTP headers
  every response from a server shares;
- the model proposes only the two AI concepts, from clusters it did not reject;
- a finding is pre-checked only when the model says `match` AND code already
  put it in an exact lens or its quote was verified (D15), and never when the
  seed's reason is `unclear`;
- a verdict on a cluster's representative speaks for another member only when
  that member shares what the model judged (`_covers`);
- every piece of model text is stripped of control, bidi and zero-width
  characters and capped. It is only ever displayed.
"""
from __future__ import annotations

import json
import re
import unicodedata

from cypherfix_triage.evidence import normalise_for_quote_check

from .clusters import (
    CLUSTERS_SENT_MAX,
    EMPTY_FINGERPRINT,
    is_same_row,
    quotable_text,
    resolved_host,
    row_key,
)
from .pool import normalised_severity
from .prompt import quotable_excerpt

GROUPS_AI_MAX = 4
TITLE_MAX = 60
WHY_MAX = 150
QUOTE_MIN = 8
#: A quote is read up to this length before it is checked, as the triage review does.
QUOTE_MAX = 1000
QUOTE_DISPLAY_MAX = 300
NAME_MAX = 200
HOST_MAX = 255
#: Bounds the work on a runaway answer.
MODEL_OUTPUT_MAX = 200_000

CONCEPT_LABELS = {
    "same_problem": "Same issue elsewhere",
    "same_detector": "Same detector",
    "same_host": "Same host",
    "same_fp_pattern": "Same false-positive pattern",
    "same_low_risk": "Same low-risk weakness",
}
EXACT_CONCEPTS = ("same_problem", "same_detector", "same_host")
AI_CONCEPTS = ("same_fp_pattern", "same_low_risk")
REASONS = ("false_positive", "not_worth_fixing", "not_our_asset", "unclear")
VERDICTS = ("match", "maybe", "no")

REASON_ORDER = {
    "false_positive": ("same_fp_pattern", "same_detector", "same_problem", "same_host"),
    "not_worth_fixing": ("same_low_risk", "same_detector", "same_problem", "same_host"),
    "not_our_asset": ("same_host", "same_problem", "same_detector"),
    "unclear": ("same_problem", "same_detector", "same_host"),
}

_EXPECTED_KEYS = frozenset({"seed", "verdicts", "groups"})
_VERDICT_ORDER = {"match": 0, "maybe": 1, None: 2, "no": 3}

#: Named for the reader; `clean_text` strips every format (Cf) character, which
#: covers all of these and the Unicode tag block used to smuggle hidden text.
BIDI_CHARS = frozenset("‪‫‬‭‮⁦⁧⁨⁩‎‏؜")
ZERO_WIDTH_CHARS = frozenset("​‌‍⁠﻿")

_SPACE_LIKE = re.compile(r"[\t\n\r\x0b\x0c\x85  ]")
_SPACES = re.compile(r"\s+")
_FENCE = re.compile(r"```[ \t]*(?:json)?[ \t]*\r?\n?(.*?)```", re.S | re.I)


def clean_text(s, cap: int) -> str:
    """Display-safe text: no control, bidi or zero-width characters, capped."""
    text = "" if s is None or isinstance(s, (dict, list)) else str(s)
    text = _SPACE_LIKE.sub(" ", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Co"))
    return _SPACES.sub(" ", text).strip()[:max(0, int(cap))].rstrip()


def _loads(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return None


def parse_model_output(text) -> dict | None:
    """The answer object: a fenced ```json block, else the first {...} in the text.

    Prefers an object carrying one of `seed` / `verdicts` / `groups`, so a
    stray object in prose before the real one does not win.
    """
    if not isinstance(text, str) or not text.strip():
        return None
    text = text[:MODEL_OUTPUT_MAX]
    found = []
    for match in _FENCE.finditer(text):
        obj = _loads(match.group(1).strip())
        if isinstance(obj, dict):
            found.append(obj)
    decoder = json.JSONDecoder()
    start, attempts = text.find("{"), 0
    while start != -1 and attempts < 50:
        try:
            obj, _ = decoder.raw_decode(text, start)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            found.append(obj)
        start, attempts = text.find("{", start + 1), attempts + 1
    for obj in found:
        if _EXPECTED_KEYS & obj.keys():
            return obj
    return found[0] if found else None


def _verify(quote, evidence: str) -> str:
    """The quote when it is really in `evidence`, else ''."""
    if not isinstance(quote, str):
        return ""
    text = quote.strip()[:QUOTE_MAX]
    needle = normalise_for_quote_check(text)
    if len(needle) < QUOTE_MIN or needle not in normalise_for_quote_check(evidence):
        return ""
    return text


def _cluster_id(value) -> str:
    return str(value).strip().lower() if isinstance(value, (str, int)) and not isinstance(value, bool) else ""


def _read(raw, seed: dict) -> dict:
    raw = raw if isinstance(raw, dict) else {}
    reason = str(raw.get("reason") or "").strip().lower()
    if reason not in REASONS:
        reason = "unclear"
    quote = _verify(raw.get("quote"), quotable_text(seed))
    return {"reason": reason, "why": clean_text(raw.get("why"), WHY_MAX),
            "quote": clean_text(quote, QUOTE_DISPLAY_MAX), "quote_verified": bool(quote)}


def _judge(raw, clusters: list) -> dict:
    """cluster id -> {verdict, why, quote, quote_verified}, for sent clusters only."""
    sent = {c.id: c for c in clusters or []}
    judged: dict = {}
    for item in (raw if isinstance(raw, list) else [])[:4 * CLUSTERS_SENT_MAX]:
        if not isinstance(item, dict):
            continue
        cid = _cluster_id(item.get("cluster"))
        if cid not in sent or cid in judged:
            continue
        verdict = str(item.get("verdict") or "").strip().lower()
        if verdict not in VERDICTS:
            verdict = "maybe"
        quote = _verify(item.get("quote"), quotable_excerpt(sent[cid].representative))
        judged[cid] = {"verdict": verdict,
                       "why": clean_text(item.get("why"), WHY_MAX) or None,
                       "quote": clean_text(quote, QUOTE_DISPLAY_MAX) or None,
                       "quote_verified": bool(quote)}
    return judged


def _ai_groups(raw, judged: dict) -> list:
    groups = []
    for item in (raw if isinstance(raw, list) else [])[:4 * GROUPS_AI_MAX]:
        if len(groups) == GROUPS_AI_MAX:
            break
        if not isinstance(item, dict):
            continue
        concept = str(item.get("concept") or "").strip().lower()
        ids = item.get("clusters")
        if concept not in AI_CONCEPTS or not isinstance(ids, list):
            continue
        picked = []
        for value in ids[:CLUSTERS_SENT_MAX]:
            cid = _cluster_id(value)
            if cid in judged and judged[cid]["verdict"] != "no" and cid not in picked:
                picked.append(cid)
        if picked:
            groups.append({"concept": concept, "clusters": picked,
                           "title": clean_text(item.get("title"), TITLE_MAX) or None,
                           "why": clean_text(item.get("why"), WHY_MAX) or None})
    return groups


def _position(reason: str, concept: str) -> int:
    order = REASON_ORDER[reason]
    if concept in order:
        return order.index(concept)
    # A concept the reason does not rank (an AI group under `not_our_asset`)
    # still shows, after the ranked ones.
    return len(order) + (EXACT_CONCEPTS + AI_CONCEPTS).index(concept)


def _concept_label(concept: str, seed: dict) -> str:
    if concept == "same_host":
        return f"{CONCEPT_LABELS['same_host']}: {clean_text(resolved_host(seed), HOST_MAX)}"
    return CONCEPT_LABELS[concept]


def _covers(cluster, row: dict, reason: str) -> bool:
    """Whether the model's verdict on `cluster`'s representative speaks for `row`.

    The model sees one representative, and the fingerprint strips hosts, URLs
    and paths, so a cluster can span exactly what decided the verdict:

    - a cluster with no evidence left to fingerprint is every finding of its
      detector and severity; the model judged one host and one path, so its
      verdict covers the representative alone;
    - `not_our_asset` is a verdict on the host; a member on another host was
      never judged.
    """
    rep = cluster.representative
    if is_same_row(row, rep):
        return True
    if cluster.fingerprint == EMPTY_FINGERPRINT:
        return False
    if reason == "not_our_asset":
        return resolved_host(row).strip().lower() == resolved_host(rep).strip().lower()
    return True


def _member(key: str, row: dict, judgement: dict | None, reason: str, in_exact: bool) -> dict:
    verdict = judgement["verdict"] if judgement else None
    quote_verified = bool(judgement and judgement["quote_verified"])
    return {
        "key": key,
        "node_id": str(row.get("node_id") or ""),
        "name": clean_text(row.get("name"), NAME_MAX),
        "host": clean_text(resolved_host(row), HOST_MAX),
        "severity": normalised_severity(row),
        "verdict": verdict,
        "why": judgement["why"] if judgement else None,
        "quote": judgement["quote"] if judgement else None,
        "quote_verified": quote_verified,
        # D15: code decides. The model can only narrow what code proposed or
        # what its own verified quote supports.
        "checked": (reason != "unclear" and verdict == "match" and (in_exact or quote_verified)),
        "ai_only": not in_exact,
    }


def _assemble(status: str, read: dict, seed: dict, clusters: list, lenses: dict,
              candidates: list, judged: dict, ai_groups: list) -> dict:
    lenses = lenses or {}
    rows = {row_key(r): r for r in candidates or [] if isinstance(r, dict) and not is_same_row(r, seed)}
    cluster_of = {key: c for c in clusters or [] for key in c.members}
    members_of = {c.id: list(c.members) for c in clusters or []}
    reason = read["reason"]

    def judgement(key: str) -> dict | None:
        cluster = cluster_of.get(key)
        if cluster is None or not _covers(cluster, rows[key], reason):
            return None
        return judged.get(cluster.id)

    exact = {str(key) for concept in EXACT_CONCEPTS for key in (lenses.get(concept) or ())}

    raw_groups = []
    for concept in EXACT_CONCEPTS:
        raw_groups.append({"concept": concept, "title": None, "why": None,
                           "keys": list(lenses.get(concept) or ())})
    for group in ai_groups:
        keys = [k for cid in group["clusters"] for k in members_of.get(cid, ())]
        raw_groups.append({**group, "keys": keys})

    merged: dict = {}
    for group in raw_groups:
        keys = list(dict.fromkeys(str(k) for k in group["keys"] if str(k) in rows))
        if not keys:
            continue
        card = merged.setdefault(frozenset(keys), {"concepts": [], "title": None, "why": None,
                                                   "keys": keys})
        if group["concept"] not in card["concepts"]:
            card["concepts"].append(group["concept"])
        card["title"] = card["title"] or group["title"]
        card["why"] = card["why"] or group["why"]

    cards = sorted(merged.values(),
                   key=lambda c: min(_position(reason, concept) for concept in c["concepts"]))
    groups = []
    for card in cards:
        card["concepts"].sort(key=lambda concept: _position(reason, concept))
        members = [_member(k, rows[k], judgement(k), reason, k in exact)
                   for k in card["keys"]]
        members.sort(key=lambda m: (_VERDICT_ORDER[m["verdict"]], m["key"]))
        groups.append({
            "id": f"g{len(groups) + 1}",
            "concepts": card["concepts"],
            "labels": [_concept_label(c, seed) for c in card["concepts"]],
            "ai": not any(c in EXACT_CONCEPTS for c in card["concepts"]),
            "title": card["title"],
            "why": card["why"],
            "members": [m for m in members if m["verdict"] != "no"],
            "probably_not": [m for m in members if m["verdict"] == "no"],
        })
    return {"status": status, "read": read, "groups": groups}


def exact_only(seed: dict, lenses: dict, candidates: list, status: str = "model_unreadable") -> dict:
    """The exact groups alone, nothing judged and nothing checked."""
    read = {"reason": "unclear", "why": "", "quote": "", "quote_verified": False}
    return _assemble(status, read, seed, [], lenses, candidates, {}, [])


def assemble(raw_text: str | None, seed: dict, clusters: list, lenses: dict,
             candidates: list) -> dict:
    """The modal's payload from the model's raw answer (§4 shape).

    An answer that is not an object carrying `seed`, `verdicts` or `groups`
    gives `model_unreadable`: the exact groups only, all unchecked. `title` and
    `why` on a group, and `why` / `quote` on a member, are model text whenever
    they are set. `ai` says the card's membership came from the model alone.
    """
    parsed = parse_model_output(raw_text) if raw_text else None
    if not isinstance(parsed, dict) or not (_EXPECTED_KEYS & parsed.keys()):
        return exact_only(seed, lenses, candidates)
    read = _read(parsed.get("seed"), seed)
    judged = _judge(parsed.get("verdicts"), clusters)
    ai_groups = _ai_groups(parsed.get("groups"), judged)
    return _assemble("ok", read, seed, clusters, lenses, candidates, judged, ai_groups)
