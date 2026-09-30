"""Evidence fingerprints, clusters, the exact lenses and ranking (plan §7.4).

A cluster is findings with the same detector, the same normalised severity and
the same normalised TARGET evidence. The model judges one representative per
cluster, so what makes two findings one cluster decides what a verdict covers:

- the fingerprint is over target-derived text only (the response body, the
  evidence, extracted values, a secret's redacted shape), never over labels the
  code adds or over the name, so a WAF page and a real hit cannot share a
  cluster just because their requests or titles match;
- it is over all the text the pool read (`queries.TEXT_CUTS`, longer than the
  excerpt the model is shown), so two responses that differ only past that
  excerpt are still two clusters;
- hosts, URLs, IPs, numbers and ids are removed first, so the same response on
  two hosts is one cluster.

Redaction lives here, not in `prompt`, because the fingerprint and the quote
check must read the same text the model was shown: `evidence_text` is the one
door target text goes through, and it redacts on the way in.
"""
from __future__ import annotations

import dataclasses
import hashlib
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from cypherfix_triage.evidence import redact_secret
from cypherfix_triage.fact_queries import normalise_finding_row
from cypherfix_triage.grouping import group_key
from cypherfix_triage.score_model import detector_key
from logging_config import redact_text

from . import projected_fields
from .pool import normalised_severity

CLUSTERS_SENT_MAX = 60

SECRET_VALUE_FIELDS = ("matched_text", "sample", "raw_secret", "secret_value")

#: Free text that can carry an operator's credential or a target's token.
TEXT_FIELDS = (
    "raw_request", "raw_response", "evidence", "description", "matched_at",
    "name", "path", "location", "fuzzing_parameter",
)

HOST_FIELDS = ("triage_host", "host", "hostname", "target_hostname")

#: JS finding types whose evidence is a credential's matched text.
_KEY_LITERAL_TYPES = frozenset({"ai-sdk-key-literal"})

_REDACTED_MARK = "_mm_redacted"
#: An object, not True, so no row read from the graph can claim to be redacted.
_REDACTED = object()

#: `redact_text` catches token shapes, but not a Basic or NTLM Authorization
#: value (the scheme word is too short for its key=value pattern) nor a session
#: cookie. Scanner requests replay the operator's own auth headers.
_AUTH_HEADER = re.compile(
    r"(?im)^([ \t]*(?:proxy-authorization|authorization|cookie|set-cookie)[ \t]*:[ \t]*)[^\r\n]*")

#: Below this a "secret" substring would scrub ordinary words out of the text.
_MIN_SCRUB = 6


def _scrub(text: str, secrets: list) -> str:
    for secret in secrets:
        text = text.replace(secret, redact_secret(secret))
    return redact_text(_AUTH_HEADER.sub(r"\1[REDACTED]", text))


def redact_row(row: dict) -> dict:
    """A copy with credentials removed from every field that can carry one.

    Secret values become `redact_secret`'s shape, and wherever the value also
    appears inside free text (a JS finding's evidence can be the matched text)
    it is replaced there too. Idempotent: a redacted row is returned as is,
    which matters because `redact_secret` of a shape is a different shape.
    """
    row = dict(row or {})
    if row.get(_REDACTED_MARK) is _REDACTED:
        return row
    # The JS scanner stores a hard-coded provider key's matched text as the
    # finding's evidence and detail, with no separate raw value to scrub by:
    # the evidence IS the secret, so it is treated as one.
    if (str(row.get("label") or "") == "JsReconFinding"
            and str(row.get("finding_type") or "") in _KEY_LITERAL_TYPES
            and not row.get("matched_text")):
        row["matched_text"] = row.get("evidence") or row.get("description") or ""
    secrets = sorted({str(row[f]) for f in SECRET_VALUE_FIELDS
                      if row.get(f) and len(str(row[f])) >= _MIN_SCRUB}, key=len, reverse=True)
    for name in TEXT_FIELDS:
        if row.get(name) is not None:
            row[name] = _scrub(str(row[name]), secrets)
    extracted = row.get("extracted_results")
    if extracted:
        if not isinstance(extracted, (list, tuple)):
            extracted = [extracted]
        row["extracted_results"] = [_scrub(str(x), secrets) for x in extracted if x]
    for name in SECRET_VALUE_FIELDS:
        if row.get(name):
            row[name] = redact_secret(row[name])
    row[_REDACTED_MARK] = _REDACTED
    return row


def secret_shape(redacted: dict) -> str:
    return next((str(redacted[f]) for f in SECRET_VALUE_FIELDS if redacted.get(f)), "")


_STATUS_LINE = re.compile(r"HTTP/\d(?:\.\d)?[ \t]+\d{3}\b")
_HEADER_LINE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+[ \t]*:")


def split_http_head(text: str) -> tuple[str, str]:
    """(status line and headers, the rest) of a raw HTTP response.

    The head ends at the blank line or at the first line that is not a header:
    scanners store responses cut to a length, and not always with the blank
    line. Text that does not start with a status line is all body.
    """
    text = str(text or "")
    if not _STATUS_LINE.match(text.lstrip()):
        return "", text
    lines = text.lstrip().splitlines(keepends=True)
    end = 1
    while end < len(lines) and _HEADER_LINE.match(lines[end]):
        end += 1
    return "".join(lines[:end]).strip(), "".join(lines[end:]).strip()


def _evidence_parts(row: dict) -> tuple[str, str]:
    r = redact_row(row)
    head, body = split_http_head(r.get("raw_response"))
    parts = [body, r.get("evidence")]
    parts.extend(r.get("extracted_results") or [])
    parts.append(secret_shape(r))
    if str(r.get("source") or "").strip().lower() == "gvm":
        parts.append(r.get("description"))
    own = "\n".join(str(p).strip() for p in parts if p is not None and str(p).strip())
    return own, head


def quotable_text(row: dict) -> str:
    """The finding's own evidence, redacted: what a quote may cite.

    Everything in `evidence_text` but the HTTP status line and headers. Every
    response from a server shares those, so a quote from them ("Content-Type:
    text/html") is found in any cluster's evidence and proves nothing about it.
    """
    return _evidence_parts(row)[0]


def evidence_text(row: dict) -> str:
    """The target-derived evidence of a row, redacted. No labels, no name, no host.

    The finding's own evidence (`quotable_text`) comes first and the HTTP head
    last, so the excerpt the model is shown opens on the response body rather
    than on headers every response shares.

    A GVM finding's description is included: it carries the scanner's detection
    result for this host, and GVM stores no response body.
    """
    own, head = _evidence_parts(row)
    return "\n".join(p for p in (own, head) if p)


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------
_URL = re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s\"'<>]+")
_EMAIL = re.compile(r"\b[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+\b")
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
#: Two or more colons between hex runs: IPv6, MAC addresses, clock times.
_COLON_HEX = re.compile(r"(?<![\w:])[0-9a-f]*:[0-9a-f]*:[0-9a-f:]*(?![\w:])")
_HOSTNAME = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b")
#: A trailing label that is a file extension makes `name.ext` a file, not a host.
_FILE_SUFFIXES = frozenset({
    "html", "htm", "xhtml", "php", "js", "mjs", "cjs", "ts", "jsx", "tsx", "css",
    "json", "xml", "txt", "md", "asp", "aspx", "jsp", "do", "action", "cgi", "pl",
    "py", "rb", "go", "java", "class", "jar", "war", "png", "jpg", "jpeg", "gif",
    "svg", "ico", "webp", "map", "min", "yml", "yaml", "conf", "cfg", "ini", "log",
    "bak", "old", "sql", "zip", "gz", "tar", "tgz", "env", "lock", "sh", "pem",
    "key", "crt", "csv", "pdf", "woff", "woff2", "ttf", "eot", "swf", "wasm",
})
#: Long mixed letter-digit runs: session ids, CSRF tokens, request ids.
_TOKEN = re.compile(r"\b(?=[a-z0-9_\-]*\d)(?=[a-z0-9_\-]*[a-z])[a-z0-9_\-]{16,}\b")
_HEX = re.compile(r"\b(?=[0-9a-f]*\d)[0-9a-f]{8,}\b")
_NUMBER = re.compile(r"\d+")
_SPACE = re.compile(r"\s+")


def _own_hosts(row: dict) -> list:
    hosts = set()
    for name in (*HOST_FIELDS, "target_ip", "matched_at", "base_url"):
        value = str((row or {}).get(name) or "").strip().lower()
        if not value:
            continue
        hosts.add(value)
        if "://" in value:
            try:
                netloc = urlsplit(value).hostname
            except ValueError:
                netloc = None
            if netloc:
                hosts.add(netloc)
    return sorted((h for h in hosts if len(h) >= 3), key=len, reverse=True)


def _drop_hostname(match: re.Match) -> str:
    return match.group(0) if match.group(1) in _FILE_SUFFIXES else " "


def normalise_evidence(text: str, row: dict | None = None) -> str:
    """What the fingerprint hashes: the evidence with everything per-host removed."""
    text = str(text or "").lower()
    for host in _own_hosts(row or {}):
        text = text.replace(host, " ")
    text = _URL.sub(" ", text)
    text = _EMAIL.sub(" ", text)
    text = _UUID.sub(" ", text)
    text = _IPV4.sub(" ", text)
    text = _COLON_HEX.sub(" ", text)
    text = _HOSTNAME.sub(_drop_hostname, text)
    text = _TOKEN.sub(" ", text)
    text = _HEX.sub(" ", text)
    text = _NUMBER.sub(" ", text)
    return _SPACE.sub(" ", text).strip()


def fingerprint(row: dict) -> str:
    """sha256 of the normalised target evidence, over all of it the pool read."""
    normalised = normalise_evidence(evidence_text(row), row)
    return hashlib.sha256(normalised.encode("utf-8", "replace")).hexdigest()


#: The fingerprint of a row with no evidence left after normalising: every such
#: row of one detector and severity lands in one cluster, whatever it says.
EMPTY_FINGERPRINT = hashlib.sha256(b"").hexdigest()


# ---------------------------------------------------------------------------
# Identity helpers shared with validate and prompt
# ---------------------------------------------------------------------------
def row_key(row: dict) -> str:
    return str((row or {}).get("key") or "")


def is_same_row(row: dict, other: dict) -> bool:
    return (row_key(row) == row_key(other)
            and str((row or {}).get("label") or "") == str((other or {}).get("label") or ""))


def resolved_host(row: dict) -> str:
    """coalesce(triage_host, host, hostname, target_hostname), '' when none."""
    for name in HOST_FIELDS:
        value = str((row or {}).get(name) or "").strip()
        if value:
            return value
    return ""


def detector_of(row: dict) -> str:
    return detector_key(normalise_finding_row(row))


def problem_key(row: dict) -> str:
    """The stored `triage_group_key`, or the key a triage run would store.

    Computed from the fields the `FINDING_QUERIES` entry projects ONLY, because
    those are all the triage run had: letting the pool's extra fields in would
    give an untriaged security check `check:<type>:<header>` while its triaged
    neighbours carry `check:<type>`, and the two would never meet.
    """
    row = row or {}
    stored = str(row.get("triage_group_key") or "").strip()
    if stored:
        return stored
    label = str(row.get("label") or "")
    fields = projected_fields(label)
    subset = {k: v for k, v in row.items() if k in fields} if fields else dict(row)
    subset["label"] = label
    if not subset.get("id"):
        subset["id"] = row_key(row)
    return group_key(normalise_finding_row(subset))


# ---------------------------------------------------------------------------
# Clusters
# ---------------------------------------------------------------------------
@dataclass
class Cluster:
    id: str
    detector: str
    severity: str
    fingerprint: str
    representative: dict
    members: list = field(default_factory=list)
    score: int = 0


def build_clusters(seed: dict, candidates: list) -> list:
    """One cluster per (detector, normalised severity, fingerprint).

    The representative is the member with the lowest key, so the same pool
    always shows the model the same example. Ids are provisional; `rank_clusters`
    assigns the ones sent.
    """
    groups: dict = {}
    for row in candidates or []:
        if is_same_row(row, seed):
            continue
        key = (detector_of(row), normalised_severity(row), fingerprint(row))
        groups.setdefault(key, []).append(row)

    clusters = []
    for (detector, severity, fp), rows in groups.items():
        rows = sorted(rows, key=row_key)
        clusters.append(Cluster(id="", detector=detector, severity=severity, fingerprint=fp,
                                representative=rows[0], members=[row_key(r) for r in rows]))
    clusters.sort(key=lambda c: (c.detector, c.severity, c.members[0]))
    return [dataclasses.replace(c, id=f"c{i}") for i, c in enumerate(clusters, 1)]


def exact_lenses(seed: dict, candidates: list) -> dict:
    """The code-built groups, over the whole pool: member keys per concept."""
    seed_problem = problem_key(seed)
    seed_detector = detector_of(seed)
    seed_host = resolved_host(seed).lower()
    lenses = {"same_problem": [], "same_detector": [], "same_host": []}
    for row in sorted(candidates or [], key=row_key):
        if is_same_row(row, seed):
            continue
        key = row_key(row)
        if seed_problem and problem_key(row) == seed_problem:
            lenses["same_problem"].append(key)
        if seed_detector and detector_of(row) == seed_detector:
            lenses["same_detector"].append(key)
        if seed_host and resolved_host(row).lower() == seed_host:
            lenses["same_host"].append(key)
    return lenses


_CWE = re.compile(r"CWE-\d+", re.I)
#: AI verdicts that say nothing about the finding, so sharing one is no signal.
_NO_AI_VERDICT = frozenset({"", "not_reviewed", "unclear"})


def _cwes(row: dict) -> set:
    raw = (row or {}).get("cwe_ids")
    values = raw if isinstance(raw, (list, tuple, set)) else [raw]
    return {m.upper() for v in values if v for m in _CWE.findall(str(v))}


def _lower(row: dict, name: str) -> str:
    return str((row or {}).get(name) or "").strip().lower()


def rank_clusters(seed: dict, clusters: list, lenses: dict) -> list:
    """The clusters to send, most seed-like first, ids re-assigned c1..cN.

    Weights (§7.4): same problem +4, same detector +3, same category or CWE +2,
    same severity +1, same tier +1, same AI verdict +1; then member count, then
    the representative's key. At most CLUSTERS_SENT_MAX.
    """
    problem = set((lenses or {}).get("same_problem") or ())
    seed_detector = detector_of(seed)
    seed_severity = normalised_severity(seed)
    seed_category = _lower(seed, "category")
    seed_cwes = _cwes(seed)
    seed_tier = _lower(seed, "triage_tier")
    seed_ai = _lower(seed, "triage_ai_verdict")

    scored = []
    for cluster in clusters or []:
        rep = cluster.representative
        score = 0
        if problem.intersection(cluster.members):
            score += 4
        if cluster.detector == seed_detector:
            score += 3
        if (seed_category and _lower(rep, "category") == seed_category) or (seed_cwes & _cwes(rep)):
            score += 2
        if cluster.severity == seed_severity:
            score += 1
        if seed_tier and _lower(rep, "triage_tier") == seed_tier:
            score += 1
        if seed_ai not in _NO_AI_VERDICT and _lower(rep, "triage_ai_verdict") == seed_ai:
            score += 1
        scored.append(dataclasses.replace(cluster, score=score))

    scored.sort(key=lambda c: (-c.score, -len(c.members), row_key(c.representative)))
    return [dataclasses.replace(c, id=f"c{i}")
            for i, c in enumerate(scored[:CLUSTERS_SENT_MAX], 1)]
