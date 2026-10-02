"""
Page-type classifier on TypeSafe Jev
====================================
httpx turns "this host answers" into "here is its page", and classification stops
there: a parked domain and a real admin panel get the same downstream effort. This
hook labels each probed URL with one class from a fixed set:

    app | login_only | parked | default | placeholder | error

It only annotates. It never drops a URL, a host or a finding, and an unsure answer
is "app", which is today's behaviour: scan it.

A deterministic pre-filter runs first, with no call: known default-page and
parking titles, parking-provider CNAMEs, tiny empty bodies, obvious login paths,
and error statuses or soft-404 titles. Jev is asked about the pages it cannot
place, so the call volume is the unresolved remainder, not every URL. Distinct
pages are bounded per scan (MAX_PAGES_PER_SCAN) and the whole pass by a wall-clock
budget; past either, the rest get no label and one line says how many.

Pages with the same title, body, status, size bucket and Server collapse to one
question set (the cache key is exactly what decides the label), and a failed
batch is remembered too, so a failure never re-asks per URL.

Kind B (no LLM twin), gated by AI_IN_PIPELINE and HTTPX_JEV_PAGE_TYPE at the
call site. ROLLOUT is ACT: Jev's label becomes the page's `page_class` on the
URL entry (and the Endpoint in the graph), with the pre-filter as the fallback
where Jev is unavailable. Each decision is still recorded next to the
deterministic label so agreement stays visible; the pre-filter's own pages are
asked about too, so their label has something to agree or disagree with.

Log lines carry counts and indexes only: a URL, title or hostname containing
"port...scan" or "http...prob" would move the recon drawer to another phase.
"""

import hashlib
import os
import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from recon.helpers.ai_planner.jev_shadow import ACT, SHADOW, ShadowRecorder, jev_model, jev_post

ROLLOUT = ACT

HOOK = "page_type"
_TAG = "PageType-Jev"

#: The agent's closed set (jev_hooks.PAGE_CLASSES); "app" is the absence of the others.
PAGE_CLASSES = ("login_only", "parked", "default", "placeholder", "error")
LABELS = frozenset(PAGE_CLASSES + ("app",))

#: Distinct pages asked about per scan. Each costs five questions; past this the
#: rest get no label, so a 10x scan costs the same as a large one.
MAX_PAGES_PER_SCAN = 300
#: Pages per agent call. The agent asks about each page in its own TypeSafe
#: request (up to 5 s each), so 4 pages stay inside TIMEOUT even when slow, and the
#: time budget, checked between calls, is overrun by at most one call.
BATCH_SIZE = 4
#: Wall-clock budget for the whole pass. It runs before the probe results are saved
#: and handed to the graph, so it must never stall the pipeline.
TIME_BUDGET_S = 60
TIMEOUT = 30

BODY_CHARS = 4096
_HEADER_VALUE_CHARS = 500
_MAX_HEADERS = 40

# ---------------------------------------------------------------------------
# Deterministic pre-filter
# ---------------------------------------------------------------------------

#: Titles of default install pages, matched case-insensitively against the whole title.
_DEFAULT_TITLES = (
    "welcome to nginx!", "it works!", "iis windows server", "iis7", "iis8",
    "apache2 ubuntu default page: it works", "apache2 debian default page: it works",
    "test page for the apache http server", "test page for the nginx http server",
    "welcome to openresty!", "welcome to tengine!", "welcome to centos",
    "apache http server test page powered by centos",
)
_PARKED_TITLE_RE = re.compile(
    r"\b(this domain (name )?(is|may be) for sale|domain (is )?for sale|buy this domain|"
    r"parked (free|domain)|domain parking)\b", re.I)
#: CNAME targets of domain-parking services.
_PARKING_CNAMES = ("sedoparking.com", "parkingcrew.net", "bodis.com", "parklogic.com",
                   "above.com", "domainparking.ru", "parkingpage.namecheap.com")
_PLACEHOLDER_TITLE_RE = re.compile(r"\b(coming soon|under construction|site (is )?under maintenance)\b", re.I)
_SOFT_404_TITLE_RE = re.compile(r"\b(404|page not found|not found|403 forbidden|access denied)\b", re.I)
_LOGIN_PATH_RE = re.compile(
    r"/(login|log-in|signin|sign-in|sso|wp-login\.php|auth/login|user/login|users/sign_in|"
    r"account/login|accounts/login)/?$", re.I)
#: A body this small, with this few words, is an empty holding page.
_TINY_WORDS = 3
_TINY_BYTES = 64


def prefilter(entry: dict) -> Optional[str]:
    """The label a page gets with no model, or None when the pre-filter cannot place it."""
    status = entry.get("status_code") or 0
    title = (entry.get("title") or "").strip()
    cname = " ".join(entry.get("cname") or []) if isinstance(entry.get("cname"), list) \
        else str(entry.get("cname") or "")
    if isinstance(status, int) and (status >= 500 or status in (403, 404, 410)):
        return "error"
    if title.lower() in _DEFAULT_TITLES:
        return "default"
    if _PARKED_TITLE_RE.search(title) or any(c in cname.lower() for c in _PARKING_CNAMES):
        return "parked"
    if _PLACEHOLDER_TITLE_RE.search(title):
        return "placeholder"
    if status == 200 and _SOFT_404_TITLE_RE.search(title):
        return "error"
    if _LOGIN_PATH_RE.search(urlparse(entry.get("url") or "").path or ""):
        return "login_only"
    # Only an HTML page can be an empty holding page: a tiny JSON or text body is
    # an API answering, which is application surface.
    ctype = str(entry.get("content_type") or "").lower()
    looks_html = "html" in ctype or (not ctype and str(entry.get("body") or "").lstrip().startswith("<"))
    words, size = entry.get("word_count"), entry.get("content_length")
    if status == 200 and looks_html and isinstance(words, int) and isinstance(size, int) \
            and words <= _TINY_WORDS and size <= _TINY_BYTES:
        return "placeholder"
    return None


# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------

def _int(value) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _ms(value) -> int:
    """httpx reports response time as a duration string ("123.4ms", "1.2s")."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(int(value), 0)
    m = re.fullmatch(r"\s*([0-9.]+)\s*(ms|s|µs|us)?\s*", str(value or ""))
    if not m:
        return 0
    try:
        number = float(m.group(1))
    except ValueError:
        return 0
    unit = m.group(2) or "ms"
    return int(number * 1000) if unit == "s" else int(number / 1000) if unit in ("µs", "us") else int(number)


def _page(entry: dict) -> dict:
    """The agent request item for one URL entry: bounded, every field typed."""
    headers = entry.get("headers") if isinstance(entry.get("headers"), dict) else {}
    cname = entry.get("cname")
    return {
        "url": str(entry.get("url") or ""),
        "host": str(entry.get("host") or ""),
        "status_code": min(_int(entry.get("status_code")), 999),
        "content_length": _int(entry.get("content_length")),
        "word_count": _int(entry.get("word_count")),
        "line_count": _int(entry.get("line_count")),
        "response_time_ms": _ms(entry.get("response_time_ms")),
        "is_cdn": bool(entry.get("is_cdn")),
        "title": str(entry.get("title") or ""),
        "server": str(entry.get("server") or ""),
        "cname": " ".join(map(str, cname)) if isinstance(cname, list) else str(cname or ""),
        "headers": {str(k): str(v)[:_HEADER_VALUE_CHARS]
                    for k, v in list(headers.items())[:_MAX_HEADERS]},
        "body": str(entry.get("body") or "")[:BODY_CHARS],
    }


def cache_key(entry: dict) -> str:
    """Exactly the fields that decide a label, so two pages that share it share the answer."""
    body = str(entry.get("body") or "")[:BODY_CHARS]
    parts = [
        str(entry.get("title") or ""),
        hashlib.sha256(body.encode("utf-8", "replace")).hexdigest(),
        str(entry.get("status_code") or ""),
        str(_int(entry.get("content_length")) // 1024),
        str(entry.get("server") or ""),
    ]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8", "replace")).hexdigest()


def _classifiable(entry: dict) -> bool:
    """A page with no body is classified on its metadata when it has a title or a size;
    with neither there is nothing to ask about."""
    if entry.get("status_code") is None:
        return False
    return bool(entry.get("body") or entry.get("title") or _int(entry.get("content_length")))


def _validate(data, n: int) -> Optional[List[Tuple[str, int]]]:
    if not isinstance(data, dict) or not isinstance(data.get("labels"), list) or len(data["labels"]) != n:
        return None
    out = []
    for label in data["labels"]:
        if not isinstance(label, dict):
            return None
        cls, conf = label.get("page_class"), label.get("confidence")
        if not isinstance(cls, str) or cls not in LABELS:
            return None
        if not isinstance(conf, int) or isinstance(conf, bool) or not 0 <= conf <= 100:
            return None
        out.append((cls, conf))
    return out


def jev_page_type_enabled(settings: dict) -> bool:
    """Kind B gating: nothing upstream folds this flag into AI_IN_PIPELINE."""
    return bool(settings.get('AI_IN_PIPELINE') and settings.get('HTTPX_JEV_PAGE_TYPE'))


def run_page_type_pass(by_url: Dict[str, dict], *, user_id: str, project_id: str,
                       recon_data: Optional[dict] = None, clock=time.monotonic) -> dict:
    """Label the probed pages. Never raises. Returns a count summary.

    `by_url` is the httpx result map, bodies still attached. In ACT every page is
    asked and Jev's answer becomes the entry's `page_class`, `page_class_confidence`
    and `page_class_source`; a page Jev leaves unanswered keeps the pre-filter's
    label, if it has one. In SHADOW nothing on the entries changes.
    """
    recorder = ShadowRecorder(HOOK, rollout=ROLLOUT)
    stats = {"pages": 0, "prefiltered": 0, "asked": 0, "labelled": 0, "not_asked": 0,
             "skipped_no_signal": 0, "failed_batches": 0}
    pre_labels: Dict[str, str] = {}
    try:
        urls = sorted(by_url)
        index = {url: i for i, url in enumerate(urls)}
        baseline: Dict[str, str] = {}
        groups: Dict[str, List[str]] = {}
        for url in urls:
            entry = by_url[url]
            if not isinstance(entry, dict) or not _classifiable(entry):
                stats["skipped_no_signal"] += 1
                continue
            stats["pages"] += 1
            pre = prefilter(entry)
            baseline[url] = pre or "app"
            if pre:
                stats["prefiltered"] += 1
                pre_labels[url] = pre
            groups.setdefault(cache_key(entry), []).append(url)

        keys = list(groups)
        if len(keys) > MAX_PAGES_PER_SCAN:
            stats["not_asked"] = sum(len(groups[k]) for k in keys[MAX_PAGES_PER_SCAN:])
            keys = keys[:MAX_PAGES_PER_SCAN]
        print(f"[*][{_TAG}] {stats['pages']} pages, {stats['prefiltered']} placed by the pre-filter, "
              f"{len(keys)} distinct to ask")

        answers: Dict[str, Tuple[str, int]] = {}
        started = clock()
        for start in range(0, len(keys), BATCH_SIZE):
            if clock() - started > TIME_BUDGET_S:
                left = keys[start:]
                stats["not_asked"] += sum(len(groups[k]) for k in left)
                print(f"[!][{_TAG}] Time budget of {TIME_BUDGET_S}s reached - "
                      f"{len(left)} distinct pages left unlabelled")
                break
            batch = keys[start:start + BATCH_SIZE]
            pages = [_page(by_url[groups[k][0]]) for k in batch]
            data = jev_post("page-type", {"pages": pages, "user_id": user_id, "project_id": project_id},
                            _TAG, TIMEOUT)
            labels = _validate(data, len(batch)) if data is not None else None
            if labels is None:
                if data is not None:
                    print(f"[!][{_TAG}] Agent answer failed validation - using the fallback.")
                stats["failed_batches"] += 1
                recorder.fallback()
                continue
            recorder.model = jev_model(data)
            stats["asked"] += len(batch)
            for k, label in zip(batch, labels):
                answers[k] = label

        if stats["not_asked"]:
            print(f"[!][{_TAG}] {stats['not_asked']} pages not asked (cap {MAX_PAGES_PER_SCAN} "
                  f"distinct pages per scan, or the time budget)")

        for k in keys:
            if k not in answers:
                continue
            label, conf = answers[k]
            for url in groups[k]:
                stats["labelled"] += 1
                recorder.decision(f"page_{index[url]}", label, conf, baseline[url],
                                  url=url, prefiltered=baseline[url] != "app")
                if ROLLOUT != SHADOW:
                    entry = by_url[url]
                    entry["page_class"] = label
                    entry["page_class_confidence"] = conf
                    entry["page_class_source"] = "jev_classifier"
        print(f"[+][{_TAG}] {stats['labelled']} pages labelled, {stats['failed_batches']} "
              f"batches fell back")
    except Exception as e:  # noqa: BLE001 - one bad page must never cost the probe
        print(f"[!][{_TAG}] Pass failed ({type(e).__name__}) - pages left unlabelled.")
        recorder.fallback()
    finally:
        if ROLLOUT != SHADOW:
            _apply_prefilter_fallback(by_url, pre_labels)
        recorder.finish(recon_data)
    return stats


def _apply_prefilter_fallback(by_url: Dict[str, dict], pre_labels: Dict[str, str]) -> None:
    """Where Jev gave no answer (a failed batch, the budget, the page cap, an
    error), the pre-filter's label stands. Never raises."""
    try:
        for url, label in pre_labels.items():
            entry = by_url.get(url)
            if isinstance(entry, dict) and "page_class" not in entry:
                entry["page_class"] = label
                entry["page_class_confidence"] = 100
                entry["page_class_source"] = "prefilter"
    except Exception:  # noqa: BLE001 - a label is never worth breaking the probe
        pass


def run_for_probe(httpx_results: dict, settings: dict, recon_data: Optional[dict]) -> None:
    """The call-site entry: gate, then the pass. Never raises."""
    try:
        if not jev_page_type_enabled(settings):
            return
        run_page_type_pass(httpx_results.get("by_url") or {},
                           user_id=os.environ.get('USER_ID', ''),
                           project_id=os.environ.get('PROJECT_ID', ''),
                           recon_data=recon_data)
    except Exception as e:  # noqa: BLE001
        print(f"[!][{_TAG}] Skipped ({type(e).__name__}).")
