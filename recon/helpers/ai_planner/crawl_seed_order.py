"""
Crawl-seed order for Hakrawler, ranked by TypeSafe Jev
======================================================
Hakrawler runs one job per seed URL, in list order, and once its shared URL cap
(HAKRAWLER_MAX_URLS) is reached every later job stops. The list is alphabetical,
so under a tight cap (the memory governor can lower it to 1,000) hosts late in
the alphabet lose out purely because of their name. This hook asks Jev, per host,
whether it is likely to have a rich web application surface, and orders the seeds
host by host by that answer.

Ordering only: every seed stays in the list, so with a cap that does not bind
nothing changes. Katana is not touched (its limit is time, not order), and
neither is the shared `target_urls` list: Kiterunner, FFuf, ZAP and the jsluice
feed check read it too. Only Hakrawler gets the reordered copy.

The per-host signal comes from the HTTP probe: our own numbers (status, size,
word and line counts, seeds per host) plain, and the hostname, title and Server
wrapped by the agent as target data. At most MAX_HOSTS hosts are scored; above
that a sample chosen by a hash of the hostname (stable between runs, and not the
alphabetical cut) is scored and the rest follow in alphabetical order.

Partial recon builds its probe data from the graph with status and content type
only, so there is nothing to rank on: it keeps the alphabetical order.

Kind B, gated by AI_IN_PIPELINE and HAKRAWLER_JEV_SEED_ORDER at each call site.
ROLLOUT is ACT: Hakrawler crawls in Jev's order (the alphabetical order is the
fallback when Jev is unavailable), and each host's rank is still recorded next
to the alphabetical one so agreement stays visible.
"""

import hashlib
import os
from typing import Dict, List, Optional
from urllib.parse import urlparse

from recon.helpers.ai_planner.jev_shadow import ACT, SHADOW, ShadowRecorder, jev_model, jev_post

ROLLOUT = ACT

HOOK = "crawl_seed_order"
_TAG = "CrawlOrder-Jev"

#: Must equal the agent's CRAWL_SEED_HOSTS_MAX and the request model's bound.
MAX_HOSTS = 400
TIMEOUT = 30


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _int(value) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _host_item(host: str, seeds: List[str], http_probe: dict) -> Optional[dict]:
    """The request item for one host, from its best probed URL; None with no probe data."""
    by_url = http_probe.get("by_url") or {}
    entries = [by_url[s] for s in seeds if isinstance(by_url.get(s), dict)]
    if not entries:
        return None
    # The root page if one was probed, else the largest one.
    root = next((e for e in entries if (urlparse(e.get("url") or "").path or "/") == "/"), None)
    best = root or max(entries, key=lambda e: _int(e.get("content_length")))
    return {
        "hostname": host[:255],
        "title": str(best.get("title") or ""),
        "server": str(best.get("server") or ""),
        "status_code": min(_int(best.get("status_code")), 999),
        "content_length": _int(best.get("content_length")),
        "word_count": _int(best.get("word_count")),
        "line_count": _int(best.get("line_count")),
        "url_count": len(seeds),
    }


def _validate(data, n: int) -> Optional[List[float]]:
    if not isinstance(data, dict) or not isinstance(data.get("scores"), list) or len(data["scores"]) != n:
        return None
    scores = data["scores"]
    if not all(isinstance(s, (int, float)) and not isinstance(s, bool) and 0.0 <= s <= 1.0 for s in scores):
        return None
    return [float(s) for s in scores]


def jev_seed_order_enabled(settings: dict) -> bool:
    """Kind B gating: nothing upstream folds this flag into AI_IN_PIPELINE."""
    return bool(settings.get('AI_IN_PIPELINE') and settings.get('HAKRAWLER_JEV_SEED_ORDER'))


def hakrawler_seed_order(target_urls: List[str], recon_data: Optional[dict], *,
                         partial: bool = False) -> List[str]:
    """The seed list for Hakrawler. Never raises; always a permutation of `target_urls`.

    The caller has already tested AI_IN_PIPELINE and HAKRAWLER_JEV_SEED_ORDER.
    """
    seeds = list(target_urls)
    if partial:
        print(f"[*][{_TAG}] Partial recon has no per-host probe signal - "
              f"keeping the alphabetical order")
        return seeds
    recorder = None
    try:
        by_host: Dict[str, List[str]] = {}
        for url in seeds:
            by_host.setdefault(_host(url), []).append(url)
        hosts = sorted(by_host)
        http_probe = (recon_data or {}).get("http_probe") or {}
        items = {h: _host_item(h, by_host[h], http_probe) for h in hosts if h}
        scorable = sorted((h for h, item in items.items() if item),
                          key=lambda h: hashlib.sha256(h.encode()).hexdigest())[:MAX_HOSTS]
        scorable.sort()
        if len(scorable) < 2:
            return seeds
        print(f"[*][{_TAG}] Scoring {len(scorable)} of {len(hosts)} hosts for the Hakrawler order")
        recorder = ShadowRecorder(HOOK, rollout=ROLLOUT)
        data = jev_post("crawl-seed-order", {
            "hosts": [items[h] for h in scorable],
            "user_id": os.environ.get('USER_ID', ''), "project_id": os.environ.get('PROJECT_ID', ''),
        }, _TAG, TIMEOUT)
        scores = _validate(data, len(scorable)) if data is not None else None
        if scores is None:
            if data is not None:
                print(f"[!][{_TAG}] Agent answer failed validation - using the fallback.")
            recorder.fallback()
            return seeds
        recorder.model = jev_model(data)

        score = dict(zip(scorable, scores))
        ranked = sorted(scorable, key=lambda h: (-score[h], h))
        jev_hosts = ranked + [h for h in hosts if h not in score]
        jev_rank = {h: i for i, h in enumerate(jev_hosts)}
        half = len(hosts) / 2
        for i, h in enumerate(hosts):
            if h not in score:
                continue
            recorder.decision(f"host_{i}", "early" if jev_rank[h] < half else "late",
                              round(score[h] * 100), "early" if i < half else "late",
                              hostname=h, jev_rank=jev_rank[h], baseline_rank=i)
        moved = sum(1 for i, h in enumerate(hosts) if h in score and jev_rank[h] < half <= i)
        print(f"[+][{_TAG}] Jev {'would move' if ROLLOUT == SHADOW else 'moved'} {moved} host(s) "
              f"from the second half of the list into the first")
        if ROLLOUT == SHADOW:
            return seeds
        return [url for h in jev_hosts for url in by_host[h]]
    except Exception as e:  # noqa: BLE001 - the crawl must start whatever happens here
        print(f"[!][{_TAG}] Ordering failed ({type(e).__name__}) - using the fallback.")
        if recorder is not None:
            recorder.fallback()
        return seeds
    finally:
        if recorder is not None:
            recorder.finish(recon_data)
