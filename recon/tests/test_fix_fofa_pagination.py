"""FOFA enrichment pages past the first 100 rows.

`_fofa_query` sent no `page` and each mode made one call with
size = min(100, FOFA_MAX_RESULTS), so FOFA_MAX_RESULTS above 100 (the default
is 1000, the UI allows 10000) was silently ignored. Pages are now walked until
max_results, a short page, or FOFA's reported total; a failing page keeps what
was already fetched. With max_results <= 100, or a short first page, exactly
one request with today's params is made.

requests.get is mocked throughout; nothing reaches fofa.info.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import fofa_enrich  # noqa: E402

N_FIELDS = len(fofa_enrich._FOFA_FIELD_NAMES)


def _row(ip, port):
    return [ip, str(port)] + [""] * (N_FIELDS - 2)


def _resp(status=200, body=None):
    m = MagicMock()
    m.status_code = status
    m.text = ""
    m.json.return_value = body if body is not None else {}
    return m


def _fofa(total_rows, total=None, fail_pages=()):
    """A fake search/all serving `total_rows` rows for any query, paged."""
    def get(url, params=None, timeout=None):
        page = int(params.get("page", 1))
        if page in fail_pages:
            return _resp(500, {})
        size = int(params["size"])
        start = (page - 1) * size
        ip = base64.b64decode(params["qbase64"]).decode().split('"')[1]
        rows = [_row(ip, 1000 + i) for i in range(start, min(start + size, total_rows))]
        return _resp(200, {"error": False, "size": total if total is not None else total_rows,
                           "page": page, "results": rows})
    return MagicMock(side_effect=get)


def _settings(**kw):
    return {"FOFA_ENABLED": True, "FOFA_API_KEY": "fofa-key", "FOFA_KEY_ROTATOR": None,
            "FOFA_MAX_RESULTS": 100, **kw}


def _domain():
    return {"domain": "example.test", "metadata": {"ip_mode": False},
            "dns": {"domain": {"ips": {"ipv4": []}}, "subdomains": {}}}


def _ip_mode(ips):
    return {"domain": "", "metadata": {"ip_mode": True, "expanded_ips": ips},
            "dns": {"domain": {"ips": {"ipv4": ips}}, "subdomains": {}}}


def _run(combined, settings, get):
    with patch.object(fofa_enrich.requests, "get", get), \
         patch.object(fofa_enrich.time, "sleep"), \
         patch.object(fofa_enrich, "filter_ips_for_enrichment", side_effect=lambda ips, *a: ips):
        return fofa_enrich.run_fofa_enrichment(combined, settings)["fofa"]


def _pages(get):
    return [c.kwargs["params"].get("page") for c in get.call_args_list]


# --------------------------------------------------------------------------- #
# Normal path: one request, today's params
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("max_results", [1, 50, 100])
def test_at_most_100_results_is_one_request_with_unchanged_params(max_results):
    get = _fofa(total_rows=5000)
    out = _run(_domain(), _settings(FOFA_MAX_RESULTS=max_results), get)
    assert get.call_count == 1
    params = get.call_args.kwargs["params"]
    assert set(params) == {"key", "qbase64", "fields", "size"}
    assert params["size"] == max_results
    assert len(out["results"]) == max_results and out["total"] == 5000


def test_a_short_first_page_is_one_request():
    get = _fofa(total_rows=37)
    out = _run(_domain(), _settings(FOFA_MAX_RESULTS=1000), get)
    assert get.call_count == 1 and "page" not in get.call_args.kwargs["params"]
    assert len(out["results"]) == 37


# --------------------------------------------------------------------------- #
# Paging
# --------------------------------------------------------------------------- #
def test_domain_mode_pages_up_to_max_results():
    get = _fofa(total_rows=1000)
    out = _run(_domain(), _settings(FOFA_MAX_RESULTS=250), get)
    assert _pages(get) == [None, 2, 3]
    assert all(c.kwargs["params"]["size"] == 100 for c in get.call_args_list)
    assert len(out["results"]) == 250
    assert [r["port"] for r in out["results"]] == list(range(1000, 1250))   # no page repeated
    assert out["total"] == 1000


def test_a_short_page_ends_the_walk():
    get = _fofa(total_rows=140)
    out = _run(_domain(), _settings(FOFA_MAX_RESULTS=1000), get)
    assert _pages(get) == [None, 2]
    assert len(out["results"]) == 140


def test_the_reported_total_ends_the_walk():
    # Full pages, but FOFA says 200 exist: page 3 is never asked for.
    get = _fofa(total_rows=10_000, total=200)
    out = _run(_domain(), _settings(FOFA_MAX_RESULTS=1000), get)
    assert _pages(get) == [None, 2]
    assert len(out["results"]) == 200


def test_a_failing_later_page_keeps_the_pages_already_fetched():
    get = _fofa(total_rows=1000, fail_pages={3})
    out = _run(_domain(), _settings(FOFA_MAX_RESULTS=500), get)
    assert _pages(get)[:3] == [None, 2, 3]
    assert 4 not in _pages(get)
    assert len(out["results"]) == 200


def test_every_page_carries_the_key():
    get = _fofa(total_rows=300)
    _run(_domain(), _settings(FOFA_MAX_RESULTS=300, FOFA_API_KEY="user@example.test:k1"), get)
    assert get.call_count == 3
    for c in get.call_args_list:
        assert c.kwargs["params"]["email"] == "user@example.test"
        assert c.kwargs["params"]["key"] == "k1"


# --------------------------------------------------------------------------- #
# IP mode
# --------------------------------------------------------------------------- #
def test_ip_mode_pages_each_ip_with_the_same_bounds():
    def get(url, params=None, timeout=None):
        ip = base64.b64decode(params["qbase64"]).decode().split('"')[1]
        return _fofa(total_rows=230 if ip == "192.88.98.10" else 12)(url, params=params,
                                                                       timeout=timeout)
    mock_get = MagicMock(side_effect=get)
    out = _run(_ip_mode(["192.88.98.10", "192.88.98.11"]),
               _settings(FOFA_MAX_RESULTS=1000, FOFA_WORKERS=1), mock_get)
    by_ip = {}
    for c in mock_get.call_args_list:
        ip = base64.b64decode(c.kwargs["params"]["qbase64"]).decode().split('"')[1]
        by_ip.setdefault(ip, []).append(c.kwargs["params"].get("page"))
    assert by_ip == {"192.88.98.10": [None, 2, 3], "192.88.98.11": [None]}
    assert len(out["results"]) == 242


def test_ip_mode_at_most_100_is_one_request_per_ip():
    get = _fofa(total_rows=5000)
    out = _run(_ip_mode(["192.88.98.10", "192.88.98.11"]),
               _settings(FOFA_MAX_RESULTS=100, FOFA_WORKERS=1), get)
    assert get.call_count == 2 and _pages(get) == [None, None]
    assert len(out["results"]) == 100


def test_fetch_pages_never_exceeds_the_bound_it_was_given():
    get = _fofa(total_rows=10_000)
    with patch.object(fofa_enrich.requests, "get", get):
        from recon.helpers import circuit_breaker as cb
        keys = cb.KeyPool(None, "k", label="FOFA")
        rows, total, answered = fofa_enrich._fofa_fetch_pages('domain="example.test"', keys, 100, 350)
    assert answered and total == 10_000
    assert get.call_count == 4 and len(rows) == 400   # the caller trims to max_results
