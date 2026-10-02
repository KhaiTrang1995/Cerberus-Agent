"""Regression: FOFA IP mode let one IP spend the whole budget and many queries.

Pagination made each IP page up to FOFA_MAX_RESULTS, but the cap applies only
to the combined list, in thread-completion order. One shared-hosting IP could
fill all 1000 rows and the target's own IPs lose theirs, differently each run,
in up to IPs x max/100 requests. IP mode is one request per IP again (size =
min(100, max_results), no `page`); domain mode still pages.

requests.get is mocked throughout; nothing reaches fofa.info.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import fofa_enrich  # noqa: E402

N_FIELDS = len(fofa_enrich._FOFA_FIELD_NAMES)
SHARED, OWN = "192.88.98.10", "192.88.98.11"
ROWS_PER_IP = {SHARED: 5000, OWN: 12}


def _ip_of(params):
    return base64.b64decode(params["qbase64"]).decode().split('"')[1]


def _get(url, params=None, timeout=None):
    ip = _ip_of(params)
    page, size = int(params.get("page", 1)), int(params["size"])
    start = (page - 1) * size
    rows = [[ip, str(1000 + i)] + [""] * (N_FIELDS - 2)
            for i in range(start, min(start + size, ROWS_PER_IP[ip]))]
    resp = MagicMock()
    resp.status_code = 200
    resp.text = ""
    resp.json.return_value = {"error": False, "size": ROWS_PER_IP[ip], "page": page,
                              "results": rows}
    return resp


def _run(ips, max_results):
    get = MagicMock(side_effect=_get)
    combined = {"domain": "", "metadata": {"ip_mode": True, "expanded_ips": ips},
                "dns": {"domain": {"ips": {"ipv4": ips}}, "subdomains": {}}}
    settings = {"FOFA_ENABLED": True, "FOFA_API_KEY": "fofa-key", "FOFA_KEY_ROTATOR": None,
                "FOFA_MAX_RESULTS": max_results, "FOFA_WORKERS": 1}
    with patch.object(fofa_enrich.requests, "get", get), \
         patch.object(fofa_enrich.time, "sleep"), \
         patch.object(fofa_enrich, "filter_ips_for_enrichment", side_effect=lambda ips, *a: ips):
        out = fofa_enrich.run_fofa_enrichment(combined, settings)["fofa"]
    return out, [c.kwargs["params"] for c in get.call_args_list]


def test_regression_fofa_ip_mode_one_ip_spends_budget():
    out, sent = _run([SHARED, OWN], max_results=1000)
    # Exactly one request per IP, with the pre-pagination parameters.
    assert sorted(_ip_of(p) for p in sent) == [SHARED, OWN]
    assert all("page" not in p and p["size"] == 100 for p in sent)
    by_ip = {}
    for r in out["results"]:
        by_ip[r["ip"]] = by_ip.get(r["ip"], 0) + 1
    assert by_ip == {SHARED: 100, OWN: 12}


def test_ip_mode_below_one_page_keeps_its_size():
    out, sent = _run([SHARED, OWN], max_results=40)
    assert len(sent) == 2
    assert all("page" not in p and p["size"] == 40 for p in sent)
    assert len(out["results"]) == 40
