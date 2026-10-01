"""Partial subdomain discovery honours the Rules of Engagement exclusions.

The full pipeline drops RoE-excluded names twice: the operator's explicit hosts
before any phase (main.py, `_filter_roe_excluded(full_subdomains, ...)`) and
every DISCOVERED name in merge_group_hosts. Partial discovery did neither: it
wrote excluded names straight into the graph, and partial Naabu/httpx/Nuclei
then read their targets back from the graph and actively scanned them. That
is a contractual boundary, so it is pinned here end to end: what the graph
writer receives, what is resolved, and what the UserInput records.

Fixture names are under example.test only.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules import helpers, subdomain_discovery  # noqa: E402

ROOT = "example.test"
EXCLUDED = ["payments.example.test", "10.20.0.0/16"]


def _dns(names):
    return {"domain": {}, "subdomains": {
        n: {"ips": {"ipv4": ["192.88.98.10"], "ipv6": []}, "has_records": True} for n in names}}


DISCOVERED = ["www.example.test", "payments.example.test", "api.payments.example.test",
              "mail.example.test"]


def _discovery_result():
    return {"domain": ROOT, "subdomains": list(DISCOVERED), "subdomain_count": len(DISCOVERED),
            "dns": _dns(DISCOVERED), "external_domains": [],
            "subdomain_status_map": {n: "resolved" for n in DISCOVERED}}


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(helpers.time, "sleep", lambda *_a, **_k: None)


@pytest.fixture
def graph(monkeypatch):
    client = MagicMock()
    client.verify_connection.return_value = True
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.update_graph_from_partial_discovery.return_value = {}
    client.create_user_input_node.return_value = None
    module = MagicMock()
    module.Neo4jClient.return_value = client
    monkeypatch.setitem(sys.modules, "graph_db", module)
    return client


def _run(settings, user_inputs=(), result=None):
    cfg = {"_settings": settings, "domains": [ROOT], "domain": ROOT, "batch_mode": False,
           "domain_groups": [{"rootDomain": ROOT, "prefixes": ["*"], "batch": False}],
           "user_inputs": list(user_inputs)}
    probed = {"puredns": [], "dns": []}

    def puredns(subs, domain, s):
        probed["puredns"].append(list(subs))
        return list(subs)

    def resolve(domain, subs, **kw):
        probed["dns"].append(list(subs))
        return _dns(subs)

    with patch("recon.main_recon_modules.domain_recon.discover_subdomains",
               return_value=result if result is not None else _discovery_result()), \
         patch("recon.main_recon_modules.domain_recon.run_puredns_resolve", side_effect=puredns), \
         patch("recon.main_recon_modules.domain_recon.resolve_all_dns", side_effect=resolve):
        statuses = subdomain_discovery.run_subdomain_discovery(cfg)
    return statuses, probed


def _written(graph):
    return graph.update_graph_from_partial_discovery.call_args.kwargs["recon_data"]


ROE_ON = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": EXCLUDED}


# --------------------------------------------------------------------------- #
# The bug path
# --------------------------------------------------------------------------- #
def test_discovered_excluded_names_never_reach_the_graph(graph, capsys):
    statuses, _ = _run(dict(ROE_ON))
    written = _written(graph)
    assert written["subdomains"] == ["www.example.test", "mail.example.test"]
    assert written["subdomain_count"] == 2
    assert set(written["dns"]["subdomains"]) == {"www.example.test", "mail.example.test"}
    assert set(written["subdomain_status_map"]) == {"www.example.test", "mail.example.test"}
    assert statuses[ROOT] == "ok"
    assert "[RoE] Excluded 2 discovered subdomain(s) per Rules of Engagement" in capsys.readouterr().out


def test_user_supplied_excluded_names_are_never_resolved_or_written(graph, capsys):
    _, probed = _run(dict(ROE_ON), user_inputs=["db.payments.example.test", "new.example.test"])
    out = capsys.readouterr().out
    assert "[RoE] Excluded 1 user-provided subdomain(s) per Rules of Engagement" in out
    for batch in probed["puredns"] + probed["dns"]:
        assert not any(n.endswith("payments.example.test") for n in batch), batch
    assert probed["dns"] == [["mail.example.test", "new.example.test", "www.example.test"]]
    written = _written(graph)
    assert "db.payments.example.test" not in written["subdomains"]
    assert "new.example.test" in written["subdomains"]
    ui = graph.create_user_input_node.call_args.kwargs["user_input_data"]
    assert ui["values"] == ["new.example.test"]


def test_only_excluded_user_inputs_create_no_user_input(graph):
    _, probed = _run(dict(ROE_ON), user_inputs=["db.payments.example.test"])
    graph.create_user_input_node.assert_not_called()
    assert probed == {"puredns": [], "dns": []}


# --------------------------------------------------------------------------- #
# Normal path unchanged
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("settings", [
    {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": EXCLUDED},
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": []},
    {},
])
def test_without_active_roe_everything_is_written_as_before(graph, settings):
    result = _discovery_result()
    expected = copy.deepcopy(result)
    _run(settings, user_inputs=["db.payments.example.test"], result=result)
    written = _written(graph)
    assert "db.payments.example.test" in written["subdomains"]
    assert set(DISCOVERED) <= set(written["subdomains"])
    ui = graph.create_user_input_node.call_args.kwargs["user_input_data"]
    assert ui["values"] == ["db.payments.example.test"]
    assert set(expected["subdomain_status_map"]) <= set(written["subdomain_status_map"])


def test_roe_active_but_nothing_excluded_leaves_the_result_untouched(graph):
    result = _discovery_result()
    expected = copy.deepcopy(result)
    _run({"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["other.example.test"]}, result=result)
    written = _written(graph)
    assert written is result
    assert {k: written[k] for k in expected} == expected
