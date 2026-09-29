"""Multi mute graph reads (`multi_mute/queries.py`), as built Cypher.

The queries were also compiled with EXPLAIN against a live Neo4j 5 during
development; what is pinned here is what an edit to this file, to a
FINDING_QUERIES entry or to the evidence code can silently break:

- the projection covers every field `build_bundle` / `group_key` / the guards
  read, for every label (plan §19: a new field there must reach the pool);
- the kind's selector is in the Cypher, parameterised;
- the long text fields are cut in Cypher;
- the pool is bounded to POOL_MAX + 1 and tenant-scoped;
- muted, stale and JS-file-container nodes never enter it;
- MalPackageFinding does not require its Package parent.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO = Path(__file__).resolve().parents[2]
for p in (str(REPO), str(REPO / "agentic")):
    if p not in sys.path:
        sys.path.insert(0, p)

from multi_mute import POOL_LABELS, REQUIRED_ROW_FIELDS, queries  # noqa: E402
from multi_mute.kind import resolve_kind  # noqa: E402
from multi_mute.pool import POOL_MAX  # noqa: E402

SEED_PROPS = {
    "Vulnerability": {"source": "nuclei"},
    "JsReconFinding": {"finding_type": "secret"},
    "Secret": {"source": "js_recon"},
    "MultiscannerFinding": {"source": "trufflehog"},
    "GithubSecret": {},
    "GithubSensitiveFile": {},
    "MalPackageFinding": {"source_tool": "osv"},
}


def _kind(label):
    return resolve_kind(label, SEED_PROPS[label])


def _aliases(query: str) -> set:
    return set(re.findall(r"\bAS\s+([A-Za-z_][A-Za-z0-9_]*)", query))


@pytest.mark.parametrize("label", POOL_LABELS)
def test_the_pool_projection_covers_every_field_the_engine_reads(label):
    query, _ = queries.pool_query(label, _kind(label))
    missing = set(REQUIRED_ROW_FIELDS[label]) - _aliases(query)
    assert not missing, f"{label} pool rows would lack {sorted(missing)}"


@pytest.mark.parametrize("label", POOL_LABELS)
def test_the_seed_has_the_same_projection_as_the_pool(label):
    kind = _kind(label)
    pool_q, _ = queries.pool_query(label, kind)
    assert set(REQUIRED_ROW_FIELDS[label]) <= _aliases(queries.seed_query(label, kind))


@pytest.mark.parametrize("label", POOL_LABELS)
def test_the_pool_is_tenant_scoped_bounded_and_excludes_muted_and_stale(label):
    query, params = queries.pool_query(label, _kind(label))
    assert "n.user_id = $userId AND n.project_id = $projectId" in query
    assert "NOT n:Muted" in query
    assert "n.stale_since IS NULL" in query
    assert query.rstrip().endswith("LIMIT $pool_limit")
    assert params["pool_limit"] == POOL_MAX + 1
    assert f"MATCH (n:{label})" in query


def test_js_file_containers_never_enter_the_pool():
    query, _ = queries.pool_query("JsReconFinding", _kind("JsReconFinding"))
    assert "coalesce(n.finding_type, '') <> 'js_file'" in query
    count, _ = queries.count_query("JsReconFinding", _kind("JsReconFinding"))
    assert "'js_file'" in count


def test_a_catalog_selector_is_in_the_cypher_and_parameterised():
    kind = _kind("Vulnerability")
    assert kind.selector is not None
    query, params = queries.pool_query("Vulnerability", kind)
    assert "nuclei" not in query, "a selector value must travel as a parameter"
    assert "nuclei" in [v for value in params.values()
                        for v in (value if isinstance(value, list) else [value])]


def test_a_fallback_kind_filters_on_the_coalesced_source():
    query, params = queries.pool_query("MultiscannerFinding", _kind("MultiscannerFinding"))
    assert "coalesce(coalesce(n.source, n.source_type, 'trufflehog'), '') = $mm_source" in query
    assert params["mm_source"] == "trufflehog"


@pytest.mark.parametrize("label", POOL_LABELS)
def test_long_text_is_cut_in_cypher(label):
    query, _ = queries.pool_query(label, _kind(label))
    for alias, cap in queries.TEXT_CUTS.items():
        for m in re.finditer(rf"(\S+)\s+AS\s+{alias}\b", query):
            assert m.group(1) == f"{cap})", m.group(0)
            window = query[max(0, m.start() - 80):m.start()]
            assert "left(toStringOrNull(" in window, m.group(0)
    # from the triage entry (Vulnerability, `v.`) or added (`n.`), cut the same
    assert re.search(rf"left\(toStringOrNull\(\w+\.raw_request\), {queries.RAW_REQUEST_CUT}\) "
                     r"AS raw_request\b", query), query
    assert query.count("AS raw_request") == 1


def test_vulnerability_raw_response_and_evidence_are_both_cut():
    query, _ = queries.pool_query("Vulnerability", _kind("Vulnerability"))
    assert "left(toStringOrNull(v.raw_response), 1500) AS raw_response" in query
    assert "left(toStringOrNull(v.evidence), 1500) AS evidence" in query
    assert "left(toStringOrNull(v.description), 1500) AS description" in query


def test_mal_packages_do_not_require_their_package_parent():
    query, _ = queries.pool_query("MalPackageFinding", _kind("MalPackageFinding"))
    head = query[:query.index("RETURN")]
    assert "MATCH (pkg:Package" not in head
    assert "head([(p:Package)-[:FLAGGED_AS]->(n)" in head
    assert "p.user_id = $userId AND p.project_id = $projectId" in head
    assert "coalesce(n.finding_id, n.id) AS key" in query


def test_closest_rows_first():
    query, _ = queries.pool_query("Vulnerability", _kind("Vulnerability"))
    assert "ORDER BY _mm_like, _mm_distance, key" in query


def test_a_label_outside_the_pool_is_refused():
    kind = _kind("Vulnerability")
    for label in ("ExploitGvm", "IP", "Vulnerability) DETACH DELETE (x"):
        with pytest.raises(ValueError):
            queries.pool_query(label, kind)


def test_the_counts_split_live_stale_and_js_files():
    query, _ = queries.count_query("Vulnerability", _kind("Vulnerability"))
    assert "NOT n:Muted" in query
    for alias in ("live", "stale", "js_file"):
        assert f"AS {alias}" in query


def test_reads_run_in_read_transactions_and_strip_the_ordering_keys():
    tx = MagicMock()
    tx.run.return_value = [{"key": "k1", "_mm_like": 0, "_mm_distance": 1, "stale_since": None}]
    session = MagicMock()
    session.execute_read.side_effect = lambda fn: fn(tx)
    session.__enter__ = lambda s: session
    session.__exit__ = lambda *a: False
    driver = MagicMock()
    driver.session.return_value = session
    rows = queries.read_pool(driver, "u1", "p1", _kind("Vulnerability"),
                             {"_mm_source": "nuclei", "_mm_detector": "t"}, 2)
    assert rows == [{"key": "k1", "stale_since": None}]
    params = tx.run.call_args.kwargs
    assert (params["userId"], params["projectId"]) == ("u1", "p1")
    assert (params["mm_seed_source"], params["mm_seed_detector"], params["mm_seed_rank"]) == ("nuclei", "t", 2)
    session.execute_write.assert_not_called()


def test_a_missing_seed_raises():
    session = MagicMock()
    session.execute_read.return_value = []
    session.__enter__ = lambda s: session
    session.__exit__ = lambda *a: False
    driver = MagicMock()
    driver.session.return_value = session
    with pytest.raises(queries.SeedMissing):
        queries.locate_seed(driver, "u1", "p1", "gone")
