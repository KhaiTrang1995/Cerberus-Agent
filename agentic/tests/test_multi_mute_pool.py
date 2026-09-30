"""Multi mute: what is never a candidate, and the seed's ceiling (plan §3, §7.3).

A candidate the model sees is one a person can mute in bulk, so these rules are
the line that keeps proof, a person's "keep this visible", and anything more
serious than the seed out of reach of a prompt injection. They run before the
model, and the mixin re-checks the ceiling under the write lock.

Run: ./agentic/run_tests.sh tests/test_multi_mute_pool.py
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multi_mute import pool as P  # noqa: E402
from multi_mute.kind import resolve_kind  # noqa: E402

NUCLEI = resolve_kind("Vulnerability", {"source": "nuclei"})


def row(key, **kw):
    base = {"key": key, "id": key, "label": "Vulnerability", "node_id": "7",
            "source": "nuclei", "severity": "low", "name": "Example banner",
            "triage_host": "https://host-a.example.com", "muted": False,
            "proven": False, "stale_since": None}
    base.update(kw)
    return base


SEED = row("seed-1")


class TestSeverity:
    @pytest.mark.parametrize("severity,source,rank", [
        ("critical", "nuclei", 4), ("HIGH", "nuclei", 3), (" medium ", "nuclei", 2),
        ("moderate", "nuclei", 2), ("low", "nuclei", 1), ("info", "nuclei", 0),
        ("informational", "nuclei", 0), ("none", "nuclei", 0),
        ("9.8", "nuclei", 4), ("7.5", "nuclei", 3), ("5", "nuclei", 2), ("2.1", "nuclei", 1),
        ("0", "nuclei", 0), ("75", "nuclei", 3),
        # OSV writes `info` for "never graded": unknown, which ranks as medium.
        ("info", "osv", 2), ("low", "osv", 1),
        (None, "nuclei", 2), ("", "nuclei", 2), ("unknown", "nuclei", 2), ("n/a", "nuclei", 2),
        ("banana", "nuclei", 2),
    ])
    def test_severity_rank(self, severity, source, rank):
        assert P.severity_rank({"severity": severity, "source": source}) == rank

    def test_normalised_word(self):
        assert P.normalised_severity({"severity": "info", "source": "osv"}) == "unknown"
        assert P.normalised_severity({"severity": "moderate"}) == "medium"
        assert P.normalised_severity({"severity": "informational"}) == "info"
        assert P.normalised_severity({}) == "unknown"

    def test_rank_table_covers_every_normalised_word(self):
        from cypherfix_triage.score_model import SEVERITY_IMPACT
        assert set(SEVERITY_IMPACT) <= set(P.SEVERITY_RANK)

    def test_tier_rank(self):
        assert P.tier_rank("T1") == 3 and P.tier_rank("t4") == 0
        assert P.tier_rank(None) is None and P.tier_rank("") is None and P.tier_rank("T9") is None


class TestCeiling:
    def test_ceiling_for(self):
        seed = row("s", severity="medium", triage_tier="T3", validation_status="validated",
                   verdict="suspicious", confidence_tier="Likely")
        assert P.ceiling_for(seed) == {"severity_rank": 2, "tier_rank": 1, "validated": True,
                                       "malicious": False, "confirmed": False}

    def test_higher_severity_is_above_the_seed(self):
        ceiling = P.ceiling_for(row("s", severity="low"))
        assert P.ceiling_reason(row("a", severity="medium"), ceiling) == "above_seed"
        assert P.within_ceiling(row("b", severity="low"), ceiling)
        assert P.within_ceiling(row("c", severity="info"), ceiling)

    def test_osv_info_counts_as_unknown_which_is_medium(self):
        low_seed = P.ceiling_for(row("s", severity="low"))
        assert not P.within_ceiling(row("a", source="osv", severity="info"), low_seed)
        osv_seed = P.ceiling_for(row("s", source="osv", severity="info"))
        assert P.within_ceiling(row("b", severity="medium"), osv_seed)
        assert not P.within_ceiling(row("c", severity="high"), osv_seed)

    def test_a_more_urgent_tier_is_out_only_when_both_are_triaged(self):
        ceiling = P.ceiling_for(row("s", triage_tier="T3"))
        assert P.ceiling_reason(row("a", triage_tier="T2"), ceiling) == "above_seed"
        assert P.within_ceiling(row("b", triage_tier="T4"), ceiling)
        assert P.within_ceiling(row("c", triage_tier="T3"), ceiling)
        assert P.within_ceiling(row("d"), ceiling)
        untriaged_seed = P.ceiling_for(row("s"))
        assert P.within_ceiling(row("e", triage_tier="T1"), untriaged_seed)

    @pytest.mark.parametrize("marker", [
        {"validation_status": "validated"}, {"verdict": "malicious"},
        {"confidence_tier": "Confirmed"}, {"confidence_tier": "confirmed"},
    ])
    def test_proof_the_seed_lacks(self, marker):
        assert P.ceiling_reason(row("a", **marker), P.ceiling_for(SEED)) == "proof_seed_lacks"
        assert P.within_ceiling(row("b", **marker), P.ceiling_for(row("s", **marker)))

    def test_proof_is_checked_before_severity(self):
        candidate = row("a", severity="critical", validation_status="validated")
        assert P.ceiling_reason(candidate, P.ceiling_for(SEED)) == "proof_seed_lacks"


def _pool():
    """One row per exclusion reason, plus candidates."""
    return [
        dict(SEED),
        row("c-low"),
        row("c-info", severity="info"),
        row("c-noise", triage_status="likely_noise", triage_source="human"),
        row("c-ai-fp", triage_ai_verdict="false_positive"),
        row("x-js", label="JsReconFinding", finding_type="js_file", source="js_recon"),
        row("x-kind", source="osv"),
        row("x-label", label="Secret", source="js_recon"),
        row("x-muted", muted=True),
        row("x-stale", stale_since="2026-01-01T00:00:00Z"),
        row("x-proven", proven=True),
        row("x-kept"),
        row("x-proof", validation_status="validated"),
        row("x-above", severity="high"),
        row("x-tier", triage_tier="T1"),
    ]


class TestApplyPoolRules:
    def _apply(self, rows=None, exempt=None, seed=None, total=None):
        seed = seed or row("seed-1", triage_tier="T4")
        return P.apply_pool_rules(seed, NUCLEI, rows if rows is not None else _pool(),
                                  exempt if exempt is not None else [["Vulnerability", "x-kept"]],
                                  total=total)

    def test_candidates(self):
        result = self._apply()
        assert [r["key"] for r in result.candidates] == ["c-low", "c-info", "c-noise", "c-ai-fp"]

    def test_exclusion_counts(self):
        assert self._apply().excluded == {
            "js_file": 1, "other_kind": 2, "muted": 1, "stale": 1, "proven": 1,
            "kept_visible": 1, "proof_seed_lacks": 1, "above_seed": 2,
        }

    def test_every_reason_is_always_reported(self):
        result = self._apply(rows=[])
        assert result.excluded == {reason: 0 for reason in P.EXCLUSION_REASONS}
        assert result.candidates == [] and result.total == 0 and not result.truncated

    def test_the_seed_is_never_a_candidate_nor_an_exclusion(self):
        result = self._apply(rows=[dict(SEED)])
        assert result.candidates == []
        assert sum(result.excluded.values()) == 0

    def test_a_persons_likely_noise_verdict_stays_a_candidate(self):
        noise = row("n1", triage_status="likely_noise", triage_source="human", triage_state="false_positive")
        assert [r["key"] for r in self._apply(rows=[noise]).candidates] == ["n1"]

    def test_proven_wins_over_later_reasons(self):
        both = row("p1", proven=True, severity="critical")
        assert self._apply(rows=[both]).excluded["proven"] == 1

    def test_kept_visible_matches_label_and_key(self):
        other_label = self._apply(rows=[row("k1")], exempt=[["Secret", "k1"]])
        assert [r["key"] for r in other_label.candidates] == ["k1"]
        kept = self._apply(rows=[row("k1")], exempt=[("Vulnerability", "k1")])
        assert kept.excluded["kept_visible"] == 1

    def test_kept_visible_matches_a_malpackage_finding_id(self):
        mal = resolve_kind("MalPackageFinding", {})
        seed = {"key": "fid-0", "label": "MalPackageFinding", "severity": "high"}
        candidate = {"key": "fid-1", "finding_id": "fid-1", "label": "MalPackageFinding",
                     "severity": "high"}
        result = P.apply_pool_rules(seed, mal, [candidate], [["MalPackageFinding", "fid-1"]])
        assert result.excluded["kept_visible"] == 1

    def test_malformed_exempt_pairs_are_ignored(self):
        result = self._apply(rows=[row("k1")], exempt=[None, ["Vulnerability"], "x", 3])
        assert [r["key"] for r in result.candidates] == ["k1"]

    def test_truncation_keeps_the_closest_rows(self):
        rows = [row(f"r{i:05d}") for i in range(P.POOL_MAX + 1)]
        result = self._apply(rows=rows, total=5000)
        assert result.truncated
        assert len(result.candidates) == P.POOL_MAX
        assert result.candidates[-1]["key"] == f"r{P.POOL_MAX - 1:05d}"
        assert result.total == 5000

    def test_not_truncated_at_the_limit(self):
        rows = [row(f"r{i:05d}") for i in range(P.POOL_MAX)]
        result = self._apply(rows=rows)
        assert not result.truncated and result.total == P.POOL_MAX
