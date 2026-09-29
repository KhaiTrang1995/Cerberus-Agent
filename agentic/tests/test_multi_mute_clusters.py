"""Multi mute: fingerprints, clusters, exact lenses and ranking (plan §7.4).

A verdict on a cluster covers every member, so what makes two findings one
cluster is a security property. The v2 fingerprint (the first 600 characters of
the bundle, labels included) could put a real hit and a WAF page in one cluster
because their requests matched. These tests pin the v3 rule: target text only,
over its full length, with per-host noise removed.

All data is synthetic: example.com hosts, RFC 5737 addresses, fake tokens.

Run: ./agentic/run_tests.sh tests/test_multi_mute_clusters.py
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage import evidence, grouping, score_model  # noqa: E402
from multi_mute import REQUIRED_ROW_FIELDS  # noqa: E402
from multi_mute import clusters as C  # noqa: E402

FAKE_GH = "ghp_" + "F4keT0kenF4keT0kenF4keT0kenF4keT0ken"


def nuclei(key, body="", **kw):
    base = {"key": key, "id": key, "label": "Vulnerability", "node_id": "11",
            "source": "nuclei", "template_id": "tech-detect", "severity": "info",
            "name": "Tech detect", "triage_host": "https://host-a.example.com",
            "matched_at": "https://host-a.example.com/", "raw_request": "GET / HTTP/1.1",
            "raw_response": body}
    base.update(kw)
    return base


SEED = nuclei("seed-0", "HTTP/1.1 200 OK\nServer: nginx")


def _page(host, ip, req_id, uuid, token, n):
    return (f"HTTP/1.1 403 Forbidden\nDate: Mon, 0{n} Sep 2026 10:1{n}:00 GMT\n"
            f"<html><title>Request blocked</title> Served by {host} ({ip}) "
            f"ray {req_id} incident {uuid} csrf {token} attempt {n}0{n} "
            f"see https://{host}/help?id={n}</html>")


BODY_A = _page("host-a.example.com", "192.0.2.10", "3f9a2c1d7e6b5a40",
               "123e4567-e89b-12d3-a456-426614174000", "Xk29dLm3Qp8zR7vT2wYs", 1)
BODY_B = _page("host-b.example.org", "198.51.100.7", "a1b2c3d4e5f60718",
               "9f8e7d6c-5b4a-3210-fedc-ba9876543210", "Pq81nZ4tLr6sW0yUe3Kd", 2)


class TestEvidenceText:
    def test_target_text_only(self):
        row = nuclei("a", "Server: nginx", extracted_results=["nginx"],
                     name="Nginx version disclosure UNIQUE-NAME")
        text = C.evidence_text(row)
        assert "Server: nginx" in text and "nginx" in text
        for absent in ("UNIQUE-NAME", "Response:", "Template", "Matched at", "GET / HTTP/1.1",
                       "tech-detect", "host-a.example.com"):
            assert absent not in text

    def test_secret_value_appears_only_as_its_shape(self):
        row = {"key": "s1", "label": "Secret", "source": "js_recon", "matched_text": FAKE_GH}
        text = C.evidence_text(row)
        assert FAKE_GH not in text
        assert evidence.redact_secret(FAKE_GH) in text

    def test_secret_value_is_scrubbed_from_free_text_too(self):
        row = {"key": "j1", "label": "JsReconFinding", "source": "js_recon",
               "matched_text": "AbCdEfGh1234567890", "evidence": 'apiKey("AbCdEfGh1234567890")'}
        assert "AbCdEfGh1234567890" not in C.evidence_text(row)

    def test_gvm_description_is_evidence(self):
        row = {"key": "g1", "label": "Vulnerability", "source": "gvm",
               "description": "Installed version: 2.4.1 detected"}
        assert "Installed version" in C.evidence_text(row)

    def test_redact_row_does_not_mutate_and_is_idempotent(self):
        row = {"key": "s1", "label": "Secret", "matched_text": FAKE_GH}
        once = C.redact_row(row)
        assert row["matched_text"] == FAKE_GH
        assert C.redact_row(once) == once

    def test_a_row_cannot_claim_to_be_redacted(self):
        forged = {"key": "s1", "label": "Secret", "matched_text": FAKE_GH, "_mm_redacted": True}
        assert FAKE_GH not in C.evidence_text(forged)


class TestFingerprint:
    def test_same_response_on_different_hosts_is_one_cluster(self):
        a = nuclei("a", BODY_A)
        b = nuclei("b", BODY_B, triage_host="https://host-b.example.org",
                   matched_at="https://host-b.example.org/")
        assert BODY_A != BODY_B
        assert C.fingerprint(a) == C.fingerprint(b)
        clusters = C.build_clusters(SEED, [b, a])
        assert len(clusters) == 1
        assert clusters[0].members == ["a", "b"]
        assert clusters[0].representative["key"] == "a"

    def test_responses_differing_past_600_chars_are_different_clusters(self):
        prefix = "<html>" + "x" * 700
        a = nuclei("a", prefix + " Access denied by the firewall policy</html>")
        b = nuclei("b", prefix + " Welcome back, the dashboard loaded</html>")
        assert C.fingerprint(a) != C.fingerprint(b)
        assert len(C.build_clusters(SEED, [a, b])) == 2

    def test_same_request_and_name_but_different_response_do_not_merge(self):
        waf = nuclei("a", "HTTP/1.1 403 Forbidden\n<title>Request blocked by WAF</title>",
                     name="Exposed admin panel", template_id="admin-panel")
        real = nuclei("b", "HTTP/1.1 200 OK\n<title>Admin console - users</title>",
                      name="Exposed admin panel", template_id="admin-panel")
        assert len(C.build_clusters(SEED, [waf, real])) == 2

    def test_name_request_and_template_do_not_change_the_fingerprint(self):
        a = nuclei("a", "Server: nginx", name="One", raw_request="GET /a HTTP/1.1")
        b = nuclei("b", "Server: nginx", name="Two", raw_request="POST /b HTTP/1.1",
                   template_id="other-template")
        assert C.fingerprint(a) == C.fingerprint(b)

    def test_file_names_are_kept_as_evidence(self):
        a = nuclei("a", "Found backup file config.php")
        b = nuclei("b", "Found backup file admin.php")
        assert C.fingerprint(a) != C.fingerprint(b)

    def test_empty_evidence_is_a_stable_fingerprint(self):
        assert C.fingerprint(nuclei("a", "")) == C.fingerprint(nuclei("b", None))


class TestBuildClusters:
    def test_key_includes_detector_and_severity(self):
        rows = [nuclei("a", "same body"), nuclei("b", "same body", severity="low"),
                nuclei("c", "same body", template_id="other")]
        clusters = C.build_clusters(SEED, rows)
        assert len(clusters) == 3
        assert {c.severity for c in clusters} == {"info", "low"}

    def test_ids_are_sequential_and_the_seed_is_never_clustered(self):
        rows = [dict(SEED), nuclei("b", "one"), nuclei("a", "two")]
        clusters = C.build_clusters(SEED, rows)
        assert [c.id for c in clusters] == ["c1", "c2"]
        assert all("seed-0" not in c.members for c in clusters)

    def test_members_and_representative_are_by_key(self):
        rows = [nuclei(k, "same") for k in ("m3", "m1", "m2")]
        (cluster,) = C.build_clusters(SEED, rows)
        assert cluster.members == ["m1", "m2", "m3"]
        assert cluster.representative["key"] == "m1"
        assert cluster.detector == "nuclei:tech-detect"


class TestExactLenses:
    def test_same_problem_uses_the_stored_group_key(self):
        seed = nuclei("s", triage_group_key="nuclei:tech-detect")
        rows = [nuclei("a", triage_group_key="nuclei:tech-detect"),
                nuclei("b", triage_group_key="cve:cve-2021-0001")]
        assert C.exact_lenses(seed, rows)["same_problem"] == ["a"]

    def test_untriaged_rows_compute_the_key_the_triage_run_would_store(self):
        seed = nuclei("s", triage_group_key="nuclei:tech-detect")
        untriaged = nuclei("a")
        assert C.problem_key(untriaged) == "nuclei:tech-detect"
        assert C.exact_lenses(seed, [untriaged])["same_problem"] == ["a"]

    def test_pool_only_fields_do_not_split_a_problem_from_its_stored_key(self):
        # A triage run keys a security check without `missing_header`, which
        # its FINDING_QUERIES row does not carry; the pool row does.
        base = {"label": "Vulnerability", "source": "security_check", "type": "missing_header"}
        stored = grouping.group_key(dict(base, id="s"))
        seed = dict(base, key="s", id="s", triage_group_key=stored)
        untriaged = dict(base, key="a", id="a", missing_header="x-frame-options")
        assert C.problem_key(untriaged) == stored
        assert C.exact_lenses(seed, [untriaged])["same_problem"] == ["a"]

    def test_nuclei_without_a_cve_problem_and_detector_coincide(self):
        rows = [nuclei("a"), nuclei("b"), nuclei("c", template_id="other")]
        lenses = C.exact_lenses(SEED, rows)
        assert lenses["same_problem"] == lenses["same_detector"] == ["a", "b"]

    def test_a_cve_joins_detectors_in_same_problem_only(self):
        seed = nuclei("s", template_id="t-one", cve_ids=["CVE-2021-44228"])
        other = nuclei("a", template_id="t-two", cve_ids=["CVE-2021-44228"])
        lenses = C.exact_lenses(seed, [other])
        assert lenses["same_problem"] == ["a"] and lenses["same_detector"] == []

    def test_same_host_coalesces_in_order_and_ignores_empty(self):
        seed = {"key": "s", "label": "Secret", "triage_host": "", "host": "Host-A.example.com"}
        rows = [{"key": "a", "label": "Secret", "hostname": "host-a.example.com"},
                {"key": "b", "label": "Secret", "triage_host": "host-b.example.com",
                 "host": "host-a.example.com"},
                {"key": "c", "label": "Secret", "target_hostname": "host-a.example.com"}]
        assert C.exact_lenses(seed, rows)["same_host"] == ["a", "c"]
        nowhere = {"key": "s", "label": "Secret"}
        assert C.exact_lenses(nowhere, [{"key": "d", "label": "Secret"}])["same_host"] == []

    def test_resolved_host(self):
        assert C.resolved_host({"triage_host": " ", "host": "h1", "hostname": "h2"}) == "h1"
        assert C.resolved_host({}) == ""


class TestRank:
    def _cluster(self, key, members, **rep):
        return C.Cluster(id="", detector=rep.pop("detector", "nuclei:other"),
                         severity=rep.pop("severity", "low"), fingerprint=key,
                         representative={"key": key, **rep}, members=members)

    def test_weights(self):
        seed = nuclei("s", category="exposure", cwe_ids=["CWE-200"], triage_tier="T4",
                      triage_ai_verdict="doubtful")
        problem = self._cluster("p", ["p1"])                                  # +4
        detector = self._cluster("d", ["d1"], detector="nuclei:tech-detect")  # +3
        cwe = self._cluster("w", ["w1"], cwe_ids="CWE-200, CWE-79")          # +2
        severity = self._cluster("v", ["v1"], severity="info")               # +1
        nothing = self._cluster("n", ["n1", "n2", "n3"])                     # 0
        lenses = {"same_problem": ["p1"], "same_detector": [], "same_host": []}
        ranked = C.rank_clusters(seed, [nothing, severity, cwe, detector, problem], lenses)
        assert [c.representative["key"] for c in ranked] == ["p", "d", "w", "v", "n"]
        assert [c.score for c in ranked] == [4, 3, 2, 1, 0]
        assert [c.id for c in ranked] == ["c1", "c2", "c3", "c4", "c5"]

    def test_tier_and_ai_verdict_each_add_one(self):
        seed = nuclei("s", triage_tier="T3", triage_ai_verdict="doubtful")
        both = self._cluster("b", ["b1"], triage_tier="T3", triage_ai_verdict="doubtful")
        (ranked,) = C.rank_clusters(seed, [both], {})
        assert ranked.score == 2

    def test_not_reviewed_is_no_signal(self):
        seed = nuclei("s", triage_ai_verdict="not_reviewed")
        other = self._cluster("b", ["b1"], triage_ai_verdict="not_reviewed")
        assert C.rank_clusters(seed, [other], {})[0].score == 0

    def test_ties_break_on_member_count_then_key(self):
        seed = nuclei("s")
        ranked = C.rank_clusters(seed, [self._cluster("z", ["z1"]), self._cluster("b", ["b1"]),
                                        self._cluster("a", ["a1", "a2"])], {})
        assert [c.representative["key"] for c in ranked] == ["a", "b", "z"]

    def test_at_most_sixty_are_sent(self):
        many = [self._cluster(f"k{i:03d}", [f"m{i}"]) for i in range(C.CLUSTERS_SENT_MAX + 15)]
        ranked = C.rank_clusters(nuclei("s"), many, {})
        assert len(ranked) == C.CLUSTERS_SENT_MAX
        assert ranked[-1].id == f"c{C.CLUSTERS_SENT_MAX}"

    def test_input_clusters_are_not_mutated(self):
        original = self._cluster("a", ["a1"])
        C.rank_clusters(nuclei("s"), [original], {})
        assert original.id == "" and original.score == 0


class _Recorder(dict):
    """A row that remembers every field a function asked it for."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.read = set()

    def get(self, key, default=None):
        self.read.add(key)
        return super().get(key, default)

    def __getitem__(self, key):
        self.read.add(key)
        return super().__getitem__(key)

    def __contains__(self, key):
        self.read.add(key)
        return super().__contains__(key)


#: Fields the reused triage functions read that a pool projection is not asked
#: for, each with the reason it is safe to leave out.
NOT_PROJECTED = {
    "raw_secret": "no writer stores it; the value lives in matched_text / sample",
    "secret_value": "no writer stores it; the value lives in matched_text / sample",
    "nvt_oid": "the Vulnerability projection folds it into oid",
    "key_type": "the Secret projection returns it as detector_name",
    "host": "normalise_finding_row derives it from triage_host",
    "cve_ids": "not in this label's FINDING_QUERIES entry; problem_key reads only those",
    "description": "not in this label's FINDING_QUERIES entry; problem_key reads only those",
}

BRANCHES = [("Vulnerability", s) for s in (
    "nuclei", "gvm", "security_check", "takeover_scan", "cache_poisoning", "graphql_scan",
    "ai_surface_recon", "ai_attack", "osv", "retirejs", "nmap_nse", "")] + [
    (label, "") for label in ("Secret", "JsReconFinding", "MultiscannerFinding",
                              "GithubSecret", "GithubSensitiveFile", "MalPackageFinding")]


class TestRowContract:
    @pytest.mark.parametrize("label,source", BRANCHES, ids=[f"{l}-{s or 'none'}" for l, s in BRANCHES])
    def test_required_fields_cover_what_the_reused_functions_read(self, label, source):
        required = REQUIRED_ROW_FIELDS[label]
        read = set()
        for fn in (evidence.build_bundle, grouping.group_key, score_model.detector_key):
            # All None: every `a or b` fallback is followed, so every read shows.
            row = _Recorder({f: None for f in required})
            row.update(label=label, source=source or None)
            fn(row)
            read |= row.read
        missing = sorted(read - required - set(NOT_PROJECTED))
        assert not missing, f"{label}/{source}: read but not in REQUIRED_ROW_FIELDS: {missing}"

    def test_every_pool_label_has_a_contract(self):
        from graph_db.mixins.recon.triage_mixin import MUTEABLE_LABELS
        assert set(REQUIRED_ROW_FIELDS) == set(MUTEABLE_LABELS) - {"ExploitGvm"}

    def test_contract_carries_identity_guards_and_extras(self):
        for fields in REQUIRED_ROW_FIELDS.values():
            assert {"key", "label", "node_id", "proven", "muted", "triage_factors",
                    "raw_request", "cwe_ids", "source", "severity", "name"} <= fields
