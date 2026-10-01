"""Regression tests for the fact and finding queries behind the score model.

F4  FFuf files a login path under Endpoint.category 'auth' while the queries
    matched only 'authentication', so FFuf's logins never made a host a login
    or sensitive host. And injectable_auth_hosts read `A OR B AND C`, which
    Cypher parses as `A OR (B AND C)`: every host with an authentication
    endpoint counted as injectable, injectable parameter or not.
F1  the vulnerabilities query must hand the model `detection_method`.
F5  the secrets query must hand the model `validation_info`.
F6  the GitHub queries must keep returning `repository_public`.

Run: ./agentic/run_tests.sh tests/test_fix_triage_fact_queries.py
"""

import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage import score_model as sm  # noqa: E402
from cypherfix_triage.fact_queries import (  # noqa: E402
    FINDING_QUERIES,
    PROJECT_FACT_QUERIES,
    build_project_facts,
    finding_query_by_id,
    normalise_finding_row,
)


def fact_query(name):
    return next(q["query"] for q in PROJECT_FACT_QUERIES if q["name"] == name)


def finding_query(name):
    return next(q for q in FINDING_QUERIES if q["name"] == name)


def where_clause(query: str) -> str:
    """The text between the first WHERE and the RETURN that follows it."""
    match = re.search(r"\bWHERE\b(.*?)\bRETURN\b", query, re.S)
    assert match, "query has no WHERE ... RETURN"
    return match.group(1)


def top_level_connectives(clause: str) -> list:
    """AND / OR at bracket depth 0, in order.

    Cypher binds AND tighter than OR, so an OR at the top level of a WHERE
    means "either side alone is enough", whatever the line breaks suggest.
    """
    found, depth = [], 0
    for token in re.findall(r"[(){}\[\]]|\bAND\b|\bOR\b", clause):
        if token in "({[":
            depth += 1
        elif token in ")}]":
            depth -= 1
        elif depth == 0:
            found.append(token)
    return found


def aliases(query: str) -> set:
    return set(re.findall(r"\bAS\s+([A-Za-z_][A-Za-z0-9_]*)", query))


# ---------------------------------------------------------------------------
# F4: both category spellings, and the injectable-auth precedence
# ---------------------------------------------------------------------------
class TestAuthCategorySpellings(unittest.TestCase):
    def test_sensitive_hosts_reads_ffuf_s_auth_category(self):
        clause = where_clause(fact_query("sensitive_hosts"))
        self.assertIn("'auth'", clause)
        self.assertIn("'authentication'", clause)

    def test_injectable_auth_hosts_reads_ffuf_s_auth_category(self):
        clause = where_clause(fact_query("injectable_auth_hosts"))
        self.assertIn("'auth'", clause)
        self.assertIn("'authentication'", clause)

    def test_the_category_is_still_compared_case_insensitively(self):
        for name in ("sensitive_hosts", "injectable_auth_hosts"):
            with self.subTest(query=name):
                self.assertIn("toLower(coalesce(e.category, ''))", fact_query(name))

    def test_an_auth_endpoint_makes_a_login_host_through_the_reducer(self):
        facts = build_project_facts({"sensitive_hosts": [
            {"host": "https://a.example", "login": True}]})
        self.assertIn("https://a.example", facts.login_hosts)


class TestInjectableAuthPrecedence(unittest.TestCase):
    Q = fact_query("injectable_auth_hosts")

    def test_the_injectable_parameter_is_required_for_every_endpoint(self):
        """(auth endpoint OR form) AND injectable: no OR at the top level."""
        connectives = top_level_connectives(where_clause(self.Q))
        self.assertNotIn("OR", connectives)
        self.assertEqual(connectives, ["AND"])

    def test_the_injectable_condition_is_still_there(self):
        clause = where_clause(self.Q)
        self.assertIn("EXISTS", clause)
        self.assertIn("p.is_injectable = true", clause)

    def test_the_helper_sees_the_bug_it_guards_against(self):
        old = ("WHERE toLower(coalesce(e.category, '')) = 'authentication' OR e.is_form = true\n"
               "  AND EXISTS {\n    MATCH (e)-[:HAS_PARAMETER]->(p:Parameter) "
               "WHERE p.is_injectable = true\n  }\nRETURN 1")
        self.assertIn("OR", top_level_connectives(where_clause(old)))

    def test_a_dangerous_combination_needs_the_host_in_the_set(self):
        row = {"id": "f", "source": "nuclei", "severity": "high", "host": "https://a.example"}
        plain = sm.score(row, build_project_facts({})).likelihood.value
        flagged = sm.score(row, build_project_facts(
            {"injectable_auth_hosts": [{"hosts": ["https://a.example"]}]})).likelihood.value
        self.assertGreater(flagged, plain)


# ---------------------------------------------------------------------------
# F1 / F5 / F6: the columns the model reads
# ---------------------------------------------------------------------------
class TestColumnsTheModelReads(unittest.TestCase):
    def test_the_vulnerabilities_query_returns_the_detection_method(self):
        self.assertIn("v.detection_method AS detection_method",
                      finding_query("vulnerabilities")["query"])

    def test_the_secrets_query_returns_the_validation_detail(self):
        self.assertIn("s.validation_info AS validation_info",
                      finding_query("secrets")["query"])

    def test_the_github_queries_return_repository_public(self):
        for name in ("github_secrets", "github_files"):
            with self.subTest(query=name):
                self.assertIn("repository_public", aliases(finding_query(name)["query"]))

    def test_the_new_columns_survive_the_by_id_narrowing(self):
        """An MCP reviewer reads the same row the run scores."""
        self.assertIn("AS detection_method", finding_query_by_id(finding_query("vulnerabilities")))
        self.assertIn("AS validation_info", finding_query_by_id(finding_query("secrets")))

    def test_the_new_columns_stay_out_of_the_evidence_bundle(self):
        """The bundle's hash is what a review is valid for: a new column in it
        would expire every stored review at the next run."""
        from cypherfix_triage import evidence
        rows = (
            ({"id": "v1", "label": "Vulnerability", "source": "security_check",
              "name": "WAF Bypass", "description": "d", "evidence": "e"},
             "detection_method", "ai_classifier"),
            ({"id": "s1", "label": "Secret", "source": "js_recon", "name": "payment",
              "secret_type": "Stripe Secret Key", "detector_name": "payment",
              "validation_status": "invalid", "triage_host": "https://a.example"},
             "validation_info", json.dumps({"error": "", "info": "status=401"})),
        )
        for row, column, value in rows:
            with self.subTest(column=column):
                self.assertEqual(evidence.build_bundle(row),
                                 evidence.build_bundle(dict(row, **{column: value})))

    def test_a_collected_waf_bypass_is_scored_by_its_method(self):
        row = normalise_finding_row({
            "id": "v1", "label": "Vulnerability", "source": "security_check",
            "type": "waf_bypass", "severity": "high", "detection_method": "ai_classifier",
            "triage_host": "a.example"})
        self.assertEqual(sm.score(row, build_project_facts({})).confidence.value, 0.6)

    def test_a_collected_rejected_secret_is_inactive(self):
        row = normalise_finding_row({
            "id": "s1", "label": "Secret", "source": "js_recon", "name": "payment",
            "severity": "critical", "secret_type": "Stripe Secret Key",
            "detector_name": "payment", "validation_status": "invalid",
            "validation_info": json.dumps({"status": "invalid", "valid": False,
                                           "info": "status=401", "error": ""}),
            "confidence": "high", "triage_host": "https://a.example"})
        self.assertEqual(sm.score(row, build_project_facts({})).state, sm.STATE_INACTIVE)

    def test_a_collected_github_secret_with_no_visibility_keeps_unknown_reach(self):
        row = normalise_finding_row({
            "id": "g1", "label": "GithubSecret", "source": "github_hunt",
            "name": "AWS Access Key ID", "severity": "high",
            "secret_type": "AWS Access Key ID", "detector_name": "AWS Access Key ID",
            "repository_public": None, "triage_host": "acme/repo"})
        self.assertEqual(sm.score(row, build_project_facts({})).reach.value, sm.REACH_UNKNOWN)


if __name__ == "__main__":
    unittest.main()
