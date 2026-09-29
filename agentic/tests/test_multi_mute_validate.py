"""Multi mute: validating the model's answer and assembling the groups (§4, §7.6).

The model reads scanner output and target response bodies, so every answer is
treated as possibly written by the target. What these tests hold, whatever the
answer says:

- ids that were not sent are dropped;
- a quote counts only if it is in the cluster's target evidence as sent, never
  in a label the code wrapped around it;
- a finding is pre-checked only on `match` plus an exact lens or a verified
  quote, and nothing is pre-checked when the seed reason is `unclear` (D15);
- model text is stripped of bidi and zero-width characters and capped;
- an unreadable answer degrades to the exact groups, all unchecked.

All data is synthetic: example.com hosts.

Run: ./agentic/run_tests.sh tests/test_multi_mute_validate.py
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multi_mute import clusters as C  # noqa: E402
from multi_mute import validate as V  # noqa: E402

WAF = "HTTP/1.1 403 Forbidden\n<title>Request blocked by the web application firewall</title>"
WAF_QUOTE = "Request blocked by the web application firewall"


def nuclei(key, template="waf-probe", host="https://host-b.example.com", body=WAF, **kw):
    base = {"key": key, "id": key, "label": "Vulnerability", "node_id": f"9{len(key)}",
            "source": "nuclei", "template_id": template, "severity": "low",
            "name": f"Finding {key}", "triage_host": host, "matched_at": host + "/admin",
            "raw_request": "GET /admin HTTP/1.1\nUser-Agent: scanner-probe-agent",
            "raw_response": body}
    base.update(kw)
    return base


SEED = nuclei("s", host="https://host-a.example.com")
CANDIDATES = [
    nuclei("a"),                                                     # exact: problem + detector
    nuclei("b", host="https://host-c.example.com"),                  # exact: problem + detector
    nuclei("c", template="other-probe", host="https://host-a.example.com",
           body="Maintenance page, back soon"),                      # exact: host
    nuclei("d", template="third-probe", host="https://host-z.example.com",
           body=WAF.replace("403", "406")),                          # AI only
    nuclei("e", template="fourth-probe", host="https://host-z.example.com",
           body="HTTP/1.1 200 OK\n<title>Admin console</title>"),    # AI only
]


def setup():
    lenses = C.exact_lenses(SEED, CANDIDATES)
    clusters = C.rank_clusters(SEED, C.build_clusters(SEED, CANDIDATES), lenses)
    ids = {key: c.id for c in clusters for key in c.members}
    return lenses, clusters, ids


def answer(reason="false_positive", verdicts=(), groups=(), seed_quote="", why="A WAF page."):
    body = {"seed": {"reason": reason, "why": why, "quote": seed_quote},
            "verdicts": list(verdicts), "groups": list(groups)}
    return "Here you go:\n```json\n" + json.dumps(body) + "\n```"


def run(text):
    lenses, clusters, _ = setup()
    return V.assemble(text, SEED, clusters, lenses, CANDIDATES)


def members(result):
    """key -> member dict, across every group (one checkbox per finding)."""
    out = {}
    for group in result["groups"]:
        for m in group["members"] + group["probably_not"]:
            assert out.setdefault(m["key"], m) == m, "a finding differs between groups"
    return out


def v(cid, verdict="match", quote="", why="Same WAF page."):
    return {"cluster": cid, "verdict": verdict, "quote": quote, "why": why}


class TestSetup:
    def test_fixture_shape(self):
        lenses, clusters, ids = setup()
        assert lenses == {"same_problem": ["a", "b"], "same_detector": ["a", "b"], "same_host": ["c"]}
        assert ids["a"] == ids["b"]
        assert len(clusters) == 4


class TestVerdicts:
    def test_an_invented_cluster_id_is_dropped(self):
        _, _, ids = setup()
        text = answer(verdicts=[v("c99"), v(ids["d"], quote=WAF_QUOTE.replace("Request", "request"))],
                      groups=[{"concept": "same_fp_pattern", "title": "WAF pages", "why": "x",
                               "clusters": ["c99", ids["d"]]}])
        result = run(text)
        ai = [g for g in result["groups"] if g["ai"]]
        assert len(ai) == 1 and [m["key"] for m in ai[0]["members"]] == ["d"]

    def test_the_first_verdict_per_cluster_wins(self):
        _, _, ids = setup()
        result = run(answer(verdicts=[v(ids["a"], "no"), v(ids["a"], "match")]))
        assert members(result)["a"]["verdict"] == "no"

    def test_an_unknown_or_missing_verdict_is_maybe(self):
        _, _, ids = setup()
        result = run(answer(verdicts=[v(ids["a"], "definitely"),
                                      {"cluster": ids["c"], "quote": "", "why": ""}]))
        found = members(result)
        assert found["a"]["verdict"] == "maybe" and not found["a"]["checked"]
        assert found["c"]["verdict"] == "maybe"

    def test_a_cluster_with_no_verdict_is_not_judged(self):
        result = run(answer(verdicts=[]))
        assert all(m["verdict"] is None and not m["checked"] for m in members(result).values())


class TestQuoteCheck:
    def _verified(self, quote):
        _, _, ids = setup()
        result = run(answer(verdicts=[v(ids["d"], quote=quote)],
                            groups=[{"concept": "same_fp_pattern", "title": "t", "why": "w",
                                     "clusters": [ids["d"]]}]))
        return members(result)["d"]

    def test_a_quote_from_the_target_evidence_is_verified(self):
        member = self._verified("  request BLOCKED by the web\n application firewall ")
        assert member["quote_verified"] and member["checked"]

    @pytest.mark.parametrize("quote", [
        "Matched at: https://host-z.example.com/admin",   # a label the bundle adds
        "Response: HTTP/1.1 406",                        # a label around the body
        "Template: third-probe",
        "Finding: Finding d",
        "User-Agent: scanner-probe-agent",               # the scanner's request, not the target
        "blocked",                                       # shorter than QUOTE_MIN
        "Request blocked by a reverse proxy",            # not in the evidence
    ])
    def test_a_quote_that_is_not_target_evidence_is_not_verified(self, quote):
        member = self._verified(quote)
        assert not member["quote_verified"] and not member["checked"]
        assert member["quote"] is None

    def test_a_quote_past_the_sent_excerpt_is_not_verified(self):
        tail = "hidden marker text beyond the excerpt"
        rep = nuclei("z1", body="x " * 400 + tail)
        clusters = C.rank_clusters(SEED, C.build_clusters(SEED, [rep]), {})
        result = V.assemble(answer(verdicts=[v(clusters[0].id, quote=tail)]), SEED, clusters,
                            {"same_problem": ["z1"]}, [rep])
        assert not members(result)["z1"]["quote_verified"]

    def test_the_seed_quote(self):
        assert run(answer(seed_quote=WAF_QUOTE))["read"]["quote_verified"]
        read = run(answer(seed_quote="Matched at: https://host-a.example.com/admin"))["read"]
        assert not read["quote_verified"] and read["quote"] == ""


class TestAHeaderQuoteVerifiedAnyCluster:
    """Review finding: a quote from the HTTP headers pre-checked unrelated findings.

    Every response from a server carries the same headers, so "Content-Type:
    text/html" was found in any cluster's excerpt. The excerpt also opened on
    the headers, so the model rarely saw the body it was meant to judge.
    """

    HEAD = ("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
            "Cache-Control: no-store\r\nX-Request-Id: 0f3a9c\r\n")

    def _admin(self, body_sep="\r\n"):
        return nuclei("x", template="exposed-admin", host="https://host-b.example.com",
                      body=self.HEAD + body_sep + "<title>Admin console</title>")

    def _judge_admin(self, quote, row):
        seed = nuclei("s", template="waf-detect", host="https://host-a.example.com")
        clusters = C.rank_clusters(seed, C.build_clusters(seed, [row]), {})
        groups = [{"concept": "same_fp_pattern", "title": "t", "why": "w",
                   "clusters": [clusters[0].id]}]
        result = V.assemble(answer(verdicts=[v(clusters[0].id, quote=quote)], groups=groups),
                            seed, clusters, {}, [row])
        return members(result)["x"]

    @pytest.mark.parametrize("body_sep", ["\r\n", ""], ids=["blank-line", "no-blank-line"])
    def test_a_quote_from_the_headers_does_not_pre_check(self, body_sep):
        member = self._judge_admin("Content-Type: text/html", self._admin(body_sep))
        assert member["ai_only"] and member["verdict"] == "match"
        assert not member["quote_verified"] and not member["checked"]

    def test_a_quote_from_the_body_still_pre_checks(self):
        member = self._judge_admin("<title>Admin console</title>", self._admin())
        assert member["quote_verified"] and member["checked"]

    def test_the_excerpt_opens_on_the_body(self):
        row = nuclei("x", body=self.HEAD + "X-Pad: " + "p" * 400 + "\r\n\r\n<h1>Maintenance</h1>")
        assert V.quotable_excerpt(row).startswith("<h1>Maintenance</h1>")
        assert "Maintenance" in C.evidence_text(row)[:40]

    def test_a_seed_quote_from_the_headers_is_not_verified(self):
        seed = nuclei("s", body=self.HEAD + "\r\n<title>Blocked</title>")
        lenses, clusters = {}, []
        read = V.assemble(answer(seed_quote="Cache-Control: no-store"), seed, clusters, lenses, [])["read"]
        assert not read["quote_verified"]


class TestAVerdictCoversOnlyWhatTheModelSaw:
    """Review finding: one cluster verdict pre-checked members whose deciding
    context the model never saw.

    The fingerprint strips hosts and paths, so a cluster can span them. The
    model is shown one representative.
    """

    BODY = "HTTP/1.1 200 OK\n<p>Served by the edge network</p>"

    def _assemble(self, reason, rows, seed):
        lenses = C.exact_lenses(seed, rows)
        clusters = C.rank_clusters(seed, C.build_clusters(seed, rows), lenses)
        assert len(clusters) == 1, "the fixture must collapse into one cluster"
        text = answer(reason=reason, verdicts=[v(clusters[0].id)])
        return members(V.assemble(text, seed, clusters, lenses, rows))

    def test_not_our_asset_match_does_not_pre_check_a_member_on_another_host(self):
        seed = nuclei("s", template="cdn-probe", host="https://cdn.example.net", body=self.BODY)
        rows = [nuclei("x1", template="cdn-probe", host="https://cdn.example.net", body=self.BODY),
                nuclei("x2", template="cdn-probe", host="https://app.example.com", body=self.BODY)]
        found = self._assemble("not_our_asset", rows, seed)
        assert found["x1"]["verdict"] == "match" and found["x1"]["checked"]
        assert found["x2"]["verdict"] is None and not found["x2"]["checked"]

    def test_other_reasons_still_cover_the_whole_cluster(self):
        seed = nuclei("s", template="cdn-probe", host="https://cdn.example.net", body=self.BODY)
        rows = [nuclei("x1", template="cdn-probe", host="https://cdn.example.net", body=self.BODY),
                nuclei("x2", template="cdn-probe", host="https://app.example.com", body=self.BODY)]
        found = self._assemble("false_positive", rows, seed)
        assert found["x1"]["checked"] and found["x2"]["checked"]

    def test_a_match_on_an_evidence_less_cluster_pre_checks_only_its_representative(self):
        seed = nuclei("s", template="secret-probe", host="https://host-a.example.com", body="")
        rows = [nuclei("k1", template="secret-probe", host="https://host-a.example.com",
                       body="", matched_at="https://host-a.example.com/tests/fixtures/aws.json"),
                nuclei("k2", template="secret-probe", host="https://host-b.example.com",
                       body="", matched_at="https://host-b.example.com/src/config/prod.py")]
        found = self._assemble("false_positive", rows, seed)
        assert found["k1"]["checked"]
        assert found["k2"]["verdict"] is None and not found["k2"]["checked"]


class TestPreCheck:
    def test_match_in_an_exact_lens_is_checked(self):
        _, _, ids = setup()
        found = members(run(answer(verdicts=[v(ids["a"]), v(ids["c"])])))
        assert found["a"]["checked"] and found["b"]["checked"] and found["c"]["checked"]
        assert not found["a"]["ai_only"]

    def test_ai_only_match_needs_a_verified_quote(self):
        _, _, ids = setup()
        groups = [{"concept": "same_fp_pattern", "title": "t", "why": "w",
                   "clusters": [ids["d"], ids["e"]]}]
        found = members(run(answer(verdicts=[v(ids["d"], quote=WAF_QUOTE.replace("403", "406")),
                                             v(ids["e"], quote="")], groups=groups)))
        assert found["d"]["ai_only"] and found["d"]["checked"]
        assert found["e"]["ai_only"] and not found["e"]["checked"]

    def test_maybe_is_never_checked(self):
        _, _, ids = setup()
        found = members(run(answer(verdicts=[v(ids["a"], "maybe", quote=WAF_QUOTE)])))
        assert not found["a"]["checked"]

    def test_unclear_pre_checks_nothing(self):
        _, _, ids = setup()
        groups = [{"concept": "same_fp_pattern", "title": "t", "why": "w", "clusters": [ids["d"]]}]
        result = run(answer(reason="unclear",
                            verdicts=[v(ids["a"]), v(ids["c"]), v(ids["d"], quote=WAF_QUOTE.replace("403", "406"))],
                            groups=groups))
        assert result["read"]["reason"] == "unclear"
        assert members(result) and not any(m["checked"] for m in members(result).values())

    def test_an_invalid_reason_is_unclear(self):
        _, _, ids = setup()
        result = run(answer(reason="mute_everything", verdicts=[v(ids["a"])]))
        assert result["read"]["reason"] == "unclear"
        assert not members(result)["a"]["checked"]

    def test_no_goes_to_probably_not(self):
        _, _, ids = setup()
        result = run(answer(verdicts=[v(ids["a"], "no")]))
        card = next(g for g in result["groups"] if "same_problem" in g["concepts"])
        assert card["members"] == []
        assert [m["key"] for m in card["probably_not"]] == ["a", "b"]


class TestGroups:
    def test_identical_groups_merge(self):
        result = run(answer(verdicts=[]))
        card = next(g for g in result["groups"] if "same_problem" in g["concepts"])
        assert card["concepts"] == ["same_detector", "same_problem"]
        assert card["labels"] == ["Same detector", "Same issue elsewhere"]
        assert not card["ai"]
        assert sum("same_problem" in g["concepts"] or "same_detector" in g["concepts"]
                   for g in result["groups"]) == 1

    def test_an_ai_group_equal_to_an_exact_lens_joins_its_card(self):
        _, _, ids = setup()
        groups = [{"concept": "same_fp_pattern", "title": "WAF block pages", "why": "w",
                   "clusters": [ids["a"]]}]
        result = run(answer(verdicts=[v(ids["a"])], groups=groups))
        card = result["groups"][0]
        assert card["concepts"] == ["same_fp_pattern", "same_detector", "same_problem"]
        assert card["title"] == "WAF block pages" and not card["ai"]

    def test_the_model_may_only_propose_ai_concepts(self):
        _, _, ids = setup()
        groups = [{"concept": "same_detector", "title": "t", "why": "w", "clusters": [ids["d"]]},
                  {"concept": "mute_all", "title": "t", "why": "w", "clusters": [ids["e"]]}]
        result = run(answer(verdicts=[v(ids["d"]), v(ids["e"])], groups=groups))
        assert not any(g["ai"] for g in result["groups"])

    def test_rejected_and_unjudged_clusters_are_left_out(self):
        _, _, ids = setup()
        groups = [{"concept": "same_low_risk", "title": "t", "why": "w", "clusters": [ids["e"]]},
                  {"concept": "same_low_risk", "title": "t", "why": "w", "clusters": [ids["d"]]}]
        result = run(answer(reason="not_worth_fixing", verdicts=[v(ids["e"], "no")], groups=groups))
        assert not any(g["ai"] for g in result["groups"])

    def test_at_most_four_ai_groups(self):
        # Assembly merges equal member sets, so the cap is asserted where it applies.
        _, clusters, _ = setup()
        judged = V._judge([v(c.id, "maybe") for c in clusters], clusters)
        groups = [{"concept": "same_fp_pattern", "title": f"group {i}", "why": "w",
                   "clusters": [clusters[i % len(clusters)].id]} for i in range(7)]
        assert len(V._ai_groups(groups, judged)) == V.GROUPS_AI_MAX

    def test_model_text_is_capped_and_stripped(self):
        _, _, ids = setup()
        title = "WAF‮ pages​ " + "x" * 100
        why = "⁦Because⁩ " + "y" * 400
        groups = [{"concept": "same_fp_pattern", "title": title, "why": why, "clusters": [ids["d"]]}]
        result = run(answer(verdicts=[v(ids["d"], why="‏same‍ page " + "z" * 300)],
                            groups=groups))
        card = next(g for g in result["groups"] if g["ai"])
        assert card["title"].startswith("WAF pages") and len(card["title"]) <= V.TITLE_MAX
        assert card["why"].startswith("Because") and len(card["why"]) <= V.WHY_MAX
        member = card["members"][0]
        assert member["why"].startswith("same page") and len(member["why"]) <= V.WHY_MAX

    def test_same_host_label_names_the_host(self):
        result = run(answer(reason="not_our_asset"))
        assert result["groups"][0]["labels"] == ["Same host: https://host-a.example.com"]

    @pytest.mark.parametrize("reason,order", [
        ("false_positive", ["same_fp_pattern", "same_detector", "same_host"]),
        ("not_worth_fixing", ["same_detector", "same_host", "same_fp_pattern"]),
        ("not_our_asset", ["same_host", "same_problem", "same_fp_pattern"]),
        ("unclear", ["same_problem", "same_host", "same_fp_pattern"]),
    ])
    def test_groups_are_ordered_by_the_seed_reason(self, reason, order):
        _, _, ids = setup()
        groups = [{"concept": "same_fp_pattern", "title": "t", "why": "w", "clusters": [ids["d"]]}]
        result = run(answer(reason=reason, verdicts=[v(ids["d"])], groups=groups))
        assert [g["concepts"][0] for g in result["groups"]] == order
        assert [g["id"] for g in result["groups"]] == ["g1", "g2", "g3"]

    def test_member_shape(self):
        _, _, ids = setup()
        result = run(answer(verdicts=[v(ids["a"])]))
        member = members(result)["a"]
        assert set(member) == {"key", "node_id", "name", "host", "severity", "verdict", "why",
                               "quote", "quote_verified", "checked", "ai_only"}
        assert member["name"] == "Finding a" and member["host"] == "https://host-b.example.com"
        assert member["severity"] == "low" and member["node_id"] == "91"

    def test_target_names_are_cleaned_for_display(self):
        seed = nuclei("s")
        row = nuclei("n1", name="Admin‮ fdp.exe")
        result = V.exact_only(seed, {"same_problem": ["n1"]}, [row])
        assert result["groups"][0]["members"][0]["name"] == "Admin fdp.exe"

    def test_empty_groups_are_dropped(self):
        result = V.exact_only(SEED, {"same_problem": [], "same_detector": ["ghost"], "same_host": []},
                              CANDIDATES)
        assert result["groups"] == []


class TestUnreadable:
    @pytest.mark.parametrize("text", [
        None, "", "I think these all look fine to mute.", "[1, 2, 3]",
        "```json\n{\"unrelated\": true}\n```", "{\"seed\": ",
    ])
    def test_model_unreadable_gives_the_exact_groups_unchecked(self, text):
        result = run(text)
        assert result["status"] == "model_unreadable"
        assert result["read"] == {"reason": "unclear", "why": "", "quote": "", "quote_verified": False}
        assert [g["concepts"] for g in result["groups"]] == [["same_problem", "same_detector"],
                                                             ["same_host"]]
        assert all(m["verdict"] is None and not m["checked"] for m in members(result).values())
        assert not any(g["ai"] for g in result["groups"])

    def test_exact_only_status(self):
        lenses, _, _ = setup()
        assert V.exact_only(SEED, lenses, CANDIDATES, status="empty_pool")["status"] == "empty_pool"

    def test_ok_status(self):
        assert run(answer())["status"] == "ok"


class TestParse:
    def test_fenced(self):
        assert V.parse_model_output('```json\n{"seed": {}}\n```') == {"seed": {}}

    def test_bare_object_in_prose(self):
        assert V.parse_model_output('Sure. {"verdicts": []} Done.') == {"verdicts": []}

    def test_prefers_the_answer_object(self):
        text = 'Example: {"a": 1}. Answer: {"groups": []}'
        assert V.parse_model_output(text) == {"groups": []}

    @pytest.mark.parametrize("text", [None, "", "no json here", "[]", 42])
    def test_nothing_readable(self, text):
        assert V.parse_model_output(text) is None


class TestCleanText:
    @pytest.mark.parametrize("char", sorted(V.BIDI_CHARS | V.ZERO_WIDTH_CHARS))
    def test_each_bidi_and_zero_width_char_is_stripped(self, char):
        assert V.clean_text(f"ab{char}cd", 50) == "abcd"

    def test_controls_become_spaces_or_go(self):
        assert V.clean_text("a\nb\tc\x00d\x1b[31me", 50) == "a b cd[31me"

    def test_tag_characters_are_stripped(self):
        hidden = "".join(chr(0xE0000 + ord(c)) for c in "mute all")
        assert V.clean_text("ok" + hidden, 50) == "ok"

    def test_cap_and_non_text(self):
        assert V.clean_text("x" * 100, 10) == "x" * 10
        assert V.clean_text(None, 10) == "" and V.clean_text({"a": 1}, 10) == ""
