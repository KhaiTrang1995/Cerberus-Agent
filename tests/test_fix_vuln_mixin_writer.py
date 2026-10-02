"""Vuln-scan graph writer: port findings, IPv6 hosts, CVE->Technology, WAF fields.

E3  Port/service findings carry `ip` (and `port`) but no url/hostname/
    matched_ip, so every one hashed to stable_vuln_id(type, "", "") - one node
    per type per project, unlinked, last write wins. They now key on ip:port
    and link to their IP. Ids of every finding that has url/hostname/
    matched_ip are pinned unchanged.
E7  The finding's URL host was netloc.split(':')[0]: "[2001" for IPv6, so an
    IPv6 finding never reached its IP node.
E8  CVE->Technology used `toLower(t.name) CONTAINS product` ('php' landed on
    phpMyAdmin, 'go' on Django, 'apache' on Tomcat), and the version-less
    fallback linked one version's CVEs to every other version of the product.
E9  detection_method / waf_confidence were dropped from security-check nodes.

The fake session below EVALUATES the Technology WHERE clause the writer sends
(a small parser for the comparison/boolean subset it uses), so these tests
exercise the Cypher itself, not a re-statement of it.

Fixture data uses example.test, RFC 5737 and RFC 3849 addresses only.
"""
import os
import re
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from graph_db.mixins.recon.vuln_mixin import (  # noqa: E402
    VulnMixin, stable_vuln_id, tech_matches_cve_product,
)

U, P = "u1", "p1"


# --------------------------------------------------------------------------- #
# A tiny evaluator for the WHERE clause of the HAS_KNOWN_CVE queries.
# Grammar: OR / AND / NOT over comparisons `operand (= | <> | =~ | CONTAINS)
# operand`; operands are toLower(x), coalesce(x, y), t.<prop>, $param, 'str'.
# Null semantics follow Cypher closely enough: a comparison with a null side is
# null, and null is falsy at the top.
# --------------------------------------------------------------------------- #
_TOKEN = re.compile(r"\s*(=~|<>|=|\(|\)|,|\$\w+|'[^']*'|[A-Za-z_][\w.]*)")


def _tokenize(text):
    pos, out = 0, []
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ValueError(f"cannot tokenize at: {text[pos:pos + 30]!r}")
        out.append(m.group(1))
        pos = m.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
    return out


class _Where:
    def __init__(self, text, node, params):
        self.toks, self.i = _tokenize(text), 0
        self.node, self.params = node, params

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self, expected=None):
        tok = self.toks[self.i]
        if expected is not None and tok.upper() != expected:
            raise ValueError(f"expected {expected}, got {tok}")
        self.i += 1
        return tok

    def evaluate(self):
        value = self.expr()
        if self.peek() is not None:
            raise ValueError(f"trailing tokens: {self.toks[self.i:]}")
        return bool(value)

    def expr(self):
        value = self.term()
        while (self.peek() or "").upper() == "OR":
            self.take()
            rhs = self.term()
            value = True if (value or rhs) else (None if value is None or rhs is None else False)
        return value

    def term(self):
        value = self.factor()
        while (self.peek() or "").upper() == "AND":
            self.take()
            rhs = self.factor()
            value = False if (value is False or rhs is False) else (
                None if value is None or rhs is None else True)
        return value

    def factor(self):
        if (self.peek() or "").upper() == "NOT":
            self.take()
            value = self.factor()
            return None if value is None else not value
        if self.peek() == "(":
            self.take()
            value = self.expr()
            self.take(")")
            return value
        left = self.operand()
        op = self.take().upper()
        right = self.operand()
        if left is None or right is None:
            return None
        if op == "=":
            return left == right
        if op == "<>":
            return left != right
        if op == "=~":
            return re.fullmatch(right, left) is not None
        if op == "CONTAINS":
            return right in left
        raise ValueError(f"unsupported operator {op}")

    def operand(self):
        tok = self.take()
        if tok.startswith("$"):
            return self.params.get(tok[1:])
        if tok.startswith("'"):
            return tok[1:-1]
        if tok.startswith("t."):
            return self.node.get(tok[2:])
        fn = tok.lower()
        self.take("(")
        args = [self.operand()]
        while self.peek() == ",":
            self.take()
            args.append(self.operand())
        self.take(")")
        if fn == "tolower":
            return None if args[0] is None else str(args[0]).lower()
        if fn == "coalesce":
            return next((a for a in args if a is not None), None)
        raise ValueError(f"unsupported function {tok}")


def _where_clause(query):
    m = re.search(r"WHERE(.*?)MATCH \(c:CVE", query, re.S)
    assert m, query
    return m.group(1)


class _Result:
    def __init__(self, row):
        self.row = row

    def single(self):
        return self.row

    def __iter__(self):
        return iter([])


class _Session:
    """Records every query; answers the CVE->Technology MERGE from `techs`."""

    def __init__(self, techs=(), matched=1):
        self.calls = []
        self.techs = list(techs)
        self.cve_links = []
        self.matched = matched

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        if "HAS_KNOWN_CVE" in query and "MATCH (t:Technology" in query:
            assert params["user_id"] == U and params["project_id"] == P
            where = _where_clause(query)
            hits = [t for t in self.techs if _Where(where, t, params).evaluate()]
            for t in hits:
                self.cve_links.append((t["name"], t.get("version"), params["cve_id"]))
            return _Result({"matched": len(hits)})
        return _Result({"matched": self.matched, "linked": 0})

    def vuln_props(self):
        return [p["props"] for q, p in self.calls if "MERGE (v:Vulnerability" in q]

    def links(self, pattern):
        """Params of each `MATCH (<pattern> ...) ... HAS_VULNERABILITY` link query."""
        return [p for q, p in self.calls
                if f"MATCH ({pattern} " in q and "HAS_VULNERABILITY" in q]


def _writer(session):
    w = VulnMixin()
    w.driver = MagicMock()
    w.driver.session.return_value = session
    return w


def _security_findings(findings, session=None):
    session = session or _Session()
    recon = {"domain": "example.test",
             "vuln_scan": {"security_checks": {"findings": findings}}}
    stats = _writer(session).update_graph_from_vuln_scan(recon, U, P)
    assert stats["errors"] == [], stats["errors"]
    return session


# --------------------------------------------------------------------------- #
# E3 - port-scoped findings
# --------------------------------------------------------------------------- #
def _port_finding(ftype, ip, port, service="SSH", severity="medium"):
    return {"type": ftype, "severity": severity, "name": f"{service} Port Exposed",
            "description": "d", "ip": ip, "port": port, "service": service,
            "evidence": f"Port {port} ({service}) is open", "recommendation": "r"}


class TestPortFindingsAreOnePerIpAndPort(unittest.TestCase):
    def test_distinct_ips_and_ports_get_distinct_nodes(self):
        session = _security_findings([
            _port_finding("admin_port_exposed", "198.51.100.1", 22),
            _port_finding("admin_port_exposed", "198.51.100.2", 22),
            _port_finding("database_exposed", "198.51.100.1", 3306, "MySQL", "high"),
            _port_finding("database_exposed", "198.51.100.1", 5432, "PostgreSQL", "high"),
        ])
        ids = [p["id"] for p in session.vuln_props()]
        self.assertEqual(len(set(ids)), 4, "port findings collapsed into one node per type")
        self.assertEqual(ids[0], stable_vuln_id("admin_port_exposed", "", "198.51.100.1:22", U, P))
        self.assertEqual(ids[2], stable_vuln_id("database_exposed", "", "198.51.100.1:3306", U, P))

    def test_each_is_linked_to_its_ip_with_tenant_keys(self):
        session = _security_findings([
            _port_finding("admin_port_exposed", "198.51.100.1", 22),
            _port_finding("redis_no_auth", "2001:db8::7", 6379, "Redis", "critical"),
        ])
        links = session.links("i:IP")
        self.assertEqual([(p["address"], p["vuln_id"]) for p in links],
                         [(p["matched_ip"], p["id"]) for p in session.vuln_props()])
        for p in links:
            self.assertEqual((p["user_id"], p["project_id"]), (U, P))

    def test_the_node_carries_ip_port_and_service(self):
        [props] = _security_findings([_port_finding("admin_port_exposed", "198.51.100.1", 22)]).vuln_props()
        self.assertEqual(props["matched_ip"], "198.51.100.1")
        self.assertEqual(props["port"], 22)
        self.assertEqual(props["service"], "SSH")
        self.assertEqual(props["url"], "")

    def test_ipv6_port_key_is_bracketed(self):
        [props] = _security_findings([_port_finding("redis_no_auth", "2001:db8::7", 6379)]).vuln_props()
        self.assertEqual(props["id"], stable_vuln_id("redis_no_auth", "", "[2001:db8::7]:6379", U, P))


class TestExistingIdsAreUnchanged(unittest.TestCase):
    """Every shape produced before the fix keeps its exact id (fix items, mutes)."""

    CASES = [
        ({"type": "direct_ip_http", "url": "http://198.51.100.10", "matched_ip": "198.51.100.10"},
         ("direct_ip_http", "http://198.51.100.10", "198.51.100.10")),
        ({"type": "waf_bypass", "url": "https://198.51.100.10", "matched_ip": "198.51.100.10",
          "subdomain": "www.example.test", "detection_method": "static_headers"},
         ("waf_bypass", "https://198.51.100.10", "198.51.100.10")),
        ({"type": "missing_coop", "url": "https://www.example.test", "hostname": "www.example.test"},
         ("missing_coop", "https://www.example.test", "www.example.test")),
        ({"type": "tls_self_signed", "url": "https://198.51.100.10:8443", "port": 8443,
          "matched_ip": "198.51.100.10"},
         ("tls_self_signed", "https://198.51.100.10:8443", "198.51.100.10")),
        ({"type": "kubernetes_api_exposed", "url": "https://198.51.100.10:6443/api",
          "ip": "198.51.100.10", "port": 6443},
         ("kubernetes_api_exposed", "https://198.51.100.10:6443/api", "")),
        ({"type": "spf_missing", "domain": "example.test"}, ("spf_missing", "", "")),
        ({"type": "no_rate_limiting", "url": "https://www.example.test/login",
          "hostname": "www.example.test"},
         ("no_rate_limiting", "https://www.example.test/login", "www.example.test")),
    ]

    def test_ids(self):
        findings = [dict(f, severity="low", name="n", description="d") for f, _ in self.CASES]
        ids = [p["id"] for p in _security_findings(findings).vuln_props()]
        self.assertEqual(ids, [stable_vuln_id(*key, U, P) for _, key in self.CASES])

    def test_the_hash_itself_is_pinned(self):
        self.assertEqual(stable_vuln_id("direct_ip_http", "http://198.51.100.10",
                                        "198.51.100.10", "u1", "p1"), "12648af07e21")
        self.assertEqual(stable_vuln_id("spf_missing", "", "", "u1", "p1"), "7813f29eacbc")


# --------------------------------------------------------------------------- #
# E7 - IPv6 URL host
# --------------------------------------------------------------------------- #
class TestIpv6UrlHost(unittest.TestCase):
    def test_an_ipv6_finding_links_to_its_ip_node(self):
        session = _security_findings([{
            "type": "ip_api_exposed", "severity": "high", "name": "n", "description": "d",
            "url": "http://[2001:db8::30]/api", "matched_ip": "2001:db8::30"}])
        self.assertEqual([p["address"] for p in session.links("i:IP")], ["2001:db8::30"])
        self.assertEqual(session.links("bu:BaseURL"), [])

    def test_ipv4_and_hostname_links_are_unchanged(self):
        session = _security_findings([
            {"type": "direct_ip_http", "severity": "medium", "name": "n", "description": "d",
             "url": "http://198.51.100.10:8080", "matched_ip": "198.51.100.10"},
            {"type": "missing_coop", "severity": "info", "name": "n", "description": "d",
             "url": "https://www.example.test:8443", "hostname": "www.example.test"},
        ])
        self.assertEqual([p["address"] for p in session.links("i:IP")], ["198.51.100.10"])
        self.assertEqual([p["baseurl"] for p in session.links("bu:BaseURL")],
                         ["https://www.example.test:8443"])


# --------------------------------------------------------------------------- #
# E9 - reliability fields
# --------------------------------------------------------------------------- #
class TestWafReliabilityFields(unittest.TestCase):
    def test_detection_method_and_confidence_are_kept(self):
        [props] = _security_findings([{
            "type": "waf_bypass", "severity": "high", "name": "n", "description": "d",
            "url": "https://198.51.100.10", "matched_ip": "198.51.100.10",
            "subdomain": "www.example.test", "detection_method": "ai_classifier",
            "waf_confidence": 88, "waf_type": "Imperva", "ai_reasoning": "blocked page"}]).vuln_props()
        self.assertEqual(props["detection_method"], "ai_classifier")
        self.assertEqual(props["waf_confidence"], 88)
        self.assertEqual(props["waf_type"], "Imperva")
        self.assertEqual(props["id"], stable_vuln_id("waf_bypass", "https://198.51.100.10",
                                                     "198.51.100.10", U, P))

    def test_absent_fields_are_not_written(self):
        [props] = _security_findings([{
            "type": "waf_bypass", "severity": "medium", "name": "n", "description": "d",
            "url": "https://198.51.100.10", "matched_ip": "198.51.100.10"}]).vuln_props()
        for key in ("detection_method", "waf_confidence", "waf_type", "ai_reasoning", "service"):
            self.assertNotIn(key, props)


# --------------------------------------------------------------------------- #
# E8 - CVE -> Technology
# --------------------------------------------------------------------------- #
def _tech_cves(entries, techs):
    """entries: (key, product, version, cve_id). techs: [{name, version}]."""
    by_tech = {key: {"technology": key, "product": product, "version": version,
                     "cves": [{"id": cve, "cvss": 7.5, "severity": "HIGH"}]}
               for key, product, version, cve in entries}
    session = _Session(techs)
    recon = {"domain": "example.test", "vuln_scan": {"scan_metadata": {}},
             "technology_cves": {"by_technology": by_tech}}
    stats = _writer(session).update_graph_from_vuln_scan(recon, U, P)
    assert stats["errors"] == [], stats["errors"]
    return sorted((n, v) for n, v, _ in session.cve_links)


class TestCveAttachesToTheRightProduct(unittest.TestCase):
    def test_php_cves_skip_php_applications(self):
        links = _tech_cves([("PHP:7.4.3", "php", "7.4.3", "CVE-2020-0001")], [
            {"name": "PHP", "version": ""},
            {"name": "phpMyAdmin", "version": ""},
            {"name": "phpBB", "version": ""},
            {"name": "PHPMailer", "version": "6.1.6"},
        ])
        self.assertEqual(links, [("PHP", "")])

    def test_go_cves_skip_django_mongodb_and_google(self):
        links = _tech_cves([("Go:1.16", "go", "1.16", "CVE-2021-0002")], [
            {"name": "Go", "version": ""},
            {"name": "Django", "version": ""},
            {"name": "MongoDB", "version": ""},
            {"name": "Google Analytics", "version": ""},
        ])
        self.assertEqual(links, [("Go", "")])

    def test_react_cves_skip_preact(self):
        links = _tech_cves([("React:16.0.0", "react", "16.0.0", "CVE-2018-0003")], [
            {"name": "React", "version": None},
            {"name": "Preact", "version": ""},
            {"name": "React Router", "version": ""},
        ])
        self.assertEqual(links, [("React", None)])

    def test_apache_httpd_cves_skip_other_apache_projects(self):
        links = _tech_cves([("Apache/2.4.49", "apache", "2.4.49", "CVE-2021-41773")], [
            {"name": "Apache HTTP Server", "version": ""},
            {"name": "Apache Tomcat", "version": ""},
            {"name": "Apache Solr", "version": "8.11.1"},
            {"name": "Apache Traffic Server", "version": ""},
        ])
        self.assertEqual(links, [("Apache HTTP Server", "")])

    def test_one_versions_cves_do_not_spread_to_other_versions(self):
        links = _tech_cves([("OpenSSH/8.2p1", "openssh", "8.2", "CVE-2020-15778")], [
            {"name": "OpenSSH/9.6p1", "version": "9.6p1"},
            {"name": "OpenSSH", "version": "9.6"},
        ])
        self.assertEqual(links, [])


class TestLegitimateMatchesAreKept(unittest.TestCase):
    def test_exact_version_on_every_detector_spelling(self):
        links = _tech_cves([("Nginx:1.18.0", "nginx", "1.18.0", "CVE-2021-23017")], [
            {"name": "Nginx", "version": "1.18.0"},
            {"name": "nginx/1.18.0", "version": "1.18.0"},
            {"name": "Nginx Unit", "version": "1.18.0"},
        ])
        self.assertEqual(links, [("Nginx", "1.18.0"), ("nginx/1.18.0", "1.18.0")])

    def test_nmap_node_whose_version_carries_a_suffix(self):
        links = _tech_cves([("OpenSSH/8.2p1", "openssh", "8.2", "CVE-2020-15778")], [
            {"name": "OpenSSH/8.2p1", "version": "8.2p1"},
        ])
        self.assertEqual(links, [("OpenSSH/8.2p1", "8.2p1")])

    def test_vendor_prefixed_and_descriptor_suffixed_names(self):
        links = _tech_cves([("Microsoft-IIS/10.0", "iis", "10.0", "CVE-2022-0004")], [
            {"name": "IIS", "version": "10.0"},
            {"name": "Microsoft IIS httpd/10.0", "version": "10.0"},
        ])
        self.assertEqual(links, [("IIS", "10.0"), ("Microsoft IIS httpd/10.0", "10.0")])

    def test_apache_http_server_and_nmap_apache_httpd(self):
        links = _tech_cves([("Apache HTTP Server:2.4.41", "apache", "2.4.41", "CVE-2020-0005")], [
            {"name": "Apache HTTP Server", "version": "2.4.41"},
            {"name": "Apache httpd/2.4.41", "version": "2.4.41"},
            {"name": "Apache Tomcat", "version": "2.4.41"},
        ])
        self.assertEqual(links, [("Apache HTTP Server", "2.4.41"), ("Apache httpd/2.4.41", "2.4.41")])

    def test_versionless_node_of_the_product_still_gets_the_cve(self):
        links = _tech_cves([("Apache-Coyote/1.1", "tomcat", "1.1", "CVE-2020-0006"),
                            ("jQuery:3.4.1", "jquery", "3.4.1", "CVE-2020-11022")], [
            {"name": "Apache Tomcat", "version": ""},
            {"name": "jQuery", "version": ""},
            {"name": "jQuery UI", "version": ""},
        ])
        self.assertEqual(links, [("Apache Tomcat", ""), ("jQuery", "")])

    def test_trailing_zero_release_is_the_same_version(self):
        links = _tech_cves([("Microsoft-IIS/10", "iis", "10", "CVE-2022-0007")], [
            {"name": "IIS", "version": "10.0"},
        ])
        self.assertEqual(links, [("IIS", "10.0")])

    def test_a_match_on_the_exact_version_skips_the_fallback(self):
        links = _tech_cves([("Nginx:1.18.0", "nginx", "1.18.0", "CVE-2021-23017")], [
            {"name": "Nginx", "version": "1.18.0"},
            {"name": "nginx", "version": ""},
        ])
        self.assertEqual(links, [("Nginx", "1.18.0")])

    def test_cypher_is_parameterised_and_tenant_scoped(self):
        session = _Session([{"name": "PHP", "version": "7.4.3"}])
        recon = {"domain": "example.test", "vuln_scan": {"scan_metadata": {}},
                 "technology_cves": {"by_technology": {"PHP:7.4.3": {
                     "product": "php", "version": "7.4.3", "cves": [{"id": "CVE-2020-0001"}]}}}}
        _writer(session).update_graph_from_vuln_scan(recon, U, P)
        [(query, params)] = [(q, p) for q, p in session.calls if "HAS_KNOWN_CVE" in q]
        self.assertIn("MATCH (t:Technology {user_id: $user_id, project_id: $project_id})", query)
        self.assertIn("$tech_name_regex", query)
        self.assertNotIn("php", query.lower().replace("$tech_product", ""))


class TestPredicateTable(unittest.TestCase):
    """(Technology.name, CVE product) -> attach? The same regex the Cypher uses."""

    TABLE = [
        ("Nginx", "nginx", True), ("nginx/1.18.0", "nginx", True), ("NGINX", "nginx", True),
        ("Nginx Unit", "nginx", False),
        ("PHP", "php", True), ("phpMyAdmin", "php", False), ("phpBB", "php", False),
        ("PHPMailer", "php", False),
        ("Go", "go", True), ("Django", "go", False), ("MongoDB", "go", False),
        ("Google Analytics", "go", False),
        ("React", "react", True), ("Preact", "react", False), ("React Router", "react", False),
        ("Apache HTTP Server", "apache", True), ("Apache httpd/2.4.41", "apache", True),
        ("Apache", "apache", True), ("Apache/2.4.49 (Unix)", "apache", True),
        ("Apache Tomcat", "apache", False), ("Apache Solr", "apache", False),
        ("Apache Tomcat", "tomcat", True), ("Apache Tomcat/Coyote JSP engine/1.1", "tomcat", True),
        ("IIS", "iis", True), ("Microsoft IIS httpd/10.0", "iis", True), ("Microsoft-IIS", "iis", True),
        ("OpenSSH/8.2p1 Ubuntu 4ubuntu0.5", "openssh", True), ("OpenSSH", "openssh", True),
        ("jQuery", "jquery", True), ("jQuery UI", "jquery", False), ("jQuery Migrate", "jquery", False),
        ("Node.js Express framework", "express", True), ("Node.js", "node.js", True),
        ("Node.js Express framework", "node.js", False),
        ("Squid http proxy", "squid", True), ("PostgreSQL DB/12.2", "postgresql", True),
        ("Oracle WebLogic Server", "weblogic server", True),
        ("F5 BIG-IP", "f5 big-ip", True),
    ]

    def test_table(self):
        wrong = [(name, product, want) for name, product, want in self.TABLE
                 if tech_matches_cve_product(name, product) is not want]
        self.assertEqual(wrong, [])

    def test_exact_names_always_match(self):
        self.assertTrue(tech_matches_cve_product("Ruby on Rails", "rails", "Ruby on Rails"))
        self.assertTrue(tech_matches_cve_product("OpenSSH/8.2p1", "openssh", "OpenSSH/8.2p1"))

    def test_never_wider_than_the_old_substring_rule(self):
        # Every attach still needs the product inside the name, as before.
        for name, product, _ in self.TABLE:
            if tech_matches_cve_product(name, product):
                self.assertIn(product, name.lower())


# --------------------------------------------------------------------------- #
# Review regressions
# --------------------------------------------------------------------------- #
class TestReviewRegressions(unittest.TestCase):
    def test_regression_version_dotted_qualifier_unlinked(self):
        # nmap's own node keeps the qualifier ("9.4.44.v20210927") while the
        # CVE lookup's version is the numeric part ("9.4.44"): Try 1 misses on
        # the exact version and the fallback rejected ".v...", so the CVE
        # linked to nothing.
        links = _tech_cves([
            ("Jetty/9.4.44.v20210927", "jetty", "9.4.44", "CVE-2021-0101"),
            ("Spring Framework/5.3.20.RELEASE", "spring framework", "5.3.20", "CVE-2022-0102"),
            ("JBoss/7.1.1.Final", "jboss", "7.1.1", "CVE-2012-0103"),
            ("Apache Tomcat/9.0.0.M26", "tomcat", "9.0.0", "CVE-2017-0104"),
        ], [
            {"name": "Jetty/9.4.44.v20210927", "version": "9.4.44.v20210927"},
            {"name": "Spring Framework/5.3.20.RELEASE", "version": "5.3.20.RELEASE"},
            {"name": "JBoss/7.1.1.Final", "version": "7.1.1.Final"},
            {"name": "Apache Tomcat/9.0.0.M26", "version": "9.0.0.M26"},
        ])
        self.assertEqual(links, [
            ("Apache Tomcat/9.0.0.M26", "9.0.0.M26"),
            ("JBoss/7.1.1.Final", "7.1.1.Final"),
            ("Jetty/9.4.44.v20210927", "9.4.44.v20210927"),
            ("Spring Framework/5.3.20.RELEASE", "5.3.20.RELEASE"),
        ])

    def test_regression_version_dotted_qualifier_keeps_other_versions_apart(self):
        from graph_db.mixins.recon.vuln_mixin import tech_version_regex
        table = [
            ("9.4.44", "9.4.44.v20210927", True), ("5.3.20", "5.3.20.RELEASE", True),
            ("7.1.1", "7.1.1.Final", True), ("9.0.0", "9.0.0.M26", True),
            ("8.2", "8.2p1", True), ("8.2", "8.2-1ubuntu", True), ("10", "10.0", True),
            ("8.2", "8.20", False), ("8.2", "8.2.1", False), ("9.4.4", "9.4.44.v1", False),
            ("9.4.44", "9.4.44.1.v1", False), ("8.2", "8.2.", False),
        ]
        wrong = [(v, node, want) for v, node, want in table
                 if (re.fullmatch(tech_version_regex(v), node) is not None) is not want]
        self.assertEqual(wrong, [])

    def test_regression_nmap_multiword_product_names_unlinked(self):
        links = _tech_cves([
            ("openresty/1.19.3.1", "openresty", "1.19.3.1", "CVE-2021-0201"),
            ("Elasticsearch:7.10.2", "elasticsearch", "7.10.2", "CVE-2021-0202"),
            ("Golang:1.16", "golang", "1.16", "CVE-2021-0203"),
            ("Samba:4.6.2", "samba", "4.6.2", "CVE-2017-0204"),
        ], [
            {"name": "OpenResty web app server/1.19.3.1", "version": "1.19.3.1"},
            {"name": "Elasticsearch REST API/7.10.2", "version": "7.10.2"},
            {"name": "Golang net/http server", "version": ""},
            {"name": "Samba smbd/4.6.2", "version": "4.6.2"},
        ])
        self.assertEqual(links, [
            ("Elasticsearch REST API/7.10.2", "7.10.2"),
            ("Golang net/http server", ""),
            ("OpenResty web app server/1.19.3.1", "1.19.3.1"),
            ("Samba smbd/4.6.2", "4.6.2"),
        ])

    def test_regression_nmap_multiword_product_names_stay_product_exact(self):
        table = [
            ("OpenResty web app server/1.19.3.1", "openresty", True),
            ("Elasticsearch REST API/7.10.2", "elasticsearch", True),
            ("Golang net/http server", "golang", True), ("Samba smbd/4.6.2", "samba", True),
            ("IBM WebSphere Application Server", "websphere", True),
            ("WordPress REST API", "wordpress", True),
            # The cross-product cases the whole-name rule exists for.
            ("phpMyAdmin", "php", False), ("Django", "go", False), ("Preact", "react", False),
            ("Apache Tomcat", "apache", False), ("jQuery UI", "jquery", False),
            # Products of their own behind a generic word.
            ("Django REST framework", "django", False),
            ("Node.js Express framework", "node.js", False),
        ]
        wrong = [(name, product, want) for name, product, want in table
                 if tech_matches_cve_product(name, product) is not want]
        self.assertEqual(wrong, [])

    def test_regression_port_findings_share_one_delta_key(self):
        session = _security_findings([
            _port_finding("admin_port_exposed", "198.51.100.1", 22),
            _port_finding("admin_port_exposed", "198.51.100.2", 22),
            _port_finding("redis_no_auth", "2001:db8::7", 6379, "Redis", "critical"),
            {"type": "missing_coop", "severity": "info", "name": "n", "description": "d",
             "url": "https://www.example.test", "hostname": "www.example.test"},
        ])
        props = session.vuln_props()
        self.assertEqual([p["matched_at"] for p in props], [
            "198.51.100.1:22", "198.51.100.2:22", "[2001:db8::7]:6379",
            "https://www.example.test"])
        # webapp/src/lib/reconDelta.ts: IDENTITY_KEYS.Vulnerability, empty values dropped.
        delta_keys = {"|".join(str(p[k]) for k in ("template_id", "matched_at", "name")
                               if p.get(k) not in (None, "")) for p in props}
        self.assertEqual(len(delta_keys), 4)
        # The id stays keyed as before, and a skipped host still protects it.
        self.assertEqual(props[0]["id"],
                         stable_vuln_id("admin_port_exposed", "", "198.51.100.1:22", U, P))
        from graph_db.mixins.base_mixin import keep_host_patterns
        for host, matched_at in (("198.51.100.1", "198.51.100.1:22"),
                                 ("2001:db8::7", "[2001:db8::7]:6379")):
            [rx] = keep_host_patterns([host])
            self.assertIsNotNone(re.fullmatch(rx, matched_at), matched_at)

    def test_regression_domain_link_counted_without_a_domain(self):
        session = _Session(matched=0)
        recon = {"domain": "example.test", "vuln_scan": {"security_checks": {"findings": [
            {"type": "missing_coop", "severity": "info", "name": "n", "description": "d",
             "url": "https://gone.example.test", "hostname": "gone.example.test"},
            {"type": "hostname_only_check", "severity": "info", "name": "n", "description": "d",
             "hostname": "gone.example.test"},
        ]}}}
        stats = _writer(session).update_graph_from_vuln_scan(recon, U, P)
        self.assertEqual(stats["errors"], [])
        self.assertEqual(stats["relationships_created"], 0)
        self.assertEqual(len(session.links("d:Domain")), 2)

    def test_domain_link_still_counted_when_the_domain_matches(self):
        class _OnlyTheDomainExists(_Session):
            def run(self, query, **params):
                result = super().run(query, **params)
                if "HAS_VULNERABILITY" in query:
                    return _Result({"matched": int("MATCH (d:Domain " in query)})
                return result

        session = _OnlyTheDomainExists()
        recon = {"domain": "example.test", "vuln_scan": {"security_checks": {"findings": [
            {"type": "missing_coop", "severity": "info", "name": "n", "description": "d",
             "url": "https://example.test", "hostname": "example.test"},
            {"type": "hostname_only_check", "severity": "info", "name": "n", "description": "d",
             "hostname": "example.test"},
        ]}}}
        stats = _writer(session).update_graph_from_vuln_scan(recon, U, P)
        self.assertEqual(stats["errors"], [])
        self.assertEqual(stats["relationships_created"], 2)
        self.assertEqual(len(session.links("d:Domain")), 2)


if __name__ == "__main__":
    unittest.main()
