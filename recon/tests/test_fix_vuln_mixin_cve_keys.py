"""CVE->Technology name matching, fed the products the CVE lookup really emits.

run_cve_lookup keys technology_cves.by_technology on the raw detector string
and stores `product` as parse_technology_string + normalize_product_name of it.
The graph writer attaches each CVE to Technology nodes whose name is that
product (whole words, optionally behind one vendor word and before generic
descriptors such as "httpd" or "server"), instead of any name containing it.

This runs the real normalisation on the strings httpx, Wappalyzer, the Server
header and nmap produce, and checks the attach decision against the Technology
names those same detectors write.
"""
import os
import sys
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

import pytest  # noqa: E402

from graph_db.mixins.recon.vuln_mixin import tech_matches_cve_product  # noqa: E402
from recon.helpers.cve_helpers import normalize_product_name, parse_technology_string  # noqa: E402


def _product(key):
    name, _version = parse_technology_string(key)
    return normalize_product_name(name)


def _clean(key):
    """The writer's tech_name_clean: the key without its ':'/'/' version suffix."""
    _name, version = parse_technology_string(key)
    for sep in (":", "/"):
        if version and key.endswith(f"{sep}{version}"):
            return key[: -len(sep + version)]
    return key


@pytest.mark.parametrize("key,node_name,attach", [
    # same product, every detector's spelling
    ("Nginx:1.18.0", "Nginx", True),
    ("nginx/1.18.0", "nginx/1.18.0", True),
    ("nginx/1.18.0", "Nginx", True),
    ("Apache/2.4.49", "Apache HTTP Server", True),
    ("Apache/2.4.49", "Apache httpd/2.4.49", True),
    ("Apache HTTP Server:2.4.49", "Apache", True),
    ("Microsoft-IIS/10.0", "IIS", True),
    ("Microsoft-IIS/10.0", "Microsoft IIS httpd/10.0", True),
    ("Apache-Coyote/1.1", "Apache Tomcat", True),
    ("Apache Tomcat/9.0.65", "Apache Tomcat", True),
    ("OpenSSH/8.2p1 Ubuntu 4ubuntu0.5", "OpenSSH/8.2p1 Ubuntu 4ubuntu0.5", True),
    ("OpenSSH_8.9p1", "OpenSSH", True),
    ("PHP/8.1.2-1ubuntu2.14", "PHP", True),
    ("Ruby on Rails:6.0.3", "Ruby on Rails", True),
    ("jQuery:3.5.1", "jQuery", True),
    # a different product that merely contains the name
    ("PHP/8.1.2", "phpMyAdmin", False),
    ("PHP/8.1.2", "phpBB", False),
    ("PHP/8.1.2", "PHPMailer", False),
    ("Go:1.16", "Django", False),
    ("Go:1.16", "MongoDB", False),
    ("Go:1.16", "Google Analytics", False),
    ("React:16.0.0", "Preact", False),
    ("Apache/2.4.49", "Apache Tomcat", False),
    ("Apache/2.4.49", "Apache Solr", False),
    ("Apache HTTP Server:2.4.49", "Apache Traffic Server", False),
    ("jQuery:3.5.1", "jQuery UI", False),
    ("jQuery:3.5.1", "jQuery Migrate", False),
])
def test_attach_decision(key, node_name, attach):
    product = _product(key)
    assert tech_matches_cve_product(node_name, product, _clean(key), key) is attach, \
        (key, product, node_name)


@pytest.mark.parametrize("key,node_name,attach", [
    # nmap's multi-word product names, reached by another detector's key
    ("openresty/1.19.3.1", "OpenResty web app server/1.19.3.1", True),
    ("OpenResty:1.19.3.1", "OpenResty web app server/1.19.3.1", True),
    ("Elasticsearch:7.10.2", "Elasticsearch REST API/7.10.2", True),
    ("Golang:1.16", "Golang net/http server", True),
    ("Samba:4.6.2", "Samba smbd/4.6.2", True),
    # still another product
    ("Django:3.2.4", "Django REST framework", False),
    ("Node.js:14.17.0", "Node.js Express framework", False),
    ("PHP/8.1.2", "phpMyAdmin", False),
    ("Apache/2.4.49", "Apache Tomcat", False),
])
def test_regression_nmap_multiword_product_names_unlinked(key, node_name, attach):
    product = _product(key)
    assert tech_matches_cve_product(node_name, product, _clean(key), key) is attach, \
        (key, product, node_name)


def test_products_are_what_the_lookup_emits():
    # Guards the table above against a normalisation change it assumes.
    assert _product("Apache/2.4.49") == "apache"
    assert _product("Apache HTTP Server:2.4.49") == "apache"
    assert _product("Apache-Coyote/1.1") == "tomcat"
    assert _product("Microsoft-IIS/10.0") == "iis"
    assert _product("OpenSSH_8.9p1") == "openssh"
    assert _product("Ruby on Rails:6.0.3") == "rails"
