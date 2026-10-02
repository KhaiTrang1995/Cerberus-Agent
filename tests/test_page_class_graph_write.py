"""The Jev page-type label reaches the Endpoint in the graph.

http_probe puts `page_class`, `page_class_confidence` and `page_class_source` on
each probed URL entry (TypeSafe Jev, the pre-filter where Jev gave no answer);
update_graph_from_http_probe must carry them onto that URL's Endpoint. A page with
no label must write no such key at all: the Endpoint write is `SET e += $props`,
so a re-probe without Jev keeps the label an earlier scan stored.

Hermetic: a fake driver records every query; no Neo4j.
Run: python -m unittest tests.test_page_class_graph_write
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.recon.http_mixin import HttpMixin  # noqa: E402

FIELDS = ("page_class", "page_class_confidence", "page_class_source")


class _Result:
    def single(self):
        return {"linked": 0, "count": 0, "c": 0}

    def __iter__(self):
        return iter([])


class _Session:
    def __init__(self, queries):
        self.queries = queries

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **kwargs):
        self.queries.append((query, kwargs))
        return _Result()


class _Driver:
    def __init__(self, queries):
        self.queries = queries

    def session(self):
        return _Session(self.queries)


class _Client(HttpMixin):
    def __init__(self):
        self.queries = []
        self.driver = _Driver(self.queries)


def _recon(**labels):
    url = "https://app.example.test/"
    entry = {"url": url, "host": "app.example.test", "status_code": 200, "content_length": 900,
             "content_type": "text/html", "title": "App", "server": "nginx", **labels}
    return {
        "domain": "example.test",
        "subdomains": ["app.example.test"],
        "metadata": {},
        "http_probe": {"scan_metadata": {}, "by_url": {url: entry},
                       "by_host": {"app.example.test": {"urls": [url], "technologies": [],
                                                        "servers": ["nginx"], "status_codes": [200]}}},
    }


def _endpoint_props(client):
    for query, kwargs in client.queries:
        if "MERGE (e:Endpoint" in query and "props" in kwargs:
            return kwargs["props"]
    raise AssertionError("no Endpoint write was issued")


class TestPageClassReachesTheEndpoint(unittest.TestCase):
    def test_a_jev_label_is_written_onto_the_endpoint(self):
        client = _Client()
        client.update_graph_from_http_probe(
            _recon(page_class="login_only", page_class_confidence=91,
                   page_class_source="jev_classifier"), "u1", "p1")
        props = _endpoint_props(client)
        self.assertEqual({k: props[k] for k in FIELDS},
                         {"page_class": "login_only", "page_class_confidence": 91,
                          "page_class_source": "jev_classifier"})

    def test_a_prefilter_fallback_label_is_written_too(self):
        client = _Client()
        client.update_graph_from_http_probe(
            _recon(page_class="error", page_class_confidence=100, page_class_source="prefilter"),
            "u1", "p1")
        self.assertEqual(_endpoint_props(client)["page_class_source"], "prefilter")

    def test_an_unlabelled_page_writes_no_page_class_key(self):
        client = _Client()
        client.update_graph_from_http_probe(_recon(), "u1", "p1")
        props = _endpoint_props(client)
        self.assertFalse(set(FIELDS) & set(props), props)


if __name__ == "__main__":
    unittest.main()
