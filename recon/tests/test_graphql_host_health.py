"""HostHealth on the GraphQL scanner (recon/graphql_scan/scanner.py).

The gate is test_single_endpoint (never test_introspection, a leaf tests drive
with fixed responses); a skipped endpoint returns None like a non-GraphQL one.
"""
from __future__ import annotations

from unittest import mock

import requests

from recon.helpers import circuit_breaker as cb
from recon.graphql_scan import introspection, scanner


def _settings():
    return {"GRAPHQL_INTROSPECTION_TEST": True, "GRAPHQL_VERIFY_SSL": False}


def test_an_endpoint_on_a_dead_host_is_skipped_without_a_request():
    for _ in range(3):
        cb.host_health.record_failure("https://dead.example.test/graphql",
                                      requests.ConnectionError("x"))
    with mock.patch.object(scanner, "test_introspection") as probe:
        out = scanner.test_single_endpoint("https://dead.example.test/graphql", {}, 5, _settings())
    assert out is None
    probe.assert_not_called()


def test_a_connection_failure_in_introspection_counts_against_the_host():
    with mock.patch.object(introspection.requests, "post",
                           side_effect=requests.exceptions.ConnectTimeout("x")):
        for _ in range(3):
            introspection.test_introspection("https://dead2.example.test/graphql", {}, 5)
    assert cb.host_health.is_down("https://dead2.example.test/graphql")


def test_a_non_graphql_answer_is_life():
    resp = mock.MagicMock(status_code=404, text="nope")
    resp.json.side_effect = ValueError("no json")
    with mock.patch.object(introspection.requests, "post", return_value=resp):
        for _ in range(10):
            introspection.test_introspection("https://web.example.test/graphql", {}, 5)
    assert not cb.host_health.is_down("https://web.example.test/graphql")
