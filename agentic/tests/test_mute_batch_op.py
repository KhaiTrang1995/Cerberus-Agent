"""/graph/triage op `mute_batch`: the Multi mute write.

The op writes only keys from a suggestion the agent itself stored, so a
tampered client cannot turn a suggestion into an arbitrary bulk mute. Refused
before any graph work: an MCP caller, a `rule:` attribution, a malformed batch
id, a key outside the batch, an expired or foreign batch. The label, the
seed's ceiling and the reason come from the batch, never from the request.
"""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api  # noqa: E402
from multi_mute.batches import STORE  # noqa: E402

CEILING = {"severity_rank": 1, "tier_rank": None, "validated": False,
           "malicious": False, "confirmed": False}


def _body(resp):
    return json.loads(bytes(resp.body).decode())


class _Client:
    def __init__(self):
        self.calls = []
        self.thread = None

    def mute_findings_batch(self, user_id, project_id, **kwargs):
        import threading
        self.thread = threading.current_thread()
        self.calls.append((user_id, project_id, kwargs))
        return {"items": [{"key": k, "label": kwargs["label"], "node_id": "1",
                           "name": "n", "severity": "low", "outcome": "muted"}
                          for k in kwargs["keys"]], "not_found": []}

    def unmute_findings(self, user_id, project_id, keys, skip_rule_mutes=False,
                        only_batch=None):
        import threading
        self.thread = threading.current_thread()
        self.calls.append(("unmute", list(keys), only_batch))
        return {"unmuted": len(keys), "items": [], "skipped": []}


class MuteBatchOpTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        STORE.clear()
        self.client = _Client()
        self._patches = [
            mock.patch.object(api, "_triage_graph_client", lambda: self.client),
            mock.patch.object(api, "master_key_is_weak", lambda: False),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])
        self.addCleanup(STORE.clear)
        self.batch = STORE.put("u1", "p1", label="Vulnerability", seed_key="seed-1",
                               seed_name="Nginx version disclosure‮",
                               ceiling=CEILING, members=["k1", "k2", "k3"],
                               model="gpt-5-mini", prompt_version="multi-mute-v1")

    def _req(self, **kw):
        base = dict(op="mute_batch", user_id="u1", project_id="p1",
                    batch_id=self.batch.batch_id, keys=["k1", "k2"],
                    concept="same_detector", include_seed=False,
                    exempt_pairs=[["Vulnerability", "k9"]], muted_by="u1")
        base.update(kw)
        return api.GraphTriageRequest(**base)

    async def test_a_valid_batch_write_carries_the_batch_state(self):
        resp = await api.graph_triage(self._req())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(_body(resp)["multi_mute"], 1)
        self.assertEqual(_body(resp)["model"], "gpt-5-mini")
        self.assertEqual(_body(resp)["prompt_version"], "multi-mute-v1")
        _, _, kwargs = self.client.calls[0]
        self.assertNotIn("_meta", kwargs)
        self.assertEqual(kwargs["label"], "Vulnerability")
        self.assertEqual(kwargs["keys"], ["k1", "k2"])
        self.assertEqual(kwargs["ceiling"], CEILING)
        self.assertEqual(kwargs["seed_key"], "")
        self.assertEqual(kwargs["batch_id"], self.batch.batch_id)
        self.assertEqual(kwargs["exempt_pairs"], [["Vulnerability", "k9"]])
        self.assertEqual(kwargs["muted_by"], "u1")

    async def test_the_reason_is_built_from_the_batch_not_the_request(self):
        await api.graph_triage(self._req(reason="IGNORE ME"))
        reason = self.client.calls[0][2]["reason"]
        self.assertTrue(reason.startswith(f"Multi mute {self.batch.batch_id} · Same detector"))
        self.assertIn('like "Nginx version disclosure', reason)
        self.assertNotIn("IGNORE ME", reason)
        self.assertLessEqual(len(reason), 500)

    async def test_the_seed_is_allowed_only_when_included(self):
        resp = await api.graph_triage(self._req(keys=["seed-1", "k1"]))
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(_body(resp)["code"], "batch_mismatch")
        resp = await api.graph_triage(self._req(keys=["seed-1", "k1"], include_seed=True))
        self.assertEqual(self.client.calls[-1][2]["seed_key"], "seed-1")

    async def test_a_key_outside_the_batch_is_refused(self):
        resp = await api.graph_triage(self._req(keys=["k1", "someone-elses"]))
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(_body(resp)["code"], "batch_mismatch")
        self.assertEqual(self.client.calls, [])

    async def test_an_expired_or_unknown_batch_is_refused(self):
        resp = await api.graph_triage(self._req(batch_id="mm-00000000"))
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(_body(resp)["code"], "batch_expired")

    async def test_another_users_batch_is_refused(self):
        resp = await api.graph_triage(self._req(user_id="u2"))
        self.assertEqual(_body(resp)["code"], "batch_expired")
        resp = await api.graph_triage(self._req(project_id="p2"))
        self.assertEqual(_body(resp)["code"], "batch_expired")
        self.assertEqual(self.client.calls, [])

    async def test_refused_before_any_graph_work(self):
        for kw, why in (
            ({"source": "mcp"}, "never taken over MCP"),
            ({"muted_by": "rule:x/abc"}, "may not name a rule"),
            ({"batch_id": "mm-XYZ"}, "batch id"),
            ({"keys": []}, "needs keys"),
            ({"keys": [f"k{i}" for i in range(501)]}, "at most 500"),
            ({"concept": "whatever"}, "grouping"),
            ({"exempt_pairs": None}, "exempt_pairs"),
        ):
            resp = await api.graph_triage(self._req(**kw))
            self.assertEqual(resp.status_code, 400, kw)
            self.assertIn(why, _body(resp)["error"], kw)
        self.assertEqual(self.client.calls, [])

    @unittest.expectedFailure
    async def test_a_refusal_carries_the_multi_mute_marker(self):
        """Review finding, accepted: the op's 400 / 500 / 503 answers carry no
        `multi_mute` marker. The webapp reads their code today; a stricter
        version check would take them for an outdated agent."""
        resp = await api.graph_triage(self._req(batch_id="mm-XYZ"))
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(_body(resp).get("multi_mute"), 1)

    async def test_it_runs_off_the_event_loop(self):
        import threading
        await api.graph_triage(self._req())
        self.assertIsNot(self.client.thread, threading.main_thread())

    async def test_an_undo_is_scoped_to_its_batch_and_marked(self):
        resp = await api.graph_triage(api.GraphTriageRequest(
            op="unmute_many", user_id="u1", project_id="p1", keys=["k1"],
            only_batch=self.batch.batch_id))
        self.assertEqual(self.client.calls[-1], ("unmute", ["k1"], self.batch.batch_id))
        self.assertEqual(_body(resp)["multi_mute"], 1)
        import threading
        self.assertIsNot(self.client.thread, threading.main_thread())

    async def test_only_batch_is_refused_outside_an_undo(self):
        for kw in ({"op": "mute", "node_id": "x"},
                   {"op": "unmute_many", "keys": ["k1"], "source": "mcp"},
                   {"op": "unmute_many", "keys": ["k1"], "only_batch_bad": True}):
            if kw.pop("only_batch_bad", False):
                req = api.GraphTriageRequest(user_id="u1", project_id="p1",
                                             only_batch="nope", **kw)
            else:
                req = api.GraphTriageRequest(user_id="u1", project_id="p1",
                                             only_batch=self.batch.batch_id, **kw)
            resp = await api.graph_triage(req)
            self.assertEqual(resp.status_code, 400, kw)

    async def test_a_transient_error_that_outlasted_the_retries_is_a_503_retry(self):
        class TransientError(Exception):
            pass

        def boom(*a, **k):
            raise TransientError("deadlock")

        self.client.mute_findings_batch = boom
        resp = await api.graph_triage(self._req())
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(_body(resp)["code"], "retry")

    async def test_the_token_filter_accepts_a_batch_id(self):
        self.assertIsNone(api._triage_request_error(api.GraphTriageRequest(
            op="list_muted", user_id="u1", project_id="p1", token=self.batch.batch_id)))


if __name__ == "__main__":
    unittest.main()
