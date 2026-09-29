"""POST /triage/runs and /triage/runs/stop: a run with no browser attached (B15).

The master key only, the weak-key 503, the one start path shared with the
websocket (so a start attaches to a run already going), a clear refusal while
the previous run is still finishing (C19), and a Stop refused once the run is
publishing (B17).

Run: ./agentic/run_tests.sh tests/test_triage_run_endpoints.py
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api  # noqa: E402


def _body(resp):
    import json

    return json.loads(bytes(resp.body).decode())


class TriageRunEndpointTests(unittest.IsolatedAsyncioTestCase):
    """POST /triage/runs and /triage/runs/stop: the headless start and stop."""

    def setUp(self):
        self.weak = False
        self._patches = [mock.patch.object(api, "master_key_is_weak", lambda: self.weak)]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])
        from cypherfix_triage import websocket_handler as wh
        self.wh = wh
        wh._RUNS.clear()
        wh._TRIAGE_IN_FLIGHT.clear()
        self.addCleanup(wh._RUNS.clear)
        self.addCleanup(wh._TRIAGE_IN_FLIGHT.clear)

    def _start(self, **kw):
        base = dict(user_id="u1", project_id="p1", trigger="mcp", token_id="tok1",
                    max_review_budget=1000)
        base.update(kw)
        return api.TriageRunStartRequest(**base)

    async def test_a_weak_master_key_refuses_both(self):
        self.weak = True
        self.assertEqual((await api.triage_run_start(self._start())).status_code, 503)
        self.assertEqual((await api.triage_run_stop(
            api.TriageRunStopRequest(project_id="p1"))).status_code, 503)

    async def test_bad_identities_are_refused(self):
        for bad in (dict(project_id="p1/../x"), dict(trigger="cron"),
                    dict(token_id="t" * 80)):
            resp = await api.triage_run_start(self._start(**bad))
            self.assertEqual(resp.status_code, 400, bad)

    async def test_a_start_answers_202_with_the_run_id(self):
        started = {}

        def fake_start(user_id, project_id, **kwargs):
            started.update(kwargs, user_id=user_id, project_id=project_id)
            run = self.wh.TriageRun(project_id, trigger=kwargs["trigger"])
            run.run_id = "run-9"
            run.authorized.set()
            return run, False, None

        with mock.patch.object(self.wh, "start_detached_run", fake_start):
            resp = await api.triage_run_start(self._start())
        self.assertEqual(resp.status_code, 202)
        self.assertEqual(_body(resp)["runId"], "run-9")
        self.assertFalse(_body(resp)["attached"])
        self.assertEqual(started["trigger"], "mcp")
        self.assertEqual(started["token_id"], "tok1")
        self.assertEqual(started["max_review_budget"], 1000)

    async def test_a_start_the_webapp_refused_is_409(self):
        def fake_start(user_id, project_id, **kwargs):
            run = self.wh.TriageRun(project_id)
            run.start_error = "A version activation is in progress for this project."
            run.authorized.set()
            return run, False, None

        with mock.patch.object(self.wh, "start_detached_run", fake_start):
            resp = await api.triage_run_start(self._start())
        self.assertEqual(resp.status_code, 409)
        self.assertIn("activation", _body(resp)["error"])

    async def test_a_start_while_the_previous_run_finishes_is_409_with_a_clear_message(self):
        self.wh._claim_triage_slot("p1")
        resp = await api.triage_run_start(self._start())
        self.assertEqual(resp.status_code, 409)
        self.assertIn("still finishing", _body(resp)["error"])

    async def test_a_stop_is_refused_while_publishing(self):
        import asyncio
        run = self.wh.TriageRun("p1")
        run.task = asyncio.ensure_future(asyncio.sleep(10))
        self.addCleanup(run.task.cancel)
        run.record("triage_phase", {"phase": "publishing", "progress": 92})
        self.wh._RUNS["p1"] = run
        body = _body(await api.triage_run_stop(api.TriageRunStopRequest(project_id="p1")))
        self.assertEqual((body["stopped"], body["reason"]), (False, "publishing"))
        self.assertFalse(run.task.cancelled())

    async def test_a_stop_before_publishing_cancels(self):
        import asyncio
        run = self.wh.TriageRun("p1")
        run.task = asyncio.ensure_future(asyncio.sleep(10))
        run.record("triage_phase", {"phase": "reviewing", "progress": 50})
        self.wh._RUNS["p1"] = run
        body = _body(await api.triage_run_stop(api.TriageRunStopRequest(project_id="p1")))
        self.assertTrue(body["stopped"])
        await asyncio.sleep(0)
        self.assertTrue(run.task.cancelled())

    async def test_no_run_is_not_stopped(self):
        body = _body(await api.triage_run_stop(api.TriageRunStopRequest(project_id="p1")))
        self.assertEqual((body["stopped"], body["reason"]), (False, "no run in progress"))



if __name__ == "__main__":
    unittest.main()
