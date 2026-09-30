"""The per-project single-flight lock on triage runs.

A second concurrent run for the same project would collect the same findings,
classify them twice against a graph that is still changing, race the first run
writing verdicts back, and bill the operator for both. It is rejected rather
than queued.

The failure mode worth guarding is not "two runs started" -- that is the easy
half. It is the lock LEAKING: a run that crashes, or a socket that drops
mid-run, must not lock the project out until the process restarts. A leaked
slot is indistinguishable from a hung run and there is no UI to clear it.

Run: python -m pytest agentic/tests/test_triage_ws_lock.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage.websocket_handler import (  # noqa: E402
    _TRIAGE_IN_FLIGHT,
    _claim_triage_slot,
    _release_triage_slot,
)

P1, P2 = "project-one", "project-two"


class TriageSlotTest(unittest.TestCase):
    def setUp(self):
        _TRIAGE_IN_FLIGHT.clear()

    tearDown = setUp


class TestOneRunPerProject(TriageSlotTest):
    def test_the_first_claim_wins(self):
        self.assertTrue(_claim_triage_slot(P1))

    def test_a_second_concurrent_claim_is_refused(self):
        _claim_triage_slot(P1)
        self.assertFalse(_claim_triage_slot(P1))

    def test_a_different_project_is_unaffected(self):
        # The lock is per project, not global: two operators triaging two
        # projects must not block each other.
        _claim_triage_slot(P1)
        self.assertTrue(_claim_triage_slot(P2))


class TestTheSlotIsNeverLeaked(TriageSlotTest):
    """A leaked slot locks a project out with no way to clear it."""

    def test_release_frees_the_slot_for_a_later_run(self):
        _claim_triage_slot(P1)
        _release_triage_slot(P1)
        self.assertTrue(_claim_triage_slot(P1), "slot not reusable after release")

    def test_a_run_that_raises_still_releases(self):
        # Mirrors run_triage()'s try/finally: the orchestrator raising must not
        # strand the lock.
        _claim_triage_slot(P1)
        try:
            raise RuntimeError("orchestrator blew up")
        except RuntimeError:
            pass
        finally:
            _release_triage_slot(P1)
        self.assertTrue(_claim_triage_slot(P1))

    def test_releasing_twice_is_safe(self):
        # The handler releases in the task's `finally` AND in the socket's, so a
        # normal run releases twice. That must not raise or free someone else's
        # slot.
        _claim_triage_slot(P1)
        _release_triage_slot(P1)
        _release_triage_slot(P1)
        self.assertNotIn(P1, _TRIAGE_IN_FLIGHT)

    def test_releasing_a_project_that_never_ran_is_safe(self):
        # The socket `finally` runs even when start_triage was never sent.
        _release_triage_slot("never-started")
        self.assertEqual(_TRIAGE_IN_FLIGHT, set())

    def test_releasing_one_project_does_not_free_another(self):
        _claim_triage_slot(P1)
        _claim_triage_slot(P2)
        _release_triage_slot(P1)
        self.assertFalse(_claim_triage_slot(P2), "P2's slot was freed by P1's release")


class TestTheHandlerWiresTheLockOnBothExitPaths(unittest.TestCase):
    """The lock is only as good as the places that release it."""

    @staticmethod
    def _handler_source() -> str:
        import cypherfix_triage.websocket_handler as mod
        with open(mod.__file__, encoding="utf-8") as fh:
            return fh.read()

    def test_a_refused_claim_does_not_start_an_orchestrator(self):
        src = self._handler_source()
        claim = src.index("if not _claim_triage_slot(project_id):")
        orchestrator = src.index("orchestrator = TriageOrchestrator", claim)
        between = src[claim:orchestrator]
        self.assertIn("return None, False, STILL_FINISHING", between,
                      "a refused claim must skip the run, not fall through to it")

    def test_a_socket_stop_does_not_free_the_slot_before_the_run_finishes(self):
        """C19: freeing it in the stop handler let a new start race the old
        run's `finish`, and the webapp answered 'already in progress'."""
        src = self._handler_source()
        stop = src[src.index('elif msg_type == "stop"'):src.index("    except WebSocketDisconnect")]
        self.assertNotIn("_release_triage_slot(", stop)

    def test_the_run_releases_its_own_slot(self):
        # The run outlives the socket, so its own `finally` is the release that
        # matters; the socket can no longer be relied on to still be there.
        src = self._handler_source()
        self.assertIn("_release_triage_slot(run.project_id)", src)


class TestTheRunOutlivesTheSocket(unittest.TestCase):
    """Closing the tab used to cancel a multi-minute, paid LLM run."""

    @staticmethod
    def _handler_source() -> str:
        import cypherfix_triage.websocket_handler as mod
        with open(mod.__file__, encoding="utf-8") as fh:
            return fh.read()

    def test_a_disconnect_detaches_and_does_not_cancel(self):
        src = self._handler_source()
        tail = src[src.rindex("    finally:"):]
        self.assertIn("attached_run.detach(websocket)", tail)
        self.assertNotIn("cancel()", tail,
                         "a disconnect must never cancel the run")

    def test_only_an_explicit_stop_cancels(self):
        src = self._handler_source()
        stop = src[src.index('elif msg_type == "stop"'):src.index("    except WebSocketDisconnect")]
        self.assertIn("cancel()", stop)

    def test_a_second_start_attaches_instead_of_starting_a_second_run(self):
        # Single-flight is still enforced -- the run is reused, not duplicated.
        src = self._handler_source()
        start = src[src.index("def start_detached_run("):
                    src.index("orchestrator = TriageOrchestrator")]
        self.assertIn("_active_run(", start)
        self.assertIn("running.attach(socket)", start)
        self.assertIn("return running, True, None", start)
        handler = src[src.index('elif msg_type == "start_triage"'):
                      src.index('elif msg_type == "stop"')]
        self.assertIn("start_detached_run(", handler)
        self.assertIn("await run.replay(websocket)", handler)

    def test_the_ticket_s_real_actor_reaches_the_run(self):
        """B13: the run recorded no real actor while an admin acted as the owner."""
        src = self._handler_source()
        handler = src[src.index('elif msg_type == "start_triage"'):
                      src.index('elif msg_type == "stop"')]
        self.assertIn('_claims.get("act")', handler)
        self.assertIn("real_actor_user_id=", handler)

    def test_a_reconnecting_tab_is_replayed(self):
        src = self._handler_source()
        self.assertIn("await existing.replay(websocket)", src)


class TestTheRunRecordsWhatAReconnectingTabMissed(unittest.TestCase):
    def setUp(self):
        from cypherfix_triage.websocket_handler import TriageRun
        self.run = TriageRun(P1)

    def test_an_unattached_run_swallows_its_events(self):
        # The run keeps working with nowhere to stream to; that is the point.
        import asyncio
        self.run.record("triage_phase", {"phase": "classifying", "progress": 68})
        asyncio.run(self.run.send("triage_phase", {"phase": "classifying"}))
        self.assertEqual(self.run.last_phase["phase"], "classifying")

    def test_terminal_state_is_kept_for_a_tab_that_reconnects_later(self):
        self.run.record("triage_complete", {"total_remediations": 3})
        self.assertEqual(self.run.status, "completed")
        self.assertEqual(self.run.terminal[0], "triage_complete")

    def test_an_error_is_terminal_too(self):
        self.run.record("error", {"message": "boom"})
        self.assertEqual(self.run.status, "error")

    def test_detach_is_identity_guarded(self):
        # A stale socket closing must not detach the tab that has since
        # reconnected and taken its place.
        current, stale = object(), object()
        self.run.socket = current
        self.run.detach(stale)
        self.assertIs(self.run.socket, current)
        self.run.detach(current)
        self.assertIsNone(self.run.socket)

    def test_a_run_with_no_task_is_not_active(self):
        self.assertFalse(self.run.is_active)



class TestStartDetachedRun(unittest.IsolatedAsyncioTestCase):
    """The one start path, for a tab and for an MCP agent."""

    def setUp(self):
        from cypherfix_triage import websocket_handler as wh
        self.wh = wh
        wh._RUNS.clear()
        _TRIAGE_IN_FLIGHT.clear()
        self.addCleanup(wh._RUNS.clear)
        self.addCleanup(_TRIAGE_IN_FLIGHT.clear)
        self.built = []
        self.gate = None

        test = self

        class FakeOrchestrator:
            def __init__(self, **kwargs):
                test.built.append(kwargs)
                self.callback = kwargs["callback"]

            async def run(self, state):
                await self.callback.on_authorized("run-1")
                if test.gate is not None:
                    await test.gate.wait()

            async def cleanup(self):
                pass

        import unittest.mock as mock
        patcher = mock.patch.object(wh, "TriageOrchestrator", FakeOrchestrator)
        patcher.start()
        self.addCleanup(patcher.stop)

    async def test_a_start_builds_one_run_with_its_trigger_and_budget(self):
        import asyncio
        run, attached, refusal = self.wh.start_detached_run(
            "u1", P1, real_actor_user_id="admin", trigger="mcp", token_id="tok1",
            max_review_budget=1000)
        self.assertIsNone(refusal)
        self.assertFalse(attached)
        await asyncio.wait_for(run.authorized.wait(), 2)
        self.assertEqual(run.run_id, "run-1")
        kwargs = self.built[0]
        self.assertEqual((kwargs["trigger"], kwargs["token_id"], kwargs["max_review_budget"],
                          kwargs["real_actor_user_id"]), ("mcp", "tok1", 1000, "admin"))
        await run.task

    async def test_a_second_start_attaches(self):
        import asyncio
        self.gate = asyncio.Event()
        first, _, _ = self.wh.start_detached_run("u1", P1)
        second, attached, refusal = self.wh.start_detached_run("u1", P1)
        self.assertIs(second, first)
        self.assertTrue(attached)
        self.assertEqual(len(self.built), 1)
        self.gate.set()
        await first.task

    async def test_the_slot_is_released_only_when_the_run_ends(self):
        import asyncio
        self.gate = asyncio.Event()
        run, _, _ = self.wh.start_detached_run("u1", P1)
        self.wh._RUNS.pop(P1)                     # what a Stop does
        _, _, refusal = self.wh.start_detached_run("u1", P1)
        self.assertEqual(refusal, self.wh.STILL_FINISHING)
        self.gate.set()
        await run.task
        _, _, refusal = self.wh.start_detached_run("u1", P1)
        self.assertIsNone(refusal)

    async def test_an_mcp_stop_tells_every_attached_tab(self):
        """A stop from outside the socket answered no tab: an attached tab stayed
        `running` for ever, and one that attached later replayed no end."""
        import asyncio

        class FakeSocket:
            def __init__(self):
                self.sent = []

            async def send_json(self, message):
                self.sent.append(message)

        self.gate = asyncio.Event()
        tab = FakeSocket()
        run, _, _ = self.wh.start_detached_run("u1", P1, socket=tab)
        await asyncio.wait_for(run.authorized.wait(), 2)
        self.assertTrue(self.wh.stop_project_run(P1)["stopped"])
        with self.assertRaises(asyncio.CancelledError):
            await run.task
        self.assertEqual(tab.sent[-1]["type"], "stopped")
        late = FakeSocket()
        await run.replay(late)
        self.assertEqual(late.sent[-1]["type"], "stopped")

    async def test_a_run_cancelled_before_it_starts_frees_the_slot(self):
        """A task cancelled before its first step never runs its `finally`."""
        import asyncio
        run, _, _ = self.wh.start_detached_run("u1", P1)
        run.task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await run.task
        await asyncio.sleep(0)
        self.assertNotIn(P1, _TRIAGE_IN_FLIGHT)

    async def test_a_second_stop_does_not_cancel_the_finish(self):
        """The first Stop's cancel lands; a second one landed inside `finish`
        and left the row `running` until its heartbeat expired."""
        import asyncio
        test = self
        test.finishing = asyncio.Event()
        test.finished = False

        class FinishingOrchestrator:
            def __init__(self, **kwargs):
                self.callback = kwargs["callback"]

            async def run(self, state):
                await self.callback.on_authorized("run-1")
                try:
                    await asyncio.Event().wait()
                finally:
                    await test.finishing.wait()           # the finish POST
                    test.finished = True

            async def cleanup(self):
                pass

        import unittest.mock as mock
        with mock.patch.object(self.wh, "TriageOrchestrator", FinishingOrchestrator):
            run, _, _ = self.wh.start_detached_run("u1", P1)
        await asyncio.wait_for(run.authorized.wait(), 2)
        self.assertTrue(self.wh.stop_project_run(P1)["stopped"])
        await asyncio.sleep(0)
        self.assertTrue(self.wh.stop_project_run(P1)["stopped"])
        test.finishing.set()
        with self.assertRaises(asyncio.CancelledError):
            await run.task
        self.assertTrue(test.finished)

    async def test_a_stop_while_publishing_is_refused(self):
        import asyncio
        self.gate = asyncio.Event()
        run, _, _ = self.wh.start_detached_run("u1", P1)
        run.record("triage_phase", {"phase": "publishing", "progress": 92})
        result = self.wh.stop_project_run(P1)
        self.assertEqual(result["reason"], "publishing")
        self.assertFalse(run.task.cancelled())
        self.gate.set()
        await run.task


if __name__ == "__main__":
    unittest.main()
