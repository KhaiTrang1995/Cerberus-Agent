"""
C-8: the webapp checks a set Conversation.agentRunning flag against the agent's
own task registry, so a flag left behind by a restarted agent stops locking the
project (preset apply, rescope, graph activation, the queued-scan dispatcher).

These tests pin the two halves the webapp relies on: the registry reports only
this project's still-running sessions, and the endpoint is internal-auth gated
and answers 503 (the webapp then stays busy) before the manager exists.

Run in-container: ./agentic/run_tests.sh tests/test_live_agent_sessions.py
"""
import asyncio
import sys
import unittest
from pathlib import Path

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)

from websocket_api import WebSocketManager  # noqa: E402
import api  # noqa: E402


async def _busy():
    await asyncio.sleep(30)


async def _done():
    return None


class LiveSessionIds(unittest.TestCase):
    def test_lists_only_this_projects_running_sessions(self):
        async def scenario():
            mgr = WebSocketManager()
            mine = asyncio.ensure_future(_busy())
            other_project = asyncio.ensure_future(_busy())
            mgr.register_task("u1:p1:sess-a", mine)
            mgr.register_task("u1:p2:sess-b", other_project)
            try:
                self.assertEqual(mgr.live_session_ids("p1"), ["sess-a"])
                self.assertEqual(mgr.live_session_ids("p2"), ["sess-b"])
                self.assertEqual(mgr.live_session_ids("p3"), [])
            finally:
                mine.cancel()
                other_project.cancel()

        asyncio.run(scenario())

    def test_a_finished_task_is_not_live_and_is_dropped(self):
        # The finally block of a run clears its task, but a crash between the
        # run ending and that clear leaves a done task behind.
        async def scenario():
            mgr = WebSocketManager()
            finished = asyncio.ensure_future(_done())
            await finished
            mgr.register_task("u1:p1:sess-a", finished)
            self.assertEqual(mgr.live_session_ids("p1"), [])
            self.assertIsNone(mgr.get_task("u1:p1:sess-a"))

        asyncio.run(scenario())

    def test_a_session_id_containing_colons_is_returned_whole(self):
        async def scenario():
            mgr = WebSocketManager()
            task = asyncio.ensure_future(_busy())
            mgr.register_task("u1:p1:sess:with:colons", task)
            try:
                self.assertEqual(mgr.live_session_ids("p1"), ["sess:with:colons"])
            finally:
                task.cancel()

        asyncio.run(scenario())

    def test_a_project_id_is_matched_exactly_not_as_a_prefix(self):
        async def scenario():
            mgr = WebSocketManager()
            task = asyncio.ensure_future(_busy())
            mgr.register_task("u1:p10:sess-a", task)
            try:
                self.assertEqual(mgr.live_session_ids("p1"), [])
            finally:
                task.cancel()

        asyncio.run(scenario())


class LiveSessionsEndpoint(unittest.TestCase):
    def _route(self):
        for r in api.app.routes:
            if getattr(r, "path", "") == "/agent-sessions/live":
                return r
        self.fail("/agent-sessions/live is not registered")

    def test_is_internal_auth_gated(self):
        deps = [getattr(d.dependency, "__name__", "") for d in self._route().dependencies]
        self.assertIn("require_internal_auth_only", deps)

    def test_returns_the_projects_live_session_ids(self):
        async def scenario():
            mgr = WebSocketManager()
            task = asyncio.ensure_future(_busy())
            mgr.register_task("u1:p1:sess-a", task)
            saved = api.ws_manager
            api.ws_manager = mgr
            try:
                body = await api.live_agent_sessions(project_id="p1")
            finally:
                api.ws_manager = saved
                task.cancel()
            self.assertEqual(body, {"project_id": "p1", "session_ids": ["sess-a"]})

        asyncio.run(scenario())

    def test_answers_503_before_the_manager_exists(self):
        saved = api.ws_manager
        api.ws_manager = None
        try:
            resp = asyncio.run(api.live_agent_sessions(project_id="p1"))
        finally:
            api.ws_manager = saved
        self.assertEqual(resp.status_code, 503)


if __name__ == "__main__":
    unittest.main(verbosity=2)
