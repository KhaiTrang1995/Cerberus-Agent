"""The agent's half of the triage-run protocol.

A triage run reads the whole graph into memory, works for minutes, then writes
its ranking back. In between, someone can activate a version, import a project
over it, delete the project, or press Stop. Before `TriageRun` existed, none of
those could see the run and the run could not see them, so it published onto a
graph that no longer matched what it had scored.

The protocol is four calls, and every one of them FAILS CLOSED:

  authorize  before reading anything. A refusal, a 5xx or an unreachable webapp
             all mean the run does not start.
  heartbeat  every 30 s. The reply carries `abort`. Two consecutive failures are
             treated as an abort, because a webapp we cannot reach is also a
             webapp that cannot tell us to stop.
  publish    the gate between memory and the graph. A conditional transition, so
             a run that lost its claim writes NOTHING rather than half a result.
  finish     always, from a `finally`. A run left `running` blocks activation
             until its heartbeat expires ten minutes later, so the failure path
             matters more here than the success one.
"""

from __future__ import annotations

import asyncio
import logging
import os

import httpx

logger = logging.getLogger(__name__)

WEBAPP_API_URL = os.environ.get("WEBAPP_API_URL", "http://webapp:3000")

#: How often to check in. The webapp calls a run lost after ten minutes, so this
#: leaves ~20 missed beats of slack for a slow LLM batch or a paused container.
HEARTBEAT_SECONDS = 30

#: Consecutive heartbeat failures before the run gives up. One failure is a
#: blip; two in a row means we can no longer be told to stop, and a run that
#: cannot be stopped must stop itself.
HEARTBEAT_FAILURE_LIMIT = 2

#: A phase change heartbeats at once, so a caller polling the run (an MCP
#: agent, another tab) sees each phase even when it lasts less than
#: HEARTBEAT_SECONDS. This floor keeps a burst of phase changes to one call.
PHASE_HEARTBEAT_MIN_GAP = 2.0


def _headers() -> dict:
    return {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}


class TriageRunAborted(Exception):
    """The run must stop now. `error_class` is what gets recorded."""

    def __init__(self, reason: str, error_class: str = "aborted"):
        super().__init__(reason)
        self.reason = reason
        self.error_class = error_class


class TriageRunClient:
    """One run's lifecycle. Construct, `authorize()`, work, `finish()`."""

    def __init__(self, project_id: str, actor_user_id: str,
                 real_actor_user_id: str | None = None):
        self.project_id = project_id
        self.actor_user_id = actor_user_id
        self.real_actor_user_id = real_actor_user_id
        self.run_id: str | None = None
        #: Where the run is, sent with every heartbeat so a caller that is not
        #: the run's own tab (another tab, an MCP agent) can see it.
        self.phase = ""
        self.progress = 0
        self._heartbeat_task: asyncio.Task | None = None
        self._abort_reason: str | None = None
        self._consecutive_failures = 0
        self._phase_changed = asyncio.Event()
        self._last_beat_at = float("-inf")

    # -- authorize ---------------------------------------------------------
    def set_progress(self, phase: str, progress: int) -> None:
        phase = str(phase or "")[:40]
        if phase != self.phase:
            self._phase_changed.set()
        self.phase = phase
        try:
            self.progress = max(0, min(100, int(progress)))
        except (TypeError, ValueError):
            pass

    async def authorize(self, model: str, score_model_version: str,
                        trigger: str = "app", token_id: str | None = None,
                        review_budget: int | None = None) -> str:
        """Create the run, or raise. Nothing is read before this succeeds.

        `trigger` says who started it (`app` or `mcp`), and `token_id` which
        access token for an MCP start. The effective review budget and model go
        with it, so the audit row records what the run may actually spend.
        """
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(
                    f"{WEBAPP_API_URL}/api/internal/triage-runs",
                    json={
                        "projectId": self.project_id,
                        "actorUserId": self.actor_user_id,
                        "realActorUserId": self.real_actor_user_id,
                        "model": model,
                        "scoreModelVersion": score_model_version,
                        "trigger": trigger,
                        **({"tokenId": token_id} if token_id else {}),
                        **({"reviewBudget": review_budget}
                           if review_budget is not None else {}),
                    },
                    headers=_headers(),
                )
        except Exception as exc:                                  # noqa: BLE001
            logger.error(f"Triage authorize failed to reach the webapp: {exc}")
            raise TriageRunAborted(
                "the run could not be authorised", "authorize_failed") from exc

        if response.status_code != 201:
            detail = _reason(response)
            logger.warning(
                f"Triage authorize refused ({response.status_code}): {detail}")
            raise TriageRunAborted(detail, "authorize_failed")

        self.run_id = str(response.json().get("runId") or "")
        if not self.run_id:
            raise TriageRunAborted("no run id was issued", "authorize_failed")
        logger.info(f"Triage run {self.run_id} authorised for {self.project_id}")
        return self.run_id

    # -- heartbeat ---------------------------------------------------------
    def start_heartbeat(self) -> None:
        if self.run_id and self._heartbeat_task is None:
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    async def stop_heartbeat(self) -> None:
        task, self._heartbeat_task = self._heartbeat_task, None
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):           # noqa: BLE001
                pass

    async def _wait_for_next_beat(self) -> None:
        try:
            await asyncio.wait_for(self._phase_changed.wait(), timeout=HEARTBEAT_SECONDS)
        except asyncio.TimeoutError:
            return
        self._phase_changed.clear()
        since_last = asyncio.get_running_loop().time() - self._last_beat_at
        if since_last < PHASE_HEARTBEAT_MIN_GAP:
            await asyncio.sleep(PHASE_HEARTBEAT_MIN_GAP - since_last)

    async def _heartbeat_loop(self) -> None:
        while True:
            await self._wait_for_next_beat()
            self._last_beat_at = asyncio.get_running_loop().time()
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.post(
                        f"{WEBAPP_API_URL}/api/internal/triage-runs/"
                        f"{self.run_id}/heartbeat",
                        json={"phase": self.phase, "progress": self.progress},
                        headers=_headers(),
                    )
                body = response.json() if response.content else {}
            except Exception as exc:                              # noqa: BLE001
                self._consecutive_failures += 1
                logger.warning(
                    f"Triage heartbeat failed "
                    f"({self._consecutive_failures}/{HEARTBEAT_FAILURE_LIMIT}): {exc}")
                if self._consecutive_failures >= HEARTBEAT_FAILURE_LIMIT:
                    self._abort_reason = "the webapp could not be reached"
                    return
                continue

            self._consecutive_failures = 0
            if body.get("abort"):
                self._abort_reason = str(body.get("reason") or "the run was stopped")
                logger.info(f"Triage run {self.run_id} told to abort: "
                            f"{self._abort_reason}")
                return

    def check_abort(self) -> None:
        """Raise if the run has been told to stop. Called between steps."""
        if self._abort_reason:
            raise TriageRunAborted(self._abort_reason, "stopped")

    @property
    def aborted(self) -> bool:
        return self._abort_reason is not None

    # -- publish -----------------------------------------------------------
    async def claim_publish(self) -> None:
        """Take the right to write, or raise before anything is written."""
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(
                    f"{WEBAPP_API_URL}/api/internal/triage-runs/{self.run_id}/publish",
                    json={}, headers=_headers(),
                )
        except Exception as exc:                                  # noqa: BLE001
            logger.error(f"Triage publish claim failed to reach the webapp: {exc}")
            raise TriageRunAborted(
                "the results could not be published", "publish_refused") from exc

        if response.status_code != 200:
            detail = _reason(response)
            logger.warning(f"Triage publish refused: {detail}")
            error_class = "publish_refused"
            try:
                error_class = response.json().get("errorClass") or error_class
            except Exception:                                     # noqa: BLE001
                pass
            raise TriageRunAborted(detail, error_class)

    # -- finish ------------------------------------------------------------
    async def finish(self, status: str, summary: dict | None = None,
                     error_class: str = "", intel_date: str = "") -> None:
        """Record the outcome. Never raises: this runs in a `finally`."""
        if not self.run_id:
            return
        await self.stop_heartbeat()
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                await client.post(
                    f"{WEBAPP_API_URL}/api/internal/triage-runs/{self.run_id}/finish",
                    json={
                        "status": status,
                        "summary": summary or {},
                        "errorClass": error_class,
                        **({"intelDate": intel_date} if intel_date else {}),
                    },
                    headers=_headers(),
                )
        except Exception as exc:                                  # noqa: BLE001
            # The run stays `running` until its heartbeat expires, which is the
            # designed fallback rather than a second failure mode.
            logger.error(f"Could not record how triage run {self.run_id} ended: {exc}")


def _reason(response: httpx.Response) -> str:
    try:
        return str(response.json().get("error") or f"HTTP {response.status_code}")
    except Exception:                                             # noqa: BLE001
        return f"HTTP {response.status_code}"
