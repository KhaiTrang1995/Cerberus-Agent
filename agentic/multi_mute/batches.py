"""The suggestions a later mute may draw from (plan §7.1, D12).

Suggest is read-only. What it proposed is kept here, server side, and the
`mute_batch` write accepts only keys from the batch it names, so a tampered
client cannot turn a suggestion into an arbitrary bulk mute.

Process memory is the source of truth: the agent runs one uvicorn worker. A
restart loses every batch, which answers `batch_expired`, the fail-closed
direction.
"""
from __future__ import annotations

import re
import secrets
import threading
import time
from dataclasses import dataclass

BATCH_TTL_S = 3600
BATCHES_PER_USER = 5
BATCH_ID_RE = re.compile(r"^mm-[0-9a-f]{8}$")


@dataclass(frozen=True)
class Batch:
    batch_id: str
    user_id: str
    project_id: str
    label: str
    seed_key: str
    seed_name: str
    ceiling: dict
    members: frozenset
    model: str
    prompt_version: str
    created_at: float

    def expired(self, now: float) -> bool:
        return now - self.created_at >= BATCH_TTL_S


class BatchStore:
    """Thread-safe: the write path runs under `asyncio.to_thread`."""

    def __init__(self):
        self._lock = threading.Lock()
        self._batches: dict = {}

    def _purge(self, now: float) -> None:
        for batch_id in [b.batch_id for b in self._batches.values() if b.expired(now)]:
            del self._batches[batch_id]

    def _new_id(self) -> str:
        while True:
            batch_id = f"mm-{secrets.token_hex(4)}"
            if batch_id not in self._batches:
                return batch_id

    def put(self, user_id, project_id, *, label, seed_key, seed_name, ceiling, members,
            model, prompt_version, now: float | None = None) -> Batch:
        now = time.time() if now is None else now
        with self._lock:
            self._purge(now)
            batch = Batch(
                batch_id=self._new_id(), user_id=str(user_id), project_id=str(project_id),
                label=str(label), seed_key=str(seed_key), seed_name=str(seed_name or ""),
                ceiling=dict(ceiling or {}), members=frozenset(str(k) for k in members or ()),
                model=str(model or ""), prompt_version=str(prompt_version or ""),
                created_at=now,
            )
            self._batches[batch.batch_id] = batch
            mine = sorted((b for b in self._batches.values() if b.user_id == batch.user_id),
                          key=lambda b: b.created_at)
            for old in mine[:-BATCHES_PER_USER]:
                del self._batches[old.batch_id]
            return batch

    def get(self, user_id, project_id, batch_id, now: float | None = None) -> Batch | None:
        """The batch, or None when it is missing, expired, or another user's or project's."""
        if not isinstance(batch_id, str) or not BATCH_ID_RE.match(batch_id):
            return None
        now = time.time() if now is None else now
        with self._lock:
            batch = self._batches.get(batch_id)
            if batch is None:
                return None
            if batch.expired(now):
                del self._batches[batch_id]
                return None
            if batch.user_id != str(user_id) or batch.project_id != str(project_id):
                return None
            return batch

    def clear(self) -> None:
        with self._lock:
            self._batches.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._batches)


STORE = BatchStore()
