"""Round-robin API key rotation to avoid rate limits."""

import logging
import threading

logger = logging.getLogger(__name__)


class KeyRotator:
    """Rotates through a pool of API keys every N calls.

    Shared by every worker thread of an enricher, so the pool is guarded by a
    lock. A key the provider refuses is dropped with ``mark_bad``; once every
    key is gone the pool is ``exhausted`` and callers must not fall back to the
    main key, which was the pool's first member.
    """

    def __init__(self, keys: list[str], rotate_every_n: int = 10):
        # 1-based positions in the pool as configured (main key = #1), so a
        # dropped key can be named in the log without printing its value.
        self._positions = [i + 1 for i, k in enumerate(keys) if k]
        self.keys = [k for k in keys if k]
        self.rotate_every_n = max(1, rotate_every_n)
        self._call_count = 0
        self._index = 0
        self._dropped = 0
        self._lock = threading.Lock()

    @property
    def current_key(self) -> str:
        with self._lock:
            if not self.keys:
                return ''
            return self.keys[self._index % len(self.keys)]

    def tick(self):
        """Call after each API request to advance the rotation counter."""
        with self._lock:
            if len(self.keys) <= 1:
                return
            self._call_count += 1
            if self._call_count >= self.rotate_every_n:
                self._call_count = 0
                old_idx = self._index
                self._index = (self._index + 1) % len(self.keys)
                logger.debug("Key rotation: switched from key index %d to %d (pool size %d)",
                             old_idx, self._index, len(self.keys))

    def mark_bad(self, key) -> tuple[int, int]:
        """Drop a key the provider refused (bad, revoked, out of quota).

        ``key`` is the key value, or an index into the current pool. Returns
        ``(position, left)``: the key's 1-based position as configured (0 when
        it was not in the pool, e.g. another thread dropped it first) and how
        many keys remain.
        """
        with self._lock:
            if isinstance(key, int) and not isinstance(key, bool):
                if not 0 <= key < len(self.keys):
                    return 0, len(self.keys)
                key = self.keys[key]
            hits = [i for i, k in enumerate(self.keys) if k == key]
            if not hits:
                return 0, len(self.keys)
            position = self._positions[hits[0]]
            current = self.keys[self._index % len(self.keys)] if self.keys else None
            for i in reversed(hits):
                del self.keys[i]
                del self._positions[i]
            self._dropped += len(hits)
            self._call_count = 0
            if current in self.keys:
                self._index = self.keys.index(current)
            else:
                # The dropped key was the current one: the next key in line
                # slid into its slot.
                self._index = hits[0] % len(self.keys) if self.keys else 0
            return position, len(self.keys)

    @property
    def exhausted(self) -> bool:
        """Every key the pool started with has been dropped."""
        with self._lock:
            return self._dropped > 0 and not self.keys

    @property
    def has_keys(self) -> bool:
        return len(self.keys) > 0

    @property
    def pool_size(self) -> int:
        return len(self.keys)
