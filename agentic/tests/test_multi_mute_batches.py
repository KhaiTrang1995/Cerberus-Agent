"""Multi mute: the server-side batch store (plan §7.1, D12).

The write accepts only keys from a stored batch, so this store is what stops a
tampered client from turning a suggestion into an arbitrary bulk mute. It must
fail closed: expired, evicted, or another user's or project's batch is simply
not there.

Run: ./agentic/run_tests.sh tests/test_multi_mute_batches.py
"""
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from multi_mute import batches as B  # noqa: E402

T0 = 1_000_000.0


def put(store, user="u1", project="p1", now=T0, members=("k1", "k2")):
    return store.put(user, project, label="Vulnerability", seed_key="seed", seed_name="Nginx banner",
                     ceiling={"severity_rank": 1, "tier_rank": None, "validated": False,
                              "malicious": False, "confirmed": False},
                     members=members, model="provider/model-x", prompt_version="multi-mute-v1",
                     now=now)


def test_id_format():
    store = B.BatchStore()
    ids = {put(store).batch_id for _ in range(50)}
    assert all(B.BATCH_ID_RE.match(i) for i in ids)
    assert len(ids) == 50


def test_round_trip():
    store = B.BatchStore()
    batch = put(store, members=["k1", "k2", "k1"])
    got = store.get("u1", "p1", batch.batch_id, now=T0 + 1)
    assert got == batch
    assert got.members == frozenset({"k1", "k2"})
    assert (got.label, got.seed_key, got.model, got.prompt_version) == (
        "Vulnerability", "seed", "provider/model-x", "multi-mute-v1")
    assert got.ceiling["severity_rank"] == 1


def test_ttl():
    store = B.BatchStore()
    batch = put(store)
    assert store.get("u1", "p1", batch.batch_id, now=T0 + B.BATCH_TTL_S - 1) is not None
    assert store.get("u1", "p1", batch.batch_id, now=T0 + B.BATCH_TTL_S) is None
    assert len(store) == 0


def test_expired_batches_are_purged_on_put():
    store = B.BatchStore()
    put(store, user="u1")
    put(store, user="u2", now=T0 + B.BATCH_TTL_S + 5)
    assert len(store) == 1


def test_per_user_cap_evicts_the_oldest():
    store = B.BatchStore()
    made = [put(store, now=T0 + i) for i in range(B.BATCHES_PER_USER + 2)]
    live = [b for b in made if store.get("u1", "p1", b.batch_id, now=T0 + 10)]
    assert live == made[2:]


def test_the_cap_is_per_user_across_projects():
    store = B.BatchStore()
    made = [put(store, project=f"p{i}", now=T0 + i) for i in range(B.BATCHES_PER_USER + 1)]
    assert store.get("u1", "p0", made[0].batch_id, now=T0 + 10) is None
    other = put(store, user="u2", now=T0 + 20)
    assert store.get("u1", "p1", made[1].batch_id, now=T0 + 21) is not None
    assert store.get("u2", "p1", other.batch_id, now=T0 + 21) is not None


def test_another_user_or_project_cannot_read_a_batch():
    store = B.BatchStore()
    batch = put(store)
    assert store.get("u2", "p1", batch.batch_id, now=T0) is None
    assert store.get("u1", "p2", batch.batch_id, now=T0) is None
    # A refused read does not delete the owner's batch.
    assert store.get("u1", "p1", batch.batch_id, now=T0) is not None


def test_unknown_or_malformed_ids():
    store = B.BatchStore()
    put(store)
    for bad in ("mm-00000000", "mm-XYZ", "mm-3f9a2c1d; MATCH (n) DETACH DELETE n", "", None, 42):
        assert store.get("u1", "p1", bad, now=T0) is None


def test_clear():
    store = B.BatchStore()
    batch = put(store)
    store.clear()
    assert store.get("u1", "p1", batch.batch_id, now=T0) is None


def test_concurrent_puts_keep_the_cap():
    store = B.BatchStore()

    def worker(offset):
        for i in range(20):
            put(store, now=T0 + offset * 100 + i)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(store) == B.BATCHES_PER_USER


def test_module_singleton():
    assert isinstance(B.STORE, B.BatchStore)
