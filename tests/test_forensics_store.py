"""Phase 1: ForensicStore conformance.

Every test taking the ``store`` fixture runs against EVERY backend (in-memory,
Cosmos via an async fake, and the SQLite file store), which is exactly the DoD
requirement that "every store passes the IDENTICAL test suite."
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel.forensics.events import (
    AuthorizationDecided,
    RuleEvaluation,
    ToolCallProposed,
)
from sentinel.forensics.span import Span
from sentinel.forensics.store import (
    ForensicIntegrityError,
    ForensicStore,
    InMemoryForensicStore,
    SqliteForensicStore,
)

# Two distinct, valid (non-zero) trace ids (mirrors the conftest constants).
TRACE_A = "a" * 32
TRACE_B = "b" * 32


async def test_put_then_get_roundtrip(
    store: ForensicStore, make_span: Callable[..., Span]
) -> None:
    span = make_span(trace_id=TRACE_A, seq=0)
    await store.put(span)
    got = await store.get_spans(TRACE_A)
    assert len(got) == 1
    assert got[0].span_id == span.span_id
    assert got[0].payload == span.payload


async def test_get_unknown_trace_is_empty(store: ForensicStore) -> None:
    assert await store.get_spans("f" * 32) == []


async def test_upsert_is_idempotent(
    store: ForensicStore, make_span: Callable[..., Span]
) -> None:
    span = make_span(trace_id=TRACE_A, seq=0, span_id="1" * 16)
    await store.put(span)
    await store.put(span)  # same span_id again
    got = await store.get_spans(TRACE_A)
    assert len(got) == 1  # exactly one record, not two


async def test_identical_redundant_write_is_noop(
    store: ForensicStore, make_span: Callable[..., Span]
) -> None:
    # Same CONTENT via a distinct instance (round-tripped) must be a silent
    # no-op — idempotency is by content, not object identity.
    span = make_span(trace_id=TRACE_A, seq=0, span_id="d" * 16)
    twin = Span.model_validate(span.model_dump())
    await store.put(span)
    await store.put(twin)
    assert len(await store.get_spans(TRACE_A)) == 1


async def test_conflicting_re_emit_is_rejected_not_overwritten(
    store: ForensicStore, make_span: Callable[..., Span]
) -> None:
    # Re-emitting the SAME span_id with DIFFERENT content must be rejected and
    # the original record preserved — forensic spans are immutable.
    original = make_span(
        trace_id=TRACE_A,
        seq=0,
        span_id="c" * 16,
        payload=ToolCallProposed(tool_name="original", arguments={}),
    )
    tampered = make_span(
        trace_id=TRACE_A,
        seq=0,
        span_id="c" * 16,
        payload=ToolCallProposed(tool_name="tampered", arguments={}),
    )
    await store.put(original)
    with pytest.raises(ForensicIntegrityError):
        await store.put(tampered)

    (kept,) = await store.get_spans(TRACE_A)
    assert isinstance(kept.payload, ToolCallProposed)
    assert kept.payload.tool_name == "original"  # untouched


async def test_get_spans_ordered_by_seq(
    store: ForensicStore, make_span: Callable[..., Span]
) -> None:
    # Insert out of order; store must return canonical (seq) order.
    for seq in (2, 0, 3, 1):
        await store.put(make_span(trace_id=TRACE_A, seq=seq))
    got = await store.get_spans(TRACE_A)
    assert [s.seq for s in got] == [0, 1, 2, 3]


async def test_partitioned_by_trace(
    store: ForensicStore, make_span: Callable[..., Span]
) -> None:
    await store.put(make_span(trace_id=TRACE_A, seq=0, span_id="a1" + "0" * 14))
    await store.put(make_span(trace_id=TRACE_A, seq=1, span_id="a2" + "0" * 14))
    await store.put(make_span(trace_id=TRACE_B, seq=0, span_id="b1" + "0" * 14))

    a_spans = await store.get_spans(TRACE_A)
    b_spans = await store.get_spans(TRACE_B)
    assert {s.span_id for s in a_spans} == {"a1" + "0" * 14, "a2" + "0" * 14}
    assert {s.span_id for s in b_spans} == {"b1" + "0" * 14}


async def test_roundtrip_preserves_rich_payload_type(
    store: ForensicStore, make_span: Callable[..., Span]
) -> None:
    # The discriminated union must survive the store's serialize/deserialize.
    payload = AuthorizationDecided(
        tool_name="send_email",
        decision="DENY",
        policy_version="v3",
        effective_provenance=["USER", "RETRIEVED_CONTENT"],
        is_tainted=True,
        rules_considered=[
            RuleEvaluation(rule_id="r1", effect="DENY", matched=True, detail="tainted"),
            RuleEvaluation(rule_id="r2", effect="ALLOW", matched=False),
        ],
        matched_rule_id="r1",
        reason="tainted -> exfil tool",
    )
    span = make_span(trace_id=TRACE_A, seq=0, payload=payload)
    await store.put(span)
    (restored,) = await store.get_spans(TRACE_A)
    assert isinstance(restored.payload, AuthorizationDecided)
    assert restored.payload == payload


# --- In-memory-specific behaviour (LRU bound is an impl detail, not the contract) ---

async def test_inmemory_lru_evicts_oldest_trace(make_span: Callable[..., Span]) -> None:
    store = InMemoryForensicStore(max_traces=2)
    t0, t1, t2 = ("0a" + "0" * 30, "1a" + "0" * 30, "2a" + "0" * 30)
    await store.put(make_span(trace_id=t0, seq=0))
    await store.put(make_span(trace_id=t1, seq=0))
    # Touch t0 so t1 becomes the least-recently-used.
    await store.get_spans(t0)
    await store.put(make_span(trace_id=t2, seq=0))  # exceeds max_traces -> evict t1

    assert await store.get_spans(t1) == []          # evicted
    assert len(await store.get_spans(t0)) == 1       # retained (recently used)
    assert len(await store.get_spans(t2)) == 1       # newest


def test_inmemory_rejects_bad_max_traces() -> None:
    with pytest.raises(ValueError, match="max_traces"):
        InMemoryForensicStore(max_traces=0)


# --- Sqlite-specific behaviour (cross-process persistence is the whole point) ---

async def test_sqlite_persists_across_reopens(
    tmp_path: Path, make_span: Callable[..., Span]
) -> None:
    db = tmp_path / "spans.db"
    a = SqliteForensicStore(db)
    await a.put(make_span(trace_id=TRACE_A, seq=0, span_id="a" + "1" * 15))
    await a.put(make_span(trace_id=TRACE_A, seq=1, span_id="a" + "2" * 15))
    a.close()

    # A SECOND store reading the same file must see the prior writes.
    b = SqliteForensicStore(db)
    got = await b.get_spans(TRACE_A)
    assert [s.seq for s in got] == [0, 1]
    # And list_trace_ids surfaces the trace for restart-resumption.
    assert TRACE_A in await b.list_trace_ids()
    b.close()


async def test_sqlite_list_trace_ids_most_recent_first(
    tmp_path: Path, make_span: Callable[..., Span]
) -> None:
    store = SqliteForensicStore(tmp_path / "spans.db")
    try:
        # TRACE_A appears with a later seq than TRACE_B → it should rank first.
        await store.put(make_span(trace_id=TRACE_B, seq=0, span_id="b" + "1" * 15))
        await store.put(make_span(trace_id=TRACE_A, seq=0, span_id="a" + "1" * 15))
        await store.put(make_span(trace_id=TRACE_A, seq=2, span_id="a" + "3" * 15))
        traces = await store.list_trace_ids()
        assert traces == [TRACE_A, TRACE_B]
    finally:
        store.close()


async def test_sqlite_lists_by_recency_not_by_trace_length(
    tmp_path: Path, make_span: Callable[..., Span]
) -> None:
    """A long old trace must not outrank a short new one (review F32).

    The order came from MAX(seq), and seq counts spans within a trace, so the
    longest trace was listed first however old it was.
    """
    from datetime import UTC, datetime, timedelta

    old = datetime.now(UTC) - timedelta(days=1)
    new = datetime.now(UTC)
    store = SqliteForensicStore(tmp_path / "spans.db")
    try:
        for seq in range(5):  # TRACE_A: older, and longer
            span = make_span(trace_id=TRACE_A, seq=seq, span_id=f"a{seq:015x}")
            await store.put(span.model_copy(update={"timestamp": old + timedelta(seconds=seq)}))
        span = make_span(trace_id=TRACE_B, seq=0, span_id="b" + "1" * 15)
        await store.put(span.model_copy(update={"timestamp": new}))
        assert await store.list_trace_ids() == [TRACE_B, TRACE_A]
    finally:
        store.close()


# --- SQLite: cancellation and orphaned ownership rows ----------------------------


async def test_a_cancelled_sqlite_write_holds_the_lock_until_its_thread_ends(
    tmp_path: Path, make_span: Callable[..., Span]
) -> None:
    """Cancelling the caller released the lock while the thread kept writing.

    The next operation then used the connection alongside it, and the write
    the caller believed abandoned still landed afterwards.
    """
    store = SqliteForensicStore(tmp_path / "forensics.db")
    events: list[str] = []
    real_put, real_read = store._put_blocking, store._read_blocking  # noqa: SLF001

    def slow_put(span: Span, body: str) -> None:
        events.append("put-start")
        time.sleep(0.3)
        real_put(span, body)
        events.append("put-end")

    def read(trace_id: str) -> list[str]:
        events.append("read")
        return real_read(trace_id)

    store._put_blocking = slow_put  # type: ignore[method-assign]  # noqa: SLF001
    store._read_blocking = read  # type: ignore[method-assign]  # noqa: SLF001
    span = make_span(seq=0)
    writer = asyncio.create_task(store.put(span))
    await asyncio.sleep(0.05)
    writer.cancel()
    with pytest.raises(asyncio.CancelledError):
        await writer
    await store.get_spans(span.trace_id)
    assert events == ["put-start", "put-end", "read"]
    store.close()


async def test_ownership_rows_without_spans_are_purged(tmp_path: Path) -> None:
    """A run that never wrote a span had nothing to age out with."""
    store = SqliteForensicStore(tmp_path / "forensics.db")
    await store.put_run("a" * 32, tenant="acme", agent_id="x", scenario="custom")
    await store.put_run("b" * 32, tenant="acme", agent_id="x", scenario="custom")
    future = datetime.now(UTC) + timedelta(days=1)
    await store.purge_older_than(future, keep=frozenset({"b" * 32}))
    assert set(await store.run_owners()) == {"b" * 32}  # the running one is kept
    store.close()


async def test_in_memory_spans_cannot_be_rewritten_through_a_reference(
    make_span: Callable[..., Span],
) -> None:
    """Span is frozen but its payload's dicts were not, and get handed out the originals."""
    from sentinel.forensics.events import ToolCallProposed

    store = InMemoryForensicStore()
    span = make_span(seq=0, payload=ToolCallProposed(tool_name="x", arguments={"a": "v"}))
    await store.put(span)
    span.payload.arguments["after_put"] = "x"  # type: ignore[attr-defined]
    got = (await store.get_spans(span.trace_id))[0]
    got.payload.arguments["after_get"] = "y"  # type: ignore[attr-defined]
    stored = (await store.get_spans(span.trace_id))[0]
    assert list(stored.payload.arguments) == ["a"]  # type: ignore[attr-defined]


async def test_two_cosmos_writers_of_one_span_id_cannot_both_win(
    make_span: Callable[..., Span], fake_cosmos_container: type
) -> None:
    """Read-then-upsert let both see "absent"; the second silently replaced the first."""
    from sentinel.forensics.events import ToolCallProposed
    from sentinel.forensics.store import CosmosForensicStore

    class SlowReads(fake_cosmos_container):  # type: ignore[misc, valid-type]
        async def read_item(self, *, item: str, partition_key: str) -> dict[str, object]:
            # Answer first, then yield, as a network round trip does: the other
            # writer runs between this check and the write that follows it.
            try:
                found = await super().read_item(item=item, partition_key=partition_key)
            except Exception:
                await asyncio.sleep(0)
                raise
            await asyncio.sleep(0)
            return found

    container = SlowReads()
    store = CosmosForensicStore(container)  # type: ignore[arg-type]
    first = make_span(seq=0, payload=ToolCallProposed(tool_name="a", arguments={}))
    second = first.model_copy(update={"payload": ToolCallProposed(tool_name="b", arguments={})})
    results = await asyncio.gather(store.put(first), store.put(second), return_exceptions=True)
    assert any(isinstance(r, ForensicIntegrityError) for r in results), results
    stored = await store.get_spans(first.trace_id)
    assert [s.payload.tool_name for s in stored] == ["a"]  # type: ignore[attr-defined]


async def test_a_database_from_before_the_timestamp_column_is_migrated(
    tmp_path: Path, make_span: Callable[..., Span]
) -> None:
    """Listing and retention parsed every span's JSON under the lock (STORE-2)."""
    import json as _json
    import sqlite3

    db = tmp_path / "old.db"
    span = make_span(seq=0)
    with sqlite3.connect(db) as conn:  # the schema as it was
        conn.execute(
            "CREATE TABLE spans (trace_id TEXT NOT NULL, span_id TEXT NOT NULL PRIMARY KEY,"
            " seq INTEGER NOT NULL, body TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO spans VALUES (?, ?, ?, ?)",
            (span.trace_id, span.span_id, span.seq, _json.dumps(span.model_dump(mode="json"))),
        )
    store = SqliteForensicStore(db)
    assert await store.list_trace_ids() == [span.trace_id]
    later = make_span(trace_id="b" * 32, seq=0, span_id="2" * 16)
    await store.put(later)
    assert await store.list_trace_ids() == ["b" * 32, span.trace_id]
    store.close()
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM spans WHERE ts IS NULL").fetchone()[0] == 0
        plan = " ".join(
            str(r) for r in conn.execute(
                "EXPLAIN QUERY PLAN SELECT trace_id FROM spans GROUP BY trace_id"
                " ORDER BY MAX(julianday(ts))"
            )
        )
    assert "spans_by_trace_ts" in plan


async def test_spans_written_without_a_timestamp_are_filled_in_and_age_out(
    tmp_path: Path, make_span: Callable[..., Span]
) -> None:
    """0.2.2 can still write to a migrated database, but leaves ``ts`` empty.

    The backfill used to run only while adding the column, so after a rollback
    to 0.2.2 and an upgrade again those spans kept no timestamp, and a trace
    made only of them was never deleted by retention.
    """
    import sqlite3
    from datetime import UTC, datetime, timedelta

    db = tmp_path / "rolled-back.db"
    store = SqliteForensicStore(db)
    span = make_span(seq=0)
    await store.put(span)
    store.close()
    with sqlite3.connect(db) as conn:  # what an INSERT from 0.2.2 leaves behind
        conn.execute("UPDATE spans SET ts = NULL")

    store = SqliteForensicStore(db)
    future = datetime.now(UTC) + timedelta(days=1)
    assert await store.purge_older_than(future) == [span.trace_id]
    store.close()

    # Checked on every open, so it must not scan the table to find nothing.
    with sqlite3.connect(db) as conn:
        plan = " ".join(
            str(r) for r in conn.execute(
                "EXPLAIN QUERY PLAN UPDATE spans SET ts = json_extract(body, '$.timestamp')"
                " WHERE ts IS NULL"
            )
        )
    assert "spans_missing_ts" in plan
