"""Phase 1: ForensicStore conformance.

Every test taking the ``store`` fixture runs against EVERY backend (in-memory,
Cosmos via an async fake, and the SQLite file store), which is exactly the DoD
requirement that "every store passes the IDENTICAL test suite."
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from whence.forensics.events import (
    AuthorizationDecided,
    RuleEvaluation,
    ToolCallProposed,
)
from whence.forensics.span import Span
from whence.forensics.store import (
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
