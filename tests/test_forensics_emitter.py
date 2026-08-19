"""Phase 1: SpanEmitter — monotonic per-trace seq at the single serialization point."""
from __future__ import annotations

import asyncio

from sentinel.forensics.emitter import SpanEmitter
from sentinel.forensics.events import InputReceived, ToolCallProposed
from sentinel.forensics.span import Span
from sentinel.forensics.store import ForensicStore, InMemoryForensicStore

TRACE_A = "a" * 32
TRACE_B = "b" * 32


class SlowStore:
    """Wraps a store and yields control inside ``put``.

    The suspension point matters: it forces concurrent ``emit`` coroutines to
    interleave at the write step. If seq were assigned AFTER the await (or
    without the lock), the interleave would produce duplicate/!contiguous seqs —
    so this is the regression guard for the serialization-point design.
    """

    def __init__(self, inner: ForensicStore) -> None:
        self._inner = inner

    async def put(self, span: Span) -> None:
        await asyncio.sleep(0)  # cooperative yield → maximize interleaving
        await self._inner.put(span)

    async def get_spans(self, trace_id: str) -> list[Span]:
        return await self._inner.get_spans(trace_id)


async def test_seq_starts_at_zero_and_increments() -> None:
    store = InMemoryForensicStore()
    emitter = SpanEmitter(store)
    spans = [
        await emitter.emit(
            ToolCallProposed(tool_name=f"t{i}", arguments={}), trace_id=TRACE_A
        )
        for i in range(3)
    ]
    assert [s.seq for s in spans] == [0, 1, 2]
    assert [s.seq for s in await store.get_spans(TRACE_A)] == [0, 1, 2]


async def test_seq_independent_per_trace() -> None:
    emitter = SpanEmitter(InMemoryForensicStore())
    a0 = await emitter.emit(ToolCallProposed(tool_name="a", arguments={}), trace_id=TRACE_A)
    b0 = await emitter.emit(ToolCallProposed(tool_name="b", arguments={}), trace_id=TRACE_B)
    a1 = await emitter.emit(ToolCallProposed(tool_name="a", arguments={}), trace_id=TRACE_A)
    assert (a0.seq, a1.seq) == (0, 1)
    assert b0.seq == 0  # independent counter


async def test_emit_returns_span_with_trace_parent_and_minted_id() -> None:
    emitter = SpanEmitter(InMemoryForensicStore())
    parent = await emitter.emit(
        InputReceived(origin_label="USER", content="hi"), trace_id=TRACE_A
    )
    child = await emitter.emit(
        ToolCallProposed(tool_name="t", arguments={}),
        trace_id=TRACE_A,
        parent_span_id=parent.span_id,
    )
    assert parent.is_root is True
    assert child.parent_span_id == parent.span_id
    assert child.trace_id == TRACE_A
    # Minted span ids are valid 16-hex and unique.
    assert len(child.span_id) == 16 and child.span_id != parent.span_id


async def test_concurrent_emits_get_unique_contiguous_seqs() -> None:
    n = 64
    store = InMemoryForensicStore()
    emitter = SpanEmitter(SlowStore(store))

    spans = await asyncio.gather(
        *(
            emitter.emit(ToolCallProposed(tool_name=f"t{i}", arguments={}), trace_id=TRACE_A)
            for i in range(n)
        )
    )

    seqs = sorted(s.seq for s in spans)
    assert seqs == list(range(n))  # unique + contiguous, no dupes, no gaps
    assert emitter.peek_next_seq(TRACE_A) == n
    assert len(await store.get_spans(TRACE_A)) == n


async def test_peek_next_seq_is_read_only() -> None:
    emitter = SpanEmitter(InMemoryForensicStore())
    assert emitter.peek_next_seq(TRACE_A) == 0
    assert emitter.peek_next_seq(TRACE_A) == 0  # peeking does not advance
    await emitter.emit(ToolCallProposed(tool_name="t", arguments={}), trace_id=TRACE_A)
    assert emitter.peek_next_seq(TRACE_A) == 1
