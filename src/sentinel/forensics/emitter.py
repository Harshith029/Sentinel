"""The span emitter — SENTINEL's single serialization point (BUILD_SPEC §2).

Spec rule: a "per-trace monotonic ``seq`` assigned at the proxy (single
serialization point) before each async write. Replay orders by
``(trace_id, seq)``."

The whole correctness argument lives in :meth:`SpanEmitter.emit`:

1. ``seq`` is read-incremented and the Span is constructed **inside an
   ``asyncio.Lock``** — so even with many coroutines emitting concurrently, no
   two spans in a trace ever share a seq and the seq order equals the order
   spans were *created*.
2. The actual ``await store.put(span)`` happens **outside the lock** — so a slow
   storage write neither serializes all other emits nor lets write-COMPLETION
   order (which is nondeterministic under concurrency) leak into ``seq``.

That separation is the bug the spec is guarding against: ordering by write
completion instead of by an authority-assigned sequence.
"""
from __future__ import annotations

import asyncio

from sentinel.forensics.events import EventPayload
from sentinel.forensics.span import Span
from sentinel.forensics.store import ForensicStore
from sentinel.redaction import redact_payload
from sentinel.tracing import new_span_id_hex, new_trace_id_hex


class SpanEmitter:
    """Assigns monotonic per-trace ``seq`` and writes spans to a store.

    One emitter can serve many concurrent traces; ``seq`` is tracked per
    ``trace_id``. ``span_id`` is minted from the OTel SDK id generator (never a
    hand-rolled UUID, per §2). :meth:`emit` returns the written Span so the
    caller can use its ``span_id`` as the ``parent_span_id`` of a child event —
    this is how branching causality is recorded.
    """

    def __init__(self, store: ForensicStore) -> None:
        self._store = store
        self._lock = asyncio.Lock()
        # trace_id -> next seq to hand out (starts at 0 for a trace's first span).
        self._next_seq: dict[str, int] = {}

    @staticmethod
    def new_trace_id() -> str:
        """Mint a fresh OTel trace id (one agent task = one trace)."""
        return new_trace_id_hex()

    async def emit(
        self,
        payload: EventPayload,
        *,
        trace_id: str,
        parent_span_id: str | None = None,
    ) -> Span:
        """Record ``payload`` as a sequenced Span under ``trace_id`` and persist it.

        Returns the written Span. The span's ``span_id`` is freshly minted; pass
        it as the next event's ``parent_span_id`` to build the causal DAG.
        """
        # Redact BEFORE anything durable sees the payload. This is the single
        # serialization point for every span, so there is no code path that can
        # persist raw caller data by forgetting to redact at the call site.
        payload = redact_payload(payload)

        # Mint the id outside the lock (CPU-only, collision-free in practice) to
        # keep the critical section to just the seq read/increment + construct.
        span_id = new_span_id_hex()

        async with self._lock:
            seq = self._next_seq.get(trace_id, 0)
            self._next_seq[trace_id] = seq + 1
            span = Span(
                trace_id=trace_id,
                span_id=span_id,
                parent_span_id=parent_span_id,
                seq=seq,
                payload=payload,
            )

        # OUTSIDE the lock: a slow/awaited write must not affect seq ordering or
        # block other coroutines' seq assignment.
        await self._store.put(span)
        return span

    def peek_next_seq(self, trace_id: str) -> int:
        """Return the seq the next :meth:`emit` would assign for ``trace_id``.

        Read-only; for tests/diagnostics. Not part of the hot path.
        """
        return self._next_seq.get(trace_id, 0)
