"""Event bus + broadcasting store (BUILD_SPEC §Phase 6).

The live monitor must survive a dropped stream. The mechanism:

* Every forensic span is also published to an in-process :class:`EventBus`, which
  assigns a monotonic GLOBAL ``event_id`` and keeps an ordered buffer.
* SSE clients stream events and remember the last ``event_id`` they saw. On
  reconnect (``Last-Event-ID``) — or via the polling fallback — they ask for
  :meth:`EventBus.events_since`, which returns exactly the events they missed,
  contiguous, with no gap and no duplication.

:meth:`EventBus.subscribe` is written so no event can slip through the crack
between "drain the buffer" and "wait for the next one": the buffer snapshot and
the wait happen under the same lock that :meth:`publish` holds, and a per-client
cursor advances monotonically.
"""
from __future__ import annotations

import asyncio
import bisect
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any, Final

from sentinel.forensics.span import Span
from sentinel.forensics.store import ForensicStore

_DEFAULT_BUFFER_LIMIT: Final[int] = 100_000


def _event_id(event: BroadcastEvent) -> int:
    return event.event_id


@dataclass(frozen=True)
class BroadcastEvent:
    """One published span, tagged with the bus's global monotonic id."""

    event_id: int
    span: Span

    def to_payload(self) -> dict[str, Any]:
        return {"event_id": self.event_id, "span": self.span.model_dump(mode="json")}


class EventBus:
    """An in-process, ordered, replayable event log with live subscriptions."""

    def __init__(self, *, buffer_limit: int = _DEFAULT_BUFFER_LIMIT) -> None:
        self._events: list[BroadcastEvent] = []
        self._next_id = 1
        self._buffer_limit = buffer_limit
        self._condition = asyncio.Condition()

    @property
    def last_event_id(self) -> int:
        return self._next_id - 1

    async def publish(self, span: Span) -> BroadcastEvent:
        async with self._condition:
            event = BroadcastEvent(event_id=self._next_id, span=span)
            self._next_id += 1
            self._events.append(event)
            # Trim in batches: deleting one element from the front of a list is
            # O(n), so trimming on EVERY publish once full made each publish cost
            # the whole buffer. Letting it overshoot by a tenth amortises that.
            if len(self._events) > self._buffer_limit + self._buffer_limit // 10:
                del self._events[: len(self._events) - self._buffer_limit]
            self._condition.notify_all()
        return event

    def events_since(self, last_event_id: int) -> list[BroadcastEvent]:
        """Every buffered event with ``event_id > last_event_id`` (the back-fill).

        Ids are assigned monotonically under the publish lock, so the buffer is
        sorted and a binary search finds the cut. This used to scan the whole
        buffer — up to 100 000 events — on every poll and every subscriber
        wake-up.
        """
        start = bisect.bisect_right(self._events, last_event_id, key=_event_id)
        return self._events[start:]

    async def subscribe(self, last_event_id: int = 0) -> AsyncIterator[BroadcastEvent]:
        """Yield events after ``last_event_id`` — buffered first, then live, gap-free."""
        cursor = last_event_id
        while True:
            async with self._condition:
                pending = self.events_since(cursor)
                if not pending:
                    # Release the lock and sleep until publish() notifies; on wake,
                    # re-snapshot. Nothing published in between can be missed,
                    # because publish() takes this same lock to append + notify.
                    await self._condition.wait()
                    pending = self.events_since(cursor)
            for event in pending:
                cursor = event.event_id
                yield event


class BroadcastStore:
    """A :class:`ForensicStore` decorator that tees every write to an EventBus.

    Writes to the inner store FIRST, then publishes — so any event a client sees
    is already durable in the store (a subsequent replay will include it).
    """

    def __init__(self, inner: ForensicStore, bus: EventBus) -> None:
        self._inner = inner
        self._bus = bus

    async def put(self, span: Span) -> None:
        await self._inner.put(span)
        await self._bus.publish(span)

    async def get_spans(self, trace_id: str) -> list[Span]:
        return await self._inner.get_spans(trace_id)
