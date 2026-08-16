"""Forensic span storage (BUILD_SPEC §2, Phase 1).

One interface, three implementations that MUST behave identically (the
conformance suite in :file:`tests/test_forensics_store.py` runs against ALL of
them):

* :class:`InMemoryForensicStore` — LRU-bounded over traces, for tests. Fast,
  offline, no persistence.
* :class:`SqliteForensicStore` — file-backed, the default for DEMO MODE so the
  dashboard and forensic trail survive a restart.
* :class:`CosmosForensicStore` — Azure Cosmos DB, partition key ``/trace_id``,
  idempotent ``upsert`` keyed by ``span_id``, relying on the Cosmos SDK's
  default retry policy (spec §2 — we do not hand-roll retries).

Idempotency is the shared invariant: writing the same ``span_id`` twice leaves
exactly one record. A re-emit with DIFFERENT content is rejected as a
:class:`ForensicIntegrityError` — forensic spans are immutable.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from collections import OrderedDict
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Protocol, runtime_checkable

from whence.forensics.span import Span

if TYPE_CHECKING:
    from azure.cosmos.aio import ContainerProxy

    from whence.config import Settings

_DEFAULT_MAX_TRACES: Final[int] = 1024
_LOG: Final[logging.Logger] = logging.getLogger("whence.forensics.store")


class ForensicIntegrityError(RuntimeError):
    """Raised when a span_id is re-emitted with DIFFERENT content.

    Forensic spans are immutable. Idempotency means "same span_id + same content
    is a no-op" — it must NOT mean "silently overwrite the prior record". A
    differing re-emit signals a bug (or tampering), so we fail loudly rather than
    destroy the original evidence.
    """


def _canonical(span: Span) -> dict[str, Any]:
    """Canonical JSON form used to decide whether two writes are identical.

    Comparing the JSON projection (not Python object identity) makes the
    in-memory and Cosmos stores reach the SAME verdict — the Cosmos copy has
    round-tripped through serialization, so object identity would never match.
    """
    return span.model_dump(mode="json")


def _ensure_no_conflict(existing: Span | None, incoming: Span) -> bool:
    """Return True if ``incoming`` is a duplicate (identical) of ``existing``.

    * No existing record        → returns False (caller should write it).
    * Existing, identical bytes  → returns True  (caller should no-op).
    * Existing, DIFFERENT bytes  → logs and raises :class:`ForensicIntegrityError`.
    """
    if existing is None:
        return False
    if _canonical(existing) == _canonical(incoming):
        return True
    _LOG.error(
        "forensic integrity violation: span_id=%s trace_id=%s re-emitted with "
        "different content; refusing to overwrite immutable record",
        incoming.span_id,
        incoming.trace_id,
    )
    raise ForensicIntegrityError(
        f"span {incoming.span_id} in trace {incoming.trace_id} was re-emitted "
        "with different content; forensic spans are immutable"
    )


@runtime_checkable
class ForensicStore(Protocol):
    """The storage contract every Whence component writes through.

    ``put`` is idempotent on ``span.span_id``. ``get_spans`` returns every span
    recorded for ``trace_id``, ordered by ``seq`` (the stable replay order);
    an unknown trace yields an empty list, never an error.
    """

    async def put(self, span: Span) -> None: ...

    async def get_spans(self, trace_id: str) -> list[Span]: ...


def _by_seq(spans: list[Span]) -> list[Span]:
    """Stable ``(seq, span_id)`` ordering — the canonical replay order.

    ``seq`` is unique per trace by construction (the emitter serializes it), so
    ``span_id`` is only a defensive tie-breaker that keeps ordering total and
    deterministic even if a malformed trace ever carried a duplicate seq.
    """
    return sorted(spans, key=lambda s: (s.seq, s.span_id))


class InMemoryForensicStore:
    """In-process store, LRU-bounded by trace count (spec: "LRU-bounded").

    Bounds memory by evicting the least-recently-used *trace* once
    ``max_traces`` is exceeded. Within a trace, spans are keyed by ``span_id``
    so a repeated write is a no-op overwrite (idempotent), matching Cosmos
    ``upsert`` semantics. Designed for single-event-loop use; all methods are
    await-free internally, so there is no read-modify-write interleaving.
    """

    def __init__(self, *, max_traces: int = _DEFAULT_MAX_TRACES) -> None:
        if max_traces < 1:
            raise ValueError("max_traces must be >= 1")
        self._max_traces = max_traces
        # trace_id -> (span_id -> Span); OrderedDict tracks LRU recency.
        self._traces: OrderedDict[str, dict[str, Span]] = OrderedDict()

    async def put(self, span: Span) -> None:
        trace = self._traces.get(span.trace_id)
        if trace is not None:
            # Immutable-record guard: identical re-emit → no-op; differing → raise.
            if _ensure_no_conflict(trace.get(span.span_id), span):
                self._traces.move_to_end(span.trace_id)  # refresh recency only
                return
        else:
            if len(self._traces) >= self._max_traces:
                self._traces.popitem(last=False)  # evict least-recently-used trace
            trace = {}
            self._traces[span.trace_id] = trace
        trace[span.span_id] = span
        self._traces.move_to_end(span.trace_id)  # mark most-recently-used

    async def get_spans(self, trace_id: str) -> list[Span]:
        trace = self._traces.get(trace_id)
        if trace is None:
            return []
        self._traces.move_to_end(trace_id)
        return _by_seq(list(trace.values()))


def _to_item(span: Span) -> dict[str, Any]:
    """Serialize a Span to a Cosmos JSON document.

    ``id`` is set to ``span_id`` so Cosmos's per-partition uniqueness gives us
    idempotent upsert for free. ``trace_id`` is already a field and is the
    container's partition key. ``mode="json"`` makes datetimes ISO strings.
    """
    item = span.model_dump(mode="json")
    item["id"] = span.span_id
    return item


def _from_item(item: dict[str, Any]) -> Span:
    """Rebuild a Span from a Cosmos document.

    Strips ``id`` (a duplicate of ``span_id``) and Cosmos's ``_``-prefixed
    system fields (``_rid``, ``_self``, ``_etag``, ``_attachments``, ``_ts``)
    so the strict (``extra="forbid"``) Span model validates cleanly.
    """
    cleaned = {k: v for k, v in item.items() if k != "id" and not k.startswith("_")}
    return Span.model_validate(cleaned)


class CosmosForensicStore:
    """Azure Cosmos DB store: partition key ``/trace_id``, idempotent upsert.

    Takes an already-constructed async ``ContainerProxy`` so the class is unit-
    testable against a fake that honors the real azure-cosmos async contract
    (``await upsert_item(body=...)``; ``query_items(...)`` returns an async
    iterable). The :func:`create_cosmos_store` factory wires the real client.
    """

    def __init__(self, container: ContainerProxy) -> None:
        self._container = container

    async def put(self, span: Span) -> None:
        # Immutable-record guard. A point read (single partition, by id) tells us
        # whether this span_id already exists; if so we must NOT blindly overwrite:
        #   identical content → idempotent no-op; different content → raise.
        # Only genuinely-new spans are written. upsert (not create) keeps the
        # write idempotent under the Cosmos SDK's default retry policy — we add
        # no retry of our own.
        from azure.cosmos.exceptions import CosmosResourceNotFoundError

        try:
            existing_doc = await self._container.read_item(
                item=span.span_id, partition_key=span.trace_id
            )
        except CosmosResourceNotFoundError:
            existing_doc = None

        if existing_doc is not None:
            # Raises on conflict; returns True (duplicate) when identical → no-op.
            _ensure_no_conflict(_from_item(existing_doc), span)
            return
        await self._container.upsert_item(body=_to_item(span))

    async def get_spans(self, trace_id: str) -> list[Span]:
        query = "SELECT * FROM c WHERE c.trace_id = @trace_id"
        parameters: list[dict[str, Any]] = [{"name": "@trace_id", "value": trace_id}]
        spans: list[Span] = []
        # Scoped to the trace's partition — a single-partition query, no fan-out.
        # query_items returns an AsyncItemPaged: iterate, do NOT await it.
        async for item in self._container.query_items(
            query=query,
            parameters=parameters,
            partition_key=trace_id,
        ):
            spans.append(_from_item(item))
        return _by_seq(spans)


def create_cosmos_store(settings: Settings) -> CosmosForensicStore:
    """Build a :class:`CosmosForensicStore` from settings (Azure mode only).

    Lazy-imports the Azure SDKs so DEMO MODE never pays for them and the package
    builds on machines without Azure installed. Auth is identity-based
    (``DefaultAzureCredential`` → system-assigned managed identity in prod,
    per §2); no keys in code. The caller owns shutdown via
    :meth:`CosmosForensicStore`'s underlying client — wired by the proxy in a
    later phase. Fails loudly if the endpoint is unset rather than guessing.
    """
    if not settings.azure_cosmos_endpoint:
        raise ValueError(
            "AZURE_COSMOS_ENDPOINT is not set; cannot build a Cosmos store. "
            "(In DEMO MODE use InMemoryForensicStore instead.)"
        )

    from azure.cosmos.aio import CosmosClient
    from azure.identity.aio import DefaultAzureCredential

    credential = DefaultAzureCredential()
    client = CosmosClient(url=settings.azure_cosmos_endpoint, credential=credential)
    database = client.get_database_client(settings.azure_cosmos_database)
    container = database.get_container_client(settings.azure_cosmos_container)
    return CosmosForensicStore(container)


class SqliteForensicStore:
    """File-backed forensic store — DEMO MODE persistence across restarts.

    The same idempotency / immutability contract as :class:`InMemoryForensicStore`
    and :class:`CosmosForensicStore`: writing the same ``span_id`` twice with
    identical content is a no-op; with different content raises
    :class:`ForensicIntegrityError`.

    Reads return spans for one ``trace_id`` ordered by ``seq`` (the canonical
    replay order). The on-disk schema is intentionally tiny — one table, one
    JSON column — so the conformance suite that runs against the other two
    stores runs unchanged against this one.

    Concurrency: every operation acquires a single ``asyncio.Lock`` then runs
    the blocking SQLite call inside ``asyncio.to_thread``. Within a single event
    loop this is race-free; cross-process write contention is not supported
    (use Cosmos / Postgres for that).
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()
        # check_same_thread=False because we hop the connection across
        # to_thread workers (still serialized by the lock).
        self._conn = sqlite3.connect(
            str(self._path), check_same_thread=False, isolation_level=None
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS spans ("
            "  trace_id TEXT NOT NULL,"
            "  span_id  TEXT NOT NULL PRIMARY KEY,"
            "  seq      INTEGER NOT NULL,"
            "  body     TEXT NOT NULL"
            ")"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS spans_by_trace ON spans(trace_id, seq)"
        )

    async def put(self, span: Span) -> None:
        body = json.dumps(span.model_dump(mode="json"))
        async with self._lock:
            await asyncio.to_thread(self._put_blocking, span, body)

    def _put_blocking(self, span: Span, body: str) -> None:
        row = self._conn.execute(
            "SELECT body FROM spans WHERE span_id = ?", (span.span_id,)
        ).fetchone()
        if row is not None:
            existing = Span.model_validate(json.loads(row[0]))
            if _ensure_no_conflict(existing, span):
                return  # identical content — idempotent no-op
        self._conn.execute(
            "INSERT OR REPLACE INTO spans (trace_id, span_id, seq, body) "
            "VALUES (?, ?, ?, ?)",
            (span.trace_id, span.span_id, span.seq, body),
        )

    async def get_spans(self, trace_id: str) -> list[Span]:
        async with self._lock:
            rows = await asyncio.to_thread(self._read_blocking, trace_id)
        return [Span.model_validate(json.loads(b)) for b in rows]

    def _read_blocking(self, trace_id: str) -> list[str]:
        cursor = self._conn.execute(
            "SELECT body FROM spans WHERE trace_id = ? ORDER BY seq, span_id",
            (trace_id,),
        )
        return [row[0] for row in cursor.fetchall()]

    async def list_trace_ids(self) -> list[str]:
        """List every trace_id present in the store, most-recent first.

        Not part of the :class:`ForensicStore` contract — :class:`InMemoryForensicStore`
        cannot offer it without state — but the control plane uses it to rebuild
        the run index after a restart.
        """
        async with self._lock:
            return await asyncio.to_thread(self._list_traces_blocking)

    def _list_traces_blocking(self) -> list[str]:
        cursor = self._conn.execute(
            "SELECT trace_id, MAX(seq) AS last_seq FROM spans GROUP BY trace_id "
            "ORDER BY last_seq DESC"
        )
        return [row[0] for row in cursor.fetchall()]

    def close(self) -> None:
        self._conn.close()
