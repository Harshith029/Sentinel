"""Pytest configuration shared across SENTINEL tests."""
from __future__ import annotations

import copy
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest

from sentinel.forensics.events import EventPayload, ToolCallProposed
from sentinel.forensics.span import Span
from sentinel.forensics.store import (
    CosmosForensicStore,
    ForensicStore,
    InMemoryForensicStore,
    SqliteForensicStore,
)

# Two distinct, valid (non-zero) trace ids for cross-partition / multi-trace tests.
TRACE_A = "a" * 32
TRACE_B = "b" * 32


@pytest.fixture(autouse=True)
def _force_demo_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Tests always run in DEMO MODE and never write to the project tree.

    §10 of BUILD_SPEC says the security pipeline is identical between modes;
    only the agent driver differs. For unit tests, demo mode is mandatory so
    that CI and laptops never depend on cloud credentials.

    We also point ``SENTINEL_DATA_DIR`` at a per-test tmp dir so the default
    SQLite store the control plane uses never leaks across tests or polutes
    the working tree.
    """
    monkeypatch.setenv("SENTINEL_DEMO_MODE", "1")
    monkeypatch.setenv(
        "SENTINEL_DATA_DIR", str(tmp_path_factory.mktemp("sentinel_data"))
    )


class FakeAsyncCosmosContainer:
    """An offline stand-in faithful to ``azure.cosmos.aio.ContainerProxy``.

    The point is to exercise the REAL :class:`CosmosForensicStore` logic without
    a network: it mirrors the exact async contract the store depends on —

    * ``await upsert_item(body=...)``  → awaitable coroutine, idempotent by ``id``
      within a partition (keyed here by ``trace_id``).
    * ``query_items(...)``             → a *synchronous* call returning an
      async-iterable (you ``async for`` it; you do NOT await the call), scoped to
      a single ``partition_key``.

    Documents are deep-copied in and out so the store can never accidentally
    alias the container's internal state — modelling the serialization boundary
    a real network store would impose.
    """

    def __init__(self) -> None:
        # partition_key (trace_id) -> { id (span_id) -> document }
        self._partitions: dict[str, dict[str, dict[str, Any]]] = {}

    async def upsert_item(self, *, body: dict[str, Any]) -> dict[str, Any]:
        partition_key = body["trace_id"]
        item_id = body["id"]
        self._partitions.setdefault(partition_key, {})[item_id] = copy.deepcopy(body)
        return copy.deepcopy(body)

    async def read_item(self, *, item: str, partition_key: str) -> dict[str, Any]:
        # Mirrors azure.cosmos.aio: a point read that raises (not returns None)
        # when the id is absent in the partition.
        partition = self._partitions.get(partition_key, {})
        if item not in partition:
            from azure.cosmos.exceptions import CosmosResourceNotFoundError

            raise CosmosResourceNotFoundError(message=f"{item} not found")
        return copy.deepcopy(partition[item])

    def query_items(
        self,
        *,
        query: str,
        parameters: list[dict[str, Any]] | None = None,
        partition_key: str | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        # Single-partition query: return exactly the requested partition's docs.
        # That is equivalent to the store's `WHERE c.trace_id = @trace_id`, since
        # the partition key IS trace_id.
        docs = list(self._partitions.get(partition_key or "", {}).values())

        async def _aiter() -> AsyncIterator[dict[str, Any]]:
            for doc in docs:
                yield copy.deepcopy(doc)

        return _aiter()


@pytest.fixture(params=["memory", "cosmos", "sqlite"])
def store(
    request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory
) -> ForensicStore:
    """A ForensicStore, run once per implementation.

    Parametrizing here is what makes "every backend passes the IDENTICAL test
    suite" literally true: every test that requests ``store`` executes against
    all three backends (in-memory, Cosmos via an async fake, and SQLite on a
    per-test tmp file).
    """
    if request.param == "memory":
        return InMemoryForensicStore()
    if request.param == "cosmos":
        return CosmosForensicStore(FakeAsyncCosmosContainer())
    db_dir = tmp_path_factory.mktemp("sentinel_sqlite_store")
    return SqliteForensicStore(db_dir / "spans.db")


@pytest.fixture
def make_span() -> Callable[..., Span]:
    """Factory for valid Spans with sensible, overridable defaults."""

    def _make(
        *,
        trace_id: str = TRACE_A,
        seq: int,
        span_id: str | None = None,
        parent_span_id: str | None = None,
        payload: EventPayload | None = None,
    ) -> Span:
        if span_id is None:
            # Deterministic, unique-per-seq, never all-zero.
            span_id = f"{seq + 1:016x}"
        if payload is None:
            payload = ToolCallProposed(tool_name="noop", arguments={})
        return Span(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            seq=seq,
            payload=payload,
        )

    return _make
