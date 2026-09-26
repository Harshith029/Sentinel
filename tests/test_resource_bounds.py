"""Resource bounds (audit F-05/F-06): no single caller can exhaust the service.

Each of these was unbounded and demonstrated before it was fixed:

* a 40 MB body to ``/runs/custom`` was buffered and JSON-parsed in full;
* 60 rapid ``POST /runs`` from one caller put 41 scenarios in flight at once;
* the run index and task table grew for as long as the process lived;
* ``/events`` could return the whole 100 000-event buffer in one response;
* nothing capped live SSE subscribers or request rate;
* a downstream tool could hand back any amount of data, which the injection
  scanner and the agent would then read in full.
"""
from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import mcp.types as mcp_types
import pytest

from sentinel.authn import SESSION_COOKIE
from sentinel.authorization.engine import AuthorizationEngine
from sentinel.authorization.policy import load_policy
from sentinel.config import reset_settings_cache
from sentinel.control.app import create_app
from sentinel.control.events import EventBus
from sentinel.control.manager import RunManager, RunRecord
from sentinel.forensics.emitter import SpanEmitter
from sentinel.forensics.replay import replay
from sentinel.forensics.store import InMemoryForensicStore
from sentinel.mcp_proxy.content import result_text
from sentinel.mcp_proxy.proxy import SentinelProxy
from sentinel.trust.config import load_default_trust_config
from sentinel.trust.scorer import TrustScorer


async def _finish_runs(manager: RunManager) -> None:
    await asyncio.gather(
        *(manager.join(r.run_id) for r in manager.list_runs()), return_exceptions=True
    )
    await manager.aclose()


@asynccontextmanager
async def _client(**env: str) -> AsyncIterator[tuple[httpx.AsyncClient, RunManager, Any]]:
    """An app under specific limits, in anonymous mode unless told otherwise."""
    base = {"SENTINEL_ALLOW_ANONYMOUS": "1", "SENTINEL_API_TOKEN": ""}
    base.update(env)
    previous = {k: os.environ.get(k) for k in base}
    manager: RunManager | None = None
    try:
        # Inside the try: if configuration is rejected, the environment must
        # still be restored, or it leaks into every test that runs after.
        os.environ.update(base)
        reset_settings_cache()
        manager = RunManager(store=InMemoryForensicStore())
        app = create_app(manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            yield client, manager, app
    finally:
        if manager is not None:
            await _finish_runs(manager)
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        reset_settings_cache()


# --- request bodies ------------------------------------------------------------


async def test_a_declared_oversized_body_is_refused_before_it_is_read() -> None:
    async with _client(SENTINEL_MAX_BODY_BYTES="4096") as (client, _, _app):
        response = await client.post(
            "/runs/custom", content=b"x" * 10_000,
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 413


async def test_an_undeclared_oversized_body_is_cut_off_while_streaming() -> None:
    """No Content-Length (chunked) must not be a way around the limit."""

    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(20):
            yield b"y" * 1024

    async with _client(SENTINEL_MAX_BODY_BYTES="4096") as (client, _, _app):
        response = await client.post(
            "/runs/custom", content=chunks(), headers={"content-type": "application/json"}
        )
        assert response.status_code == 413


async def test_the_body_limit_sits_in_front_of_every_path_including_mcp() -> None:
    """Middleware, not a route dependency: /mcp is a mount the routes never see."""
    async with _client(SENTINEL_MAX_BODY_BYTES="4096") as (client, _, _app):
        response = await client.post("/mcp", content=b"z" * 10_000)
        assert response.status_code == 413


# --- request rate --------------------------------------------------------------


_TENANTS = '{"acme": "tok-acme", "globex": "tok-globex"}'


async def test_a_tenant_over_its_rate_is_throttled_and_others_are_not() -> None:
    async with _client(
        SENTINEL_RATE_LIMIT_PER_MINUTE="5",
        SENTINEL_ALLOW_ANONYMOUS="0",
        SENTINEL_API_TOKENS=_TENANTS,
    ) as (client, _, _app):
        acme = {"Authorization": "Bearer tok-acme"}
        codes = [(await client.get("/runs", headers=acme)).status_code for _ in range(6)]
        assert codes[:5] == [200] * 5
        assert codes[5] == 429
        throttled = await client.get("/runs", headers=acme)
        assert int(throttled.headers["retry-after"]) >= 1

        # Another tenant has its own budget.
        globex = {"Authorization": "Bearer tok-globex"}
        assert (await client.get("/runs", headers=globex)).status_code == 200
        # Liveness is never throttled, or the platform would kill a busy service.
        assert (await client.get("/healthz", headers=acme)).status_code == 200


async def test_the_session_cookie_draws_on_the_same_budget_as_the_token() -> None:
    """Switching credential carrier is not a way to double a tenant's budget."""
    async with _client(
        SENTINEL_RATE_LIMIT_PER_MINUTE="4",
        SENTINEL_ALLOW_ANONYMOUS="0",
        SENTINEL_API_TOKENS=_TENANTS,
    ) as (client, _, _app):
        acme = {"Authorization": "Bearer tok-acme"}
        for _ in range(2):
            assert (await client.get("/runs", headers=acme)).status_code == 200
        cookie = {"Cookie": f"{SESSION_COOKIE}=tok-acme"}
        codes = [(await client.get("/runs", headers=cookie)).status_code for _ in range(3)]
        assert codes == [200, 200, 429]


async def test_made_up_credentials_do_not_each_get_a_fresh_budget() -> None:
    """Rotating invented tokens must not escape the limiter.

    Keying buckets by whatever credential a request carried gave every invented
    token its own budget, so the two cases that most need throttling were not
    throttled at all: guessing credentials against a secured deployment, and
    any traffic to an anonymous one (where no token is checked).
    """
    async with _client(
        SENTINEL_RATE_LIMIT_PER_MINUTE="5",
        SENTINEL_ALLOW_ANONYMOUS="0",
        SENTINEL_API_TOKENS=_TENANTS,
    ) as (client, _, _app):
        guesses = [
            (await client.get("/runs", headers={"Authorization": f"Bearer guess-{i}"}))
            .status_code
            for i in range(6)
        ]
        assert guesses[:5] == [401] * 5
        assert guesses[5] == 429, "credential guessing was not rate limited"

    async with _client(SENTINEL_RATE_LIMIT_PER_MINUTE="5") as (client, _, _app):
        anonymous = [
            (await client.get("/runs", headers={"Authorization": f"Bearer any-{i}"}))
            .status_code
            for i in range(6)
        ]
        assert anonymous[5] == 429, "anonymous traffic escaped the limiter"


# --- background runs -----------------------------------------------------------


async def test_a_tenant_at_its_run_quota_is_refused_with_429() -> None:
    async with _client(SENTINEL_MAX_ACTIVE_RUNS="2") as (client, manager, _app):
        for i in range(2):  # two runs genuinely in flight for acme
            manager._runs[f"t{i}"] = RunRecord(  # noqa: SLF001
                run_id=f"t{i}", trace_id=f"t{i}", agent_id="a",
                scenario="hero-obvious", tenant="acme", status="running",
            )
        refused = await client.post(
            "/runs", json={"scenario": "hero-obvious", "tenant": "acme"}
        )
        assert refused.status_code == 429
        assert refused.headers.get("retry-after")

        # The quota is per tenant: globex is unaffected by acme's load.
        other = await client.post(
            "/runs", json={"scenario": "hero-obvious", "tenant": "globex"}
        )
        assert other.status_code == 200
        for i in range(2):
            manager._runs[f"t{i}"].status = "completed"  # noqa: SLF001


async def test_finished_runs_are_retained_up_to_the_limit_only() -> None:
    async with _client(
        SENTINEL_MAX_RETAINED_RUNS="3", SENTINEL_MAX_ACTIVE_RUNS="50"
    ) as (client, manager, _app):
        in_flight = RunRecord(
            run_id="live", trace_id="live", agent_id="a",
            scenario="live-mcp", tenant="default", status="running",
        )
        manager._runs["live"] = in_flight  # noqa: SLF001
        ids = []
        for _ in range(6):
            posted = await client.post("/runs", json={"scenario": "hero-obvious"})
            ids.append(posted.json()["run_id"])
        for run_id in ids:
            await manager.join(run_id)

        finished = [r for r in manager.list_runs() if r.status != "running"]
        assert len(finished) <= 3, "finished runs were not pruned"
        assert manager.get_run("live") is in_flight, "a run in flight was evicted"
        assert not manager._tasks, "finished tasks kept their references"  # noqa: SLF001
        in_flight.status = "completed"


# --- the event feed ------------------------------------------------------------


async def test_event_polling_is_paged_with_a_resume_cursor() -> None:
    async with _client() as (client, manager, _app):
        posted = await client.post("/runs", json={"scenario": "hero-obvious"})
        await manager.join(posted.json()["run_id"])
        total = manager.bus.last_event_id
        assert total > 3

        first = (await client.get("/events", params={"limit": 2})).json()
        assert len(first["events"]) == 2
        assert first["truncated"] is True
        second = (
            await client.get("/events", params={"limit": 2, "since": first["next_since"]})
        ).json()
        ids = [e["event_id"] for e in first["events"] + second["events"]]
        assert ids == sorted(set(ids)), "pages overlapped or went backwards"

        # The cap applies even when a caller asks for more.
        huge = (await client.get("/events", params={"limit": 10_000_000})).json()
        assert len(huge["events"]) <= 1000


async def test_live_stream_subscribers_are_capped_and_slots_come_back() -> None:
    async with _client(SENTINEL_MAX_SSE_SUBSCRIBERS="1") as (client, _, app):
        slots = app.state.sse_streams
        # A completed catch-up stream must give its slot back.
        done = await client.get("/events/stream", params={"follow": "false"})
        assert done.status_code == 200
        assert slots.active == 0, "a finished stream leaked its subscriber slot"

        slots.active = 1  # one subscriber already holding the only slot
        refused = await client.get("/events/stream", params={"follow": "false"})
        assert refused.status_code == 503
        slots.active = 0


def test_the_event_buffer_cut_matches_a_linear_scan() -> None:
    """The binary search must return exactly what the old linear scan did."""

    async def fill() -> EventBus:
        bus = EventBus(buffer_limit=50)
        store = InMemoryForensicStore()
        emitter = SpanEmitter(store)
        trace = emitter.new_trace_id()
        from sentinel.control.events import BroadcastStore
        from sentinel.forensics.events import InputReceived

        broadcast = SpanEmitter(BroadcastStore(store, bus))
        for i in range(120):
            await broadcast.emit(
                InputReceived(content=f"m{i}", origin_label="USER"), trace_id=trace
            )
        return bus

    bus = asyncio.run(fill())
    buffered = bus.events_since(0)
    assert [e.event_id for e in buffered] == sorted(e.event_id for e in buffered)
    for cursor in (0, 1, 50, 80, 119, 120, 10_000):
        expected = [e for e in buffered if e.event_id > cursor]
        assert bus.events_since(cursor) == expected


# --- downstream results --------------------------------------------------------


class _HugeDownstream:
    def __init__(self, size: int) -> None:
        self.size = size
        self.calls: list[str] = []

    async def call_tool(self, name: str, arguments: dict[str, object]) -> object:
        self.calls.append(name)
        return mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text="A" * self.size)],
            isError=False,
        )


class _CountingShield:
    backend = "local"

    def __init__(self) -> None:
        self.scanned: list[int] = []

    async def inspect_user_prompt(self, content: str) -> Any:
        from sentinel.shield.input_shield import ShieldVerdict

        return ShieldVerdict(attack_detected=False, shield="test")

    async def inspect_document(self, content: str) -> Any:
        self.scanned.append(len(content))
        from sentinel.shield.input_shield import ShieldVerdict

        return ShieldVerdict(attack_detected=False, shield="test")


async def test_an_oversized_tool_result_is_withheld_before_anything_reads_it() -> None:
    store = InMemoryForensicStore()
    emitter = SpanEmitter(store)
    downstream = _HugeDownstream(size=200_000)
    shield = _CountingShield()
    proxy = SentinelProxy(
        downstream=downstream,  # type: ignore[arg-type]
        emitter=emitter,
        engine=AuthorizationEngine(
            load_policy("policy_version: 1\ntools:\n  read_page:\n    rules: []\n")
        ),
        scorer=TrustScorer(emitter, load_default_trust_config()),
        agent_id="bounds",
        trace_id=emitter.new_trace_id(),
        input_shield=shield,  # type: ignore[arg-type]
        max_result_bytes=64 * 1024,
    )
    await proxy.start(user_input="read the page")
    got = await proxy.handle_call("read_page", {})

    assert got.isError is True
    assert "withheld" in result_text(got)
    assert downstream.calls == ["read_page"], "the tool should still have run"
    assert all(n < 64 * 1024 for n in shield.scanned), "the scanner read the oversized result"

    rep = await replay(store, proxy.trace_id)
    assert any(s.event_type == "ToolExecuted" for s in rep.ordered)


def test_a_malformed_limit_is_an_error_not_a_silent_default() -> None:
    from sentinel.config import get_settings

    os.environ["SENTINEL_MAX_BODY_BYTES"] = "four megabytes"
    reset_settings_cache()
    try:
        with pytest.raises(ValueError, match="SENTINEL_MAX_BODY_BYTES"):
            get_settings()
    finally:
        os.environ.pop("SENTINEL_MAX_BODY_BYTES", None)
        reset_settings_cache()
