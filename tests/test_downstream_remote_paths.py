"""Both SUPPORTED remote downstream paths, over real TCP, plus the contract of
the single connection factory they share.

SENTINEL reaches downstream MCP servers two ways, and both are shipped:

* ``SENTINEL_MCP_SERVERS`` — the operator declares their own servers. This is
  the product path.
* ``SENTINEL_TOOLS_{WEB,EMAIL,RECORDS}_URL`` — the example topology the ACA
  bicep deploys as separate internal apps.

Parsing tests do not cover either of them: they prove a JSON string becomes a
dataclass, not that a tool call crosses a socket, gets authorized, and comes
back. Everything here runs a real uvicorn server and a real MCP client.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
from contextlib import AsyncExitStack
from typing import Final

import httpx
import pytest
import uvicorn
from starlette.applications import Starlette

from sentinel.config import reset_settings_cache
from sentinel.control.manager import RunManager
from sentinel.control.mcp_gateway import SentinelGateway
from sentinel.demo.tool_servers import ToolServerState, build_downstream
from sentinel.downstream import (
    _CONNECT_TIMEOUT_SECONDS,
    DownstreamServer,
    _downstream_http_client,
    connect_downstream,
    open_downstream_session,
)
from sentinel.forensics.store import InMemoryForensicStore
from sentinel.mcp_proxy.content import result_text

# QUARANTINED DIAGNOSTICS — opt in with SENTINEL_RUN_REAL_MCP_TESTS=1.
#
# These are NOT part of passing coverage. Each one passes on its own, but two of
# them in a process wedge on the open teardown defect
# (docs/mcp-streamable-http-teardown.md), so they cannot run as a module or
# alongside the suite. An unconditional skip would have made even
# ``-k declared`` silently skip, so the gate is an environment variable and the
# tests really run when you ask for them:
#
#   SENTINEL_RUN_REAL_MCP_TESTS=1 pytest tests/test_downstream_remote_paths.py -k declared
#
# The `real_mcp` CI job runs them one at a time and is non-blocking until the
# teardown defect is fixed; at that point delete the gate and fold them in.
#
# They are also evidence about that defect: they tear down SENTINEL's OWN
# downstream sessions, so the wedge follows open_downstream_session teardown and
# is not confined to the external test client.
_OPT_IN: Final[bool] = os.getenv("SENTINEL_RUN_REAL_MCP_TESTS") == "1"

pytestmark = [
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.skipif(
        not _OPT_IN,
        reason="quarantined real-MCP diagnostic; set SENTINEL_RUN_REAL_MCP_TESTS=1 "
               "and select ONE test (see docs/mcp-streamable-http-teardown.md)",
    ),
]


class _Server:
    """One tool server under uvicorn on a pre-bound ephemeral port."""

    def __init__(self, app: Starlette) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(128)
        self.port: int = self._sock.getsockname()[1]
        config = uvicorn.Config(
            app, host="127.0.0.1", port=self.port, log_level="error",
            lifespan="on", ws="none",
        )
        self._server = uvicorn.Server(config)
        self._server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
        self._task: asyncio.Task[None] | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"

    async def __aenter__(self) -> _Server:
        self._task = asyncio.create_task(self._server.serve(sockets=[self._sock]))
        for _ in range(250):
            if self._server.started:
                return self
            await asyncio.sleep(0.02)
        raise RuntimeError("uvicorn did not start in time")

    async def __aexit__(self, *exc: object) -> None:
        self._server.should_exit = True
        try:
            if self._task is not None:
                await asyncio.wait_for(self._task, timeout=30)
        finally:
            self._sock.close()


def _tool_servers() -> dict[str, Starlette]:
    return {
        key: server.streamable_http_app()
        for key, server in build_downstream(ToolServerState()).items()
    }


async def test_declared_servers_path_discovers_and_proxies_over_tcp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SENTINEL_MCP_SERVERS: real discovery and a real proxied call.

    The generic path is what an operator actually uses, and it had no integration
    coverage — only unit tests over ``parse_servers``. Those cannot show that
    discovery crosses a socket or that a call routes to the right server.
    """
    servers = _tool_servers()
    async with AsyncExitStack() as stack:
        running = {
            key: await stack.enter_async_context(_Server(app))
            for key, app in servers.items()
        }
        declared = [{"name": key, "url": srv.url} for key, srv in running.items()]
        monkeypatch.setenv("SENTINEL_MCP_SERVERS", json.dumps(declared))
        for var in ("SENTINEL_TOOLS_WEB_URL", "SENTINEL_TOOLS_EMAIL_URL",
                    "SENTINEL_TOOLS_RECORDS_URL"):
            monkeypatch.delenv(var, raising=False)
        reset_settings_cache()
        try:
            manager = RunManager(store=InMemoryForensicStore())
            gateway = SentinelGateway(manager)
            async with gateway:
                assert gateway.downstream_mode == "declared"
                # Discovery really crossed the wire.
                names = {tool.name for tool in gateway._cache}  # noqa: SLF001
                assert {"web_fetch", "send_email", "get_customer_record"} <= names

                # And a call really routes to the owning server and comes back.
                proxy = gateway._manager.new_live_proxy(  # noqa: SLF001
                    downstream=gateway._router,  # noqa: SLF001
                    cache=gateway._cache,  # noqa: SLF001
                    agent_id="declared-path", tenant="default",
                )
                await proxy.start(user_input="check the declared path")
                got = await proxy.handle_call("get_customer_record", {"id": 42})
                assert "SYNTHETIC" in result_text(got)
        finally:
            reset_settings_cache()


async def test_legacy_tools_url_path_discovers_and_proxies_over_tcp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SENTINEL_TOOLS_*_URL: the topology the bicep deploys, over real TCP.

    This is the path ``deploy/main.bicep`` wires, so it must be exercised as
    deployed — including the ``/mcp`` suffix the template now sets, whose absence
    would have failed discovery at startup.
    """
    servers = _tool_servers()
    async with AsyncExitStack() as stack:
        running = {
            key: await stack.enter_async_context(_Server(app))
            for key, app in servers.items()
        }
        monkeypatch.delenv("SENTINEL_MCP_SERVERS", raising=False)
        for key, var in (("web", "WEB"), ("email", "EMAIL"), ("records", "RECORDS")):
            monkeypatch.setenv(f"SENTINEL_TOOLS_{var}_URL", running[key].url)
        reset_settings_cache()
        try:
            manager = RunManager(store=InMemoryForensicStore())
            gateway = SentinelGateway(manager)
            async with gateway:
                assert gateway.downstream_mode == "remote-http"
                proxy = gateway._manager.new_live_proxy(  # noqa: SLF001
                    downstream=gateway._router,  # noqa: SLF001
                    cache=gateway._cache,  # noqa: SLF001
                    agent_id="legacy-path", tenant="default",
                )
                await proxy.start(user_input="check the legacy path")
                got = await proxy.handle_call("get_customer_record", {"id": 7})
                assert "SYNTHETIC" in result_text(got)
        finally:
            reset_settings_cache()


async def test_partial_startup_failure_leaves_nothing_open() -> None:
    """First server connects, second is unreachable → the first is CLOSED.

    ``open_downstream_session`` binds its HTTP client and transport to the
    caller's long-lived stack. If server N fails, the caller usually propagates
    the error rather than closing that stack, so servers 1..N-1 would stay
    connected for the life of the process — sockets and transport tasks for a
    gateway that never started.
    """
    servers = _tool_servers()
    async with AsyncExitStack() as stack:
        reachable = await stack.enter_async_context(_Server(servers["records"]))

        dead_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dead_sock.bind(("127.0.0.1", 0))
        dead_port = dead_sock.getsockname()[1]
        dead_sock.close()  # nothing is listening here

        declared = [
            DownstreamServer(name="ok", url=reachable.url),
            DownstreamServer(name="dead", url=f"http://127.0.0.1:{dead_port}/mcp"),
        ]
        caller_stack = AsyncExitStack()
        async with caller_stack:
            with pytest.raises(Exception) as err:
                await connect_downstream(declared, caller_stack)
            # The error names the server that failed, not something generic.
            assert "dead" in str(err.value)

        # The first server's session was handed to caller_stack and closed with
        # it; the FAILED one left nothing behind at all. Proven by connecting
        # again: a leaked half-open session would still be counted by the server.
        async with AsyncExitStack() as second:
            session = await open_downstream_session(reachable.url, second)
            listed = await session.list_tools()
            assert [t.name for t in listed.tools]


async def test_factory_closes_the_http_client_it_was_given() -> None:
    """The caller-owned httpx client is closed when the stack unwinds.

    The SDK closes an HTTP client only when it created it, so a client we supply
    is ours to close. If it were not closed, every gateway restart in a process
    would leak a connection pool.
    """
    servers = _tool_servers()
    async with AsyncExitStack() as stack:
        srv = await stack.enter_async_context(_Server(servers["records"]))
        opened: list[httpx.AsyncClient] = []
        real = httpx.AsyncClient

        def _track(*args: object, **kwargs: object) -> httpx.AsyncClient:
            client = real(*args, **kwargs)  # type: ignore[arg-type]
            opened.append(client)
            return client

        import sentinel.downstream as ds

        original = ds.httpx.AsyncClient
        ds.httpx.AsyncClient = _track  # type: ignore[misc,assignment]
        try:
            async with AsyncExitStack() as inner:
                await open_downstream_session(srv.url, inner)
                assert opened, "factory did not build an HTTP client"
                assert not opened[0].is_closed
            assert opened[0].is_closed, "supplied HTTP client outlived the session"
        finally:
            ds.httpx.AsyncClient = original  # type: ignore[misc]


async def test_factory_client_is_configured_with_the_documented_bounds() -> None:
    """The client handed to the SDK carries the bounds we claim it does.

    Asserted on the constructed client rather than by timing a connection: httpx
    enforces connect timeouts inside its own transport, so a stub transport would
    bypass the very code under test and a real unroutable address is at the mercy
    of how the host network answers. This checks the configuration that httpx
    then enforces, and the behavioural half is covered by
    ``test_unreachable_downstream_fails_fast_instead_of_hanging``.
    """
    client = _downstream_http_client()
    try:
        assert client.timeout.connect == _CONNECT_TIMEOUT_SECONDS
        assert client.timeout.pool == _CONNECT_TIMEOUT_SECONDS
        # Reads MUST stay unbounded: an MCP session holds a long-lived GET/SSE
        # stream, and a read timeout would tear down a healthy idle session.
        assert client.timeout.read is None
        assert client.follow_redirects is True
    finally:
        await client.aclose()


async def test_unreachable_downstream_fails_fast_instead_of_hanging() -> None:
    """A refused port raises promptly — startup reports, it does not wedge."""
    dead = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dead.bind(("127.0.0.1", 0))
    port = dead.getsockname()[1]
    dead.close()  # nothing listening: connect is refused

    loop = asyncio.get_running_loop()
    started = loop.time()
    async with AsyncExitStack() as stack:
        with pytest.raises(Exception):  # noqa: B017 - anyio wraps the transport error
            await open_downstream_session(f"http://127.0.0.1:{port}/mcp", stack)
    assert loop.time() - started < _CONNECT_TIMEOUT_SECONDS


async def test_factory_follows_the_mcp_trailing_slash_redirect() -> None:
    """The MCP POST to ``/mcp`` is answered with a 307 to ``/mcp/``.

    An explicitly configured ``httpx.AsyncClient`` does NOT follow redirects by
    default, so the factory has to opt in or every ordinary MCP mount breaks.
    Proven behaviourally rather than by probing a status code: a client with
    redirects disabled fails, the factory's client succeeds against the same
    server.
    """
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    servers = _tool_servers()
    async with AsyncExitStack() as stack:
        srv = await stack.enter_async_context(_Server(servers["records"]))

        # Redirects disabled → the handshake cannot complete.
        with pytest.raises((httpx.HTTPStatusError, ExceptionGroup)) as err:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(None, connect=10.0), follow_redirects=False
            ) as blind:
                async with streamable_http_client(srv.url, http_client=blind) as (r, w, _):
                    async with ClientSession(r, w) as cs:
                        await cs.initialize()
        assert "307" in str(err.value) or "edirect" in str(err.value), str(err.value)

        # The shipped factory follows it and discovery works.
        session = await open_downstream_session(srv.url, stack)
        listed = await session.list_tools()
        assert [t.name for t in listed.tools]


def _recording_app(app: Starlette, seen: list[tuple[str, str]]) -> Starlette:
    """Wrap an ASGI app so every HTTP method+path is recorded.

    Lets a test assert what actually went over the wire — an MCP
    session-termination DELETE — instead of asserting that a constant is True.
    """

    async def wrapper(scope, receive, send):  # type: ignore[no-untyped-def]
        if scope["type"] == "http":
            seen.append((scope["method"], scope["path"]))
        await app(scope, receive, send)  # type: ignore[operator]

    return wrapper  # type: ignore[return-value]


def _declare(monkeypatch: pytest.MonkeyPatch, servers: list[dict[str, str]]) -> None:
    monkeypatch.setenv("SENTINEL_MCP_SERVERS", json.dumps(servers))
    for var in ("SENTINEL_TOOLS_WEB_URL", "SENTINEL_TOOLS_EMAIL_URL",
                "SENTINEL_TOOLS_RECORDS_URL"):
        monkeypatch.delenv(var, raising=False)
    reset_settings_cache()


def _dead_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port: int = sock.getsockname()[1]
    sock.close()  # nothing listening here
    return port


async def test_declared_path_sends_session_termination_on_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SENTINEL_MCP_SERVERS: closing the gateway DELETEs the MCP session.

    Observed on the server, not inferred from a constant. Without the DELETE the
    downstream keeps the session in ``_server_instances`` forever, because the
    SDK's ``session_idle_timeout`` defaults to None.
    """
    seen: list[tuple[str, str]] = []
    app = _recording_app(_tool_servers()["records"], seen)
    async with AsyncExitStack() as stack:
        srv = await stack.enter_async_context(_Server(app))
        _declare(monkeypatch, [{"name": "records", "url": srv.url}])
        try:
            gateway = SentinelGateway(RunManager(store=InMemoryForensicStore()))
            async with gateway:
                assert gateway.downstream_mode == "declared"
            assert any(m == "DELETE" for m, _ in seen), (
                f"no session-termination DELETE reached the server; saw {seen}"
            )
        finally:
            reset_settings_cache()


async def test_legacy_path_sends_session_termination_on_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SENTINEL_TOOLS_*_URL: the same protocol obligation on the bicep path."""
    seen: list[tuple[str, str]] = []
    apps = _tool_servers()
    async with AsyncExitStack() as stack:
        running = {}
        for key, app in apps.items():
            wrapped = _recording_app(app, seen) if key == "records" else app
            running[key] = await stack.enter_async_context(_Server(wrapped))
        monkeypatch.delenv("SENTINEL_MCP_SERVERS", raising=False)
        for key, var in (("web", "WEB"), ("email", "EMAIL"), ("records", "RECORDS")):
            monkeypatch.setenv(f"SENTINEL_TOOLS_{var}_URL", running[key].url)
        reset_settings_cache()
        try:
            gateway = SentinelGateway(RunManager(store=InMemoryForensicStore()))
            async with gateway:
                assert gateway.downstream_mode == "remote-http"
            assert any(m == "DELETE" for m, _ in seen), (
                f"no session-termination DELETE reached the server; saw {seen}"
            )
        finally:
            reset_settings_cache()


async def test_gateway_aenter_failure_closes_already_connected_servers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``__aenter__`` raises on server 2 → server 1's client is already closed.

    The caller never gets to call ``__aexit__``: Python only guarantees it for a
    context manager whose ``__aenter__`` RETURNED. So this drives ``__aenter__``
    directly and deliberately never calls ``__aexit__`` — exactly what a failed
    startup leaves behind.
    """
    opened: list[httpx.AsyncClient] = []
    import sentinel.downstream as ds

    real = ds.httpx.AsyncClient

    def _track(*args, **kwargs):  # type: ignore[no-untyped-def]
        client = real(*args, **kwargs)
        opened.append(client)
        return client

    async with AsyncExitStack() as stack:
        good = await stack.enter_async_context(_Server(_tool_servers()["records"]))
        _declare(monkeypatch, [
            {"name": "records", "url": good.url},
            {"name": "dead", "url": f"http://127.0.0.1:{_dead_port()}/mcp"},
        ])
        monkeypatch.setattr(ds.httpx, "AsyncClient", _track)
        try:
            gateway = SentinelGateway(RunManager(store=InMemoryForensicStore()))
            with pytest.raises(Exception) as err:  # noqa: B017 - startup surfaces many
                await gateway.__aenter__()
            assert "dead" in str(err.value)
            # __aexit__ is deliberately NOT called.
            assert opened, "no downstream HTTP client was ever built"
            assert all(c.is_closed for c in opened), (
                f"failed startup left HTTP clients open: {[c.is_closed for c in opened]}"
            )
        finally:
            reset_settings_cache()


async def test_gateway_aenter_failure_after_connect_closes_everything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A LATER startup failure also unwinds connections that already succeeded.

    Connection failure is not the only way ``__aenter__`` can raise: a poisoned
    catalogue or a shadowed tool name rejects a downstream that connected
    perfectly well. Those must clean up too.
    """
    opened: list[httpx.AsyncClient] = []
    import sentinel.control.mcp_gateway as gw_mod
    import sentinel.downstream as ds

    real = ds.httpx.AsyncClient

    def _track(*args, **kwargs):  # type: ignore[no-untyped-def]
        client = real(*args, **kwargs)
        opened.append(client)
        return client

    async def _boom(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("catalogue rejected at preflight")

    async with AsyncExitStack() as stack:
        good = await stack.enter_async_context(_Server(_tool_servers()["records"]))
        _declare(monkeypatch, [{"name": "records", "url": good.url}])
        monkeypatch.setattr(ds.httpx, "AsyncClient", _track)
        monkeypatch.setattr(gw_mod, "preflight", _boom)
        try:
            gateway = SentinelGateway(RunManager(store=InMemoryForensicStore()))
            with pytest.raises(RuntimeError, match="catalogue rejected"):
                await gateway.__aenter__()
            assert opened, "downstream connected before preflight, so a client exists"
            assert all(c.is_closed for c in opened), (
                "a post-connect startup failure left HTTP clients open"
            )
        finally:
            reset_settings_cache()
