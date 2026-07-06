"""SENTINEL MCP-over-HTTP gateway (the wire transport).

Phases 4–8 proved the pipeline but connected the agent to SENTINEL over an
IN-PROCESS (in-memory) MCP stream: the demo driver and the proxy ran in one
Python process. That is enough to prove the security properties, but it is not
yet something you can put in front of YOUR agent — a real external MCP client
(Claude Desktop, an Azure AI Foundry agent, a custom MCP app) speaks MCP over a
network transport, not an in-memory stream.

This module closes that gap. It exposes SENTINEL's proxy as a real
**streamable-HTTP MCP server** at ``/mcp``. Any MCP client that can reach the URL
registers SENTINEL as its tool server and is then secured by the IDENTICAL
pipeline — provenance, authorization, trust, forensics — with nothing about that
pipeline changed. Interception is still guaranteed by topology: the client's only
route to a downstream tool is a ``call_tool`` that lands in
:meth:`~sentinel.mcp_proxy.proxy.SentinelProxy.handle_call`.

Topology::

    external MCP client (session A) ─┐
                                     ├─ HTTP/MCP ─▶ SENTINEL gateway ─▶ per-session
    external MCP client (session B) ─┘                                  SentinelProxy
                                                                            │
                                                  shared (mock) downstream tool servers

One front :class:`~mcp.server.lowlevel.Server` accepts every HTTP session; each
MCP **session** gets its OWN :class:`~sentinel.mcp_proxy.proxy.SentinelProxy`
(own ``trace_id``, provenance graph, frontier, per-agent trust) — one session ==
one agent task == one trace, the proxy's contract. The downstream tool servers
are shared infrastructure behind the proxy (exactly as in a real deployment),
connected once at startup and preflighted so a transport hiccup can't break tool
discovery mid-session.

DEMO scope: the downstream tool servers here are the in-memory mock servers from
``demo/tool_servers.py`` (no real egress). The load-bearing hop this module adds
is the AGENT↔SENTINEL one — the one that must be REAL for a buyer to put SENTINEL
in front of their agent. Pointing the proxy at REMOTE tool servers is an
orthogonal change (the ACA bicep already models them as separate services).
"""
from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from typing import Final

import mcp.types as mcp_types
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.lowlevel import Server
from mcp.server.session import ServerSession
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.shared.memory import create_connected_server_and_client_session as connect
from starlette.types import Receive, Scope, Send

from sentinel.authorization.registry import DEFAULT_TENANT
from sentinel.config import get_settings
from sentinel.control.manager import RunManager
from sentinel.demo.preflight import preflight
from sentinel.demo.tool_servers import (
    REQUIRED_TOOLS,
    TOOL_TO_SERVER,
    ToolServerState,
    build_downstream,
)
from sentinel.mcp_proxy.content import mcp_error
from sentinel.mcp_proxy.proxy import SentinelProxy
from sentinel.mcp_proxy.router import ToolRouter

_GATEWAY_NAME: Final[str] = "sentinel"
_LIVE_USER_INPUT: Final[str] = "(live MCP session over HTTP)"
# Concurrency cap. A session's proxy, once created, is NEVER replaced or evicted
# while the gateway lives — evicting a live session would reset its provenance
# frontier and let a tainted action through on a fresh clean proxy (a laundering
# bypass). So at capacity we FAIL CLOSED: refuse NEW sessions rather than reset an
# existing one. (Idle-TTL cleanup of genuinely-closed sessions is a future
# enhancement; it must only ever drop sessions proven closed, never live ones.)
_MAX_SESSIONS: Final[int] = 512


def _request_authorized(scope: Scope) -> bool:
    """Bearer-token gate for the /mcp wire endpoint.

    Reads ``api_token`` fresh per request (so flipping the env + restart takes
    effect). When unset → open (DEMO). When set → require an exact-match
    ``Authorization: Bearer <token>``.
    """
    expected = get_settings().api_token
    if expected is None:
        return True
    raw = dict(scope.get("headers") or []).get(b"authorization", b"")
    presented = raw.decode("latin-1")
    token = presented[7:].strip() if presented[:7].lower() == "bearer " else ""
    return bool(token) and token == expected


async def _reject_unauthorized(send: Send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"www-authenticate", b"Bearer"),
            ],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": b'{"detail":"invalid or missing bearer token for /mcp"}',
        }
    )


class SentinelGateway:
    """A streamable-HTTP MCP server that fronts the SENTINEL pipeline.

    Use as an async context manager around the app's lifetime: ``__aenter__``
    connects the (shared) downstream tool servers, preflights them, and starts
    the session manager; ``__aexit__`` tears them down. Mount :meth:`handle_asgi`
    at ``/mcp``.
    """

    def __init__(
        self,
        manager: RunManager,
        *,
        tenant: str = DEFAULT_TENANT,
        max_sessions: int = _MAX_SESSIONS,
    ) -> None:
        self._manager = manager
        self._tenant = tenant
        self._max_sessions = max_sessions
        self._stack = AsyncExitStack()
        self._router: ToolRouter | None = None
        self._cache: tuple[mcp_types.Tool, ...] = ()
        # Shared mock tool servers (observable side effects live on this state).
        self._state = ToolServerState()
        self._downstream_mode = "memory"  # "memory" | "remote-http"
        # session-id → (session, proxy). The session object is held so its id()
        # cannot be reused by a different session while we still track it.
        self._sessions: dict[int, tuple[ServerSession, SentinelProxy]] = {}
        self._session_lock = asyncio.Lock()
        self._front = self._build_front_server()
        # stateless=False: keep one ServerSession per MCP session so a session's
        # provenance frontier persists across its successive tool calls.
        self._session_manager = StreamableHTTPSessionManager(
            app=self._front, json_response=False, stateless=False
        )

    @property
    def outbox(self) -> list[dict[str, object]]:
        """The in-memory mock outbox (in-memory downstream mode only).

        In ``remote-http`` mode the outbox lives on the remote email tool server,
        so this is empty — observability of a remote send is the tool server's job.
        """
        return self._state.outbox

    @property
    def downstream_mode(self) -> str:
        """``"memory"`` (in-process mocks) or ``"remote-http"`` (tool servers over HTTP)."""
        return self._downstream_mode

    async def __aenter__(self) -> SentinelGateway:
        # Choose the downstream: remote MCP-over-HTTP tool servers if their URLs
        # are configured (the deploy sets them), else the in-process mock servers.
        urls = get_settings().tool_server_urls()
        if urls:
            await self._connect_remote_downstream(urls)
        else:
            await self._connect_inmemory_downstream()
        assert self._router is not None  # both connect paths set it
        # Preflight (health-check + cache schemas) so list_tools can't flake.
        cache = await preflight(self._router, required_tools=REQUIRED_TOOLS)
        self._cache = cache.tools
        # The session manager's run() owns the task group every HTTP session lives
        # in; it must wrap the whole app lifetime.
        await self._stack.enter_async_context(self._session_manager.run())
        return self

    async def _connect_inmemory_downstream(self) -> None:
        """The DEMO default: three in-process mock tool servers over in-memory MCP."""
        servers = build_downstream(
            self._state, real_web=get_settings().real_web_fetch
        )
        clients: dict[str, ClientSession] = {}
        for key, server in servers.items():
            client = await self._stack.enter_async_context(connect(server))
            await client.initialize()
            clients[key] = client
        self._router = ToolRouter(
            {tool: clients[TOOL_TO_SERVER[tool]] for tool in TOOL_TO_SERVER}
        )
        self._downstream_mode = "memory"

    async def _connect_remote_downstream(self, urls: dict[str, str]) -> None:
        """Connect to REMOTE tool servers over MCP-over-HTTP (one per server key).

        This is the real-deployment path: SENTINEL is the only thing that reaches
        the (internal-ingress) tool-server apps. Fails LOUDLY at startup if a
        required server URL is missing or a server is unreachable — better a
        refused boot than a half-wired proxy.
        """
        required_keys = set(TOOL_TO_SERVER.values())
        missing = sorted(required_keys - urls.keys())
        if missing:
            raise RuntimeError(
                f"remote tool-server mode is missing URLs for {missing}; set "
                "SENTINEL_TOOLS_{WEB,EMAIL,RECORDS}_URL for all of them, or unset "
                "all to use the in-memory mock servers."
            )
        clients: dict[str, ClientSession] = {}
        for key in required_keys:
            read, write, _id = await self._stack.enter_async_context(
                streamable_http_client(urls[key])
            )
            session = await self._stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            clients[key] = session
        self._router = ToolRouter(
            {tool: clients[TOOL_TO_SERVER[tool]] for tool in TOOL_TO_SERVER}
        )
        self._downstream_mode = "remote-http"

    async def __aexit__(self, *exc: object) -> None:
        await self._stack.aclose()

    async def handle_asgi(self, scope: Scope, receive: Receive, send: Send) -> None:
        """ASGI app mounted at ``/mcp`` — delegates to the MCP session manager.

        When ``SENTINEL_API_TOKEN`` is set, the wire endpoint requires a matching
        ``Authorization: Bearer`` header (the same posture as the REST mutating
        endpoints), so a public deploy is not an open tool server. When the token
        is unset (the offline DEMO default), it stays open.
        """
        if scope["type"] == "http" and not _request_authorized(scope):
            await _reject_unauthorized(send)
            return
        await self._session_manager.handle_request(scope, receive, send)

    def _build_front_server(self) -> Server:
        front: Server = Server(_GATEWAY_NAME)

        @front.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
        async def _list_tools() -> list[mcp_types.Tool]:
            # The preflighted catalogue, identical to what the in-process proxy
            # serves. Every entry is still gated by the call_tool pipeline below.
            return list(self._cache)

        @front.call_tool()  # type: ignore[untyped-decorator]
        async def _call_tool(
            name: str, arguments: dict[str, object]
        ) -> mcp_types.CallToolResult:
            proxy = await self._proxy_for_current_session()
            if proxy is None:
                # Fail closed at capacity (see _proxy_for_current_session). We
                # refuse rather than mint a fresh proxy that would carry no taint.
                return mcp_error(
                    "SENTINEL: at session capacity; refusing a new agent session "
                    "rather than reset an existing one. Retry shortly."
                )
            return await proxy.handle_call(name, arguments)

        return front

    async def _proxy_for_current_session(self) -> SentinelProxy | None:
        """The :class:`SentinelProxy` bound to the CURRENT MCP session.

        Looked up by the per-connection :class:`ServerSession` the SDK sets on
        ``request_context``. Created lazily (and seeded with :meth:`start`) on the
        session's first tool call, so each session is one trace with its own
        provenance frontier and trust.

        Returns ``None`` (caller fails closed) when at capacity for a NEW session.
        A session that already has a proxy is ALWAYS returned its own proxy — it is
        never replaced, so its provenance frontier can never be silently reset.
        """
        session: ServerSession = self._front.request_context.session
        key = id(session)
        # Fast path: established session, no lock.
        existing = self._sessions.get(key)
        if existing is not None:
            return existing[1]
        async with self._session_lock:
            existing = self._sessions.get(key)  # re-check under lock
            if existing is not None:
                return existing[1]
            if self._router is None:  # pragma: no cover - set in __aenter__
                raise RuntimeError("gateway used before __aenter__ connected downstream")
            # Capacity reached → fail CLOSED. We must NOT evict a live session to
            # make room: that would reset its frontier and let a tainted action
            # through on a fresh, clean proxy (provenance laundering).
            if len(self._sessions) >= self._max_sessions:
                return None
            proxy = self._manager.new_live_proxy(
                downstream=self._router,
                cache=self._cache,
                agent_id=f"live-{key:x}",
                tenant=self._tenant,
            )
            await proxy.start(user_input=_LIVE_USER_INPUT)
            self._sessions[key] = (session, proxy)
            return proxy
