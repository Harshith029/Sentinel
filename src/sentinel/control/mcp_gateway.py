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

Downstream selection is config-driven, and all three paths are wired:

* ``SENTINEL_MCP_SERVERS`` — the operator's own MCP servers (the product path);
* ``SENTINEL_TOOLS_{WEB,EMAIL,RECORDS}_URL`` — the remote example topology the
  ACA bicep deploys as separate internal apps;
* neither set — the bundled in-memory example servers (offline demo, no egress).

The remote paths share ONE connection factory
(:func:`~sentinel.downstream.open_downstream_session`), so connect timeout,
redirect policy, HTTP-client ownership and MCP session-termination policy cannot
drift between the deployment wiring and the product path.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
import weakref
from collections.abc import Sequence
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any, Final
from uuid import uuid4

import mcp.types as mcp_types
from mcp import ClientSession
from mcp.server.lowlevel import Server
from mcp.server.session import ServerSession
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.shared.memory import create_connected_server_and_client_session as connect
from starlette.types import Receive, Scope, Send

from sentinel.authorization.registry import DEFAULT_TENANT
from sentinel.catalogue import CatalogueFinding, CatalogueMonitor
from sentinel.config import get_settings
from sentinel.control.manager import RunManager
from sentinel.demo.preflight import preflight
from sentinel.demo.tool_servers import (
    REQUIRED_TOOLS,
    TOOL_TO_SERVER,
    ToolServerState,
    build_downstream,
)
from sentinel.downstream import (
    DownstreamServer,
    DownstreamTopology,
    connect_downstream,
    open_downstream_session,
    parse_servers,
)
from sentinel.mcp_proxy.content import mcp_error
from sentinel.mcp_proxy.proxy import SentinelProxy
from sentinel.mcp_proxy.router import ToolRouter
from sentinel.shield import InputShield

_LOG: Final[logging.Logger] = logging.getLogger("sentinel.control.mcp_gateway")
_GATEWAY_NAME: Final[str] = "sentinel"
_LIVE_USER_INPUT: Final[str] = "(live MCP session over HTTP)"
# CONCURRENCY cap — not a lifetime quota. A live session's proxy is NEVER
# replaced or evicted: evicting it would reset its provenance frontier and let a
# tainted action through on a fresh clean proxy (a laundering bypass). So under
# pressure we FAIL CLOSED, refusing NEW sessions rather than resetting existing
# ones. Sessions the transport has FINISHED with are a different matter: they can
# never make another call, so reclaiming them is safe by construction and is what
# keeps the cap a measure of concurrency. See :class:`_TrackedSession`.
_MAX_SESSIONS: Final[int] = 512
# Backstop for a session the transport never releases (a half-open connection, or
# a transport-layer leak). Retiring it frees the proxy; it does NOT hand a
# returning caller a clean one — see ``_retire_idle``.
_SESSION_IDLE_TTL_SECONDS: Final[float] = 900.0
# Salt for principal ids. Per process, matching the trust scorer's own lifetime:
# scores live in memory, so a principal that outlived the process would name
# state that no longer exists. Persisting trust would require promoting this to
# a deployment-scoped secret so the same credential maps to the same principal
# across restarts.
_PRINCIPAL_SALT: Final[bytes] = os.urandom(16)


def _principal_id(request: object | None) -> str | None:
    """A stable id for the AUTHENTICATED caller, or ``None`` when anonymous.

    Derived from the credential the request already had to present to get past
    :func:`_request_authorized` — never from anything the client merely claims
    about itself. A client-supplied agent name would be trivially spoofable, and
    an agent that could choose its own identity could shed a quarantine by
    choosing a different one, which is the exact failure this fixes.

    Hashed so the credential never reaches a span, a log or the dashboard: the
    id identifies a caller without being usable to impersonate one.

    Bearer header only, because that is the ONLY credential ``/mcp`` accepts
    (see :func:`_request_authorized`). The control plane also honours a session
    cookie for browsers, but ``EventSource`` is not how an MCP client connects,
    and deriving identity from a credential this endpoint would not have
    accepted would attribute a session to a principal that never authenticated.
    """
    headers = getattr(request, "headers", None)
    if headers is None:
        return None
    raw = headers.get("authorization", "")
    if not raw.lower().startswith("bearer "):
        return None
    credential = raw[7:].strip()
    if not credential:
        return None
    digest = hashlib.sha256(_PRINCIPAL_SALT + credential.encode("utf-8", "replace"))
    return digest.hexdigest()[:16]


@dataclass
class _TrackedSession:
    """Gateway-side state for one live MCP session.

    Held in a :class:`weakref.WeakKeyDictionary` keyed by the ``ServerSession``
    itself rather than in a plain dict keyed by ``id(session)``. That choice is
    load-bearing twice over:

    * The entry disappears exactly when the transport drops the session, so the
      gateway tracks a session for precisely as long as the MCP SDK considers it
      alive. There is no removal path to forget, and no cleanup task to fall
      behind. A dead session cannot issue another call, so reclaiming it cannot
      launder provenance.
    * A weak key IS the session object, so it cannot collide. ``id()`` is a
      memory address that CPython recycles: keyed that way, a *new* session
      landing on a freed address would be handed the *previous* session's proxy —
      inheriting another principal's trace, frontier and trust.

    ``proxy is None`` marks a RETIRED session: idle past the TTL, its proxy
    released. A retired session is refused, never re-seeded, so retirement can
    never become the laundering bypass that eviction would be.
    """

    agent_id: str
    proxy: SentinelProxy | None
    last_used: float


def _request_authorized(scope: Scope) -> bool:
    """Bearer-token gate for the /mcp wire endpoint.

    Reads settings fresh per request (so changing the env + restarting takes
    effect). Fail-closed when unconfigured: with no token and no explicit
    ``SENTINEL_ALLOW_ANONYMOUS``, this refuses. An unauthenticated /mcp is an
    OPEN TOOL SERVER — anyone who can reach the URL can drive the operator's
    downstream tools — so forgetting to set a token must not be the same thing
    as choosing to have none.
    """
    settings = get_settings()
    expected = settings.api_token
    if expected is None:
        return settings.allow_anonymous
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
        idle_ttl: float = _SESSION_IDLE_TTL_SECONDS,
    ) -> None:
        self._manager = manager
        self._tenant = tenant
        self._max_sessions = max_sessions
        self._idle_ttl = idle_ttl
        self._stack = AsyncExitStack()
        self._router: ToolRouter | None = None
        self._cache: tuple[mcp_types.Tool, ...] = ()
        # Shared mock tool servers (observable side effects live on this state).
        self._state = ToolServerState()
        self._downstream_mode = "memory"  # "memory" | "remote-http" | "declared"
        # Set only on the declared-servers (product) path: per-server catalogues.
        self._topology: DownstreamTopology | None = None
        # Pins the approved catalogue at connect; re-checked on tool discovery.
        self._monitor: CatalogueMonitor | None = None
        # Live session → its proxy. Weakly keyed, so an entry lives exactly as
        # long as the transport's session does (see _TrackedSession).
        self._sessions: weakref.WeakKeyDictionary[ServerSession, _TrackedSession] = (
            weakref.WeakKeyDictionary()
        )
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
        """``"memory"`` / ``"remote-http"`` / ``"declared"`` (the operator's own servers)."""
        return self._downstream_mode

    def describe(self) -> dict[str, Any]:
        """Operator-facing view of what SENTINEL is actually protecting.

        Surfaces the things that make this a product rather than a demo: WHICH
        downstream servers are connected, WHICH tools were discovered on each, and
        WHICH catalogue defenses are active. Rendered by the dashboard so the
        posture is visible instead of implied.
        """
        servers: list[dict[str, Any]] = []
        if self._topology is not None:
            servers = [
                {"name": name, "tools": sorted(t.name for t in tools)}
                for name, tools in sorted(self._topology.catalogues.items())
            ]
        elif self._cache:
            # Example/legacy topology: one merged catalogue, no per-server split.
            servers = [
                {
                    "name": "bundled example servers",
                    "tools": sorted(t.name for t in self._cache),
                }
            ]
        settings = get_settings()
        return {
            "mode": self._downstream_mode,
            "declared": self._downstream_mode == "declared",
            "servers": servers,
            "server_count": len(servers),
            "tool_count": sum(len(s["tools"]) for s in servers),
            "checks": {
                "cross_server_shadowing": "enforced (connect fails closed)",
                "tool_poisoning": (
                    "strict (refuse to serve)"
                    if settings.catalogue_strict
                    else "flag-only"
                ),
                "rug_pull": (
                    "DRIFT DETECTED after approval"
                    if (self._monitor is not None and self._monitor.drifted)
                    else "catalogue pinned; re-checked on tool discovery"
                ),
                "unknown_tools": "default-denied until policy is written",
            },
            "catalogue_monitor": (
                self._monitor.status() if self._monitor is not None else {}
            ),
        }

    async def __aenter__(self) -> SentinelGateway:
        """Connect the downstream, vet its catalogue, start the session manager.

        All-or-nothing. Python only guarantees ``__aexit__`` for a context manager
        whose ``__aenter__`` RETURNED, so a failure here — an unreachable server,
        a poisoned catalogue, a shadowed tool name — would otherwise strand every
        connection opened before it. Any failure closes the stack and re-raises.
        """
        try:
            return await self._enter()
        except BaseException:
            await self._stack.aclose()
            raise

    async def _enter(self) -> SentinelGateway:
        # Choose the downstream: remote MCP-over-HTTP tool servers if their URLs
        # are configured (the deploy sets them), else the in-process mock servers.
        declared = parse_servers(get_settings().mcp_servers)
        urls = get_settings().tool_server_urls()
        if declared:
            # PRODUCT PATH: the operator's own MCP servers, discovered dynamically.
            await self._connect_declared_downstream(declared)
        elif urls:
            await self._connect_remote_downstream(urls)
        else:
            await self._connect_inmemory_downstream()
        assert self._router is not None  # every connect path sets it
        # Preflight (health-check + cache schemas) so list_tools can't flake, AND
        # vet the catalogue itself: a poisoned tool DESCRIPTION subverts the agent
        # before anything is retrieved, so provenance alone cannot catch it. By
        # default a poisoned catalogue refuses to boot. (Cross-server tool-name
        # shadowing already fails closed inside ToolRouter.list_tools.)
        settings = get_settings()
        cache = await preflight(
            self._router,
            # With declared servers there is no fixed expected tool set — whatever
            # discovery found IS the catalogue. Only the bundled example topology
            # has required tools to assert.
            required_tools=() if declared else REQUIRED_TOOLS,
            shield=InputShield.from_settings(settings),
            strict=settings.catalogue_strict,
        )
        self._cache = cache.tools
        # Pin the approved catalogue so a later mutation (rug pull) is detectable.
        self._monitor = CatalogueMonitor(pinned=cache.fingerprints)
        # The session manager's run() owns the task group every HTTP session lives
        # in; it must wrap the whole app lifetime.
        await self._stack.enter_async_context(self._session_manager.run())
        return self

    async def _connect_declared_downstream(
        self, servers: Sequence[DownstreamServer]
    ) -> None:
        """The PRODUCT path: connect the operator's own MCP servers and discover.

        Routing comes from ``tools/list`` on each declared server, not from any
        hardcoded map, so SENTINEL proxies servers it has never seen. Fails closed
        on an unreachable server or a cross-server tool-name collision.
        """
        topology = await connect_downstream(servers, self._stack)
        self._router = topology.router
        self._downstream_mode = "declared"
        self._topology = topology

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
        # Same factory as the declared-servers path: one place decides connect
        # timeout, redirect policy, HTTP-client ownership and termination policy,
        # so the deployment wiring cannot drift from the product path.
        clients: dict[str, Any] = {}
        for key in required_keys:
            clients[key] = await open_downstream_session(urls[key], self._stack)
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

    async def _verify_catalogue(self) -> tuple[CatalogueFinding, ...]:
        """Re-check the live downstream against the catalogue pinned at connect.

        Logs loudly on first detection — a downstream that mutates its published
        definitions after approval is misbehaving, and an operator needs to know
        even though the agent is protected (it only ever sees the pinned copy).
        """
        if self._monitor is None or self._router is None:
            return ()
        was_clean = not self._monitor.drifted
        findings = await self._monitor.check(self._router)
        if findings and was_clean:
            _LOG.error(
                "downstream catalogue changed after approval (possible rug pull): %s",
                "; ".join(str(f) for f in findings),
            )
        return findings

    def _build_front_server(self) -> Server:
        front: Server = Server(_GATEWAY_NAME)

        @front.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
        async def _list_tools() -> list[mcp_types.Tool]:
            # Re-verify the downstream against the catalogue approved at connect.
            # This is the rug-pull check, run at the moment it matters (an agent
            # is about to learn what tools exist). The agent is ALWAYS served the
            # pinned catalogue, so a mutated description can never reach it; the
            # check exists to detect and report that a server changed its
            # definitions after approval. A transport hiccup is not drift — the
            # monitor records the error and we keep serving the cache.
            await self._verify_catalogue()
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

        Returns ``None`` (caller fails closed) when at capacity for a NEW session,
        or when the session has been retired. A session that already has a proxy is
        ALWAYS returned its own proxy — it is never replaced, so its provenance
        frontier can never be silently reset.
        """
        context = self._front.request_context
        return await self._proxy_for_session(
            context.session, principal=_principal_id(getattr(context, "request", None))
        )

    async def _proxy_for_session(
        self, session: ServerSession, *, principal: str | None = None
    ) -> SentinelProxy | None:
        """:meth:`_proxy_for_current_session` with the inputs passed explicitly.

        Split out so the session-lifecycle rules can be exercised directly,
        without standing up an HTTP transport for each session under test.
        """
        now = time.monotonic()
        # Fast path: established session, no lock.
        tracked = self._sessions.get(session)
        if tracked is not None:
            if tracked.proxy is None:
                return None  # retired → refuse; never re-seed a clean proxy
            tracked.last_used = now
            return tracked.proxy
        async with self._session_lock:
            tracked = self._sessions.get(session)  # re-check under lock
            if tracked is not None:
                if tracked.proxy is None:
                    return None
                tracked.last_used = now
                return tracked.proxy
            if self._router is None:  # pragma: no cover - set in __aenter__
                raise RuntimeError("gateway used before __aenter__ connected downstream")
            self._retire_idle(now)
            # Capacity reached → fail CLOSED. We must NOT evict a live session to
            # make room: that would reset its frontier and let a tainted action
            # through on a fresh, clean proxy (provenance laundering).
            if self.active_sessions >= self._max_sessions:
                return None
            # Identity follows the AUTHENTICATED caller, so trust and quarantine
            # survive a reconnect. Keying on the connection instead — as a random
            # per-session id did — made quarantine unenforceable: an agent that
            # tripped it only had to reconnect to be handed a clean score.
            #
            # With no credential there is no caller to attribute anything to, so
            # the fallback is per-session and trust genuinely does not carry.
            # That is a property of running unauthenticated, not a workaround:
            # durable trust requires a durable identity.
            agent_id = f"agent-{principal}" if principal else f"anon-{uuid4().hex}"
            proxy = self._manager.new_live_proxy(
                downstream=self._router,
                cache=self._cache,
                agent_id=agent_id,
                tenant=self._tenant,
            )
            await proxy.start(user_input=_LIVE_USER_INPUT)
            self._sessions[session] = _TrackedSession(
                agent_id=agent_id, proxy=proxy, last_used=now
            )
            # The run is in-flight only while the transport holds the session.
            # finalize() fires when the session is collected — the same moment
            # the WeakKeyDictionary entry disappears — so the run index stops
            # showing disconnected agents as permanently running. It captures
            # the trace id, never the session, or it would keep alive the very
            # object whose death it waits for.
            weakref.finalize(session, self._manager.finish_live_run, proxy.trace_id)
            return proxy

    @property
    def active_sessions(self) -> int:
        """Sessions currently holding a proxy (retired ones don't count)."""
        return sum(1 for t in self._sessions.values() if t.proxy is not None)

    def _retire_idle(self, now: float) -> None:
        """Release the proxies of sessions idle past the TTL.

        Only reached when a NEW session needs room, so a healthy gateway never
        pays for this. Retirement is deliberately not deletion: the entry stays
        as a tombstone, so if a retired session does come back it is REFUSED
        rather than handed a fresh, untainted proxy. That is the same reasoning
        that makes eviction unacceptable — a clean proxy is a laundering bypass —
        and it is why this can be a safe backstop rather than a new hole.
        """
        for tracked in self._sessions.values():
            if tracked.proxy is not None and now - tracked.last_used >= self._idle_ttl:
                _LOG.info(
                    "retiring idle MCP session",
                    extra={"agent_id": tracked.agent_id, "idle_seconds": now - tracked.last_used},
                )
                self._manager.finish_live_run(tracked.proxy.trace_id, status="failed")
                tracked.proxy = None
