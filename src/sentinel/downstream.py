"""Config-driven connection to ARBITRARY downstream MCP servers.

SENTINEL is a proxy: it should secure the operator's *own* MCP servers, not ship
tools of its own. Historically the downstream topology was hardcoded to the three
bundled example servers (``web`` / ``email`` / ``records``) via a fixed
``TOOL_TO_SERVER`` map. This module replaces that with **discovery**:

1. the operator declares their servers (``SENTINEL_MCP_SERVERS``);
2. SENTINEL connects to each and asks what tools it has (``tools/list``);
3. the routing table is built from what was discovered, not from a constant.

That is what makes SENTINEL a **cross-server** information-flow layer: it is the
one component that sees every server's catalogue and every call, so it can both
vet the catalogues against each other and taint-track data flowing between them.

Security properties enforced here (all fail CLOSED):

* **Shadowing** — a tool name exposed by two servers is refused at connect, so a
  malicious server cannot silently claim a trusted server's tool name.
* **Poisoning** — discovered definitions are shield-scanned before being served
  to an agent (:mod:`sentinel.catalogue`, applied by the caller's preflight).
* **Unknown tools stay denied** — discovery does NOT grant permission. A newly
  discovered tool has no policy entry, so the authorization engine default-denies
  it until the operator writes a rule. Discovery is routing; permission is policy.

Parsing and topology construction are separated from IO so both are unit testable
without a network.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping, Sequence
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any, Final, Protocol

import httpx
import mcp.types as mcp_types

from sentinel.catalogue import CatalogueIntegrityError, detect_shadowing
from sentinel.mcp_proxy.router import (
    DEFAULT_DOWNSTREAM_OPERATION_TIMEOUT_SECONDS,
    ToolRouter,
)


def _display_url(url: str) -> str:
    """A server URL fit for an error message or a log line.

    Without user info, query or fragment: those are where a URL carries a
    credential (``https://user:token@host`` or ``?api_key=``), and connection
    errors are printed and logged.
    """
    try:
        parsed = httpx.URL(url)
        return str(parsed.copy_with(userinfo=b"", query=None, fragment=None))
    except (httpx.InvalidURL, TypeError, ValueError):
        return "<unparseable url>"


class DownstreamConfigError(ValueError):
    """Raised when the declared downstream-server configuration is invalid."""


@dataclass(frozen=True)
class DownstreamServer:
    """One operator-declared downstream MCP server."""

    name: str
    url: str

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise DownstreamConfigError("server 'name' must be a non-empty string")
        if not self.url or not self.url.strip():
            raise DownstreamConfigError(f"server {self.name!r}: 'url' must be a non-empty string")
        if not self.url.startswith(("http://", "https://")):
            raise DownstreamConfigError(
                f"server {self.name!r}: url must start with http:// or https://, "
                f"got {_display_url(self.url)!r}"
            )


class SessionLike(Protocol):
    """The downstream surface we need: discovery + invocation."""

    async def list_tools(self) -> mcp_types.ListToolsResult: ...

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> mcp_types.CallToolResult: ...


@dataclass(frozen=True)
class DownstreamTopology:
    """The discovered downstream: how to route, and what each server exposes."""

    router: ToolRouter
    catalogues: Mapping[str, tuple[mcp_types.Tool, ...]]

    @property
    def tools(self) -> tuple[mcp_types.Tool, ...]:
        return tuple(t for tools in self.catalogues.values() for t in tools)

    @property
    def tool_names(self) -> frozenset[str]:
        return frozenset(t.name for t in self.tools)

    def server_of(self, tool_name: str) -> str | None:
        """Which declared server owns ``tool_name`` (for forensics/debugging)."""
        for server, tools in self.catalogues.items():
            if any(t.name == tool_name for t in tools):
                return server
        return None


def parse_servers(raw: str | None) -> tuple[DownstreamServer, ...]:
    """Parse ``SENTINEL_MCP_SERVERS`` into validated server specs.

    Accepted JSON forms::

        [{"name": "github", "url": "https://mcp.example/github"}, ...]
        {"github": "https://mcp.example/github", ...}

    Empty/unset yields ``()`` — the caller then falls back to the bundled example
    servers. Duplicate names are rejected: the name identifies a server in
    forensics, so a silent collapse would misattribute calls.
    """
    if raw is None or not raw.strip():
        return ()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DownstreamConfigError(f"SENTINEL_MCP_SERVERS is not valid JSON: {exc}") from exc

    servers: list[DownstreamServer] = []
    if isinstance(data, dict):
        servers = [DownstreamServer(name=str(k), url=str(v)) for k, v in data.items()]
    elif isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                raise DownstreamConfigError(
                    f"each server entry must be an object, got {type(entry).__name__}"
                )
            missing = {"name", "url"} - entry.keys()
            if missing:
                raise DownstreamConfigError(f"server entry missing {sorted(missing)}: {entry!r}")
            servers.append(DownstreamServer(name=str(entry["name"]), url=str(entry["url"])))
    else:
        raise DownstreamConfigError(
            f"SENTINEL_MCP_SERVERS must be a JSON array or object, got {type(data).__name__}"
        )

    seen: set[str] = set()
    for server in servers:
        if server.name in seen:
            raise DownstreamConfigError(f"duplicate server name {server.name!r}")
        seen.add(server.name)
    if not servers:
        raise DownstreamConfigError("SENTINEL_MCP_SERVERS declared no servers")
    return tuple(servers)


async def build_topology(
    sessions: Mapping[str, SessionLike],
    *,
    operation_timeout_seconds: float = DEFAULT_DOWNSTREAM_OPERATION_TIMEOUT_SECONDS,
) -> DownstreamTopology:
    """Discover each session's tools and build the routing table.

    Fails closed on a cross-server tool-name collision (shadowing) rather than
    picking a winner — the operator must disambiguate.
    """
    if operation_timeout_seconds <= 0:
        raise DownstreamConfigError("downstream operation timeout must be positive")
    catalogues: dict[str, tuple[mcp_types.Tool, ...]] = {}
    try:
        # Bound the complete discovery pass. A per-server timeout would allow a
        # large topology to hold startup hostage for N times the deadline.
        async with asyncio.timeout(operation_timeout_seconds):
            for name, session in sessions.items():
                listed = await session.list_tools()
                catalogues[name] = tuple(listed.tools)
    except TimeoutError as exc:
        raise DownstreamConfigError("downstream tool discovery timed out") from exc
    except Exception as exc:  # noqa: BLE001 - any transport failure is fatal here
        raise DownstreamConfigError(f"downstream tool discovery failed: {exc}") from exc

    collisions = detect_shadowing(catalogues)
    if collisions:
        raise CatalogueIntegrityError(
            "downstream servers expose colliding tool names "
            "(possible cross-server shadowing):\n  " + "\n  ".join(str(c) for c in collisions)
        )

    routes: dict[str, Any] = {}
    for server, tools in catalogues.items():
        for tool in tools:
            routes[tool.name] = sessions[server]
    if not routes:
        raise DownstreamConfigError("no tools discovered across any declared downstream server")
    return DownstreamTopology(
        router=ToolRouter(routes, operation_timeout_seconds=operation_timeout_seconds),
        catalogues=catalogues,
    )


# Bounds CONNECTION ESTABLISHMENT only. The long-lived streaming transport itself
# may stay idle; the per-operation deadline below bounds RPCs on that transport.
_CONNECT_TIMEOUT_SECONDS: Final[float] = 10.0


def _downstream_http_client(
    *, transport: httpx.AsyncBaseTransport | None = None
) -> httpx.AsyncClient:
    """The HTTP client SENTINEL uses for downstream MCP connections.

    Supplying our own rather than letting the SDK build a default is for two
    proven reasons, and no others:

    * **A hang becomes an error.** The SDK default does not bound connect, so a
      misconfigured or black-holed downstream URL wedges startup instead of
      failing with something the operator can act on.
    * **Cross-origin redirects are refused.** An MCP mount commonly answers
      ``/mcp`` with a 307 to ``/mcp/``, which must keep working; a redirect to
      another origin must not, because a 307 replays the JSON-RPC body there.
      Since mcp 1.30.0 the SDK enforces this itself: it sends every request
      with redirect following off and follows only same-origin redirects, so
      ``follow_redirects`` here no longer decides anything for MCP requests.
      The response hook stays as a second, SENTINEL-owned check that does not
      depend on the SDK keeping that policy.

    It is NOT a workaround for the teardown wedge in
    ``docs/mcp-streamable-http-teardown.md``. An early reading of one standalone
    run suggested it was; that did not hold under retest.
    """
    return httpx.AsyncClient(
        timeout=httpx.Timeout(
            None, connect=_CONNECT_TIMEOUT_SECONDS, pool=_CONNECT_TIMEOUT_SECONDS
        ),
        follow_redirects=True,
        event_hooks={"response": [_reject_cross_origin_redirect]},
        transport=transport,
    )


async def _reject_cross_origin_redirect(response: httpx.Response) -> None:
    """Fail closed before HTTPX follows a downstream redirect off-origin.

    MCP tool calls are POSTs whose JSON-RPC body may contain agent-selected
    data. HTTPX preserves that body for 307/308 redirects, so an untrusted
    downstream server must not be able to redirect it to an arbitrary host.
    Response hooks run before HTTPX constructs the follow-up request.
    """
    if not response.is_redirect:
        return
    location = response.headers.get("location")
    if not location:
        return
    try:
        target = response.request.url.join(location)
    except (httpx.InvalidURL, TypeError, ValueError) as exc:
        raise httpx.RemoteProtocolError("downstream returned an invalid redirect") from exc
    source = response.request.url
    if (target.scheme, target.host, target.port) != (
        source.scheme,
        source.host,
        source.port,
    ):
        raise httpx.RemoteProtocolError("downstream cross-origin redirect refused")


# Whether a closing downstream connection sends the MCP session-termination
# DELETE. True, for two independent reasons.
#
# It is CORRECT: the SDK server's ``session_idle_timeout`` defaults to None, so a
# server that never receives the DELETE keeps the session forever. Those servers
# belong to the operator, and we will not strand resources on someone else's
# server.
#
# And there is nothing to trade it against: skipping the DELETE does NOT avoid
# the teardown wedge in ``docs/mcp-streamable-http-teardown.md``. Measured both
# ways — set here, the sequence still fails; set on the external client, it still
# fails.
_TERMINATE_ON_CLOSE: Final[bool] = True


async def open_downstream_session(
    url: str,
    stack: AsyncExitStack,
    *,
    operation_timeout_seconds: float = DEFAULT_DOWNSTREAM_OPERATION_TIMEOUT_SECONDS,
) -> SessionLike:
    """Open ONE downstream MCP session — the single way SENTINEL connects out.

    Both downstream paths route through here (operator-declared
    ``SENTINEL_MCP_SERVERS`` and the legacy ``SENTINEL_TOOLS_*_URL`` deployment
    wiring), so connect timeout, redirect policy, HTTP-client ownership and
    session-termination policy are decided in exactly one place.

    Ownership matters and is easy to get wrong: the SDK closes the HTTP client
    **only when it created it** (``if not client_provided``). A caller-supplied
    client is never closed by the SDK, so ours is entered into ``stack`` and
    closed with the session.
    """
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    # Transactional: everything opened here is owned by a LOCAL stack until the
    # handshake succeeds. A server that fails to connect, or connects and then
    # fails `initialize()`, must not leave its HTTP client and transport tasks
    # behind on the caller's long-lived stack — the caller may propagate the
    # error before it ever gets to close that stack.
    if operation_timeout_seconds <= 0:
        raise DownstreamConfigError("downstream operation timeout must be positive")
    local = AsyncExitStack()
    try:
        # The HTTP client's connect timeout does not cover a peer that accepts
        # TCP and then withholds the MCP handshake. Bound opening and initialize
        # as one operation so startup reliably returns control to the operator.
        async with asyncio.timeout(operation_timeout_seconds):
            client = await local.enter_async_context(_downstream_http_client())
            read, write, _id = await local.enter_async_context(
                streamable_http_client(
                    url, http_client=client, terminate_on_close=_TERMINATE_ON_CLOSE
                )
            )
            session = await local.enter_async_context(ClientSession(read, write))
            await session.initialize()
    except TimeoutError as exc:
        await local.aclose()  # nothing half-open escapes
        raise DownstreamConfigError("downstream session initialization timed out") from exc
    except BaseException:
        await local.aclose()  # nothing half-open escapes
        raise
    # Handshake succeeded: hand ownership to the caller, intact and in order.
    stack.push_async_callback(local.pop_all().aclose)
    return session  # ClientSession satisfies SessionLike


async def connect_downstream(
    servers: Sequence[DownstreamServer],
    stack: AsyncExitStack,
    *,
    operation_timeout_seconds: float = DEFAULT_DOWNSTREAM_OPERATION_TIMEOUT_SECONDS,
) -> DownstreamTopology:
    """Connect to each declared server over MCP-over-HTTP and discover its tools.

    Connections are bound to ``stack``, so the caller owns their lifetime. Fails
    loudly on an unreachable server: a half-wired proxy is worse than no proxy.
    """
    sessions: dict[str, SessionLike] = {}
    for server in servers:
        try:
            session = await open_downstream_session(
                server.url, stack, operation_timeout_seconds=operation_timeout_seconds
            )
        except Exception as exc:  # noqa: BLE001 - surface any connect failure clearly
            raise DownstreamConfigError(
                f"downstream server {server.name!r} at {_display_url(server.url)}: "
                f"connection failed: {exc}"
            ) from exc
        sessions[server.name] = session
    return await build_topology(sessions, operation_timeout_seconds=operation_timeout_seconds)
