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

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

import mcp.types as mcp_types

from sentinel.catalogue import CatalogueIntegrityError, detect_shadowing
from sentinel.mcp_proxy.router import ToolRouter

if TYPE_CHECKING:
    from contextlib import AsyncExitStack


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
            raise DownstreamConfigError(
                f"server {self.name!r}: 'url' must be a non-empty string"
            )
        if not self.url.startswith(("http://", "https://")):
            raise DownstreamConfigError(
                f"server {self.name!r}: url must start with http:// or https://, "
                f"got {self.url!r}"
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
        raise DownstreamConfigError(
            f"SENTINEL_MCP_SERVERS is not valid JSON: {exc}"
        ) from exc

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
                raise DownstreamConfigError(
                    f"server entry missing {sorted(missing)}: {entry!r}"
                )
            servers.append(
                DownstreamServer(name=str(entry["name"]), url=str(entry["url"]))
            )
    else:
        raise DownstreamConfigError(
            "SENTINEL_MCP_SERVERS must be a JSON array or object, "
            f"got {type(data).__name__}"
        )

    seen: set[str] = set()
    for server in servers:
        if server.name in seen:
            raise DownstreamConfigError(f"duplicate server name {server.name!r}")
        seen.add(server.name)
    if not servers:
        raise DownstreamConfigError("SENTINEL_MCP_SERVERS declared no servers")
    return tuple(servers)


async def build_topology(sessions: Mapping[str, SessionLike]) -> DownstreamTopology:
    """Discover each session's tools and build the routing table.

    Fails closed on a cross-server tool-name collision (shadowing) rather than
    picking a winner — the operator must disambiguate.
    """
    catalogues: dict[str, tuple[mcp_types.Tool, ...]] = {}
    for name, session in sessions.items():
        try:
            listed = await session.list_tools()
        except Exception as exc:  # noqa: BLE001 - any transport failure is fatal here
            raise DownstreamConfigError(
                f"downstream server {name!r}: tool discovery failed: {exc}"
            ) from exc
        catalogues[name] = tuple(listed.tools)

    collisions = detect_shadowing(catalogues)
    if collisions:
        raise CatalogueIntegrityError(
            "downstream servers expose colliding tool names "
            "(possible cross-server shadowing):\n  "
            + "\n  ".join(str(c) for c in collisions)
        )

    routes: dict[str, Any] = {}
    for server, tools in catalogues.items():
        for tool in tools:
            routes[tool.name] = sessions[server]
    if not routes:
        raise DownstreamConfigError(
            "no tools discovered across any declared downstream server"
        )
    return DownstreamTopology(router=ToolRouter(routes), catalogues=catalogues)


async def connect_downstream(
    servers: Sequence[DownstreamServer], stack: AsyncExitStack
) -> DownstreamTopology:
    """Connect to each declared server over MCP-over-HTTP and discover its tools.

    Connections are bound to ``stack``, so the caller owns their lifetime. Fails
    loudly on an unreachable server: a half-wired proxy is worse than no proxy.
    """
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    sessions: dict[str, SessionLike] = {}
    for server in servers:
        try:
            read, write, _id = await stack.enter_async_context(
                streamable_http_client(server.url)
            )
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
        except Exception as exc:  # noqa: BLE001 - surface any connect failure clearly
            raise DownstreamConfigError(
                f"downstream server {server.name!r} at {server.url}: "
                f"connection failed: {exc}"
            ) from exc
        sessions[server.name] = session
    return await build_topology(sessions)
