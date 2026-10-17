"""Downstream routing for the proxy (BUILD_SPEC §Phase 5).

The Phase-4 proxy fronted a single tool server. Phase 5 isolates tools into
SEPARATE MCP servers (web_fetch / send_email / the records service). The proxy
talks to a :class:`DownstreamConnection`; a single ``ClientSession`` already
satisfies that shape, and :class:`ToolRouter` aggregates several of them behind
the same interface — routing each ``call_tool`` to the server that owns the
tool and merging their catalogues for ``list_tools``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any, Final, Protocol, runtime_checkable

import mcp.types as mcp_types

from sentinel.catalogue import CatalogueCollisionError
from sentinel.mcp_proxy.content import mcp_error

# A downstream HTTP connection may remain open while idle, but individual MCP
# operations must not be allowed to wait forever for a peer that stops replying.
DEFAULT_DOWNSTREAM_OPERATION_TIMEOUT_SECONDS: Final[float] = 30.0


@runtime_checkable
class DownstreamConnection(Protocol):
    """The tool-facing surface the proxy depends on (a subset of ``ClientSession``)."""

    async def list_tools(self) -> mcp_types.ListToolsResult: ...

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> mcp_types.CallToolResult: ...


class ToolRouter:
    """Fronts several isolated tool servers as one :class:`DownstreamConnection`.

    ``routes`` maps a tool name to the ``ClientSession`` that hosts it. A call to
    an unrouted tool returns a clean MCP error (it never silently no-ops).
    """

    def __init__(
        self,
        routes: Mapping[str, DownstreamConnection],
        *,
        operation_timeout_seconds: float = DEFAULT_DOWNSTREAM_OPERATION_TIMEOUT_SECONDS,
    ) -> None:
        if operation_timeout_seconds <= 0:
            raise ValueError("operation_timeout_seconds must be positive")
        self._routes = dict(routes)
        self._operation_timeout_seconds = operation_timeout_seconds
        # De-duplicate the backing sessions while preserving first-seen order.
        self._sessions: list[DownstreamConnection] = []
        for session in self._routes.values():
            if session not in self._sessions:
                self._sessions.append(session)

    async def list_tools(self) -> mcp_types.ListToolsResult:
        """Merge every backing server's catalogue, refusing name collisions.

        A tool name exposed by two servers is the **cross-server shadowing**
        attack: whichever catalogue wins, the agent reads that server's
        description while ``call_tool`` may route to the *other* server — so the
        described tool and the executed tool differ. Silently first-winning
        (``setdefault``) hides exactly that mismatch, so we fail CLOSED instead
        and make the operator disambiguate.
        """
        merged: dict[str, mcp_types.Tool] = {}
        collisions: dict[str, int] = {}
        try:
            # One deadline applies to the merged response, not one deadline per
            # server. Otherwise a large configured fleet could multiply a 30s
            # bound into minutes of blocked agent discovery.
            async with asyncio.timeout(self._operation_timeout_seconds):
                for session in self._sessions:
                    for tool in (await session.list_tools()).tools:
                        if tool.name in merged:
                            collisions[tool.name] = collisions.get(tool.name, 1) + 1
                            continue
                        merged[tool.name] = tool
        except TimeoutError as exc:
            raise TimeoutError("downstream tool listing timed out") from exc
        if collisions:
            raise CatalogueCollisionError(collisions)
        return mcp_types.ListToolsResult(tools=list(merged.values()))

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> mcp_types.CallToolResult:
        session = self._routes.get(name)
        if session is None:
            return mcp_error(f"no downstream server routes tool {name!r}")
        try:
            async with asyncio.timeout(self._operation_timeout_seconds):
                return await session.call_tool(name, arguments)
        except TimeoutError as exc:
            raise TimeoutError(f"downstream tool {name!r} timed out") from exc
