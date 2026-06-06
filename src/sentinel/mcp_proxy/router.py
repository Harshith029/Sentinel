"""Downstream routing for the proxy (BUILD_SPEC §Phase 5).

The Phase-4 proxy fronted a single tool server. Phase 5 isolates tools into
SEPARATE MCP servers (web_fetch / send_email / the records service). The proxy
talks to a :class:`DownstreamConnection`; a single ``ClientSession`` already
satisfies that shape, and :class:`ToolRouter` aggregates several of them behind
the same interface — routing each ``call_tool`` to the server that owns the
tool and merging their catalogues for ``list_tools``.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

import mcp.types as mcp_types
from mcp.client.session import ClientSession

from sentinel.mcp_proxy.content import mcp_error


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

    def __init__(self, routes: Mapping[str, ClientSession]) -> None:
        self._routes = dict(routes)
        # De-duplicate the backing sessions while preserving first-seen order.
        self._sessions: list[ClientSession] = []
        for session in self._routes.values():
            if session not in self._sessions:
                self._sessions.append(session)

    async def list_tools(self) -> mcp_types.ListToolsResult:
        merged: dict[str, mcp_types.Tool] = {}
        for session in self._sessions:
            for tool in (await session.list_tools()).tools:
                merged.setdefault(tool.name, tool)
        return mcp_types.ListToolsResult(tools=list(merged.values()))

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> mcp_types.CallToolResult:
        session = self._routes.get(name)
        if session is None:
            return mcp_error(f"no downstream server routes tool {name!r}")
        return await session.call_tool(name, arguments)
