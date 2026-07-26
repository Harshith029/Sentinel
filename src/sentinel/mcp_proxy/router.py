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

from sentinel.catalogue import CatalogueIntegrityError
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
        for session in self._sessions:
            for tool in (await session.list_tools()).tools:
                if tool.name in merged:
                    collisions[tool.name] = collisions.get(tool.name, 1) + 1
                    continue
                merged[tool.name] = tool
        if collisions:
            raise CatalogueIntegrityError(
                "downstream tool-name collision (possible cross-server shadowing): "
                + ", ".join(
                    f"{name!r} exposed by {count} servers"
                    for name, count in sorted(collisions.items())
                )
                + " — refusing to guess which server is authoritative"
            )
        return mcp_types.ListToolsResult(tools=list(merged.values()))

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> mcp_types.CallToolResult:
        session = self._routes.get(name)
        if session is None:
            return mcp_error(f"no downstream server routes tool {name!r}")
        return await session.call_tool(name, arguments)
