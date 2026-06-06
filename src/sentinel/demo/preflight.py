"""Downstream preflight (BUILD_SPEC §Phase 5).

Before any demo run, health-check every downstream MCP server and CACHE its tool
schema locally, so a malformed registration or a mid-run transport hiccup cannot
kill the live demo. This is the defense against the MCP-transport flakiness seen
earlier: tool discovery is served from the cache once preflight has passed.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

import mcp.types as mcp_types

from sentinel.mcp_proxy.router import DownstreamConnection


class PreflightError(RuntimeError):
    """Raised when a downstream server is unhealthy or missing a required tool."""


@dataclass(frozen=True)
class ToolSchemaCache:
    """The tool schemas captured at preflight, ready to serve to the proxy."""

    tools: tuple[mcp_types.Tool, ...]

    @property
    def names(self) -> frozenset[str]:
        return frozenset(tool.name for tool in self.tools)


async def preflight(
    downstream: DownstreamConnection, *, required_tools: Iterable[str]
) -> ToolSchemaCache:
    """Health-check ``downstream`` and cache its schema.

    Fails loudly (``PreflightError``) if the catalogue cannot be fetched or any
    required tool is absent — BEFORE the demo starts, not during it.
    """
    required = set(required_tools)
    try:
        listed = await downstream.list_tools()
    except Exception as exc:  # noqa: BLE001 - surface ANY transport failure as preflight
        raise PreflightError(f"downstream health-check failed: {exc}") from exc

    cache = ToolSchemaCache(tools=tuple(listed.tools))
    missing = required - cache.names
    if missing:
        raise PreflightError(
            f"downstream is missing required tools: {sorted(missing)}; "
            f"available: {sorted(cache.names)}"
        )
    return cache
