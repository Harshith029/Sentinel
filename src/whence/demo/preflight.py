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

from whence.catalogue import (
    CatalogueFinding,
    detect_drift,
    fingerprint_catalogue,
    scan_descriptions,
)
from whence.mcp_proxy.router import DownstreamConnection


class PreflightError(RuntimeError):
    """Raised when a downstream server is unhealthy or missing a required tool."""


@dataclass(frozen=True)
class ToolSchemaCache:
    """The tool schemas captured at preflight, ready to serve to the proxy.

    The cache is also the **approved catalogue**: its fingerprints pin what the
    operator implicitly signed off at connect time, so a later ``tools/list``
    that differs (a rug pull) can be detected via :meth:`drift_against`.
    """

    tools: tuple[mcp_types.Tool, ...]

    @property
    def names(self) -> frozenset[str]:
        return frozenset(tool.name for tool in self.tools)

    @property
    def fingerprints(self) -> dict[str, str]:
        """``{tool_name: fingerprint}`` of the catalogue approved at preflight."""
        return fingerprint_catalogue(self.tools)

    def drift_against(
        self, current: Iterable[mcp_types.Tool]
    ) -> list[CatalogueFinding]:
        """Findings for any way ``current`` diverges from the approved catalogue."""
        return detect_drift(self.fingerprints, list(current))


async def preflight(
    downstream: DownstreamConnection,
    *,
    required_tools: Iterable[str],
    shield: object | None = None,
    strict: bool = True,
) -> ToolSchemaCache:
    """Health-check ``downstream``, vet its catalogue, and cache the schema.

    Fails loudly (``PreflightError``) if the catalogue cannot be fetched, a
    required tool is absent, or — when ``shield`` is supplied — a tool's own
    definition carries prompt-injection markers (**tool poisoning**). The model
    reads and obeys tool descriptions, so a poisoned catalogue is a supply-chain
    compromise that provenance alone cannot catch: nothing the agent *retrieves*
    is tainted, yet its instructions are already subverted. Refusing to serve it
    is therefore the right default.

    ``strict=False`` downgrades poisoning to flag-only (findings are returned via
    the raised-or-not path being skipped) for operators who prefer to triage.

    Cross-server shadowing needs no handling here: :meth:`ToolRouter.list_tools`
    already fails closed on a tool-name collision, and this call goes through it.
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

    if shield is not None:
        findings = await scan_descriptions(cache.tools, shield)
        if findings and strict:
            raise PreflightError(
                "downstream tool catalogue appears poisoned; refusing to serve it:\n  "
                + "\n  ".join(str(f) for f in findings)
            )
    return cache
