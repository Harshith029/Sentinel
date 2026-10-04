"""Downstream preflight (BUILD_SPEC §Phase 5).

Before any demo run, health-check every downstream MCP server and CACHE its tool
schema locally, so a malformed registration or a mid-run transport hiccup cannot
kill the live demo. This is the defense against the MCP-transport flakiness seen
earlier: tool discovery is served from the cache once preflight has passed.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace

import mcp.types as mcp_types

from sentinel.catalogue import (
    CatalogueFinding,
    detect_drift,
    fingerprint_catalogue,
    scan_descriptions,
)
from sentinel.mcp_proxy.router import DownstreamConnection


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
    # What the catalogue scan found and no approval covers. Only ever non-empty
    # in flag-only mode (``strict=False``); strict mode raises instead.
    findings: tuple[CatalogueFinding, ...] = ()
    # Findings an operator approved by fingerprint: served, and still reported.
    acknowledged: tuple[CatalogueFinding, ...] = ()

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
    approved: Mapping[str, str] | None = None,
) -> ToolSchemaCache:
    """Health-check ``downstream``, vet its catalogue, and cache the schema.

    ``approved`` maps tool name to the fingerprint of a definition an operator
    reviewed and accepted (``SENTINEL_CATALOGUE_APPROVALS``). The scanner is a
    heuristic: "Send an email to a recipient, e.g. user@example.com." trips it.
    Before approvals, the only way past a false positive was turning strict
    mode off for every tool at once.

    Fails loudly (``PreflightError``) if the catalogue cannot be fetched, a
    required tool is absent, or — when ``shield`` is supplied — a tool's own
    definition carries prompt-injection markers (**tool poisoning**). The model
    reads and obeys tool descriptions, so a poisoned catalogue is a supply-chain
    compromise that provenance alone cannot catch: nothing the agent *retrieves*
    is tainted, yet its instructions are already subverted. Refusing to serve it
    is therefore the right default.

    ``strict=False`` downgrades poisoning to flag-only for operators who prefer
    to triage: the catalogue is served and the findings travel with the cache
    (:attr:`ToolSchemaCache.findings`) so the caller can surface them. They
    used to be computed and then dropped, so flag-only mode flagged nothing.

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
        scanned = await scan_descriptions(cache.tools, shield)
        findings, acknowledged = _apply_approvals(scanned, cache.tools, approved or {})
        if findings and strict:
            raise PreflightError(_refusal(findings, cache.tools))
        if findings or acknowledged:
            cache = ToolSchemaCache(
                tools=cache.tools, findings=tuple(findings), acknowledged=tuple(acknowledged)
            )
    return cache


def _apply_approvals(
    findings: Sequence[CatalogueFinding],
    tools: Sequence[mcp_types.Tool],
    approved: Mapping[str, str],
) -> tuple[list[CatalogueFinding], list[CatalogueFinding]]:
    """Split findings into those still standing and those an operator approved.

    An approval covers one EXACT definition: the fingerprint of the tool's name,
    description and schema. If the tool has changed since, the approval does not
    match and the finding stands, saying so.
    """
    prints = fingerprint_catalogue(tools)
    standing: list[CatalogueFinding] = []
    acknowledged: list[CatalogueFinding] = []
    for finding in findings:
        current = prints.get(finding.tool_name)
        approval = approved.get(finding.tool_name)
        if approval is not None and approval == current:
            acknowledged.append(finding)
        elif approval is not None:
            standing.append(
                replace(
                    finding,
                    detail=finding.detail + "; an approval exists for an earlier "
                    "definition of this tool, which has changed since",
                )
            )
        else:
            standing.append(finding)
    return standing, acknowledged


def _refusal(findings: Sequence[CatalogueFinding], tools: Sequence[mcp_types.Tool]) -> str:
    """The refusal, with what an operator needs to act on it."""
    prints = fingerprint_catalogue(tools)
    flagged = sorted({f.tool_name for f in findings})
    return (
        "downstream tool catalogue appears poisoned; refusing to serve it:\n  "
        + "\n  ".join(str(f) for f in findings)
        + "\n\nThe scanner is a heuristic and flags ordinary descriptions too. After "
        "reviewing each definition, approve exactly that definition in sentinel.yaml:\n"
        "  catalogue_approvals:\n"
        + "".join(f"    {name}: {prints[name]}\n" for name in flagged if name in prints)
        + "(or as JSON in SENTINEL_CATALOGUE_APPROVALS). If a tool's definition "
        "changes, its approval stops matching and it is flagged again."
    )
