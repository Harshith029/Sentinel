"""Tool-catalogue integrity — defending the *catalogue*, not just tool results.

SENTINEL's provenance engine treats every tool RESULT as untrusted. But an MCP
agent also reads the tool **catalogue** — each tool's name, description and input
schema — and a model follows instructions it finds there. That makes the catalogue
itself an attack surface, and it is one SENTINEL is uniquely placed to defend:
the proxy is the only component that sees every downstream server's catalogue.

Three documented attack classes are covered here:

* **Tool poisoning** — malicious instructions hidden in a tool's ``description``
  (the model reads ``tools/list`` and obeys). We scan every description through
  the same Layer-1 shield used for tool results and report findings; the caller
  decides whether to refuse or merely flag (see :func:`verify_catalogue`).
* **Cross-server shadowing** — a malicious server exposes a tool with the SAME
  NAME as a trusted server's tool, hoping the router silently routes to it.
  :func:`detect_shadowing` makes the collision explicit instead.
* **Rug pull** — a server serves a benign catalogue at approval time, then pushes
  a changed definition afterwards (``notifications/tools/list_changed``).
  :func:`fingerprint_tool` / :func:`detect_drift` pin the approved catalogue and
  detect any later divergence.

Design notes:

* This module is **pure and side-effect free** apart from the optional shield
  call, so it is trivially testable and reusable by any connect path.
* It emits no new forensic event type: description findings map onto the existing
  ``InjectionScanned`` payload (``target="tool_description:<name>"``), and the
  integrity failures are connect-time errors that fail CLOSED — matching how
  preflight already refuses to start on an unhealthy downstream.
* Shadowing is reported for *any* duplicate name, without guessing which server
  is malicious. Naming the winner is a policy decision for the operator, not an
  inference for us to make.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

import mcp.types as mcp_types

FindingKind = Literal["poisoned_description", "shadowed_tool", "schema_drift"]


class CatalogueIntegrityError(RuntimeError):
    """Raised when a catalogue fails a check the caller treats as fatal."""


@dataclass(frozen=True)
class CatalogueFinding:
    """One problem found in a tool catalogue."""

    kind: FindingKind
    tool_name: str
    detail: str
    servers: tuple[str, ...] = ()

    def __str__(self) -> str:
        where = f" [{', '.join(self.servers)}]" if self.servers else ""
        return f"{self.kind}: {self.tool_name}{where} — {self.detail}"


# --- rug-pull detection -------------------------------------------------------


def fingerprint_tool(tool: mcp_types.Tool) -> str:
    """A stable hash of everything about a tool the model can read.

    Covers name, description AND input schema: a rug pull that only rewrites the
    schema (leaving the description intact) must be caught too. The schema is
    serialized with sorted keys so semantically identical schemas hash equally.
    """
    payload = json.dumps(
        {
            "name": tool.name,
            "description": tool.description or "",
            "inputSchema": tool.inputSchema or {},
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def fingerprint_catalogue(tools: Sequence[mcp_types.Tool]) -> dict[str, str]:
    """``{tool_name: fingerprint}`` for a whole catalogue (order-independent)."""
    return {tool.name: fingerprint_tool(tool) for tool in tools}


def detect_drift(
    pinned: Mapping[str, str], current: Sequence[mcp_types.Tool]
) -> list[CatalogueFinding]:
    """Compare a live catalogue against the fingerprints pinned at approval time.

    Reports changed definitions (the rug pull), tools that vanished, and tools
    that appeared after approval — all three are unapproved catalogue mutations.
    """
    findings: list[CatalogueFinding] = []
    live = fingerprint_catalogue(current)
    for name, pinned_fp in pinned.items():
        live_fp = live.get(name)
        if live_fp is None:
            findings.append(
                CatalogueFinding(
                    "schema_drift", name, "tool disappeared after approval"
                )
            )
        elif live_fp != pinned_fp:
            findings.append(
                CatalogueFinding(
                    "schema_drift",
                    name,
                    "tool definition changed after approval (possible rug pull)",
                )
            )
    for name in live.keys() - pinned.keys():
        findings.append(
            CatalogueFinding("schema_drift", name, "tool appeared after approval")
        )
    return findings


# --- cross-server shadowing ---------------------------------------------------


def detect_shadowing(
    per_server: Mapping[str, Sequence[mcp_types.Tool]],
) -> list[CatalogueFinding]:
    """Find tool names exposed by MORE THAN ONE downstream server.

    A duplicate name is never benign in a proxy: whichever server wins, the agent
    believes it is calling the other one. We report the collision and let the
    caller fail closed rather than silently picking a winner.
    """
    owners: dict[str, list[str]] = {}
    for server, tools in per_server.items():
        for tool in tools:
            owners.setdefault(tool.name, []).append(server)
    return [
        CatalogueFinding(
            "shadowed_tool",
            name,
            f"exposed by {len(servers)} servers; refusing to guess which is authoritative",
            tuple(sorted(servers)),
        )
        for name, servers in sorted(owners.items())
        if len(servers) > 1
    ]


# --- tool poisoning -----------------------------------------------------------


def describe_tool_surface(tool: mcp_types.Tool) -> str:
    """The text a model actually reads for a tool (description + schema text).

    Injection can hide in the input schema's own descriptions, not just the
    top-level one, so both are scanned.
    """
    parts = [tool.description or ""]
    if tool.inputSchema:
        parts.append(json.dumps(tool.inputSchema, sort_keys=True))
    return "\n".join(p for p in parts if p)


async def scan_descriptions(
    tools: Sequence[mcp_types.Tool], shield: object
) -> list[CatalogueFinding]:
    """Scan each tool's readable surface with the Layer-1 shield.

    ``shield`` is anything exposing ``inspect_document(text) -> verdict`` (our
    :class:`~sentinel.shield.InputShield`). Layer 1 is fallible by design — this
    is detection/telemetry for the catalogue, exactly as it is for tool results.
    """
    findings: list[CatalogueFinding] = []
    for tool in tools:
        surface = describe_tool_surface(tool)
        if not surface:
            continue
        verdict = await shield.inspect_document(surface)  # type: ignore[attr-defined]
        if verdict.attack_detected:
            findings.append(
                CatalogueFinding(
                    "poisoned_description",
                    tool.name,
                    f"injection markers in tool definition ({verdict.detail})",
                )
            )
    return findings


# --- the composed check -------------------------------------------------------


async def verify_catalogue(
    per_server: Mapping[str, Sequence[mcp_types.Tool]],
    *,
    shield: object | None = None,
    pinned: Mapping[str, str] | None = None,
    strict: bool = True,
) -> list[CatalogueFinding]:
    """Run every catalogue check and return the findings.

    ``strict=True`` (the default, and the right default for a security proxy)
    raises :class:`CatalogueIntegrityError` when anything is found, so a poisoned
    or shadowed catalogue refuses to boot rather than being served to an agent.
    ``strict=False`` returns the findings for flag-only / reporting use.
    """
    flat = [tool for tools in per_server.values() for tool in tools]
    findings = detect_shadowing(per_server)
    if pinned is not None:
        findings.extend(detect_drift(pinned, flat))
    if shield is not None:
        findings.extend(await scan_descriptions(flat, shield))
    if strict and findings:
        raise CatalogueIntegrityError(
            "downstream tool catalogue failed integrity checks:\n  "
            + "\n  ".join(str(f) for f in findings)
        )
    return findings
