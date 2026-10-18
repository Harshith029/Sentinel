"""Tool-catalogue integrity — defending the *catalogue*, not just tool results.

SENTINEL's provenance engine treats every tool RESULT as untrusted. But an MCP
agent also reads the tool **catalogue** — each tool's name, description and input
schema — and a model follows instructions it finds there. That makes the catalogue
itself an attack surface, and it is one SENTINEL is uniquely placed to defend:
the proxy is the only component that sees every downstream server's catalogue.

Three documented attack classes are covered here:

* **Tool poisoning** — malicious instructions hidden in a tool's definition (the
  model reads ``tools/list`` and obeys). We scan every agent-visible field
  (description, title, annotations, schemas, metadata) through the same Layer-1
  shield used for tool results and report findings; the caller decides whether
  to refuse or merely flag (see :func:`verify_catalogue`).
* **Cross-server shadowing** — a malicious server exposes a tool with the SAME
  NAME as a trusted server's tool, hoping the router silently routes to it.
  :func:`detect_shadowing` makes the collision explicit instead.
* **Rug pull** — a server serves a benign catalogue at approval time, then serves
  a changed definition afterwards. :func:`fingerprint_tool` / :func:`detect_drift`
  pin the approved catalogue and detect a later divergence when the catalogue is
  re-listed (on ``tools/list`` and on a schedule). SENTINEL does not subscribe to
  ``notifications/tools/list_changed``.

Design notes:

* This module is **pure and side-effect free** apart from the optional shield
  call, so it is trivially testable and reusable by any connect path.
* It emits no forensic events. Findings are reported through ``GET /downstream``
  and the logs, and the integrity failures are connect-time errors that fail
  CLOSED — matching how preflight already refuses to start on an unhealthy
  downstream.
* Shadowing is reported for *any* duplicate name, without guessing which server
  is malicious. Naming the winner is a policy decision for the operator, not an
  inference for us to make.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

import mcp.types as mcp_types

FindingKind = Literal["poisoned_description", "shadowed_tool", "schema_drift"]


class CatalogueIntegrityError(RuntimeError):
    """Raised when a catalogue fails a check the caller treats as fatal."""


class CatalogueCollisionError(CatalogueIntegrityError):
    """A live downstream listed tool names that collide across servers."""

    def __init__(self, collisions: Mapping[str, int]) -> None:
        self.collisions = dict(collisions)
        super().__init__(
            "downstream tool-name collision (possible cross-server shadowing): "
            + ", ".join(
                f"{name!r} exposed by {count} servers"
                for name, count in sorted(self.collisions.items())
            )
            + " — refusing to guess which server is authoritative"
        )


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

    Covers the complete MCP tool definition, including title, annotations,
    output schema, icons, metadata, and execution hints. A rug pull that rewrites
    any agent-visible part of a definition must be caught, not only a description
    or input schema. The payload is serialized canonically so equivalent
    definitions hash equally.
    """
    payload = json.dumps(
        _tool_surface_payload(tool),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


_FINGERPRINT_HEX_LENGTH = 64


def parse_approvals(raw: str | None) -> dict[str, str]:
    """``{tool_name: fingerprint}`` from ``SENTINEL_CATALOGUE_APPROVALS`` (JSON).

    An approval says an operator reviewed one tool's EXACT definition and
    accepts it despite scanner findings. Malformed input is an error, not an
    empty map: silently dropping approvals would refuse a catalogue the
    operator believes approved, and a typo'd fingerprint must not look valid.
    """
    if not raw or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"SENTINEL_CATALOGUE_APPROVALS is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("SENTINEL_CATALOGUE_APPROVALS must be an object of tool -> fingerprint")
    approvals: dict[str, str] = {}
    for name, fingerprint in parsed.items():
        value = str(fingerprint).strip().lower()
        if len(value) != _FINGERPRINT_HEX_LENGTH or any(c not in "0123456789abcdef" for c in value):
            raise ValueError(
                f"SENTINEL_CATALOGUE_APPROVALS: {name!r} needs a 64-character hex "
                "fingerprint, as printed by `sentinel check`"
            )
        approvals[str(name)] = value
    return approvals


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
                CatalogueFinding("schema_drift", name, "tool disappeared after approval")
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
        findings.append(CatalogueFinding("schema_drift", name, "tool appeared after approval"))
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


def _tool_surface_payload(tool: mcp_types.Tool) -> dict[str, object]:
    """Return the complete serializable MCP definition presented to a client.

    ``Tool`` is a Pydantic model and its JSON-mode dump includes future
    protocol-defined fields and accepted extension fields as well as the current
    title/annotations/output-schema fields. Keeping one payload source prevents
    the scanner and rug-pull fingerprint from drifting apart.
    """
    return tool.model_dump(mode="json", by_alias=True, exclude_none=True)


def describe_tool_surface(tool: mcp_types.Tool) -> str:
    """The complete text a model could read from a tool definition.

    Injection can hide in a title, annotation, output schema, icon URL, metadata,
    or schema description. Preserve Unicode characters rather than escaping them
    to make the shield inspect exactly the textual surface the agent sees.
    """
    return json.dumps(
        _tool_surface_payload(tool), sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )


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


# --- continuous re-verification (the rug-pull loop) ---------------------------


@dataclass
class CatalogueMonitor:
    """Re-checks a live catalogue against the one pinned at approval time.

    Pinning at connect stops an agent ever *reading* a rug-pulled description
    (the proxy serves the approved cache), but it does not tell anyone the
    downstream **lied**. This closes that loop: re-fetch, compare, and report.

    Resilience matters more than eagerness here. A downstream hiccup must not
    break tool discovery — that is why the catalogue is cached in the first place
    — so a failed re-fetch is recorded as ``last_error`` and the caller keeps
    serving the pinned catalogue. Only a *successful* fetch that DIFFERS is drift.
    """

    pinned: Mapping[str, str]
    findings: tuple[CatalogueFinding, ...] = ()
    checks: int = 0
    last_error: str | None = None
    # Every tool a successful re-fetch has ever shown diverging from its pin.
    # The call path refuses these (see SentinelGateway), so the set only grows:
    # reverting a definition does not re-approve it.
    drifted_tools: set[str] = field(default_factory=set)

    @property
    def drifted(self) -> bool:
        """True once a successful re-fetch has diverged from the approved pin."""
        return bool(self.findings)

    async def check(self, downstream: object) -> tuple[CatalogueFinding, ...]:
        """Re-fetch ``downstream``'s catalogue and diff it against the pin.

        ``downstream`` is anything with ``list_tools()`` (the proxy's router).
        Findings are sticky AND cumulative: once drift is observed it stays
        reported, because a server that mutates its catalogue and reverts has
        still misbehaved, and a second mutation does not erase the first.
        """
        self.checks += 1
        try:
            listed = await downstream.list_tools()  # type: ignore[attr-defined]
        except CatalogueCollisionError as exc:
            # ``ToolRouter`` correctly refuses a dynamic duplicate name. Treat
            # that as catalogue drift, not a transient transport error, so it
            # remains visible and its previously approved route is blocked.
            self.last_error = None
            found = [
                CatalogueFinding(
                    "shadowed_tool",
                    name,
                    "tool-name collision appeared after approval (possible cross-server shadowing)",
                )
                for name in sorted(exc.collisions)
            ]
            self.findings = tuple(dict.fromkeys((*self.findings, *found)))
            self.drifted_tools.update(exc.collisions)
            return self.findings
        except Exception as exc:  # noqa: BLE001 - transport failure is not drift
            self.last_error = f"{type(exc).__name__}: {exc}"
            return self.findings
        self.last_error = None
        found = detect_drift(self.pinned, list(listed.tools))
        if found:
            self.findings = tuple(dict.fromkeys((*self.findings, *found)))
            self.drifted_tools.update(f.tool_name for f in found)
        return self.findings

    def status(self) -> dict[str, object]:
        """Operator-facing summary (rendered by the dashboard)."""
        return {
            "checks": self.checks,
            "drifted": self.drifted,
            "last_error": self.last_error,
            "findings": [str(f) for f in self.findings],
            "drifted_tools": sorted(self.drifted_tools),
        }


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
