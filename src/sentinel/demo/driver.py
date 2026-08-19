"""Agent drivers (BUILD_SPEC §Phase 5).

The driver is the ONLY thing that changes between DEMO MODE and real-cloud mode.
It is the component that PROPOSES tool calls; everything downstream of the call
(provenance, authorization, trust, forensics) is the one production pipeline.

* :class:`ScriptedAgentDriver` — a deterministic transcript that GUARANTEES the
  forbidden tool call is proposed, so SENTINEL deterministically acts. This is
  honest: it demonstrates the SECURITY LAYER, not an LLM's susceptibility.
* :class:`CallbackAgentDriver` — an arbitrary async routine, used to PROVE the
  pipeline is driver-independent (two different drivers, identical security).

A live Foundry driver (real-cloud mode) is just another implementation of the
:class:`AgentDriver` protocol; it plugs into the same orchestrator unchanged
once the HTTP/SSE endpoint exists (Phase 6).
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

import mcp.types as mcp_types
from mcp.client.session import ClientSession


@dataclass(frozen=True)
class ToolInvocation:
    """A single proposed tool call."""

    tool: str
    arguments: dict[str, object]


# A transcript step is either a fixed invocation or one computed from the results
# observed so far (so e.g. an exfil body can include a previously fetched record),
# while staying fully deterministic.
StepFactory = Callable[[list[mcp_types.CallToolResult]], ToolInvocation]
Step = ToolInvocation | StepFactory


@runtime_checkable
class AgentDriver(Protocol):
    """Whatever proposes tool calls to SENTINEL over an MCP client session."""

    name: str

    async def run(self, client: ClientSession) -> list[mcp_types.CallToolResult]: ...


class ScriptedAgentDriver:
    """Issues a fixed, deterministic transcript of tool calls."""

    name = "scripted"

    def __init__(self, steps: Sequence[Step]) -> None:
        self._steps = list(steps)

    async def run(self, client: ClientSession) -> list[mcp_types.CallToolResult]:
        results: list[mcp_types.CallToolResult] = []
        for step in self._steps:
            invocation = step(results) if callable(step) else step
            results.append(await client.call_tool(invocation.tool, invocation.arguments))
        return results


class CallbackAgentDriver:
    """Runs an arbitrary async routine against the client (for equivalence proofs)."""

    name = "callback"

    def __init__(
        self,
        routine: Callable[[ClientSession], Awaitable[list[mcp_types.CallToolResult]]],
    ) -> None:
        self._routine = routine

    async def run(self, client: ClientSession) -> list[mcp_types.CallToolResult]:
        return await self._routine(client)


class _DirectAgentClient:
    """A minimal duck-typed stand-in for ``ClientSession`` that bypasses the proxy.

    The "without SENTINEL" baseline runs the same scripted driver against the
    same downstream tool servers, but routes every ``call_tool`` directly to
    the :class:`~sentinel.mcp_proxy.router.DownstreamConnection`. No spans are
    emitted — there is no SENTINEL in this path, which IS the point: a viewer
    can see that the exfiltration succeeds when nothing intercepts it.

    Not part of the public API; the scenario orchestrator constructs it.
    """

    def __init__(self, downstream: Any) -> None:  # noqa: ANN401 - duck-typed
        # Any DownstreamConnection-shaped object (ToolRouter or a single
        # ClientSession) — duck-typed because a ClientSession is not declared
        # as a DownstreamConnection in the mcp SDK.
        self._downstream = downstream

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> mcp_types.CallToolResult:
        result = await self._downstream.call_tool(name, arguments or {})
        # The downstream is duck-typed Any; narrow at the boundary so callers
        # see the concrete CallToolResult mypy expects.
        assert isinstance(result, mcp_types.CallToolResult)
        return result
