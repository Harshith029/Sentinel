"""Thin MCP interception skeleton (BUILD_SPEC Phase 1, last step).

Spec: "a no-op proxy that forwards a call and emits ``ToolCallProposed`` +
``ToolExecuted`` spans, so Phase 2 provenance is designed against REAL MCP
message shapes, not abstraction."

Topology (interception is TOPOLOGICAL — §1):

    agent client ──MCP──▶ Whence proxy server ──MCP──▶ downstream tool server
                          (this module)            (a real ClientSession)

The proxy is a low-level ``mcp.server.lowlevel.Server`` whose two handlers
forward to a downstream ``ClientSession``:

* ``list_tools`` → returns the downstream server's tool list verbatim.
* ``call_tool``  → emits ``ToolCallProposed``, forwards the call downstream,
  emits ``ToolExecuted`` as the proposal's CHILD, then returns the downstream
  ``CallToolResult`` unchanged.

There is NO security logic here yet (no provenance, no authorization) — that is
Phase 2's job. This skeleton exists only to prove the span shapes line up with
the wire protocol. Result content is labelled ``RETRIEVED_CONTENT`` because tool
output is external, least-trusted data (§4.1) — the one piece of provenance
truth the skeleton already encodes so Phase 2 builds on a correct seed.
"""
from __future__ import annotations

from typing import Final

import mcp.types as mcp_types
from mcp.client.session import ClientSession
from mcp.server.fastmcp import FastMCP
from mcp.server.lowlevel import Server

from whence.forensics.emitter import SpanEmitter
from whence.forensics.events import ToolCallProposed, ToolExecuted
from whence.forensics.span import Span
from whence.labels import RETRIEVED_CONTENT
from whence.mcp_proxy.content import summarize_result

PROXY_SERVER_NAME: Final[str] = "whence"


def make_downstream_server(name: str = "downstream") -> FastMCP:
    """A trivial real MCP tool server with one ``noop_echo`` tool, for tests/demo.

    Returned as a :class:`FastMCP`; the in-memory transport helper accepts it
    directly. ``noop_echo`` just returns its input so a round-trip is verifiable.
    """
    server = FastMCP(name)

    @server.tool()
    def noop_echo(message: str) -> str:
        """Echo the message back unchanged (a no-op tool for skeleton tests)."""
        return f"echo: {message}"

    return server


class WhenceProxySkeleton:
    """A no-op interception proxy: forwards MCP calls and emits forensic spans.

    Construct with a connected downstream ``ClientSession``, a
    :class:`SpanEmitter`, and the ``trace_id`` for this agent task. Expose
    :attr:`server` to the agent via any MCP transport. ``session_parent_span_id``
    optionally roots tool proposals under a prior reasoning/input span; left
    ``None``, each proposal is a trace root.
    """

    def __init__(
        self,
        *,
        downstream: ClientSession,
        emitter: SpanEmitter,
        trace_id: str,
        session_parent_span_id: str | None = None,
    ) -> None:
        self._downstream = downstream
        self._emitter = emitter
        self._trace_id = trace_id
        self._session_parent_span_id = session_parent_span_id
        self._server: Server = self._build_server()

    @property
    def server(self) -> Server:
        return self._server

    def _build_server(self) -> Server:
        server: Server = Server(PROXY_SERVER_NAME)

        # mcp's low-level Server decorators are untyped; the handlers themselves
        # are fully typed. Ignore only the third-party-decorator boundary.
        @server.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
        async def _list_tools() -> list[mcp_types.Tool]:
            # Proxy the downstream catalogue verbatim. Phase 4 will restrict this
            # to the explicitly-enumerated allowlist (§6); the skeleton passes through.
            downstream_tools = await self._downstream.list_tools()
            return list(downstream_tools.tools)

        @server.call_tool()  # type: ignore[untyped-decorator]
        async def _call_tool(
            name: str, arguments: dict[str, object]
        ) -> mcp_types.CallToolResult:
            return await self._forward_call(name, arguments)

        return server

    async def _forward_call(
        self, name: str, arguments: dict[str, object]
    ) -> mcp_types.CallToolResult:
        # 1) Record the proposal BEFORE touching the downstream tool.
        proposed: Span = await self._emitter.emit(
            ToolCallProposed(tool_name=name, arguments=dict(arguments)),
            trace_id=self._trace_id,
            parent_span_id=self._session_parent_span_id,
        )

        # 2) Forward across the second MCP hop to the real tool server.
        result = await self._downstream.call_tool(name, arguments)

        # 3) Record execution as a CHILD of the proposal (branching causality).
        #    Tool output is external → RETRIEVED_CONTENT (least-trusted, §4.1).
        await self._emitter.emit(
            ToolExecuted(
                tool_name=name,
                arguments=dict(arguments),
                result_label=RETRIEVED_CONTENT,
                result_summary=summarize_result(result),
            ),
            trace_id=self._trace_id,
            parent_span_id=proposed.span_id,
        )

        # 4) Forward the downstream result back to the agent unchanged.
        return result
