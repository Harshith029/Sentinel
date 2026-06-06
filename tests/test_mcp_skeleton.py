"""Phase 1 DoD: the thin MCP skeleton round-trips a no-op call emitting spans.

Uses the official MCP in-memory transport, nested twice to build the real
two-hop topology:  agent client → SENTINEL proxy server → downstream tool server.
Asserting against real ``Tool`` / ``CallToolResult`` shapes is the whole point —
Phase 2 provenance is then designed against the wire protocol, not a stand-in.
"""
from __future__ import annotations

from mcp.shared.memory import create_connected_server_and_client_session as connect

from sentinel.forensics.emitter import SpanEmitter
from sentinel.forensics.events import ToolCallProposed, ToolExecuted
from sentinel.forensics.replay import replay
from sentinel.forensics.store import InMemoryForensicStore
from sentinel.labels import RETRIEVED_CONTENT
from sentinel.mcp_proxy.skeleton import SentinelProxySkeleton, make_downstream_server


async def test_skeleton_round_trips_and_emits_correctly_shaped_spans() -> None:
    store = InMemoryForensicStore()
    emitter = SpanEmitter(store)
    trace_id = emitter.new_trace_id()

    downstream = make_downstream_server()
    async with connect(downstream) as downstream_client:
        await downstream_client.initialize()
        proxy = SentinelProxySkeleton(
            downstream=downstream_client, emitter=emitter, trace_id=trace_id
        )
        async with connect(proxy.server) as agent_client:
            await agent_client.initialize()

            # The agent sees the downstream tool THROUGH the proxy.
            tools = await agent_client.list_tools()
            assert [t.name for t in tools.tools] == ["noop_echo"]

            # A real MCP call round-trips end-to-end.
            result = await agent_client.call_tool("noop_echo", {"message": "ping"})
            assert result.isError is False
            assert [b.text for b in result.content if b.type == "text"] == ["echo: ping"]

    # Exactly two spans, correctly shaped and parented.
    rep = await replay(store, trace_id)
    assert rep.malformed is False
    assert [s.seq for s in rep.ordered] == [0, 1]

    proposed, executed = rep.ordered
    assert isinstance(proposed.payload, ToolCallProposed)
    assert proposed.payload.tool_name == "noop_echo"
    assert proposed.payload.arguments == {"message": "ping"}
    assert proposed.is_root is True

    assert isinstance(executed.payload, ToolExecuted)
    assert executed.parent_span_id == proposed.span_id  # execution is the proposal's child
    assert executed.payload.tool_name == "noop_echo"
    assert executed.payload.result_label == RETRIEVED_CONTENT  # external output is tainted
    assert "echo: ping" in executed.payload.result_summary

    # The branch view links them.
    assert [c.span_id for c in rep.children_of(proposed.span_id)] == [executed.span_id]


async def test_skeleton_two_calls_emit_two_proposal_execution_pairs() -> None:
    store = InMemoryForensicStore()
    emitter = SpanEmitter(store)
    trace_id = emitter.new_trace_id()

    downstream = make_downstream_server()
    async with connect(downstream) as downstream_client:
        await downstream_client.initialize()
        proxy = SentinelProxySkeleton(
            downstream=downstream_client, emitter=emitter, trace_id=trace_id
        )
        async with connect(proxy.server) as agent_client:
            await agent_client.initialize()
            await agent_client.call_tool("noop_echo", {"message": "one"})
            await agent_client.call_tool("noop_echo", {"message": "two"})

    rep = await replay(store, trace_id)
    assert [s.event_type for s in rep.ordered] == [
        "ToolCallProposed",
        "ToolExecuted",
        "ToolCallProposed",
        "ToolExecuted",
    ]
    assert [s.seq for s in rep.ordered] == [0, 1, 2, 3]
