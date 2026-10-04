"""Provenance as a running union: same answers as the graph walk, linear cost (F11).

Every call derived from every earlier result, and the proxy recomputed each
call's provenance by walking that whole graph, so cost grew with the square of
the session length: measured 1.5 ms per call at call 100, 13 ms at call 400 and
40 ms at call 800, on the single event loop every session shares. The proxy now
keeps the union incrementally.

The equivalence test rebuilds, with :class:`ProvenanceGraph`, exactly the graph
the proxy used to build, and checks the proxy's provenance against the walk for
every call of random sessions, including declassified results.
"""
from __future__ import annotations

import random
import textwrap
import time

import mcp.types as mcp_types

from sentinel.authorization.engine import AuthorizationEngine
from sentinel.authorization.policy import load_policy
from sentinel.forensics.emitter import SpanEmitter
from sentinel.forensics.replay import replay
from sentinel.forensics.store import InMemoryForensicStore
from sentinel.labels import AGENT, USER, Label
from sentinel.mcp_proxy.proxy import SentinelProxy
from sentinel.provenance.graph import ProvenanceGraph
from sentinel.provenance.model import ProvenanceNode
from sentinel.trust.config import load_default_trust_config
from sentinel.trust.scorer import TrustScorer

POLICY = textwrap.dedent(
    """
    policy_version: 1
    tools:
      read_page:
        rules: []
      read_price:
        declassify:
          schema: decimal_amount
        rules: []
      act:
        rules: []
    """
).strip()


class _Downstream:
    def __init__(self, rng: random.Random) -> None:
        self._rng = rng

    async def call_tool(
        self, name: str, arguments: dict[str, object]
    ) -> mcp_types.CallToolResult:
        # read_price sometimes returns a valid decimal (declassified), sometimes not.
        if name == "read_price":
            text = "42.50" if self._rng.random() < 0.5 else "about forty"
        else:
            text = "ok"
        return mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text=text)], isError=False
        )


def _proxy(rng: random.Random) -> tuple[SentinelProxy, InMemoryForensicStore]:
    store = InMemoryForensicStore()
    emitter = SpanEmitter(store)
    proxy = SentinelProxy(
        downstream=_Downstream(rng),  # type: ignore[arg-type]
        emitter=emitter,
        engine=AuthorizationEngine(load_policy(POLICY)),
        scorer=TrustScorer(emitter, load_default_trust_config(), enforce=False),
        agent_id="incremental",
        trace_id=emitter.new_trace_id(),
        authorization_config={},
    )
    return proxy, store


async def test_the_running_union_equals_the_graph_walk() -> None:
    for seed in range(20):
        rng = random.Random(seed)  # noqa: S311 - reproducible sequences, not crypto
        proxy, store = _proxy(rng)
        await proxy.start(user_input="go")
        for _ in range(rng.randint(1, 25)):
            await proxy.handle_call(rng.choice(("read_page", "read_price", "act")), {})

        # Rebuild the graph the proxy used to build, from the forensic record:
        # each proposal derives from the whole frontier; each result from its
        # proposal, or from nothing when declassified.
        rep = await replay(store, proxy.trace_id)
        graph = ProvenanceGraph()
        frontier: list[str] = []
        expected: list[frozenset[Label]] = []
        observed: list[frozenset[Label]] = []
        for span in rep.ordered:
            payload = span.payload
            if span.event_type == "InputReceived":
                graph.add(ProvenanceNode(span_id=span.span_id, label=USER, derived_from=()))
                frontier.append(span.span_id)
            elif span.event_type == "ToolCallProposed":
                graph.add(
                    ProvenanceNode(
                        span_id=span.span_id, label=AGENT, derived_from=tuple(frontier)
                    )
                )
                walk = graph.effective_provenance(span.span_id, include_self=False)
                assert not walk.anomalous
                expected.append(walk.labels)
                proposal = span.span_id
            elif span.event_type == "AuthorizationDecided":
                observed.append(frozenset(payload.effective_provenance))  # type: ignore[attr-defined]
            elif span.event_type == "ToolExecuted":
                declassified = payload.result_label == "SYSTEM"  # type: ignore[attr-defined]
                graph.add(
                    ProvenanceNode(
                        span_id=span.span_id,
                        label=payload.result_label,  # type: ignore[attr-defined]
                        derived_from=() if declassified else (proposal,),
                    )
                )
                frontier.append(span.span_id)
        assert observed == expected, f"seed {seed}: union and walk disagree"


async def test_per_call_cost_does_not_grow_with_the_session() -> None:
    """Ratio, not absolute time, so a slow machine does not fail it.

    Before: the last calls of an 800-call session cost ~25x the first.
    """
    proxy, _ = _proxy(random.Random(0))  # noqa: S311
    await proxy.start(user_input="go")
    timings: list[float] = []
    for _ in range(800):
        started = time.perf_counter()
        await proxy.handle_call("read_page", {})
        timings.append(time.perf_counter() - started)
    early = sorted(timings[50:150])[50]   # medians resist GC and scheduler noise
    late = sorted(timings[-100:])[50]
    assert late < 3 * early, f"call cost grew {late / early:.1f}x over the session"
