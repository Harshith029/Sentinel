"""Whence MCP proxy core (BUILD_SPEC §Phase 4) — interception by topology.

To the agent, :class:`WhenceProxy` presents as an MCP **server**; to the real
tool servers it is an MCP **client**. Every tool the agent can reach is one the
proxy chose to expose, and the ONLY way to invoke it is through
:meth:`WhenceProxy._intercept`. There is no code path from agent to a
downstream tool that skips the pipeline — interception is guaranteed by the wire
topology, not by a convention a caller might forget.

The pipeline, in the exact order §Phase 4 mandates, for every proxied call:

1. emit ``ToolCallProposed`` and record the call's provenance ancestry (a node
   derived from the session's current context frontier);
2. the Authorization Engine decides (Phase 2), emitting ``AuthorizationDecided``;
3. the Trust Scorer updates (Phase 3) — transition telemetry on allowed calls,
   a hard blocked-call penalty on denied ones;
4. if ALLOWED → forward downstream, tag the result's provenance (external tool
   output is ``RETRIEVED_CONTENT``), emit ``ToolExecuted``, return the result;
5. if BLOCKED → return a clean MCP error to the agent and emit ``ToolBlocked``.

This interception bus is entirely SEPARATE from any HTTP/FastAPI layer (Phase 6):
it operates at the MCP message boundary.

Provenance is tracked in an in-memory per-session graph plus a "context
frontier" — the user input node and every tool RESULT the agent has since
observed. A new proposal derives from the frontier, so a ``send_email`` issued
after a ``web_fetch`` computes as tainted through the real §4.2 walk. Because the
graph lives in memory and a per-session lock serializes intercepts, provenance
never depends on store write-ordering — the Phase-2 fail-closed-on-missing-parent
watch item cannot produce a transient false taint here.

The proxy is agent-agnostic by construction: it knows nothing about Foundry,
Claude, or any specific client. Any MCP speaker is secured identically.
"""
from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from typing import Final

import mcp.types as mcp_types
from mcp.server.lowlevel import Server

from whence.authorization.engine import (
    AuthorizationEngine,
    ToolCall,
    to_decision_payload,
)
from whence.forensics.emitter import SpanEmitter
from whence.forensics.events import (
    InjectionScanned,
    InputReceived,
    ToolBlocked,
    ToolCallProposed,
    ToolExecuted,
)
from whence.forensics.span import Span
from whence.labels import AGENT, RETRIEVED_CONTENT, USER, Label
from whence.mcp_proxy.content import mcp_error, result_text, summarize_result
from whence.mcp_proxy.router import DownstreamConnection
from whence.observability import log_allowed, log_blocked, log_injection_flagged
from whence.provenance.graph import ProvenanceGraph
from whence.provenance.model import ProvenanceNode
from whence.provenance.sanitizer import StructuredExtractor, get_schema
from whence.shield import InputShield
from whence.trust.scorer import TrustScorer

PROXY_SERVER_NAME: Final[str] = "whence"


def default_normalize(arguments: Mapping[str, object]) -> dict[str, object]:
    """Normalize raw MCP arguments into the engine's evaluation namespace.

    Adds typed/derived fields the policy references (e.g. ``recipient_domain``
    from an email ``to``/``recipient``). Conservative and tiny by design — the
    engine consumes a normalized :class:`ToolCall`, per §2B.
    """
    namespace = dict(arguments)
    recipient = namespace.get("to") or namespace.get("recipient")
    if isinstance(recipient, str) and "@" in recipient:
        namespace["recipient_domain"] = recipient.rsplit("@", 1)[-1]
    return namespace


class WhenceProxy:
    """A stateful, per-session MCP interception proxy.

    One instance == one agent task == one trace. Construct it, call
    :meth:`start` to seed the user input, expose :attr:`server` to the agent via
    any MCP transport, and connect its tool-facing :class:`ClientSession`
    (``downstream``) to the real tool servers.
    """

    def __init__(
        self,
        *,
        downstream: DownstreamConnection,
        emitter: SpanEmitter,
        engine: AuthorizationEngine,
        scorer: TrustScorer,
        agent_id: str,
        trace_id: str,
        authorization_config: Mapping[str, object] | None = None,
        result_labels: Mapping[str, Label] | None = None,
        default_result_label: Label = RETRIEVED_CONTENT,
        input_shield: InputShield | None = None,
        tool_schema_cache: Sequence[mcp_types.Tool] | None = None,
    ) -> None:
        self._downstream = downstream
        self._emitter = emitter
        self._engine = engine
        # Policy decides WHETHER a tool may declassify; this performs it.
        self._sanitizer = StructuredExtractor()
        self._scorer = scorer
        self._agent_id = agent_id
        self._trace_id = trace_id
        self._authz_config = dict(authorization_config or {})
        self._result_labels = dict(result_labels or {})
        # External tool output is least-trusted by default (§4.1).
        self._default_result_label = default_result_label
        # Optional Layer-1 shield (§5): flags injection in prompts/results.
        self._input_shield = input_shield
        # Optional preflighted tool schemas: serve list_tools from this cache so a
        # mid-demo downstream hiccup cannot break tool discovery (§Phase 5).
        self._tool_schema_cache = list(tool_schema_cache) if tool_schema_cache else None

        self._graph = ProvenanceGraph()
        self._frontier: list[str] = []  # span_ids the agent has observed
        self._root_span_id: str | None = None
        # Serializes intercepts so the provenance graph/frontier mutate as a
        # consistent causal chain (and the watch-item ordering issue can't arise).
        self._lock = asyncio.Lock()
        self._server: Server = self._build_server()

    @property
    def server(self) -> Server:
        return self._server

    @property
    def trace_id(self) -> str:
        return self._trace_id

    async def start(self, *, user_input: str, origin_label: Label = USER) -> Span:
        """Seed the session with the user's input as the trace root + provenance.

        The returned ``InputReceived`` span is the trace root and the first
        provenance node (label ``USER`` by default); the context frontier starts
        as just this node.
        """
        span = await self._emitter.emit(
            InputReceived(origin_label=origin_label, content=user_input),
            trace_id=self._trace_id,
        )
        self._root_span_id = span.span_id
        self._graph.add(
            ProvenanceNode(span_id=span.span_id, label=origin_label, derived_from=())
        )
        self._frontier.append(span.span_id)

        # Layer-1 scan of the user prompt itself (§5), recorded for forensics.
        if self._input_shield is not None:
            verdict = await self._input_shield.inspect_user_prompt(user_input)
            await self._emitter.emit(
                InjectionScanned(
                    target="user_prompt",
                    attack_detected=verdict.attack_detected,
                    shield=verdict.shield,
                    detail=verdict.detail,
                ),
                trace_id=self._trace_id,
                parent_span_id=span.span_id,
            )
        return span

    def _build_server(self) -> Server:
        server: Server = Server(PROXY_SERVER_NAME)

        @server.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
        async def _list_tools() -> list[mcp_types.Tool]:
            # Serve preflighted schemas if cached (resilient to downstream
            # hiccups); otherwise proxy the live downstream catalogue. Either way
            # every entry is still gated by the call_tool pipeline below.
            if self._tool_schema_cache is not None:
                return list(self._tool_schema_cache)
            downstream_tools = await self._downstream.list_tools()
            return list(downstream_tools.tools)

        @server.call_tool()  # type: ignore[untyped-decorator]
        async def _call_tool(
            name: str, arguments: dict[str, object]
        ) -> mcp_types.CallToolResult:
            return await self._intercept(name, arguments)

        return server

    async def handle_call(
        self, name: str, arguments: Mapping[str, object]
    ) -> mcp_types.CallToolResult:
        """Public entry for one proxied tool call — the exact same pipeline as
        :attr:`server`'s ``call_tool`` handler.

        The in-memory demo exposes :attr:`server` and lets the SDK invoke
        ``_intercept`` for it. The over-the-wire gateway (Phase 9) instead drives
        many sessions through ONE front Server and calls this method, so the
        provenance / authorization / trust / forensic path is byte-for-byte
        identical whether the agent connects in-process or over real HTTP. There
        is still exactly one interception path; this is just a named door to it.
        """
        return await self._intercept(name, arguments)

    async def _intercept(
        self, name: str, arguments: Mapping[str, object]
    ) -> mcp_types.CallToolResult:
        """THE single path from agent to tool. Nothing reaches downstream but here."""
        async with self._lock:
            # 0. Containment: a quarantined agent's calls are refused up front,
            #    and the refusal stays VISIBLE (Phase 3).
            if self._scorer.is_quarantined(self._agent_id):
                await self._scorer.record_quarantined_block(
                    self._agent_id, name, trace_id=self._trace_id,
                    parent_span_id=self._root_span_id,
                )
                log_blocked(
                    name, reason="agent quarantined", rule="quarantine",
                    trace_id=self._trace_id, agent_id=self._agent_id, provenance=(),
                )
                return mcp_error(
                    f"Whence: agent {self._agent_id!r} is quarantined; "
                    f"tool {name!r} refused"
                )

            # 1. Record the proposal and its provenance ancestry. The proposal
            #    node derives from the whole context frontier (user input + every
            #    result observed so far), so taint propagates by lineage.
            proposed = await self._emitter.emit(
                ToolCallProposed(tool_name=name, arguments=dict(arguments)),
                trace_id=self._trace_id,
                parent_span_id=self._root_span_id,
            )
            self._graph.add(
                ProvenanceNode(
                    span_id=proposed.span_id,
                    label=AGENT,
                    derived_from=tuple(self._frontier),
                )
            )
            lineage = self._graph.effective_provenance(proposed.span_id)
            if lineage.anomalous:
                # A cycle or a dangling ancestor means the traversal did not
                # complete, so this call's provenance is UNKNOWN — not clean.
                # ProvenanceGraph.is_tainted is fail-closed for exactly this
                # reason, but the enforcement path reached past it to `.labels`
                # and the engine then derived taint as `RETRIEVED_CONTENT in
                # provenance`. A broken lineage whose surviving labels happened
                # to omit that flag therefore authorized as untrusted-free.
                #
                # We refuse before consulting policy: an anomaly means the state
                # policy would reason over is itself corrupt, so evaluating rules
                # against it would launder "unknown" into "allowed". This is a
                # deterministic deny, not a policy decision.
                reason = (
                    "provenance graph anomaly: lineage could not be computed "
                    f"(malformed={lineage.malformed}, missing={len(lineage.missing)})"
                )
                await self._emitter.emit(
                    ToolBlocked(
                        tool_name=name,
                        reason=reason,
                        blocked_by="provenance",
                        matched_rule_id=None,
                    ),
                    trace_id=self._trace_id,
                    parent_span_id=proposed.span_id,
                )
                log_blocked(
                    name, reason=reason, rule=None,
                    trace_id=self._trace_id, agent_id=self._agent_id,
                    provenance=tuple(sorted(lineage.labels)),
                )
                return mcp_error(f"Whence blocked {name!r}: {reason}")
            provenance = lineage.labels

            # 2. Authorize (Phase 2) and record the full decision trace.
            call = ToolCall(
                name=name,
                arguments=default_normalize(arguments),
                provenance=provenance,
                config=self._authz_config,
            )
            decision = self._engine.authorize(call)
            await self._emitter.emit(
                to_decision_payload(name, self._engine.policy_version, decision),
                trace_id=self._trace_id,
                parent_span_id=proposed.span_id,
            )

            # 3 + 5. Blocked: hard-signal trust penalty, ToolBlocked, clean error.
            if not decision.allowed:
                await self._scorer.record_blocked_call(
                    self._agent_id, name, reason=decision.reason,
                    trace_id=self._trace_id, parent_span_id=proposed.span_id,
                )
                await self._emitter.emit(
                    ToolBlocked(
                        tool_name=name,
                        reason=decision.reason,
                        blocked_by="authorization",
                        matched_rule_id=decision.matched_rule_id,
                    ),
                    trace_id=self._trace_id,
                    parent_span_id=proposed.span_id,
                )
                log_blocked(
                    name, reason=decision.reason,
                    rule=decision.matched_rule_id,
                    trace_id=self._trace_id, agent_id=self._agent_id,
                    provenance=decision.effective_provenance,
                )
                return mcp_error(f"Whence blocked {name!r}: {decision.reason}")

            # 3. Allowed: transition telemetry feeds the anomaly model.
            await self._scorer.record_tool_transition(
                self._agent_id, name, trace_id=self._trace_id,
                parent_span_id=proposed.span_id,
            )

            # 4. Forward across the second MCP hop and tag the RESULT's provenance.
            log_allowed(
                name, trace_id=self._trace_id, agent_id=self._agent_id,
                provenance=decision.effective_provenance,
            )
            result = await self._downstream.call_tool(name, dict(arguments))
            label = self._result_labels.get(name, self._default_result_label)

            # 4b. DECLASSIFICATION (§4.4), the only way taint ever clears.
            #
            # Opt-in per tool, declared in POLICY rather than decided here: the
            # same document that says what a tool may do says whether its output
            # may cross the trust boundary, and for which schema. Without this
            # the taint model has no escape hatch — every lineage that ever
            # touched retrieved content stays tainted forever, so operators must
            # either permit tainted actions outright or watch the workflow stop.
            #
            # Fail-closed in both directions: a tool with no declared schema can
            # never clear taint, and a declared schema that does not MATCH leaves
            # the result exactly as tainted as it was.
            cleared_from: str | None = None
            schema_name = self._engine.declassifier_for(name)
            if schema_name is not None:
                source = ProvenanceNode(
                    span_id=proposed.span_id, label=label, derived_from=()
                )
                sanitized = self._sanitizer.sanitize(
                    source, get_schema(schema_name), content=result_text(result)
                )
                if sanitized is not None:
                    label = self._sanitizer.output_label
                    cleared_from = proposed.span_id

            executed = await self._emitter.emit(
                ToolExecuted(
                    tool_name=name,
                    arguments=dict(arguments),
                    # Records the OUTCOME: an operator reading the trail sees
                    # SYSTEM here exactly when a value was declassified.
                    result_label=label,
                    result_summary=summarize_result(result),
                ),
                trace_id=self._trace_id,
                parent_span_id=proposed.span_id,
            )
            # The result becomes part of what the agent has observed: add it to
            # the graph and the frontier so future calls derive from it. A
            # declassified value starts FRESH — derived_from is empty, so the
            # walk never reaches its tainted origin, and cleared_from records
            # that origin for audit without making it an ancestor.
            self._graph.add(
                ProvenanceNode(
                    span_id=executed.span_id,
                    label=label,
                    derived_from=() if cleared_from else (proposed.span_id,),
                    cleared_from=cleared_from,
                )
            )
            self._frontier.append(executed.span_id)

            # Layer-1 scan of the RETRIEVED content (§5). Flag-only: it records an
            # InjectionScanned span and feeds the trust scorer a hard signal, but
            # does NOT block — Authorization is the backstop that actually stops
            # the exfiltration even when this shield is evaded.
            if self._input_shield is not None:
                verdict = await self._input_shield.inspect_document(result_text(result))
                await self._emitter.emit(
                    InjectionScanned(
                        target=f"tool_result:{name}",
                        attack_detected=verdict.attack_detected,
                        shield=verdict.shield,
                        detail=verdict.detail,
                    ),
                    trace_id=self._trace_id,
                    parent_span_id=executed.span_id,
                )
                if verdict.attack_detected:
                    log_injection_flagged(
                        f"tool_result:{name}", trace_id=self._trace_id,
                        shield=verdict.shield,
                    )
                    await self._scorer.record_injection(
                        self._agent_id,
                        target=f"tool_result:{name}",
                        trace_id=self._trace_id,
                        parent_span_id=executed.span_id,
                    )
            return result
