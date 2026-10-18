"""SENTINEL MCP proxy core (BUILD_SPEC §Phase 4) — interception by topology.

To the agent, :class:`SentinelProxy` presents as an MCP **server**; to the real
tool servers it is an MCP **client**. Every tool the agent can reach is one the
proxy chose to expose, and the ONLY way to invoke it is through
:meth:`SentinelProxy._intercept`. There is no code path from agent to a
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

Provenance is tracked per session as the union of trust labels over everything
the agent has observed: the user input and every tool RESULT since. A new
proposal derives from all of it, so a ``send_email`` issued after a
``web_fetch`` is tainted. The union is kept incrementally (one set operation per
call) and gives the same answer as the §4.2 graph walk over the same lineage;
see :mod:`sentinel.provenance.graph` for that model. Because it lives in memory
and a per-session lock serializes intercepts, provenance never depends on store
write-ordering.

The proxy is agent-agnostic by construction: it knows nothing about Foundry,
Claude, or any specific client. Any MCP speaker is secured identically.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable, Mapping, Sequence
from email.utils import getaddresses
from typing import Final
from urllib.parse import urlsplit

import mcp.types as mcp_types
from mcp.server.lowlevel import Server

from sentinel.authorization.engine import (
    DERIVED_FIELDS,
    AuthorizationEngine,
    ToolCall,
    to_decision_payload,
)
from sentinel.config import get_settings
from sentinel.forensics.emitter import SpanEmitter
from sentinel.forensics.events import (
    InjectionScanned,
    InputReceived,
    ToolBlocked,
    ToolCallProposed,
    ToolExecuted,
)
from sentinel.forensics.span import Span
from sentinel.labels import AGENT, RETRIEVED_CONTENT, USER, Label
from sentinel.mcp_proxy.content import mcp_error, result_text, summarize_result
from sentinel.mcp_proxy.router import DownstreamConnection
from sentinel.observability import log_allowed, log_blocked, log_injection_flagged
from sentinel.provenance.model import ProvenanceNode
from sentinel.provenance.sanitizer import StructuredExtractor, get_schema
from sentinel.shield import InputShield
from sentinel.shield.input_shield import ShieldVerdict
from sentinel.trust.scorer import TrustScorer

PROXY_SERVER_NAME: Final[str] = "sentinel"
_LOG: Final[logging.Logger] = logging.getLogger("sentinel.mcp_proxy.proxy")


# Every argument that can name a message recipient. All of them are parsed:
# checking only `to` let `cc`/`bcc` carry data anywhere.
_ADDRESS_FIELDS: Final[tuple[str, ...]] = ("to", "cc", "bcc", "recipient", "recipients")
# Values no operator allowlist will contain, so `recipient_domain not in
# allowed_domains` denies. Used when one domain cannot honestly be named.
_MULTIPLE_DOMAINS: Final[str] = "<multiple-domains>"
_UNPARSEABLE_ADDRESS: Final[str] = "<unparseable-address>"
_UNPARSEABLE_URL: Final[str] = "<unparseable-url>"


def _recipient_domains(value: object) -> list[str] | None:
    """Every recipient domain in one address field, or ``None`` if any is unparseable.

    Handles a single string, a comma-separated string and a list, and takes the
    domain from the parsed ADDRESS, so a display name such as
    ``"cfo@corp.example" <x@evil.test>`` yields ``evil.test``.
    """
    items = value if isinstance(value, (list, tuple)) else [value]
    domains: list[str] = []
    for item in items:
        if not isinstance(item, str):
            return None
        # A control character has no place in an address, and it is where a
        # downstream mail tool and this parser can disagree: the raw value is
        # what gets forwarded, so "cfo@corp.example" + CRLF + "Bcc: ..." passed an
        # allowlist here and could add headers there.
        if any(ord(char) < 32 or ord(char) == 127 for char in item):
            return None
        for _name, address in getaddresses([item]):
            if "@" not in address:
                return None
            domain = address.rsplit("@", 1)[1].strip().rstrip(".").lower()
            if not domain:
                return None
            domains.append(domain)
    return domains


def _url_host(value: object) -> str:
    """Return the canonical HTTP(S) host, or a value no allowlist can contain."""
    if not isinstance(value, str):
        return _UNPARSEABLE_URL
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
    except ValueError:
        return _UNPARSEABLE_URL
    if parsed.scheme.lower() not in {"http", "https"} or not host:
        return _UNPARSEABLE_URL
    return host.rstrip(".").lower()


def default_normalize(arguments: Mapping[str, object]) -> dict[str, object]:
    """Normalize raw MCP arguments into the engine's evaluation namespace.

    Adds the derived fields policy references: ``recipient_domain`` (the one
    domain every recipient shares), ``recipient_domains`` (all of them), and
    ``url_host`` (the canonical HTTP(S) host of a URL tool argument).

    It used to take everything after the last ``@`` of ``to`` alone, so
    ``"attacker@evil.test,cfo@corp.example"`` normalized to ``corp.example``
    and was delivered; ``cc``/``bcc`` were never looked at; and with a list
    ``to``, a ``recipient_domain`` the AGENT supplied was used as-is. Now every
    address field is parsed, derived fields are always SENTINEL's own, and a
    recipient set that does not resolve to a single parseable domain gets a
    value no allowlist contains, so an allowlist rule denies it.
    """
    namespace = dict(arguments)
    for field in DERIVED_FIELDS:
        namespace.pop(field, None)
    if "url" in namespace:
        namespace["url_host"] = _url_host(namespace["url"])
    fields = [
        namespace[name] for name in _ADDRESS_FIELDS if namespace.get(name) not in (None, "", [], ())
    ]
    if not fields:
        return namespace
    domains: list[str] = []
    for value in fields:
        parsed = _recipient_domains(value)
        if parsed is None:
            namespace["recipient_domain"] = _UNPARSEABLE_ADDRESS
            namespace["recipient_domains"] = [_UNPARSEABLE_ADDRESS]
            return namespace
        domains.extend(parsed)
    distinct = sorted(set(domains))
    namespace["recipient_domains"] = distinct
    namespace["recipient_domain"] = distinct[0] if len(distinct) == 1 else _MULTIPLE_DOMAINS
    return namespace


def _only_text(result: mcp_types.CallToolResult) -> bool:
    """Whether a result is nothing but text, so a schema check sees all of it.

    Declassification validates ``result_text``, which reads only text blocks.
    An image, an embedded resource, or ``structuredContent`` would reach the
    agent unexamined, so a result carrying any of them is never declassified.
    An error result is not a value either.
    """
    return (
        not result.isError
        and result.structuredContent is None
        and all(isinstance(block, mcp_types.TextContent) for block in result.content)
    )


def _result_size(result: mcp_types.CallToolResult) -> int:
    """Bytes of payload in a tool result, across every content block type.

    Text alone is not enough: image and audio blocks carry base64 ``data`` and
    embedded resources carry ``text`` or ``blob``, any of which can be large.
    """
    total = 0
    if result.structuredContent is not None:
        # Forwarded to the agent like the content blocks, so it counts too; it
        # used to be outside the cap entirely.
        total += len(json.dumps(result.structuredContent, default=str).encode("utf-8", "replace"))
    for block in result.content:
        for field in ("text", "data"):
            value = getattr(block, field, None)
            if isinstance(value, str):
                total += len(value.encode("utf-8", "replace"))
        resource = getattr(block, "resource", None)
        for field in ("text", "blob"):
            value = getattr(resource, field, None)
            if isinstance(value, str):
                total += len(value.encode("utf-8", "replace"))
    return total


class SentinelProxy:
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
        result_labels: Mapping[str, Label] | None = None,
        default_result_label: Label = RETRIEVED_CONTENT,
        input_shield: InputShield | None = None,
        tool_schema_cache: Sequence[mcp_types.Tool] | None = None,
        max_result_bytes: int | None = None,
        catalogue_gate: Callable[[str], str | None] | None = None,
        tenant: str | None = None,
        engine_provider: Callable[[], AuthorizationEngine] | None = None,
    ) -> None:
        self._downstream = downstream
        self._max_result_bytes = (
            max_result_bytes if max_result_bytes is not None else get_settings().max_result_bytes
        )
        self._emitter = emitter
        self._engine = engine
        # A live MCP session must observe a tenant policy reload on its NEXT
        # call. Demo runs omit this provider and intentionally keep one engine
        # snapshot for their reproducible transcript.
        self._engine_provider = engine_provider
        # Policy decides WHETHER a tool may declassify; this performs it.
        self._sanitizer = StructuredExtractor()
        self._scorer = scorer
        self._agent_id = agent_id
        self._trace_id = trace_id
        self._result_labels = dict(result_labels or {})
        # External tool output is least-trusted by default (§4.1).
        self._default_result_label = default_result_label
        # Optional Layer-1 shield (§5): flags injection in prompts/results.
        self._input_shield = input_shield
        # Optional preflighted tool schemas: serve list_tools from this cache so a
        # mid-demo downstream hiccup cannot break tool discovery (§Phase 5).
        self._tool_schema_cache = list(tool_schema_cache) if tool_schema_cache else None
        # Optional: given a tool name, the reason it may NOT be called because it
        # is outside the approved catalogue, or None. Supplied by the gateway,
        # which owns the pinned catalogue and the drift monitor.
        self._catalogue_gate = catalogue_gate
        # Whose agent this is: trust state is kept per (tenant, agent).
        self._tenant = tenant

        # The union of trust labels over everything the agent has observed in
        # this session. None until start() seeds it: unknown, not clean.
        self._lineage: frozenset[Label] | None = None
        self._root_span_id: str | None = None
        # Serializes intercepts so the lineage changes as a consistent causal
        # chain (and the watch-item ordering issue can't arise).
        self._lock = asyncio.Lock()
        self._server: Server = self._build_server()

    @property
    def server(self) -> Server:
        return self._server

    @property
    def trace_id(self) -> str:
        return self._trace_id

    def _current_engine(self) -> AuthorizationEngine:
        """Return one policy snapshot for the current intercepted call.

        ``engine_provider`` is only used by the long-lived wire-session path.
        Resolving it once per call keeps authorization, audit version and
        declassification decisions internally consistent even if an operator
        reloads policy while a downstream call is in flight.
        """
        return self._engine_provider() if self._engine_provider is not None else self._engine

    async def start(self, *, user_input: str, origin_label: Label = USER) -> Span:
        """Seed the session with the user's input as the trace root + provenance.

        The returned ``InputReceived`` span is the trace root and the first
        provenance node (label ``USER`` by default); the context frontier starts
        as just this node.
        """
        async with self._lock:
            # Once only. A second start() reset the lineage to the origin label
            # alone, clearing whatever taint the session had picked up, and it
            # did so without the lock every tool call takes.
            if self._root_span_id is not None:
                raise RuntimeError("this proxy session has already been started")
            span = await self._emitter.emit(
                InputReceived(origin_label=origin_label, content=user_input),
                trace_id=self._trace_id,
            )
            self._root_span_id = span.span_id
            self._lineage = frozenset({origin_label})

        # Layer-1 scan of the user prompt itself (§5), recorded for forensics.
        if self._input_shield is not None:
            verdict = await self._scan(self._input_shield.inspect_user_prompt, user_input)
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

    async def _scan(
        self, inspect: Callable[[str], Awaitable[ShieldVerdict]], content: str
    ) -> ShieldVerdict:
        """Run one Layer-1 scan; a failing backend is recorded, not raised.

        The scan informs, it does not block. For a tool result the tool has
        already run by now, so an Azure Prompt Shields error used to fail the
        call after its side effect, and withhold a result that is tainted
        either way.
        """
        try:
            return await inspect(content)
        except Exception as exc:  # noqa: BLE001 - an outage must not fail the call
            _LOG.warning("injection scan failed: %s", type(exc).__name__)
            backend = self._input_shield.backend if self._input_shield is not None else "none"
            return ShieldVerdict(
                attack_detected=False,
                shield=backend,
                detail=f"scan failed: {type(exc).__name__}",
                penalize_trust=False,
            )

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
        async def _call_tool(name: str, arguments: dict[str, object]) -> mcp_types.CallToolResult:
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
            if self._scorer.is_quarantined(self._agent_id, tenant=self._tenant):
                await self._scorer.record_quarantined_block(
                    self._agent_id,
                    name,
                    trace_id=self._trace_id,
                    parent_span_id=self._root_span_id,
                    tenant=self._tenant,
                )
                log_blocked(
                    name,
                    reason="agent quarantined",
                    rule="quarantine",
                    trace_id=self._trace_id,
                    agent_id=self._agent_id,
                    provenance=(),
                    tenant=self._tenant,
                )
                return mcp_error(
                    f"SENTINEL: agent {self._agent_id!r} is quarantined; tool {name!r} refused"
                )

            # 1. Record the proposal. It derives from everything the agent has
            #    observed in this session (the user input and every result
            #    since), so its provenance is the session's lineage.
            proposed = await self._emitter.emit(
                ToolCallProposed(tool_name=name, arguments=dict(arguments)),
                trace_id=self._trace_id,
                parent_span_id=self._root_span_id,
            )
            # 1b. Only tools in the APPROVED catalogue may be called. The agent
            #     is only ever shown the pinned catalogue, but nothing stopped
            #     it naming a tool that appeared downstream after approval, or
            #     one whose definition has since changed (a rug pull), and the
            #     router would forward either. Recorded like any other block,
            #     without a trust penalty: calling a tool the agent was shown
            #     is not agent misbehaviour; the downstream's change is.
            refusal = self._catalogue_gate(name) if self._catalogue_gate else None
            if refusal is not None:
                await self._emitter.emit(
                    ToolBlocked(
                        tool_name=name,
                        reason=refusal,
                        blocked_by="catalogue",
                        matched_rule_id=None,
                    ),
                    trace_id=self._trace_id,
                    parent_span_id=proposed.span_id,
                )
                log_blocked(
                    name,
                    reason=refusal,
                    rule="catalogue",
                    trace_id=self._trace_id,
                    agent_id=self._agent_id,
                    provenance=(),
                    tenant=self._tenant,
                )
                return mcp_error(f"SENTINEL blocked {name!r}: {refusal}")

            # The call's provenance is that of what it was derived FROM, never
            # its own AGENT label: counting that made `effective_provenance !=
            # {USER}` deny every call, including a first call made on the
            # user's request alone.
            lineage = self._lineage
            if lineage is None:
                # A session whose lineage was never seeded has UNKNOWN
                # provenance, not clean provenance. Treating "unknown" as an
                # empty set would make `RETRIEVED_CONTENT in provenance` false
                # and authorize the call as untainted (audit F-12). Refused
                # before policy is consulted: the state policy would reason
                # over is missing, so this is a deterministic deny, not a
                # policy decision.
                reason = (
                    "provenance unknown: this session's lineage was never seeded, "
                    "so the call cannot be shown to be untainted"
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
                    name,
                    reason=reason,
                    rule=None,
                    trace_id=self._trace_id,
                    agent_id=self._agent_id,
                    provenance=(),
                    tenant=self._tenant,
                )
                return mcp_error(f"SENTINEL blocked {name!r}: {reason}")
            provenance = lineage

            # 2. Authorize (Phase 2) and record the full decision trace.
            engine = self._current_engine()
            call = ToolCall(
                name=name,
                arguments=default_normalize(arguments),
                provenance=provenance,
            )
            decision = engine.authorize(call)
            await self._emitter.emit(
                to_decision_payload(name, engine.policy_version, decision),
                trace_id=self._trace_id,
                parent_span_id=proposed.span_id,
            )

            # 3 + 5. Blocked: hard-signal trust penalty, ToolBlocked, clean error.
            if not decision.allowed:
                await self._scorer.record_blocked_call(
                    self._agent_id,
                    name,
                    reason=decision.reason,
                    trace_id=self._trace_id,
                    parent_span_id=proposed.span_id,
                    tenant=self._tenant,
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
                    name,
                    reason=decision.reason,
                    rule=decision.matched_rule_id,
                    trace_id=self._trace_id,
                    agent_id=self._agent_id,
                    provenance=decision.effective_provenance,
                    tenant=self._tenant,
                )
                # The agent learns which rule refused it, not the evaluation
                # detail (a missing config name, an operand type): that stays
                # in the forensic record and the log for the operator.
                shown = (
                    f"denied by rule {decision.matched_rule_id!r}"
                    if decision.matched_rule_id is not None
                    else decision.reason
                )
                return mcp_error(f"SENTINEL blocked {name!r}: {shown}")

            # 3. Allowed: transition telemetry feeds the anomaly model.
            await self._scorer.record_tool_transition(
                self._agent_id,
                name,
                trace_id=self._trace_id,
                parent_span_id=proposed.span_id,
                tenant=self._tenant,
            )

            # 4. Forward across the second MCP hop and tag the RESULT's provenance.
            log_allowed(
                name,
                trace_id=self._trace_id,
                agent_id=self._agent_id,
                provenance=decision.effective_provenance,
                tenant=self._tenant,
            )
            try:
                result = await self._downstream.call_tool(name, dict(arguments))
            except Exception:  # noqa: BLE001 - a downstream is an untrusted boundary
                # A transport/server failure is still an observed downstream
                # outcome. Convert it to a tainted MCP error so the execution
                # span and lineage cannot be skipped, and never hand an
                # implementation exception (which may contain secrets) to the
                # agent.
                _LOG.exception("downstream tool %r failed", name)
                result = mcp_error("SENTINEL: downstream tool failed; result withheld")
            # Bound what a downstream can hand back. A fetched page is
            # attacker-sized, and everything below reads the whole result — the
            # declassifier, the injection scanner, and finally the agent. An
            # oversized result is replaced by an error HERE, before any of them
            # see it. The tool did run, so the trail still records an execution;
            # only its output is withheld.
            size = _result_size(result)
            if size > self._max_result_bytes:
                result = mcp_error(
                    f"SENTINEL withheld {name!r}'s result: {size} bytes exceeds the "
                    f"{self._max_result_bytes}-byte limit (SENTINEL_MAX_RESULT_BYTES)"
                )
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
            schema_name = engine.declassifier_for(name)
            if schema_name is not None and _only_text(result):
                source = ProvenanceNode(span_id=proposed.span_id, label=label, derived_from=())
                sanitized = self._sanitizer.sanitize(
                    source, get_schema(schema_name), content=result_text(result)
                )
                if sanitized is not None:
                    label = self._sanitizer.output_label
                    cleared_from = proposed.span_id
                    # Hand the agent exactly the value that was declassified and
                    # nothing else. Returning the original result let anything
                    # the schema never looked at ride along as trusted.
                    result = mcp_types.CallToolResult(
                        content=[mcp_types.TextContent(type="text", text=str(sanitized.value))],
                        isError=False,
                    )

            executed = await self._emitter.emit(
                ToolExecuted(
                    tool_name=name,
                    arguments=dict(arguments),
                    # Records the OUTCOME: an operator reading the trail sees
                    # SYSTEM here exactly when a value was declassified.
                    result_label=label,
                    result_summary=summarize_result(result),
                    declassified_by=schema_name if cleared_from else None,
                ),
                trace_id=self._trace_id,
                parent_span_id=proposed.span_id,
            )
            # The result becomes part of what the agent has observed, so every
            # later call derives from it. An ordinary result carries its own
            # label plus everything its call derived from, which includes the
            # call itself (AGENT). A declassified value starts FRESH: only the
            # sanitizer's label, none of its tainted origin.
            #
            # This is the union a graph walk over the whole session used to
            # recompute on every call. Every call derived from every earlier
            # result, so the walk's cost grew with the square of the session
            # length (measured: 1.5 ms per call at call 100, 40 ms at call 800,
            # on the one event loop every session shares). Kept incrementally,
            # it is one set union per call; tests/test_provenance_incremental.py
            # checks it gives the same answer as the walk.
            gained = frozenset({label}) if cleared_from else frozenset({label, AGENT})
            self._lineage = lineage | gained

            # Layer-1 scan of the RETRIEVED content (§5). Flag-only: it records an
            # InjectionScanned span and feeds the trust scorer a hard signal, but
            # does NOT block — Authorization is the backstop that actually stops
            # the exfiltration even when this shield is evaded.
            if self._input_shield is not None:
                verdict = await self._scan(
                    self._input_shield.inspect_document, result_text(result)
                )
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
                        f"tool_result:{name}",
                        trace_id=self._trace_id,
                        shield=verdict.shield,
                        tenant=self._tenant,
                    )
                    if verdict.penalize_trust:
                        await self._scorer.record_injection(
                            self._agent_id,
                            target=f"tool_result:{name}",
                            trace_id=self._trace_id,
                            parent_span_id=executed.span_id,
                            tenant=self._tenant,
                        )
            return result
