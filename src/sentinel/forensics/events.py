"""Typed forensic event payloads (BUILD_SPEC §2, Phase 1).

Spec rule: "TYPED payloads per event_type — discriminated Pydantic union (NO
generic dict)." There are exactly EIGHT event types, and they form a closed
discriminated union keyed on the ``event_type`` literal:

    InputReceived, ToolCallProposed, InjectionScanned, AuthorizationDecided,
    TrustUpdated, AgentQuarantined, ToolExecuted, ToolBlocked

Every payload is *frozen* — a forensic record must never mutate after it is
written. Argument blobs use :data:`pydantic.JsonValue` rather than a bare
``dict`` so the contents stay JSON-serializable and typed end-to-end (a bare
``dict[str, Any]`` would silently admit non-serializable values that then blow
up at the Cosmos write boundary).

Phases 1–2 populate ``Input/ToolCallProposed/AuthorizationDecided/ToolExecuted/
ToolBlocked``. ``InjectionScanned`` (Layer-1 shield, §5), ``TrustUpdated`` and
``AgentQuarantined`` (Tier-2 trust scorer, Phase 3) are *defined here now* —
the spec lists all eight as the Phase-1 spine — but the components that EMIT
them arrive in later phases. Defining the shapes up front is what lets the
forensic store and replay be written once against the full union.
"""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from sentinel.labels import Label

# A tool call's argument map. Typed-JSON, never a free `Any`, so anything that
# reaches the store is guaranteed serializable and round-trips losslessly.
Arguments = dict[str, JsonValue]

# Authorization verdict (the engine itself lands in Phase 2; the shape is fixed
# here because AuthorizationDecided / ToolBlocked reference it).
Decision = Literal["ALLOW", "DENY"]

# Which component refused a tool call. DENY-OVERRIDES means several layers can
# block; recording which one did is core forensic value.
BlockedBy = Literal[
    "authorization", "input_shield", "trust_scorer", "quarantine", "provenance"
]


class _FrozenPayload(BaseModel):
    """Base for every event payload: immutable, strict, no extra fields.

    ``extra="forbid"`` means a typo'd field name fails loudly at construction
    instead of being silently dropped from the forensic record.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")


class RuleEvaluation(_FrozenPayload):
    """One policy rule's outcome within a single authorization decision.

    The authorization engine (Phase 2) evaluates every candidate rule and
    records each here so replay can show WHY a decision was reached, not just
    the verdict. Defined now so :class:`AuthorizationDecided` is complete.
    """

    rule_id: str
    effect: Decision
    matched: bool
    detail: str | None = None


class InputReceived(_FrozenPayload):
    """An input entered the trace (user prompt, or content fed back to the agent).

    ``origin_label`` is the trust label of the input at its source — ``USER`` for
    a human prompt, ``RETRIEVED_CONTENT`` for tool/web output looped back into the
    agent's context. It seeds the provenance lattice (§4) for everything derived
    from this input.
    """

    event_type: Literal["InputReceived"] = "InputReceived"
    origin_label: Label
    content: str


class ToolCallProposed(_FrozenPayload):
    """The agent proposed a tool call. Mirrors the MCP ``call_tool`` request shape.

    Emitted BEFORE authorization — this is the proposal, not the execution. Its
    span is the parent of the subsequent AuthorizationDecided / ToolExecuted /
    ToolBlocked spans for this call.
    """

    event_type: Literal["ToolCallProposed"] = "ToolCallProposed"
    tool_name: str
    arguments: Arguments = Field(default_factory=dict)


class InjectionScanned(_FrozenPayload):
    """Result of a Layer-1 injection scan (Prompt Shields / InputShield, §5).

    Layer 1 is EXPECTED to miss obfuscated attacks by design — the authorization
    engine is the backstop. ``attack_detected`` records the shield's verdict;
    ``target`` names what was scanned ("user_prompt", "tool_result", ...).
    """

    event_type: Literal["InjectionScanned"] = "InjectionScanned"
    target: str
    attack_detected: bool
    shield: str
    detail: str | None = None


class AuthorizationDecided(_FrozenPayload):
    """The Authorization Engine's verdict for a proposed tool call (Phase 2).

    ``effective_provenance`` is the §4.2 provenance SET serialized as a sorted
    list (JSON has no sets); ``is_tainted`` is exactly
    ``RETRIEVED_CONTENT in effective_provenance``. ``rules_considered`` records
    every rule the DENY-OVERRIDES evaluation looked at, for auditable replay.
    """

    event_type: Literal["AuthorizationDecided"] = "AuthorizationDecided"
    tool_name: str
    decision: Decision
    policy_version: str
    effective_provenance: list[Label]
    is_tainted: bool
    rules_considered: list[RuleEvaluation] = Field(default_factory=list)
    matched_rule_id: str | None = None
    reason: str


class TrustUpdated(_FrozenPayload):
    """A trust-score delta for an agent (Tier-2 trust scorer, Phase 3 logic).

    Spec §2: every delta is DERIVED from an event and carries a stated reason —
    ``reason`` is therefore required, never optional. ``reason`` spells out the
    full arithmetic of the delta; ``smoothed_probability`` carries the add-one
    smoothed transition probability that drove a transition-based delta (None for
    hard-signal deltas such as a blocked call or detected injection), so the math
    is inspectable structurally and not only as prose (spec §Phase 3).
    """

    event_type: Literal["TrustUpdated"] = "TrustUpdated"
    agent_id: str
    previous_score: float
    new_score: float
    delta: float
    reason: str
    smoothed_probability: float | None = None


class AgentQuarantined(_FrozenPayload):
    """An agent crossed the quarantine threshold and was isolated (Phase 3 logic)."""

    event_type: Literal["AgentQuarantined"] = "AgentQuarantined"
    agent_id: str
    score_at_quarantine: float
    reason: str


class ToolExecuted(_FrozenPayload):
    """A tool actually ran downstream and returned a result.

    ``result_label`` is the trust label assigned to the result — external tool
    output is ``RETRIEVED_CONTENT`` and so taints anything derived from it.
    """

    event_type: Literal["ToolExecuted"] = "ToolExecuted"
    tool_name: str
    arguments: Arguments = Field(default_factory=dict)
    result_label: Label
    result_summary: str


class ToolBlocked(_FrozenPayload):
    """A proposed tool call was refused before (or instead of) execution.

    ``blocked_by`` names the component that refused it; ``matched_rule_id`` ties
    an authorization block back to the specific policy rule.
    """

    event_type: Literal["ToolBlocked"] = "ToolBlocked"
    tool_name: str
    reason: str
    blocked_by: BlockedBy
    matched_rule_id: str | None = None


# The closed discriminated union. Pydantic uses the `event_type` literal to pick
# the right model on parse — so a stored span round-trips back to its exact
# payload class, and an unknown event_type fails loudly instead of degrading to
# an untyped dict.
EventPayload = Annotated[
    InputReceived
    | ToolCallProposed
    | InjectionScanned
    | AuthorizationDecided
    | TrustUpdated
    | AgentQuarantined
    | ToolExecuted
    | ToolBlocked,
    Field(discriminator="event_type"),
]

# Every event_type literal, for tests and exhaustiveness checks.
EVENT_TYPES: frozenset[str] = frozenset(
    {
        "InputReceived",
        "ToolCallProposed",
        "InjectionScanned",
        "AuthorizationDecided",
        "TrustUpdated",
        "AgentQuarantined",
        "ToolExecuted",
        "ToolBlocked",
    }
)
