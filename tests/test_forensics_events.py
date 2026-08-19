"""Phase 1: the 8 typed event payloads and their discriminated union."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentinel.forensics.events import (
    EVENT_TYPES,
    AgentQuarantined,
    AuthorizationDecided,
    InjectionScanned,
    InputReceived,
    RuleEvaluation,
    ToolBlocked,
    ToolCallProposed,
    ToolExecuted,
    TrustUpdated,
)
from sentinel.forensics.span import Span

ALL_PAYLOADS = [
    InputReceived(origin_label="USER", content="hello"),
    ToolCallProposed(tool_name="web_fetch", arguments={"url": "https://x"}),
    InjectionScanned(target="user_prompt", attack_detected=False, shield="prompt_shields"),
    AuthorizationDecided(
        tool_name="send_email",
        decision="DENY",
        policy_version="v1",
        effective_provenance=["USER", "RETRIEVED_CONTENT"],
        is_tainted=True,
        rules_considered=[RuleEvaluation(rule_id="r1", effect="DENY", matched=True)],
        matched_rule_id="r1",
        reason="tainted content reaching exfil-capable tool",
    ),
    TrustUpdated(
        agent_id="agent-1",
        previous_score=1.0,
        new_score=0.7,
        delta=-0.3,
        reason="proposed blocked tool",
    ),
    AgentQuarantined(agent_id="agent-1", score_at_quarantine=0.1, reason="below threshold"),
    ToolExecuted(
        tool_name="web_fetch",
        arguments={"url": "https://x"},
        result_label="RETRIEVED_CONTENT",
        result_summary="200 OK",
    ),
    ToolBlocked(
        tool_name="send_email",
        reason="denied by policy",
        blocked_by="authorization",
        matched_rule_id="r1",
    ),
]


def test_there_are_exactly_eight_event_types() -> None:
    assert len(EVENT_TYPES) == 8
    assert {p.event_type for p in ALL_PAYLOADS} == EVENT_TYPES


@pytest.mark.parametrize("payload", ALL_PAYLOADS, ids=lambda p: p.event_type)
def test_event_type_discriminator_matches_class(payload: object) -> None:
    # event_type literal must equal the class name (the discriminator contract).
    assert payload.event_type == type(payload).__name__  # type: ignore[attr-defined]


@pytest.mark.parametrize("payload", ALL_PAYLOADS, ids=lambda p: p.event_type)
def test_payload_round_trips_through_span_json(payload: object) -> None:
    # A Span wrapping the payload must serialize to JSON and validate back to the
    # EXACT same concrete payload class — i.e. the discriminated union resolves.
    span = Span(trace_id="a" * 32, span_id="b" * 16, seq=0, payload=payload)  # type: ignore[arg-type]
    as_json = span.model_dump(mode="json")
    restored = Span.model_validate(as_json)
    assert type(restored.payload) is type(payload)
    assert restored.payload == payload
    assert restored.event_type == payload.event_type  # type: ignore[attr-defined]


def test_payloads_are_frozen() -> None:
    payload = ToolCallProposed(tool_name="x", arguments={})
    with pytest.raises(ValidationError):
        payload.tool_name = "y"  # type: ignore[misc]


def test_unknown_field_is_rejected() -> None:
    # extra="forbid": a typo'd field must fail loudly, not be silently dropped.
    with pytest.raises(ValidationError):
        ToolCallProposed(tool_name="x", arguments={}, typo_field=1)  # type: ignore[call-arg]


def test_arguments_must_be_json_values() -> None:
    # A set is not a JSON value; JsonValue must reject it at construction so a
    # non-serializable arg can never reach the Cosmos write boundary.
    with pytest.raises(ValidationError):
        ToolCallProposed(tool_name="x", arguments={"bad": {1, 2, 3}})  # type: ignore[dict-item]


def test_arguments_accepts_nested_json() -> None:
    payload = ToolCallProposed(
        tool_name="x",
        arguments={"nested": {"list": [1, "two", True, None], "n": 3.5}},
    )
    assert payload.arguments["nested"]["list"][1] == "two"  # type: ignore[index]


def test_trust_update_requires_reason() -> None:
    # §2: every trust delta carries a stated reason — it is not optional.
    with pytest.raises(ValidationError):
        TrustUpdated(agent_id="a", previous_score=1.0, new_score=0.5, delta=-0.5)  # type: ignore[call-arg]


def test_unknown_event_type_fails_validation() -> None:
    bad = {
        "trace_id": "a" * 32,
        "span_id": "b" * 16,
        "parent_span_id": None,
        "seq": 0,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "payload": {"event_type": "NotARealEvent"},
    }
    with pytest.raises(ValidationError):
        Span.model_validate(bad)
