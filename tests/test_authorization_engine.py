"""Phase 2B: engine mechanics — deny-overrides, default-deny, fail-closed."""
from __future__ import annotations

import textwrap
from decimal import Decimal

from whence.authorization.engine import AuthorizationEngine, ToolCall
from whence.authorization.policy import load_policy

# A two-rule tool used to demonstrate short-circuiting precedence.
_POLICY = load_policy(
    textwrap.dedent(
        """
        policy_version: 5
        tools:
          pay:
            rules:
              - id: cap
                deny_if: "amount >= max_amount"
              - id: domain
                deny_if: "recipient_domain not in allowed_domains"
        """
    )
)


def _engine() -> AuthorizationEngine:
    return AuthorizationEngine(_POLICY)


def test_allow_when_no_deny_matches() -> None:
    result = _engine().authorize(
        ToolCall(
            name="pay",
            arguments={"amount": Decimal("10"), "recipient_domain": "corp.example"},
            config={"max_amount": Decimal("1000"), "allowed_domains": ["corp.example"]},
        )
    )
    assert result.allowed is True
    assert result.matched_rule_id is None
    # Both rules were considered (and neither matched).
    assert [r.rule_id for r in result.rules_considered] == ["cap", "domain"]
    assert all(r.matched is False for r in result.rules_considered)


def test_deny_overrides_short_circuits_later_rule() -> None:
    # amount>=cap (rule 'cap' matches) AND domain allowed (rule 'domain' would NOT
    # deny → "would-allow"). The earlier deny must win and the later rule must not
    # even be evaluated.
    result = _engine().authorize(
        ToolCall(
            name="pay",
            arguments={"amount": Decimal("1000"), "recipient_domain": "corp.example"},
            config={"max_amount": Decimal("1000"), "allowed_domains": ["corp.example"]},
        )
    )
    assert result.allowed is False
    assert result.matched_rule_id == "cap"
    # Short-circuit proof: only 'cap' is in the trace; 'domain' never ran.
    assert [r.rule_id for r in result.rules_considered] == ["cap"]


def test_default_deny_for_unknown_tool() -> None:
    result = _engine().authorize(ToolCall(name="not_in_policy"))
    assert result.allowed is False
    assert result.matched_rule_id is None
    assert result.rules_considered == ()
    assert "default-deny" in result.reason


def test_fail_closed_when_predicate_cannot_evaluate() -> None:
    # 'recipient_domain' missing → the 'domain' rule cannot evaluate. Engine must
    # fail closed (deny), not skip the rule. (amount<cap so 'cap' does not match.)
    result = _engine().authorize(
        ToolCall(
            name="pay",
            arguments={"amount": Decimal("1")},
            config={"max_amount": Decimal("1000"), "allowed_domains": ["corp.example"]},
        )
    )
    assert result.allowed is False
    assert result.matched_rule_id == "domain"
    matched = [r for r in result.rules_considered if r.rule_id == "domain"][0]
    assert matched.matched is True
    assert "fail-closed" in (matched.detail or "")


def test_decision_payload_is_complete() -> None:
    engine = _engine()
    payload = engine.decision_payload(
        ToolCall(
            name="pay",
            arguments={"amount": Decimal("5000"), "recipient_domain": "corp.example"},
            provenance=frozenset({"USER", "RETRIEVED_CONTENT"}),
            config={"max_amount": Decimal("1000"), "allowed_domains": ["corp.example"]},
        )
    )
    assert payload.event_type == "AuthorizationDecided"
    assert payload.tool_name == "pay"
    assert payload.decision == "DENY"
    assert payload.policy_version == "5"
    assert payload.is_tainted is True
    assert payload.matched_rule_id == "cap"
    assert payload.reason
    assert len(payload.rules_considered) == 1


# --- compound predicates in deny_if -----------------------------------------

_COMPOUND_POLICY = load_policy(
    textwrap.dedent(
        """
        policy_version: 6
        tools:
          send_email:
            rules:
              # The "lineage-aware whitelist" — answers the over-blocking objection.
              # Block only when tainted AND the recipient is NOT in our domain.
              - id: tainted-and-bad-domain
                deny_if: >-
                  RETRIEVED_CONTENT in effective_provenance
                  and recipient_domain not in allowed_domains
        """
    )
)


def test_compound_deny_if_blocks_when_both_halves_true() -> None:
    result = AuthorizationEngine(_COMPOUND_POLICY).authorize(
        ToolCall(
            name="send_email",
            arguments={"recipient_domain": "evil.test"},
            provenance=frozenset({"USER", "RETRIEVED_CONTENT"}),
            config={"allowed_domains": ["corp.example"]},
        )
    )
    assert result.allowed is False
    assert result.matched_rule_id == "tainted-and-bad-domain"


def test_compound_deny_if_allows_tainted_to_safe_domain() -> None:
    """The lineage-aware whitelist: tainted but to a safe domain is allowed.

    This is the over-blocking-objection answer: previously you'd need separate
    rules + one of them would always match. With AND the rule only bites when
    BOTH conditions hold."""
    result = AuthorizationEngine(_COMPOUND_POLICY).authorize(
        ToolCall(
            name="send_email",
            arguments={"recipient_domain": "corp.example"},
            provenance=frozenset({"USER", "RETRIEVED_CONTENT"}),
            config={"allowed_domains": ["corp.example"]},
        )
    )
    assert result.allowed is True


def test_compound_deny_if_allows_clean_lineage() -> None:
    # AND requires BOTH halves: clean lineage → rule doesn't bite even to a bad
    # domain.
    result = AuthorizationEngine(_COMPOUND_POLICY).authorize(
        ToolCall(
            name="send_email",
            arguments={"recipient_domain": "evil.test"},
            provenance=frozenset({"USER"}),
            config={"allowed_domains": ["corp.example"]},
        )
    )
    assert result.allowed is True
