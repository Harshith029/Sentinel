"""The policy's config namespace must be operator-owned, not agent-influenced.

Policy predicates read deployment values — ``allowed_domains``, ``max_amount`` —
from a config namespace. Two defects made that namespace untrustworthy:

* **Arguments could shadow config.** The namespace wrote config first and tool
  arguments second, so an agent-supplied argument NAMED like a config key
  overwrote the operator's value. Attacker-controllable data then decided the
  outcome of a deny rule, which is a policy bypass in the deterministic path
  this system exists to defend.
* **Live sessions used the DEMO config.** ``new_live_proxy`` hardcoded
  ``sentinel.demo.scenario.DEFAULT_CONFIG``, so a real MCP session over the wire
  was authorized against ``allowed_domains: ["corp.example"]`` — an operator had
  no way to set it at all.
"""
from __future__ import annotations

import textwrap

from sentinel.authorization.engine import AuthorizationEngine, ToolCall
from sentinel.authorization.policy import load_policy

POLICY = textwrap.dedent(
    """
    policy_version: 1
    config:
      allowed_domains: ["corp.example"]
      max_amount: 1000
    tools:
      send_email:
        rules:
          - id: domain-allowlist
            deny_if: "recipient_domain not in allowed_domains"
    """
).strip()


def test_a_tool_argument_cannot_shadow_operator_config() -> None:
    """An argument named like a config key must not override the operator's value.

    Observed before the fix: the same call flipped from DENY to ALLOW purely by
    adding an argument called ``allowed_domains``. The agent chooses argument
    names and values, and the agent may be acting on injected content, so this
    let untrusted input rewrite the operator's allowlist mid-decision.

    The namespace is now layered by TRUST: arguments (agent-supplied) first,
    then config (operator-declared), then provenance (computed) — each layer
    overwriting the less trusted one below it.
    """
    engine = AuthorizationEngine(load_policy(POLICY))
    config = {"allowed_domains": ["corp.example"]}

    honest = ToolCall(
        name="send_email",
        arguments={"recipient_domain": "evil.test"},
        config=config,
    )
    assert engine.authorize(honest).decision == "DENY"

    shadowed = ToolCall(
        name="send_email",
        arguments={
            "recipient_domain": "evil.test",
            "allowed_domains": ["evil.test"],  # the bypass attempt
        },
        config=config,
    )
    assert engine.authorize(shadowed).decision == "DENY", (
        "a tool argument overrode the operator's allowlist"
    )


def test_provenance_still_cannot_be_shadowed_by_config_or_arguments() -> None:
    """The computed security facts stay authoritative over both other layers.

    Re-ordering the namespace must not have opened a new hole: provenance is
    written LAST precisely so nothing below it can forge a clean lineage.
    """
    policy = textwrap.dedent(
        """
        policy_version: 1
        tools:
          send_email:
            rules:
              - id: block-untrusted-origin
                deny_if: "RETRIEVED_CONTENT in effective_provenance"
        """
    ).strip()
    engine = AuthorizationEngine(load_policy(policy))

    from sentinel.labels import RETRIEVED_CONTENT

    forged = ToolCall(
        name="send_email",
        # Both lower layers claim a clean lineage; the computed one says otherwise.
        arguments={"effective_provenance": frozenset(), "is_tainted": False},
        config={"effective_provenance": frozenset(), "is_tainted": False},
        provenance=frozenset({RETRIEVED_CONTENT}),
    )
    assert engine.authorize(forged).decision == "DENY", (
        "provenance was shadowed — a tainted call authorized as clean"
    )


def test_policy_declares_its_own_config() -> None:
    """Config belongs WITH the rules that read it, and is per tenant as a result.

    The predicates referencing ``allowed_domains`` live in the policy document,
    so the values they resolve against should too: one reviewable artefact, and
    per-tenant automatically because the registry already loads policy per
    tenant.
    """
    policy = load_policy(POLICY)
    assert policy.config["allowed_domains"] == ["corp.example"]
    assert policy.config["max_amount"] == 1000


def test_policy_without_a_config_block_gets_an_empty_one() -> None:
    """Omitting config is legal and yields nothing — never a demo default.

    A policy that references an undeclared key then hits the engine's
    fail-closed path and denies, which is the correct outcome: better a refused
    action than one authorized against values the operator never set.
    """
    policy = load_policy(
        textwrap.dedent(
            """
            policy_version: 1
            tools:
              send_email:
                rules: []
            """
        ).strip()
    )
    assert policy.config == {}
