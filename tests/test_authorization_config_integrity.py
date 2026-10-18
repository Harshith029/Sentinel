"""The policy's config namespace must be operator-owned, not agent-influenced.

Policy predicates read deployment values — ``allowed_domains``, ``max_amount`` —
from a config namespace. Two defects made that namespace untrustworthy:

* **Arguments could shadow config.** The namespace wrote config first and tool
  arguments second, so an agent-supplied argument NAMED like a config key
  overwrote the operator's value. Attacker-controllable data then decided the
  outcome of a deny rule, which is a policy bypass in the deterministic path
  this system exists to defend.
* **Proxy callers could supply config.** Demo and live code had a separate
  ``authorization_config`` input beside the reviewed policy document, which
  made it too easy to mistake scenario/request data for operator policy.
"""

from __future__ import annotations

import logging
import textwrap

import pytest

from sentinel.authorization.engine import AuthorizationEngine, ToolCall
from sentinel.authorization.policy import load_policy
from sentinel.control.manager import RunManager
from sentinel.forensics.store import InMemoryForensicStore
from sentinel.mcp_proxy.proxy import default_normalize

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
    honest = ToolCall(
        name="send_email",
        arguments={"recipient_domain": "evil.test"},
    )
    assert engine.authorize(honest).decision == "DENY"

    shadowed = ToolCall(
        name="send_email",
        arguments={
            "recipient_domain": "evil.test",
            "allowed_domains": ["evil.test"],  # the bypass attempt
        },
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
        provenance=frozenset({RETRIEVED_CONTENT}),
    )
    assert engine.authorize(forged).decision == "DENY", (
        "provenance was shadowed — a tainted call authorized as clean"
    )


def test_caller_supplied_config_cannot_replace_the_policy_config() -> None:
    """Authorization uses only config compiled from the policy document."""
    engine = AuthorizationEngine(load_policy(POLICY))
    call = ToolCall(
        name="send_email",
        arguments={"recipient_domain": "evil.test"},
        config={"allowed_domains": ["evil.test"]},
    )
    assert engine.authorize(call).decision == "DENY"


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


def test_an_argument_cannot_supply_an_undeclared_comparand() -> None:
    """With no config block, the call must not provide its own allowlist (AUTHZ-1).

    Config is layered over arguments, so a DECLARED allowlist always won; an
    undeclared one used to fall back to the agent's argument of the same name.
    """
    engine = AuthorizationEngine(
        load_policy(
            "policy_version: 1\ntools:\n  send_email:\n    rules:\n"
            '      - id: domain\n        deny_if: "recipient_domain not in allowed_domains"\n'
        )
    )
    decision = engine.authorize(
        ToolCall(
            name="send_email",
            arguments={"recipient_domain": "other.test", "allowed_domains": ["other.test"]},
            provenance=frozenset({"USER"}),
        )
    )
    assert decision.decision == "DENY"
    assert "fail-closed" in decision.reason


def test_live_proxy_observes_a_higher_version_after_reload() -> None:
    """A long-lived MCP proxy should not retain an obsolete policy snapshot."""
    manager = RunManager(store=InMemoryForensicStore())
    manager.reload_policy("acme", "policy_version: 1\ntools: {web_fetch: {rules: []}}\n")
    proxy = manager.new_live_proxy(
        downstream=object(),  # type: ignore[arg-type] - no downstream call in this unit test
        cache=(),
        agent_id="test-agent",
        tenant="acme",
    )
    assert proxy._current_engine().authorize(ToolCall(name="web_fetch")).decision == "ALLOW"  # noqa: SLF001

    manager.reload_policy(
        "acme",
        """\
policy_version: 2
tools:
  web_fetch:
    rules:
      - id: emergency-stop
        deny_always: true
""",
    )
    decision = proxy._current_engine().authorize(ToolCall(name="web_fetch"))  # noqa: SLF001
    assert decision.decision == "DENY"
    assert decision.matched_rule_id == "emergency-stop"


def test_a_rule_may_compare_against_a_field_sentinel_derives() -> None:
    """Derived fields describe the call and no agent can set them, so they stay.

    The AUTHZ-1 filter drops comparands from a call's arguments. Applied to
    ``recipient_domains`` too, it turned this denylist into a rule that denied
    every message.
    """
    engine = AuthorizationEngine(
        load_policy(
            "policy_version: 1\ntools:\n  send_email:\n    rules:\n"
            "      - id: never-evil\n"
            '        deny_if: "\'evil.test\' in recipient_domains"\n'
        )
    )

    def decide(to: str) -> str:
        call = ToolCall(
            name="send_email", arguments=default_normalize({"to": to}), provenance=frozenset()
        )
        return engine.authorize(call).decision

    assert decide("cfo@corp.example") == "ALLOW"
    assert decide("cfo@corp.example, x@evil.test") == "DENY"


def test_an_undeclared_comparand_is_reported_when_the_policy_loads(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="sentinel.authorization.engine"):
        AuthorizationEngine(
            load_policy(
                "policy_version: 1\ntools:\n  send_email:\n    rules:\n"
                '      - id: domain\n        deny_if: "recipient_domain not in allowed_domains"\n'
            )
        )
    assert "'allowed_domains'" in caplog.text and "denies every" in caplog.text
