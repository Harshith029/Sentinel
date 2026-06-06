"""Phase 2B: versioned YAML policy loads strictly; malformed is rejected at LOAD."""
from __future__ import annotations

import textwrap

import pytest

from sentinel.authorization.policy import (
    PolicyLoadError,
    load_default_policy,
    load_policy,
)


def test_default_policy_loads_and_compiles() -> None:
    policy = load_default_policy()
    assert policy.policy_version == 3
    assert set(policy.tools) == {
        "web_fetch",
        "send_email",
        "get_customer_record",
        "delete_record",
        "transfer_funds",
    }
    # web_fetch is a read tool with no deny rules → always allowed.
    assert policy.rules_for("web_fetch") == ()
    # delete_record is a deny_always rule with no predicate.
    (rule,) = policy.rules_for("delete_record")  # type: ignore[misc]
    assert rule.deny_always is True
    assert rule.condition is None
    # send_email's predicates are compiled to AST, not left as strings.
    send_rules = policy.rules_for("send_email")
    assert send_rules is not None
    assert [r.id for r in send_rules] == ["block-untrusted-origin", "domain-allowlist"]
    assert all(r.condition is not None for r in send_rules)


def test_unknown_tool_has_no_rules() -> None:
    assert load_default_policy().rules_for("no_such_tool") is None


VALID = textwrap.dedent(
    """
    policy_version: 7
    tools:
      send_email:
        rules:
          - id: block
            deny_if: "RETRIEVED_CONTENT in effective_provenance"
    """
)


def test_valid_inline_policy() -> None:
    policy = load_policy(VALID)
    assert policy.policy_version == 7
    assert policy.rules_for("send_email") is not None


_MALFORMED = {
    "top_level_list": "- a\n- b\n",
    "top_level_scalar": "just a string\n",
    "missing_version": "tools: {}\n",
    "version_not_int": "policy_version: three\ntools: {}\n",
    "extra_top_key": "policy_version: 1\ntools: {}\nbogus: 1\n",
    "tools_not_mapping": "policy_version: 1\ntools: [1, 2]\n",
    "rule_missing_id": (
        "policy_version: 1\ntools:\n  x:\n    rules:\n"
        '      - deny_if: "amount >= max_amount"\n'
    ),
    "rule_extra_key": (
        "policy_version: 1\ntools:\n  x:\n    rules:\n"
        '      - id: r\n        deny_if: "amount >= max_amount"\n        oops: 1\n'
    ),
    "rule_both_effects": (
        "policy_version: 1\ntools:\n  x:\n    rules:\n"
        '      - id: r\n        deny_if: "amount >= max_amount"\n'
        "        deny_always: true\n"
    ),
    "rule_neither_effect": (
        "policy_version: 1\ntools:\n  x:\n    rules:\n      - id: r\n"
    ),
    "deny_always_false": (
        "policy_version: 1\ntools:\n  x:\n    rules:\n"
        "      - id: r\n        deny_always: false\n"
    ),
    "unsupported_operator": (
        "policy_version: 1\ntools:\n  x:\n    rules:\n"
        '      - id: r\n        deny_if: "amount > max_amount"\n'
    ),
    "unbalanced_set": (
        "policy_version: 1\ntools:\n  x:\n    rules:\n"
        '      - id: r\n        deny_if: "effective_provenance != {USER"\n'
    ),
}


@pytest.mark.parametrize("name", sorted(_MALFORMED))
def test_malformed_policy_rejected_at_load(name: str) -> None:
    with pytest.raises(PolicyLoadError):
        load_policy(_MALFORMED[name])
