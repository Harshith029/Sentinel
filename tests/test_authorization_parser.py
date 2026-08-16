"""Phase 2B: the predicate parser accepts the grammar and rejects everything else."""
from __future__ import annotations

from decimal import Decimal

import pytest

from whence.authorization.ast import (
    And,
    Comparison,
    LabelLiteral,
    Not,
    NumberLiteral,
    Or,
    SetLiteral,
    Variable,
)
from whence.authorization.parser import PolicyParseError, parse_condition


def test_parses_provenance_membership() -> None:
    cmp = parse_condition("RETRIEVED_CONTENT in effective_provenance")
    assert isinstance(cmp, Comparison)
    assert isinstance(cmp.left, LabelLiteral) and cmp.left.value == "RETRIEVED_CONTENT"
    assert cmp.op == "in"
    assert isinstance(cmp.right, Variable) and cmp.right.name == "effective_provenance"


def test_parses_not_in() -> None:
    cmp = parse_condition("recipient_domain not in allowed_domains")
    assert cmp.op == "not in"
    assert isinstance(cmp.left, Variable)
    assert isinstance(cmp.right, Variable)


def test_parses_set_inequality() -> None:
    cmp = parse_condition("effective_provenance != {USER}")
    assert cmp.op == "!="
    assert isinstance(cmp.right, SetLiteral)
    assert len(cmp.right.members) == 1
    assert isinstance(cmp.right.members[0], LabelLiteral)


def test_parses_numeric_ge() -> None:
    cmp = parse_condition("amount >= max_amount")
    assert cmp.op == ">="


def test_parses_multi_member_set() -> None:
    cmp = parse_condition("effective_provenance != {USER, SYSTEM}")
    assert isinstance(cmp.right, SetLiteral)
    assert len(cmp.right.members) == 2


def test_parses_number_literal() -> None:
    cmp = parse_condition("amount >= 1000")
    assert isinstance(cmp.right, NumberLiteral)
    assert cmp.right.value == Decimal("1000")


@pytest.mark.parametrize(
    "bad",
    [
        "",                                   # empty
        "   ",                                # blank
        "amount > max_amount",                # '>' unsupported
        "amount <= max_amount",               # '<=' unsupported
        "amount = max_amount",                # '=' unsupported
        "amount === 1",                       # bad operator
        "RETRIEVED_CONTENT in",               # missing right operand
        "in effective_provenance",            # missing left operand
        "amount >=",                          # missing right operand
        "effective_provenance != {USER",      # unbalanced set
        "effective_provenance != USER}",      # stray closing brace
        "a == b == c",                        # trailing tokens
        "amount & 1",                         # illegal character
        "(amount == 1",                       # unbalanced paren
        "amount == 1)",                       # stray close paren
        "amount == 1 and",                    # dangling 'and'
        "and amount == 1",                    # leading 'and'
        "amount == 1 or",                     # dangling 'or'
        "not",                                # bare 'not' with nothing to negate
    ],
)
def test_malformed_predicates_rejected(bad: str) -> None:
    with pytest.raises(PolicyParseError):
        parse_condition(bad)


# --- compound predicates -----------------------------------------------------


def test_compound_and_two_comparisons() -> None:
    p = parse_condition(
        "RETRIEVED_CONTENT in effective_provenance and amount >= max_amount"
    )
    assert isinstance(p, And)
    assert isinstance(p.left, Comparison)
    assert isinstance(p.right, Comparison)


def test_compound_or_two_comparisons() -> None:
    p = parse_condition("amount >= 1000 or recipient_domain not in allowed_domains")
    assert isinstance(p, Or)
    assert isinstance(p.left, Comparison)
    assert isinstance(p.right, Comparison)


def test_and_binds_tighter_than_or() -> None:
    # Python precedence: `a or b and c` parses as `a or (b and c)`.
    p = parse_condition("amount >= 1 or amount >= 2 and amount >= 3")
    assert isinstance(p, Or)
    assert isinstance(p.left, Comparison)
    assert isinstance(p.right, And)


def test_parentheses_override_precedence() -> None:
    p = parse_condition("(amount >= 1 or amount >= 2) and amount >= 3")
    assert isinstance(p, And)
    assert isinstance(p.left, Or)


def test_unary_not_negates_comparison() -> None:
    p = parse_condition("not amount >= max_amount")
    assert isinstance(p, Not)
    assert isinstance(p.inner, Comparison)


def test_not_in_still_works_as_a_binary_operator() -> None:
    # Regression: extending `not` to mean unary boolean must NOT break the
    # existing `not in` binary comparison — it is still a single Comparison.
    p = parse_condition("recipient_domain not in allowed_domains")
    assert isinstance(p, Comparison)
    assert p.op == "not in"


def test_compound_predicate_evaluates() -> None:
    p = parse_condition(
        "RETRIEVED_CONTENT in effective_provenance and amount >= max_amount"
    )
    tainted_big = {
        "effective_provenance": frozenset({"USER", "RETRIEVED_CONTENT"}),
        "amount": Decimal("9999"),
        "max_amount": Decimal("1000"),
    }
    tainted_small = {
        "effective_provenance": frozenset({"USER", "RETRIEVED_CONTENT"}),
        "amount": Decimal("10"),
        "max_amount": Decimal("1000"),
    }
    clean_big = {
        "effective_provenance": frozenset({"USER"}),
        "amount": Decimal("9999"),
        "max_amount": Decimal("1000"),
    }
    assert p.evaluate(tainted_big) is True
    assert p.evaluate(tainted_small) is False  # AND requires both halves
    assert p.evaluate(clean_big) is False      # AND requires both halves
