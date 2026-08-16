"""Phase 2B: the typed condition AST evaluates correctly and fails loudly."""
from __future__ import annotations

from decimal import Decimal

import pytest

from whence.authorization.ast import (
    Comparison,
    ConditionError,
    LabelLiteral,
    NumberLiteral,
    SetLiteral,
    StringLiteral,
    Variable,
)


def test_equality_numeric_and_cross_type() -> None:
    # 12 == 12.0 == Decimal('12') all hold (value comparison, not type).
    cmp = Comparison(Variable("amount"), "==", NumberLiteral(Decimal("12")))
    assert cmp.evaluate({"amount": 12}) is True
    assert cmp.evaluate({"amount": 12.0}) is True
    assert cmp.evaluate({"amount": 13}) is False


def test_inequality() -> None:
    cmp = Comparison(Variable("d"), "!=", StringLiteral("corp.example"))
    assert cmp.evaluate({"d": "evil.test"}) is True
    assert cmp.evaluate({"d": "corp.example"}) is False


def test_ordered_comparisons_and_boundary() -> None:
    ge = Comparison(Variable("amount"), ">=", Variable("cap"))
    assert ge.evaluate({"amount": Decimal("100"), "cap": Decimal("100")}) is True
    assert ge.evaluate({"amount": Decimal("99"), "cap": Decimal("100")}) is False
    lt = Comparison(Variable("amount"), "<", NumberLiteral(Decimal("100")))
    assert lt.evaluate({"amount": 99}) is True
    assert lt.evaluate({"amount": 100}) is False


def test_set_membership() -> None:
    cmp = Comparison(LabelLiteral("RETRIEVED_CONTENT"), "in", Variable("ep"))
    assert cmp.evaluate({"ep": frozenset({"USER", "RETRIEVED_CONTENT"})}) is True
    assert cmp.evaluate({"ep": frozenset({"USER"})}) is False


def test_not_in_membership_over_list() -> None:
    cmp = Comparison(Variable("domain"), "not in", Variable("allowed"))
    assert cmp.evaluate({"domain": "evil.test", "allowed": ["corp.example"]}) is True
    assert cmp.evaluate({"domain": "corp.example", "allowed": ["corp.example"]}) is False


def test_set_equality() -> None:
    cmp = Comparison(Variable("ep"), "!=", SetLiteral((LabelLiteral("USER"),)))
    assert cmp.evaluate({"ep": frozenset({"USER"})}) is False  # exactly {USER}
    assert cmp.evaluate({"ep": frozenset({"USER", "AGENT"})}) is True


def test_unknown_variable_raises() -> None:
    cmp = Comparison(Variable("missing"), "==", NumberLiteral(Decimal("1")))
    with pytest.raises(ConditionError, match="unknown variable"):
        cmp.evaluate({})


def test_ordered_comparison_on_non_number_raises() -> None:
    cmp = Comparison(Variable("x"), "<", NumberLiteral(Decimal("1")))
    with pytest.raises(ConditionError):
        cmp.evaluate({"x": "not-a-number"})


def test_in_on_non_collection_raises() -> None:
    cmp = Comparison(LabelLiteral("USER"), "in", Variable("x"))
    with pytest.raises(ConditionError):
        cmp.evaluate({"x": 5})
