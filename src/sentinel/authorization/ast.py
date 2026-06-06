"""The typed condition AST (BUILD_SPEC §2B).

Policy predicates are evaluated by walking THIS tree — never by ``eval`` or
string matching. Supported operators are EXACTLY the six the spec lists::

    ==  !=  <  >=  in  "not in"

(Note: ``<=`` and ``>`` are deliberately NOT supported; the parser rejects them
at load time.) Operands are typed literals (label / string / number / set) or
variables resolved from an evaluation namespace (typed tool args + provenance +
config). Set membership and set equality are first-class so provenance
predicates like ``RETRIEVED_CONTENT in effective_provenance`` and
``effective_provenance != {USER}`` evaluate directly.

Any evaluation problem (unknown variable, non-numeric operand to ``<``, ``in``
against a non-collection) raises :class:`ConditionError`; the engine turns that
into a fail-closed DENY rather than letting an unevaluable rule pass silently.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Literal

from sentinel.labels import Label

Operator = Literal["==", "!=", "<", ">=", "in", "not in"]


class ConditionError(RuntimeError):
    """Raised when a predicate cannot be evaluated against a given namespace."""


def _is_number(value: object) -> bool:
    # bool is an int subclass; never treat True/False as a number in policy.
    return isinstance(value, (int, float, Decimal)) and not isinstance(value, bool)


def _to_decimal(value: object) -> Decimal:
    """Coerce a numeric operand to Decimal for exact ordered comparison."""
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal, str)):
        raise ConditionError(
            f"operand is not numeric for ordered comparison: {value!r}"
        )
    try:
        return value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ConditionError(f"operand is not a valid number: {value!r}") from exc


def _equal(left: object, right: object) -> bool:
    # Numbers compare by value (12 == 12.0 == Decimal('12')); everything else,
    # including frozenset == frozenset for provenance, uses Python equality.
    if _is_number(left) and _is_number(right):
        return _to_decimal(left) == _to_decimal(right)
    return bool(left == right)


def _contains(container: object, item: object) -> bool:
    if isinstance(container, (frozenset, set, list, tuple, str)):
        return item in container
    raise ConditionError(
        f"right-hand operand of 'in' is not a collection: {type(container).__name__}"
    )


class Operand(ABC):
    """An expression that resolves to a concrete value given a namespace."""

    @abstractmethod
    def resolve(self, namespace: Mapping[str, object]) -> object: ...


@dataclass(frozen=True)
class LabelLiteral(Operand):
    """A trust-label keyword, e.g. ``RETRIEVED_CONTENT`` (resolves to its string)."""

    value: Label

    def resolve(self, namespace: Mapping[str, object]) -> object:
        return self.value


@dataclass(frozen=True)
class StringLiteral(Operand):
    value: str

    def resolve(self, namespace: Mapping[str, object]) -> object:
        return self.value


@dataclass(frozen=True)
class NumberLiteral(Operand):
    value: Decimal

    def resolve(self, namespace: Mapping[str, object]) -> object:
        return self.value


@dataclass(frozen=True)
class SetLiteral(Operand):
    """A set literal like ``{USER}`` or ``{USER, SYSTEM}`` → a frozenset."""

    members: tuple[Operand, ...]

    def resolve(self, namespace: Mapping[str, object]) -> object:
        return frozenset(member.resolve(namespace) for member in self.members)


@dataclass(frozen=True)
class Variable(Operand):
    """A name resolved from the evaluation namespace (arg / provenance / config)."""

    name: str

    def resolve(self, namespace: Mapping[str, object]) -> object:
        if self.name not in namespace:
            raise ConditionError(f"unknown variable {self.name!r} in policy context")
        return namespace[self.name]


@dataclass(frozen=True)
class Comparison:
    """A single ``left OP right`` predicate — the leaf of the condition grammar."""

    left: Operand
    op: Operator
    right: Operand

    def evaluate(self, namespace: Mapping[str, object]) -> bool:
        left = self.left.resolve(namespace)
        right = self.right.resolve(namespace)
        if self.op == "==":
            return _equal(left, right)
        if self.op == "!=":
            return not _equal(left, right)
        if self.op == "<":
            return _to_decimal(left) < _to_decimal(right)
        if self.op == ">=":
            return _to_decimal(left) >= _to_decimal(right)
        if self.op == "in":
            return _contains(right, left)
        if self.op == "not in":
            return not _contains(right, left)
        raise ConditionError(f"unsupported operator {self.op!r}")  # unreachable


@dataclass(frozen=True)
class And:
    """Logical AND of two :class:`Predicate`s (left-associative, lazy)."""

    left: Predicate
    right: Predicate

    def evaluate(self, namespace: Mapping[str, object]) -> bool:
        # Short-circuit: only evaluate the right side if the left is True.
        # This matches the behaviour a reader expects from ``and`` AND keeps a
        # rule like ``A and B`` from raising ConditionError on B when A is False.
        return self.left.evaluate(namespace) and self.right.evaluate(namespace)


@dataclass(frozen=True)
class Or:
    """Logical OR of two :class:`Predicate`s (left-associative, lazy)."""

    left: Predicate
    right: Predicate

    def evaluate(self, namespace: Mapping[str, object]) -> bool:
        return self.left.evaluate(namespace) or self.right.evaluate(namespace)


@dataclass(frozen=True)
class Not:
    """Logical NOT of a :class:`Predicate`."""

    inner: Predicate

    def evaluate(self, namespace: Mapping[str, object]) -> bool:
        return not self.inner.evaluate(namespace)


# A condition is either a leaf comparison or a Boolean combination of conditions.
# Order of precedence (highest → lowest): comparisons / parens / not, then `and`,
# then `or`. This matches Python's `and`/`or` precedence so policy authors who
# read it as a sentence get what they expect.
Predicate = Comparison | And | Or | Not
