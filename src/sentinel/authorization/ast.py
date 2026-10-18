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
            # Never echo the operand: this message reaches RuleEvaluation.detail,
            # which is persisted and served. Report the type, not the value.
            f"operand is not numeric for ordered comparison: {type(value).__name__}"
        )
    try:
        number = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ConditionError(
            f"operand is not a valid number: {type(value).__name__}"
        ) from exc
    # NaN and the infinities are not amounts. "-Infinity" used to pass a cap
    # such as `amount >= max_amount`; a non-finite operand is now an error,
    # which the engine turns into a deny.
    if not number.is_finite():
        raise ConditionError("operand is not a finite number")
    return number


def _numeric_text(value: object) -> bool:
    """A string an ordered comparison would accept as a number."""
    if not isinstance(value, str):
        return False
    try:
        return Decimal(value.strip()).is_finite()
    except (InvalidOperation, ValueError):
        return False


def _equal(left: object, right: object) -> bool:
    # Booleans equal only booleans. Python's True == 1 used to make
    # `flag == 1` match a boolean argument.
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left is right
    # Numbers compare by value (12 == 12.0 == Decimal('12')), and so does a
    # numeric string against a number, exactly as `<` and `>=` already treat
    # it. Otherwise "1000" escaped `amount == 1000` but not `amount >= 1000`.
    if (_is_number(left) or _numeric_text(left)) and (_is_number(right) or _numeric_text(right)):
        if _is_number(left) or _is_number(right):
            return _to_decimal(left) == _to_decimal(right)
    # Everything else, including frozenset == frozenset for provenance, uses
    # Python equality.
    return bool(left == right)


def _contains(container: object, item: object) -> bool:
    # Strings are deliberately NOT collections in the policy language:
    # ``"evil.test" in "evil.test.example"`` is substring matching, not an
    # allow-list membership check. A scalar config value is a configuration
    # error and must be denied by the engine's fail-closed path.
    if isinstance(container, (frozenset, set, list, tuple)):
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
class BoolLiteral(Operand):
    """``true`` or ``false``. Before these existed, both parsed as variables."""

    value: bool

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


def comparand_names(predicate: Comparison | And | Or | Not) -> frozenset[str]:
    """Variables used as the RIGHT-hand side of any comparison in ``predicate``.

    By the policy language's convention the left side describes the call and
    the right side is what the operator allows: in ``recipient_domain not in
    allowed_domains`` and ``amount >= max_amount``, the comparands are
    ``allowed_domains`` and ``max_amount``. The engine never lets a call's own
    arguments supply these names (see :class:`AuthorizationEngine`).
    """
    names: set[str] = set()
    pending: list[Predicate] = [predicate]
    while pending:  # iterative: a long and/or chain must not hit the recursion limit
        node = pending.pop()
        if isinstance(node, Comparison):
            if isinstance(node.right, Variable):
                names.add(node.right.name)
        elif isinstance(node, Not):
            pending.append(node.inner)
        else:
            pending.extend((node.left, node.right))
    return frozenset(names)


def subject_names(predicate: Comparison | And | Or | Not) -> frozenset[str]:
    """Variables used as the LEFT-hand side of any comparison: the call's fields."""
    names: set[str] = set()
    pending: list[Predicate] = [predicate]
    while pending:
        node = pending.pop()
        if isinstance(node, Comparison):
            if isinstance(node.left, Variable):
                names.add(node.left.name)
        elif isinstance(node, Not):
            pending.append(node.inner)
        else:
            pending.extend((node.left, node.right))
    return frozenset(names)


def predicate_depth(predicate: Comparison | And | Or | Not) -> int:
    """Nesting depth of ``predicate``: 1 for a lone comparison.

    A left-deep ``a and b and c`` chain is as deep as it is long, and
    evaluation recurses once per level, so the loader bounds this.
    """
    deepest = 0
    pending: list[tuple[Predicate, int]] = [(predicate, 1)]
    while pending:
        node, depth = pending.pop()
        deepest = max(deepest, depth)
        if isinstance(node, Not):
            pending.append((node.inner, depth + 1))
        elif isinstance(node, (And, Or)):
            pending.extend(((node.left, depth + 1), (node.right, depth + 1)))
    return deepest


# A condition is either a leaf comparison or a Boolean combination of conditions.
# Order of precedence (highest → lowest): comparisons / parens / not, then `and`,
# then `or`. This matches Python's `and`/`or` precedence so policy authors who
# read it as a sentence get what they expect.
Predicate = Comparison | And | Or | Not
