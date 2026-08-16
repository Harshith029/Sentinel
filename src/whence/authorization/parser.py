"""Predicate parser: text → typed :mod:`ast` — strictly, with NO ``eval``.

A tiny tokenizer plus a recursive-descent parser turn a policy predicate string
into a :class:`~whence.authorization.ast.Predicate`. The grammar is::

    condition  := or_expr
    or_expr    := and_expr ( "or" and_expr )*
    and_expr   := not_expr ( "and" not_expr )*
    not_expr   := "not" not_expr | atom
    atom       := comparison | "(" condition ")"
    comparison := operand cmp_op operand
    cmp_op     := "==" | "!=" | "<" | ">=" | "in" | "not" "in"
    operand    := number | string | label | variable | set
    set        := "{" ( operand ("," operand)* )? "}"

Operator precedence (highest → lowest): comparisons, parens, ``not``,
``and``, ``or`` — matching Python so policy authors who read the rule as a
sentence get what they expect.

Anything outside this grammar — an unsupported operator (``>``, ``<=``, ``=``),
an unbalanced ``{`` / ``(``, a missing operand, trailing tokens — raises
:class:`PolicyParseError`. The loader calls this at LOAD time, so a malformed
rule can never reach runtime evaluation.

Backwards compatibility: every single-comparison predicate that parsed before
still parses (the single comparison is the trivial ``or_expr → and_expr →
not_expr → atom``); existing policies are untouched.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Final, cast

from whence.authorization.ast import (
    And,
    Comparison,
    LabelLiteral,
    Not,
    NumberLiteral,
    Operand,
    Operator,
    Or,
    Predicate,
    SetLiteral,
    StringLiteral,
    Variable,
)
from whence.labels import ALL_LABELS, Label


class PolicyParseError(ValueError):
    """Raised when a predicate string is not valid policy-condition syntax."""


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str


_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    r"""
      (?P<WS>\s+)
    | (?P<NUMBER>\d+(?:\.\d+)?)
    | (?P<STRING>"[^"]*"|'[^']*')
    | (?P<OP>==|!=|>=|<)
    | (?P<LBRACE>\{)
    | (?P<RBRACE>\})
    | (?P<LPAREN>\()
    | (?P<RPAREN>\))
    | (?P<COMMA>,)
    | (?P<WORD>[A-Za-z_][A-Za-z0-9_]*)
    """,
    re.VERBOSE,
)


def _tokenize(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    pos = 0
    while pos < len(text):
        match = _TOKEN_RE.match(text, pos)
        if match is None:
            raise PolicyParseError(
                f"unexpected character {text[pos]!r} at position {pos} in {text!r}"
            )
        pos = match.end()
        kind = match.lastgroup
        assert kind is not None
        if kind == "WS":
            continue
        value = match.group()
        if kind == "WORD":
            if value == "in":
                kind = "IN"
            elif value == "not":
                kind = "NOT"
            elif value == "and":
                kind = "AND"
            elif value == "or":
                kind = "OR"
            elif value in ALL_LABELS:
                kind = "LABEL"
            else:
                kind = "VAR"
        tokens.append(_Token(kind, value))
    return tokens


class _Parser:
    def __init__(self, tokens: list[_Token], text: str) -> None:
        self._tokens = tokens
        self._text = text
        self._pos = 0

    def _peek(self) -> _Token | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _advance(self) -> _Token:
        token = self._peek()
        if token is None:
            raise PolicyParseError(f"unexpected end of predicate in {self._text!r}")
        self._pos += 1
        return token

    def parse_condition(self) -> Predicate:
        predicate = self._parse_or()
        if self._peek() is not None:
            raise PolicyParseError(
                f"trailing tokens after predicate in {self._text!r}"
            )
        return predicate

    # --- precedence climb (lowest to highest) --------------------------------

    def _parse_or(self) -> Predicate:
        left = self._parse_and()
        while self._peek() is not None and self._peek().kind == "OR":  # type: ignore[union-attr]
            self._advance()  # consume "or"
            right = self._parse_and()
            left = Or(left=left, right=right)
        return left

    def _parse_and(self) -> Predicate:
        left = self._parse_not()
        while self._peek() is not None and self._peek().kind == "AND":  # type: ignore[union-attr]
            self._advance()  # consume "and"
            right = self._parse_not()
            left = And(left=left, right=right)
        return left

    def _parse_not(self) -> Predicate:
        token = self._peek()
        # `not` is only a unary boolean here when it is NOT immediately followed
        # by `in` (which is the binary comparison operator `not in`). A bare
        # `not` followed by a comparison (or a parenthesised predicate) is the
        # Boolean negation.
        if (
            token is not None
            and token.kind == "NOT"
            and self._pos + 1 < len(self._tokens)
            and self._tokens[self._pos + 1].kind != "IN"
        ):
            self._advance()  # consume "not"
            return Not(inner=self._parse_not())
        return self._parse_atom()

    def _parse_atom(self) -> Predicate:
        token = self._peek()
        if token is not None and token.kind == "LPAREN":
            self._advance()  # consume "("
            inner = self._parse_or()
            close = self._advance()
            if close.kind != "RPAREN":
                raise PolicyParseError(
                    f"expected ')' to close group in {self._text!r}"
                )
            return inner
        # Otherwise it's a leaf comparison.
        return self._parse_comparison()

    def _parse_comparison(self) -> Comparison:
        left = self._parse_operand()
        op = self._parse_operator()
        right = self._parse_operand()
        return Comparison(left=left, op=op, right=right)

    def _parse_operator(self) -> Operator:
        token = self._advance()
        if token.kind == "OP":
            return cast(Operator, token.value)
        if token.kind == "IN":
            return "in"
        if token.kind == "NOT":
            nxt = self._advance()
            if nxt.kind != "IN":
                raise PolicyParseError(
                    f"expected 'in' after 'not' in {self._text!r}"
                )
            return "not in"
        raise PolicyParseError(
            f"expected an operator but found {token.value!r} in {self._text!r}"
        )

    def _parse_operand(self) -> Operand:
        token = self._peek()
        if token is None:
            raise PolicyParseError(f"expected an operand in {self._text!r}")
        if token.kind == "LBRACE":
            return self._parse_set()
        return self._parse_primary()

    def _parse_primary(self) -> Operand:
        token = self._advance()
        if token.kind == "NUMBER":
            try:
                return NumberLiteral(Decimal(token.value))
            except InvalidOperation as exc:  # pragma: no cover - regex guards this
                raise PolicyParseError(f"invalid number {token.value!r}") from exc
        if token.kind == "STRING":
            return StringLiteral(token.value[1:-1])
        if token.kind == "LABEL":
            # token.value is one of ALL_LABELS, so it is a valid Label.
            return LabelLiteral(cast(Label, token.value))
        if token.kind == "VAR":
            return Variable(token.value)
        raise PolicyParseError(
            f"expected a value but found {token.value!r} in {self._text!r}"
        )

    def _parse_set(self) -> SetLiteral:
        self._advance()  # consume '{'
        members: list[Operand] = []
        if self._peek() is not None and self._peek().kind == "RBRACE":  # type: ignore[union-attr]
            self._advance()
            return SetLiteral(members=())
        while True:
            members.append(self._parse_primary())
            nxt = self._advance()
            if nxt.kind == "RBRACE":
                break
            if nxt.kind != "COMMA":
                raise PolicyParseError(
                    f"expected ',' or '}}' in set literal in {self._text!r}"
                )
        return SetLiteral(members=tuple(members))


def parse_condition(text: str) -> Predicate:
    """Parse a predicate string into a typed :class:`Predicate` (or raise).

    The return type widened from :class:`Comparison` to :class:`Predicate`
    when compound operators landed; a single-comparison predicate still parses
    to a :class:`Comparison` instance (i.e. ``isinstance(p, Comparison)`` is
    still true for legacy rules), so callers that only matched on Comparison
    are unaffected for existing policies.
    """
    if not text or not text.strip():
        raise PolicyParseError("empty predicate")
    return _Parser(_tokenize(text), text).parse_condition()
