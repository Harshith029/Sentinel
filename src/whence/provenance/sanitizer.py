"""Sanitization — the ONE principled way to clear taint (BUILD_SPEC §4.4).

A ``Sanitizer`` is an explicit, named transformation across a trust boundary. We
ship exactly ONE concrete implementation — :class:`StructuredExtractor` — though
the protocol stays open for more (human-approval, allowlisted-extractor, etc.,
all DELIBERATELY OUT OF SCOPE).

The model that makes taint-clearing sound rather than a laundering hole:

* A sanitized value starts FRESH at the sanitizer's own trust label with an
  EMPTY ``derived_from`` — so :func:`effective_provenance` of the new node is
  just ``{output_label}``; its tainted source is NOT an ancestor.
* The tainted source is recorded in ``cleared_from`` for audit, and is NEVER
  traversed by the walk.
* Therefore sanitizing a value only clears THAT value. If the value is later
  recombined with a still-tainted sibling, the recombined span lists that
  sibling in ``derived_from`` and taint reappears (the recombination-regression
  case). A sanitized node cannot launder its neighbours.

Syntactic, not semantic: a schema-valid ``{"price": 999999}`` is structurally
trustworthy but STILL subject to argument-level policy (e.g. an ``amount`` cap).
The sanitizer and the authorization engine catch different classes of problem
and compose; the sanitizer never claims a value is "safe", only "well-formed".

Reconciliation with §4.4's ``-> Span | None`` sketch: provenance is carried by
:class:`ProvenanceNode` (§4.3 — it owns ``label``/``derived_from``/
``cleared_from``), so the concrete carrier here is :class:`SanitizedValue`,
which bundles the new node with the typed value that was extracted (the
"SYSTEM-trust typed value" the spec describes). ``None`` still means failure.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Protocol, runtime_checkable

from whence.labels import SYSTEM, Label
from whence.provenance.model import ProvenanceNode
from whence.tracing import new_span_id_hex


@runtime_checkable
class ExtractionSchema(Protocol):
    """A strict, total validator: returns a typed value on match, ``None`` on miss.

    Implementations MUST be syntactic and deterministic — no eval, no network,
    no free-text passthrough. A schema that returns its input unchanged would
    defeat the trust boundary and is forbidden.
    """

    # Read-only by design — a schema's name is its identity. Declared as a
    # property so a frozen-dataclass field (read-only) satisfies the protocol.
    @property
    def name(self) -> str: ...

    def extract(self, content: object) -> object | None: ...


@dataclass(frozen=True)
class DecimalAmountSchema:
    """Extract a SINGLE finite decimal (e.g. a price), optionally range-bounded.

    Free text such as ``"ignore previous instructions"`` or ``"buy now $12"``
    fails (it is not a lone decimal), which is the whole point: only a value that
    is structurally a number crosses the boundary.
    """

    name: str = "decimal_amount"
    minimum: Decimal | None = None
    maximum: Decimal | None = None

    def extract(self, content: object) -> Decimal | None:
        # bool is an int subclass — reject it explicitly so True/False is not a price.
        if isinstance(content, bool):
            return None
        if isinstance(content, int):
            value = Decimal(content)
        elif isinstance(content, Decimal):
            value = content
        elif isinstance(content, float):
            value = Decimal(str(content))  # via str → avoid binary-float artefacts
        elif isinstance(content, str):
            try:
                value = Decimal(content.strip())
            except (InvalidOperation, ValueError):
                return None
        else:
            return None
        if not value.is_finite():
            return None
        if self.minimum is not None and value < self.minimum:
            return None
        if self.maximum is not None and value > self.maximum:
            return None
        return value


@dataclass(frozen=True)
class IsoDateSchema:
    """Extract a strict ISO-8601 calendar date (``YYYY-MM-DD``)."""

    name: str = "iso_date"

    def extract(self, content: object) -> date | None:
        if not isinstance(content, str):
            return None
        try:
            return date.fromisoformat(content.strip())
        except ValueError:
            return None


@dataclass(frozen=True)
class SanitizedValue:
    """The result of a successful sanitization: a fresh node + the typed value."""

    node: ProvenanceNode
    value: object


@runtime_checkable
class Sanitizer(Protocol):
    """An explicit, named transformation that may clear taint across a boundary."""

    name: str
    output_label: Label

    def sanitize(
        self, tainted: ProvenanceNode, schema: ExtractionSchema, *, content: object
    ) -> SanitizedValue | None: ...


class StructuredExtractor:
    """The single concrete sanitizer: validate untrusted content against a strict
    schema; on success emit a fresh SYSTEM-trust value whose lineage is CUT.

    You can trust a number you parsed out of a malicious page — but only the
    number, and only because the schema proved it is a number.
    """

    name: str = "structured_extractor"
    # A value we successfully parsed is structurally trustworthy → SYSTEM.
    output_label: Label = SYSTEM

    def __init__(self, *, id_factory: Callable[[], str] = new_span_id_hex) -> None:
        # Injectable id source keeps audit ids deterministic in tests.
        self._new_id = id_factory

    def sanitize(
        self, tainted: ProvenanceNode, schema: ExtractionSchema, *, content: object
    ) -> SanitizedValue | None:
        extracted = schema.extract(content)
        if extracted is None:
            # Schema MISMATCH → sanitization FAILS → taint persists (return None,
            # so the caller keeps using the original tainted node).
            return None

        # Schema MATCH → a brand-new node at the sanitizer's own trust label.
        # The crucial line is derived_from=(): the new value inherits NONE of the
        # tainted source's ancestry. The source is recorded in cleared_from for
        # audit only and is never followed by effective_provenance — that is how,
        # and the ONLY way, taint is cleared.
        cleared = ProvenanceNode(
            span_id=self._new_id(),
            label=self.output_label,
            derived_from=(),
            cleared_from=tainted.span_id,
        )
        return SanitizedValue(node=cleared, value=extracted)


# --- schema registry ----------------------------------------------------------
#
# Policy names a schema as a STRING (``declassify: {schema: decimal_amount}``),
# so the string has to resolve to a real validator. The registry is closed on
# purpose: an operator can only select from schemas that ship with Whence and
# have been reviewed. Letting policy name an arbitrary import path would make
# the trust boundary configurable by whoever can write policy, which is exactly
# the thing declassification must not become.
_SCHEMAS: dict[str, ExtractionSchema] = {
    DecimalAmountSchema().name: DecimalAmountSchema(),
    IsoDateSchema().name: IsoDateSchema(),
}


def schema_names() -> tuple[str, ...]:
    """Every schema a policy may name, for validation and error messages."""
    return tuple(sorted(_SCHEMAS))


def get_schema(name: str) -> ExtractionSchema:
    """Resolve a policy-declared schema name. Raises ``KeyError`` if unknown."""
    return _SCHEMAS[name]
