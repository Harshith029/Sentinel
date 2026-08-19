"""Trust labels and the provenance lattice (BUILD_SPEC §4.1).

The label set, ordered by trust (most-trusted first)::

    SYSTEM > USER > AGENT > RETRIEVED_CONTENT

``RETRIEVED_CONTENT`` is the least-trusted / most-tainted label. A span's
provenance is a SET of these labels (the union over its transitive ancestry);
there is no other lattice algebra — the "join" of two provenances is set union.

This module is intentionally tiny and dependency-free: every later component
(provenance tracker, authorization engine, sanitizer, dashboard badges) imports
these constants so the lattice is defined in exactly ONE place and cannot drift.
"""
from __future__ import annotations

from typing import Final, Literal, get_args

# The canonical label type. Using a Literal (not an Enum) keeps Pydantic models
# JSON-trivial and lets the discriminated event union validate labels for free.
Label = Literal["SYSTEM", "USER", "AGENT", "RETRIEVED_CONTENT"]

# Ordered MOST-TRUSTED first. The ordering is documented by the spec; we encode
# it as data so trust comparisons never hard-code magic positions.
TRUST_ORDER: Final[tuple[Label, ...]] = ("SYSTEM", "USER", "AGENT", "RETRIEVED_CONTENT")

# Frozenset of every valid label, derived from the Literal so the two can never
# disagree. (get_args on the Literal returns the members in declaration order.)
ALL_LABELS: Final[frozenset[Label]] = frozenset(get_args(Label))

# The single tainting label. is_tainted(span) is exactly membership of this
# label in the span's effective provenance (spec §4.2).
RETRIEVED_CONTENT: Final[Label] = "RETRIEVED_CONTENT"
SYSTEM: Final[Label] = "SYSTEM"
USER: Final[Label] = "USER"
AGENT: Final[Label] = "AGENT"

# Sanity: TRUST_ORDER must enumerate exactly the Literal members, once each.
assert frozenset(TRUST_ORDER) == ALL_LABELS
assert len(TRUST_ORDER) == len(ALL_LABELS)


def trust_rank(label: Label) -> int:
    """Return the trust rank of ``label`` (0 = most trusted).

    Provenance itself is a set-union model (§4.2), so SENTINEL never needs a
    scalar "trust level" for the taint decision. This helper exists only for
    presentation concerns (e.g. ordering badges, picking the least-trusted label
    in a set for a human-readable summary) and must NOT be repurposed to collapse
    a provenance set into a single enum — that is the exact anti-pattern §2 bans.
    """
    return TRUST_ORDER.index(label)
