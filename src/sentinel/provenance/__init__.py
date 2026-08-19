"""Provenance taint tracking (BUILD_SPEC §4) — the differentiator.

Provenance is a SET of trust labels accumulated over a span's transitive
``derived_from`` ancestry; a span is tainted iff ``RETRIEVED_CONTENT`` is in
that set. There is no scalar "trust level" and no single mutable label — the
whole model is a set and a membership test, computed by a real graph walk
(:mod:`graph`), with the one principled way to REMOVE taint being an explicit,
auditable sanitizer (:mod:`sanitizer`).

Public surface:
* :mod:`model`     — :class:`ProvenanceNode` (§4.3).
* :mod:`graph`     — :class:`ProvenanceGraph`: ``effective_provenance`` (the
  transitive union) + the ``is_tainted`` predicate, cycle-safe.
* :mod:`sanitizer` — the ``Sanitizer`` protocol and the single concrete
  ``StructuredExtractor`` (§4.4).
"""
from __future__ import annotations
