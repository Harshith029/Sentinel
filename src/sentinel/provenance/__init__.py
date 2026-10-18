"""Provenance taint tracking (BUILD_SPEC §4) — the differentiator.

Provenance is a SET of trust labels accumulated over a span's transitive
``derived_from`` ancestry; a span is tainted iff ``RETRIEVED_CONTENT`` is in
that set. There is no scalar "trust level" and no single mutable label — the
whole model is a set and a membership test, with the one principled way to
REMOVE taint being an explicit, auditable sanitizer (:mod:`sanitizer`).

Enforcement does not walk :mod:`graph` per call: the proxy keeps the union
incrementally (walking the graph made each call cost grow with the session).
:class:`~sentinel.provenance.graph.ProvenanceGraph` is the reference model the
incremental union is tested against.

Public surface:
* :mod:`model`     — :class:`ProvenanceNode` (§4.3).
* :mod:`graph`     — :class:`ProvenanceGraph`: ``effective_provenance`` (the
  transitive union) + the ``is_tainted`` predicate, cycle-safe.
* :mod:`sanitizer` — the ``Sanitizer`` protocol and the single concrete
  ``StructuredExtractor`` (§4.4).
"""
from __future__ import annotations
