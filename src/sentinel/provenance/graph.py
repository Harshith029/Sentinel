"""The provenance graph and the taint predicate (BUILD_SPEC §4.2).

```
is_tainted(span)          := RETRIEVED_CONTENT in effective_provenance(span)
effective_provenance(span) := union of labels over transitive derived_from ancestry
```

:meth:`ProvenanceGraph.effective_provenance` is a REAL transitive graph walk: it
starts at a span and unions the ``label`` of every node reachable through
``derived_from`` edges. It does NOT read the most-recent node's label and does
NOT consult any cached taint flag — taint is *derived* from the ancestry every
time, which is exactly why "summarize a fetched doc then email it" stays tainted
(the RETRIEVED_CONTENT ancestor is still in the union) and why a sanitized value
cannot launder a tainted sibling (the sibling remains an ancestor of the
recombined node).

Cycle safety (§4.2): lineage SHOULD be a DAG, but tool/conversation loops can
create recursive ``derived_from`` references. The walk uses a three-colour
visited scheme (white→gray→black):

* gray  = node is on the CURRENT path. Re-entering a gray node is a back-edge =
  a cycle → flag ``malformed`` and stop that branch (no infinite recursion).
* black = node already fully unioned via another path. Re-reaching a black node
  is a legitimate DAG **diamond** (two paths to a shared ancestor) → skip it,
  do NOT flag malformed.

A single visited-set (as in Phase 1's single-parent span tree) cannot tell a
diamond from a cycle; provenance is a true multi-parent DAG, so the colour
scheme is required to avoid both infinite loops AND false malformed flags.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from sentinel.labels import RETRIEVED_CONTENT, Label
from sentinel.provenance.model import ProvenanceNode


@dataclass(frozen=True)
class ProvenanceResult:
    """Outcome of an :meth:`ProvenanceGraph.effective_provenance` walk.

    ``labels`` is the union over the reachable ancestry. ``malformed`` is True if
    a cycle was detected; ``missing`` lists any referenced ancestor absent from
    the graph (a dangling edge). Both are anomalies that :meth:`is_tainted`
    treats as fail-closed.
    """

    labels: frozenset[Label]
    malformed: bool = False
    missing: tuple[str, ...] = field(default_factory=tuple)

    @property
    def anomalous(self) -> bool:
        return self.malformed or bool(self.missing)


class ProvenanceGraph:
    """An append-only collection of :class:`ProvenanceNode`, walkable for taint."""

    def __init__(self, nodes: Iterable[ProvenanceNode] | None = None) -> None:
        self._nodes: dict[str, ProvenanceNode] = {}
        for node in nodes or ():
            self.add(node)

    def add(self, node: ProvenanceNode) -> ProvenanceNode:
        """Register ``node``. Re-adding an identical node is a no-op; a conflicting
        node for an existing span_id is rejected (provenance is write-once)."""
        existing = self._nodes.get(node.span_id)
        if existing is not None and existing != node:
            raise ValueError(
                f"conflicting provenance for span_id {node.span_id!r}: "
                "nodes are write-once"
            )
        self._nodes[node.span_id] = node
        return node

    def __contains__(self, span_id: object) -> bool:
        return span_id in self._nodes

    def get(self, span_id: str) -> ProvenanceNode | None:
        return self._nodes.get(span_id)

    def effective_provenance(self, span_id: str) -> ProvenanceResult:
        """Union of trust labels over the transitive ``derived_from`` ancestry.

        Iterative, cycle-safe (three-colour) DFS — see the module docstring.
        """
        labels: set[Label] = set()
        gray: set[str] = set()   # on the current DFS path
        black: set[str] = set()  # fully processed (subtree complete)
        missing: set[str] = set()
        malformed = False

        # Stack frames are (span_id, is_exit). The exit frame flips gray→black
        # AFTER a node's whole subtree has been visited, which is what lets us
        # distinguish a back-edge (cycle) from a shared ancestor (diamond).
        stack: list[tuple[str, bool]] = [(span_id, False)]
        while stack:
            sid, is_exit = stack.pop()
            if is_exit:
                gray.discard(sid)
                black.add(sid)
                continue
            if sid in gray:
                malformed = True  # back-edge to a node on the current path = cycle
                continue
            if sid in black:
                continue  # already unioned via another path = legal DAG diamond
            node = self._nodes.get(sid)
            if node is None:
                missing.add(sid)
                black.add(sid)
                continue
            gray.add(sid)
            stack.append((sid, True))  # schedule the gray→black transition
            labels.add(node.label)
            for parent in node.derived_from:
                stack.append((parent, False))

        return ProvenanceResult(
            labels=frozenset(labels),
            malformed=malformed,
            missing=tuple(sorted(missing)),
        )

    def is_tainted(self, span_id: str) -> bool:
        """``RETRIEVED_CONTENT`` in the effective provenance — or any anomaly.

        Fail-closed: a malformed (cyclic) or dangling lineage cannot be PROVEN
        clean, so it is treated as tainted. The authorization engine therefore
        never green-lights a call whose provenance we could not fully compute.
        """
        result = self.effective_provenance(span_id)
        if result.anomalous:
            return True
        return RETRIEVED_CONTENT in result.labels
