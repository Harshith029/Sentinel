"""Trace replay — reconstruct the branching causality DAG (BUILD_SPEC Phase 1).

Spec: "``replay(trace_id)`` → full span DAG, walkable into the kill-chain view"
and the DoD requires that "a synthetic trace with a branch (one reasoning span →
two tool proposals) replays both branches with correct parentage and stable
``(trace_id, seq)`` ordering."

Two facts shape this module:

* Ordering is authoritative by ``(seq, span_id)`` — NEVER by store iteration or
  write-completion order. ``seq`` is unique per trace (the emitter serializes
  it); ``span_id`` is a defensive tie-breaker only.
* Each span has exactly one ``parent_span_id``, so the span graph is a forest; a
  "branch" is a parent with several children. The walk is still made cycle-safe
  with a visited-set (§4.2's requirement): MCP tool/conversation loops can
  accidentally create recursive parent references, and a naive walk that can
  infinite-loop is a defect. Cycles and dangling parents are detected and the
  trace is flagged ``malformed`` rather than crashing or looping forever.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.forensics.span import Span
from sentinel.forensics.store import ForensicStore


def _seq_key(span: Span) -> tuple[int, str]:
    return (span.seq, span.span_id)


@dataclass(frozen=True)
class TraceReplay:
    """An immutable, walkable reconstruction of one trace.

    ``ordered`` is every span by ``(seq, span_id)``. ``depth_first`` is a
    cycle-safe pre-order walk from the roots (siblings in seq order) — the shape
    the kill-chain view renders. ``malformed`` is True (with human-readable
    ``malformed_reasons``) if a cycle or dangling parent was detected.
    """

    trace_id: str
    ordered: list[Span]
    spans_by_id: dict[str, Span]
    roots: list[Span]
    children: dict[str, list[Span]]
    depth_first: list[Span]
    malformed: bool = False
    malformed_reasons: tuple[str, ...] = field(default_factory=tuple)

    def children_of(self, span_id: str) -> list[Span]:
        """Direct children of ``span_id`` in stable seq order (empty if none)."""
        return self.children.get(span_id, [])

    def get(self, span_id: str) -> Span | None:
        return self.spans_by_id.get(span_id)


def build_replay(trace_id: str, spans: list[Span]) -> TraceReplay:
    """Pure (store-free) replay builder — the testable core of :func:`replay`."""
    ordered = sorted(spans, key=_seq_key)
    spans_by_id: dict[str, Span] = {s.span_id: s for s in ordered}

    reasons: list[str] = []

    # Group real parent->child edges (parent present in this trace), seq-ordered.
    children: dict[str, list[Span]] = {}
    roots: list[Span] = []
    for span in ordered:
        pid = span.parent_span_id
        if pid is None:
            roots.append(span)
        elif pid in spans_by_id:
            children.setdefault(pid, []).append(span)
        else:
            # Parent referenced but absent → treat as a pseudo-root so the
            # subtree is still reachable, and flag the lineage malformed.
            roots.append(span)
            reasons.append(
                f"span {span.span_id} references absent parent {pid} (dangling)"
            )
    for kids in children.values():
        kids.sort(key=_seq_key)

    # Cycle-safe iterative pre-order DFS. The visited-set guarantees termination
    # even if parent references form a cycle (spec §4.2).
    visited: set[str] = set()
    depth_first: list[Span] = []
    stack: list[Span] = list(reversed(roots))  # reversed → pop in seq order
    while stack:
        span = stack.pop()
        if span.span_id in visited:
            # Re-entry can only happen via a malformed (cyclic) edge; stop branch.
            reasons.append(f"cycle/re-entry detected at span {span.span_id}")
            continue
        visited.add(span.span_id)
        depth_first.append(span)
        for child in reversed(children.get(span.span_id, [])):
            stack.append(child)

    # Any span never reached from a root is stranded in a cycle.
    unreachable = set(spans_by_id) - visited
    if unreachable:
        reasons.append(
            f"{len(unreachable)} span(s) unreachable from any root "
            f"(cycle): {sorted(unreachable)}"
        )

    return TraceReplay(
        trace_id=trace_id,
        ordered=ordered,
        spans_by_id=spans_by_id,
        roots=roots,
        children=children,
        depth_first=depth_first,
        malformed=bool(reasons),
        malformed_reasons=tuple(reasons),
    )


async def replay(store: ForensicStore, trace_id: str) -> TraceReplay:
    """Load every span for ``trace_id`` from ``store`` and reconstruct its DAG."""
    spans = await store.get_spans(trace_id)
    return build_replay(trace_id, spans)
