"""Phase 2A: effective_provenance is a REAL transitive union, cycle-safe."""
from __future__ import annotations

import pytest

from whence.provenance.graph import ProvenanceGraph
from whence.provenance.model import ProvenanceNode


def _node(span_id: str, label: str, *parents: str) -> ProvenanceNode:
    return ProvenanceNode(span_id=span_id, label=label, derived_from=tuple(parents))  # type: ignore[arg-type]


def test_single_node_provenance_is_its_own_label() -> None:
    g = ProvenanceGraph([_node("a", "USER")])
    assert g.effective_provenance("a").labels == frozenset({"USER"})
    assert g.is_tainted("a") is False


def test_transitive_union_over_chain() -> None:
    # u(USER) <- doc(RETRIEVED_CONTENT) <- summary(AGENT)
    g = ProvenanceGraph(
        [
            _node("u", "USER"),
            _node("doc", "RETRIEVED_CONTENT", "u"),
            _node("summary", "AGENT", "doc"),
        ]
    )
    # The union must include the RETRIEVED_CONTENT *ancestor*, not just the
    # most-recent node's AGENT label.
    assert g.effective_provenance("summary").labels == frozenset(
        {"USER", "AGENT", "RETRIEVED_CONTENT"}
    )
    assert g.is_tainted("summary") is True


def test_taint_is_derived_not_read_off_latest_node() -> None:
    # The latest node is SYSTEM, yet a RETRIEVED_CONTENT ancestor still taints.
    g = ProvenanceGraph(
        [
            _node("bad", "RETRIEVED_CONTENT"),
            _node("top", "SYSTEM", "bad"),
        ]
    )
    assert g.is_tainted("top") is True  # would be False if we read top.label only


def test_diamond_is_not_flagged_malformed() -> None:
    # R derives from A and B, both deriving from a shared C — a legal DAG diamond.
    g = ProvenanceGraph(
        [
            _node("C", "USER"),
            _node("A", "AGENT", "C"),
            _node("B", "RETRIEVED_CONTENT", "C"),
            _node("R", "AGENT", "A", "B"),
        ]
    )
    result = g.effective_provenance("R")
    assert result.malformed is False  # diamond != cycle
    assert result.labels == frozenset({"USER", "AGENT", "RETRIEVED_CONTENT"})


def test_cycle_is_detected_and_terminates() -> None:
    # a <- b <- a : a recursive derived_from reference.
    g = ProvenanceGraph(
        [
            _node("a", "AGENT", "b"),
            _node("b", "USER", "a"),
        ]
    )
    result = g.effective_provenance("a")  # must NOT hang
    assert result.malformed is True
    assert g.is_tainted("a") is True  # fail-closed on malformed lineage


def test_self_loop_is_cycle_safe() -> None:
    g = ProvenanceGraph([_node("a", "AGENT", "a")])
    result = g.effective_provenance("a")
    assert result.malformed is True


def test_missing_ancestor_is_failclosed() -> None:
    g = ProvenanceGraph([_node("a", "AGENT", "ghost")])
    result = g.effective_provenance("a")
    assert result.missing == ("ghost",)
    assert g.is_tainted("a") is True  # cannot prove clean → tainted


def test_write_once_conflict_rejected() -> None:
    g = ProvenanceGraph([_node("a", "USER")])
    g.add(_node("a", "USER"))  # identical re-add is fine
    with pytest.raises(ValueError, match="write-once"):
        g.add(_node("a", "AGENT"))  # conflicting label for same span_id
