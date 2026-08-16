"""Phase 1 DoD: replay reconstructs BRANCHING causality, ordered by (trace_id, seq)."""
from __future__ import annotations

from collections.abc import Callable

from whence.forensics.emitter import SpanEmitter
from whence.forensics.events import InputReceived, ToolCallProposed, ToolExecuted
from whence.forensics.replay import build_replay, replay
from whence.forensics.span import Span
from whence.forensics.store import ForensicStore

TRACE_A = "a" * 32


async def test_branch_trace_replays_both_branches(store: ForensicStore) -> None:
    """The headline DoD: one reasoning span → TWO tool proposals, each with a
    child execution, replays both branches with correct parentage and stable
    (trace_id, seq) ordering — identically across in-memory and Cosmos stores.
    """
    emitter = SpanEmitter(store)
    tid = emitter.new_trace_id()

    s0 = await emitter.emit(
        InputReceived(origin_label="USER", content="do two things"), trace_id=tid
    )
    # Branch 1
    s1 = await emitter.emit(
        ToolCallProposed(tool_name="web_fetch", arguments={"url": "https://a"}),
        trace_id=tid,
        parent_span_id=s0.span_id,
    )
    s2 = await emitter.emit(
        ToolExecuted(
            tool_name="web_fetch",
            arguments={"url": "https://a"},
            result_label="RETRIEVED_CONTENT",
            result_summary="page A",
        ),
        trace_id=tid,
        parent_span_id=s1.span_id,
    )
    # Branch 2 — SECOND child of the same reasoning span s0
    s3 = await emitter.emit(
        ToolCallProposed(tool_name="get_customer_record", arguments={"id": 7}),
        trace_id=tid,
        parent_span_id=s0.span_id,
    )
    s4 = await emitter.emit(
        ToolExecuted(
            tool_name="get_customer_record",
            arguments={"id": 7},
            result_label="RETRIEVED_CONTENT",
            result_summary="record 7",
        ),
        trace_id=tid,
        parent_span_id=s3.span_id,
    )

    rep = await replay(store, tid)

    # Stable (trace_id, seq) ordering, regardless of store/backend.
    assert [s.seq for s in rep.ordered] == [0, 1, 2, 3, 4]
    assert rep.malformed is False

    # Single reasoning root with TWO children — the branch.
    assert [r.span_id for r in rep.roots] == [s0.span_id]
    assert [c.span_id for c in rep.children_of(s0.span_id)] == [s1.span_id, s3.span_id]

    # Each branch's execution hangs off its own proposal.
    assert [c.span_id for c in rep.children_of(s1.span_id)] == [s2.span_id]
    assert [c.span_id for c in rep.children_of(s3.span_id)] == [s4.span_id]

    # Correct parentage end-to-end.
    assert rep.get(s1.span_id).parent_span_id == s0.span_id  # type: ignore[union-attr]
    assert rep.get(s2.span_id).parent_span_id == s1.span_id  # type: ignore[union-attr]
    assert rep.get(s3.span_id).parent_span_id == s0.span_id  # type: ignore[union-attr]
    assert rep.get(s4.span_id).parent_span_id == s3.span_id  # type: ignore[union-attr]

    # Pre-order depth-first walk visits branch 1 fully, then branch 2.
    assert [s.span_id for s in rep.depth_first] == [
        s0.span_id, s1.span_id, s2.span_id, s3.span_id, s4.span_id
    ]


def test_replay_orders_by_seq_not_input_order(make_span: Callable[..., Span]) -> None:
    # Pass spans deliberately shuffled; ordering must come from seq, never input.
    spans = [
        make_span(trace_id=TRACE_A, seq=3),
        make_span(trace_id=TRACE_A, seq=0),
        make_span(trace_id=TRACE_A, seq=2),
        make_span(trace_id=TRACE_A, seq=1),
    ]
    rep = build_replay(TRACE_A, spans)
    assert [s.seq for s in rep.ordered] == [0, 1, 2, 3]


def test_replay_empty_trace(make_span: Callable[..., Span]) -> None:
    rep = build_replay(TRACE_A, [])
    assert rep.ordered == []
    assert rep.roots == []
    assert rep.depth_first == []
    assert rep.malformed is False


def test_replay_flags_dangling_parent(make_span: Callable[..., Span]) -> None:
    # Parent referenced but absent → treated as a pseudo-root and flagged.
    orphan = make_span(trace_id=TRACE_A, seq=0, span_id="1" * 16, parent_span_id="9" * 16)
    rep = build_replay(TRACE_A, [orphan])
    assert rep.malformed is True
    assert any("dangling" in r for r in rep.malformed_reasons)
    assert [s.span_id for s in rep.roots] == ["1" * 16]   # still reachable
    assert [s.span_id for s in rep.depth_first] == ["1" * 16]


def test_replay_is_cycle_safe(make_span: Callable[..., Span]) -> None:
    # Mutual parents (A<-B, B<-A): neither is a root, so the cycle is unreachable.
    # build_replay must TERMINATE (no infinite recursion) and flag malformed.
    a = make_span(trace_id=TRACE_A, seq=0, span_id="a" * 16, parent_span_id="b" * 16)
    b = make_span(trace_id=TRACE_A, seq=1, span_id="b" * 16, parent_span_id="a" * 16)
    rep = build_replay(TRACE_A, [a, b])
    assert rep.malformed is True
    assert rep.roots == []
    assert any("unreachable" in r for r in rep.malformed_reasons)
