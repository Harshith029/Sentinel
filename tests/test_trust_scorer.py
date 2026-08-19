"""Phase 3 unit tests: smoothed-probability math, penalties, quarantine, denials."""
from __future__ import annotations

import pytest

from sentinel.forensics.emitter import SpanEmitter
from sentinel.forensics.replay import replay
from sentinel.forensics.store import InMemoryForensicStore
from sentinel.trust.config import TrustConfig, load_default_trust_config
from sentinel.trust.scorer import (
    START,
    TrustScorer,
    transition_penalty,
    transition_stats,
)

TID = "a" * 32


def _scorer(config: TrustConfig | None = None) -> tuple[TrustScorer, InMemoryForensicStore]:
    store = InMemoryForensicStore()
    scorer = TrustScorer(SpanEmitter(store), config or load_default_trust_config())
    return scorer, store


# --- pure math (hand-computed, independent of the scorer) --------------------

def test_first_transition_is_certain() -> None:
    # Empty history, START→A: P = (0+1)/(0+1) = 1.0, V = 1, chance = 1.0.
    stats = transition_stats([], START, "A")
    assert stats.probability == pytest.approx(1.0)
    assert stats.vocab_size == 1
    assert stats.relative == pytest.approx(1.0)
    assert transition_penalty(stats, 25.0) == pytest.approx(0.0)


def test_deterministic_repeat_is_at_or_above_chance() -> None:
    # A always → B: P = (1+1)/(1+1) = 1.0 → free.
    stats = transition_stats([("A", "B")], "A", "B")
    assert stats.probability == pytest.approx(1.0)
    assert transition_penalty(stats, 25.0) == pytest.approx(0.0)


def test_at_chance_alternative_is_free() -> None:
    # A → B or C equally; B is exactly at chance (P=0.5, chance=0.5) → free.
    history = [("A", "B"), ("A", "C")]
    stats = transition_stats(history, "A", "B")
    assert stats.probability == pytest.approx(0.5)
    assert stats.chance == pytest.approx(0.5)
    assert transition_penalty(stats, 25.0) == pytest.approx(0.0)


def test_below_chance_transition_is_penalized() -> None:
    # A usually → B (twice) or C (once); now A → D (novel).
    # from(A)=3, pair(A,D)=0, V=|{B,C,D}|=3 → P=1/6, chance=1/3, relative=0.5.
    history = [("A", "B"), ("A", "B"), ("A", "C")]
    stats = transition_stats(history, "A", "D")
    assert stats.probability == pytest.approx(1 / 6)
    assert stats.chance == pytest.approx(1 / 3)
    assert stats.relative == pytest.approx(0.5)
    assert transition_penalty(stats, 25.0) == pytest.approx(12.5)  # 25 * (1 - 0.5)


def test_penalty_is_bounded_by_max() -> None:
    # A seen many times → B; A → Z is near-impossible → penalty approaches max.
    history = [("A", "B")] * 20
    stats = transition_stats(history, "A", "Z")
    assert 0.0 < transition_penalty(stats, 25.0) <= 25.0


# --- scorer behaviour --------------------------------------------------------

async def test_transition_span_records_probability_and_arithmetic() -> None:
    scorer, _ = _scorer()
    span = await scorer.record_tool_transition("agent", "search", trace_id=TID)
    assert span.event_type == "TrustUpdated"
    assert span.payload.smoothed_probability == pytest.approx(1.0)  # first tool
    assert span.payload.delta == pytest.approx(0.0)
    assert scorer.score("agent") == pytest.approx(100.0)
    assert "add-one smoothed" in span.payload.reason


async def test_hard_signal_penalties_are_fixed_weights() -> None:
    cfg = load_default_trust_config()
    scorer, _ = _scorer(cfg)
    blocked = await scorer.record_blocked_call("agent", "send_email", reason="policy", trace_id=TID)
    assert blocked.payload.delta == pytest.approx(-cfg.blocked_call_penalty)
    assert blocked.payload.smoothed_probability is None  # not probability-based
    injected = await scorer.record_injection("agent", target="user_prompt", trace_id=TID)
    assert injected.payload.delta == pytest.approx(-cfg.injection_detected_penalty)


async def test_quarantine_fires_once_below_threshold() -> None:
    cfg = load_default_trust_config()  # blocked=30, threshold=40
    scorer, store = _scorer(cfg)
    # 100 → 70 → 40 (not yet, 40 is not < 40) → 10 (< 40 → quarantine)
    await scorer.record_blocked_call("agent", "t", reason="r", trace_id=TID)
    await scorer.record_blocked_call("agent", "t", reason="r", trace_id=TID)
    assert scorer.is_quarantined("agent") is False
    await scorer.record_blocked_call("agent", "t", reason="r", trace_id=TID)
    assert scorer.is_quarantined("agent") is True

    # Further penalties must NOT emit a second AgentQuarantined.
    await scorer.record_blocked_call("agent", "t", reason="r", trace_id=TID)
    rep = await replay(store, TID)
    quarantines = [s for s in rep.ordered if s.event_type == "AgentQuarantined"]
    assert len(quarantines) == 1
    assert quarantines[0].payload.score_at_quarantine < cfg.quarantine_threshold


async def test_quarantined_block_is_visible_and_score_unchanged() -> None:
    cfg = load_default_trust_config()
    scorer, store = _scorer(cfg)
    for _ in range(4):  # drive below threshold
        await scorer.record_blocked_call("agent", "t", reason="r", trace_id=TID)
    assert scorer.is_quarantined("agent") is True
    score_at_quarantine = scorer.score("agent")

    block = await scorer.record_quarantined_block("agent", "send_email", trace_id=TID)
    assert block.event_type == "ToolBlocked"
    assert block.payload.blocked_by == "quarantine"
    assert scorer.score("agent") == pytest.approx(score_at_quarantine)  # unchanged


async def test_reset_clears_state() -> None:
    scorer, _ = _scorer()
    for _ in range(4):
        await scorer.record_blocked_call("agent", "t", reason="r", trace_id=TID)
    assert scorer.is_quarantined("agent") is True
    scorer.reset("agent")
    assert scorer.is_quarantined("agent") is False
    assert scorer.score("agent") == pytest.approx(100.0)
