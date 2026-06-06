"""Phase 3 Definition of Done (BUILD_SPEC §Phase 3).

Baseline → anomalous burst trajectory (score matches the smoothed-probability
math at EVERY step), quarantine fires at the defined point, post-quarantine
attempts still emit visible denials, and concurrent updates to one agent are
race-free.
"""
from __future__ import annotations

import asyncio
from collections import deque

import pytest

from sentinel.forensics.emitter import SpanEmitter
from sentinel.forensics.replay import replay
from sentinel.forensics.span import Span
from sentinel.forensics.store import InMemoryForensicStore
from sentinel.trust.config import TrustConfig, load_default_trust_config
from sentinel.trust.scorer import (
    START,
    TrustScorer,
    transition_penalty,
    transition_stats,
)


class _SlowStore:
    """A store wrapper that YIELDS inside put, forcing coroutines to interleave.

    Without this, an in-memory put completes without ever suspending, so the
    race window (the await between reading the old score and committing the new
    one) would never actually be exercised. With it, the per-agent lock is what
    keeps concurrent updates correct — which is exactly what the race test checks.
    """

    def __init__(self, inner: InMemoryForensicStore) -> None:
        self._inner = inner

    async def put(self, span: Span) -> None:
        await asyncio.sleep(0)
        await self._inner.put(span)

    async def get_spans(self, trace_id: str) -> list[Span]:
        return await self._inner.get_spans(trace_id)


def _burst(n: int) -> list[str]:
    """Anomalous burst: each established source jumps to a brand-new sink, then
    returns to an established tool (so the next jump is again from a known source).
    """
    established = ["search", "fetch", "summarize"]
    out: list[str] = []
    for i in range(n):
        out.append(f"exfil{i}")
        out.append(established[i % 3])
    return out


async def test_dod_baseline_then_burst_trajectory_and_quarantine() -> None:
    cfg = load_default_trust_config()
    store = InMemoryForensicStore()
    emitter = SpanEmitter(store)
    scorer = TrustScorer(emitter, cfg)
    tid = emitter.new_trace_id()
    agent = "agent-1"

    baseline = ["search", "fetch", "summarize"] * 6
    burst = _burst(16)

    # A mirror of the scorer's window so the test computes expected P / penalty
    # INDEPENDENTLY from the same primitives and checks the scorer step by step.
    mirror: deque[tuple[str, str]] = deque(maxlen=cfg.window_size)
    last: str | None = None

    def expect(tool: str) -> tuple[float, float]:
        from_tool = last if last is not None else START
        stats = transition_stats(mirror, from_tool, tool)
        return stats.probability, transition_penalty(stats, cfg.max_transition_penalty)

    # --- baseline: a stable, repeated pattern must cost NOTHING ---
    for tool in baseline:
        exp_p, exp_pen = expect(tool)
        span = await scorer.record_tool_transition(agent, tool, trace_id=tid)
        assert span.payload.smoothed_probability == pytest.approx(exp_p)
        assert span.payload.delta == pytest.approx(-exp_pen)
        mirror.append((last if last is not None else START, tool))
        last = tool

    assert scorer.score(agent) == pytest.approx(cfg.starting_score)  # baseline free
    assert scorer.is_quarantined(agent) is False

    # --- burst: anomalous transitions drive the score down to quarantine ---
    blocked_attempts = 0
    for tool in burst:
        if scorer.is_quarantined(agent):
            await scorer.record_quarantined_block(agent, tool, trace_id=tid)
            blocked_attempts += 1
            continue
        exp_p, exp_pen = expect(tool)
        span = await scorer.record_tool_transition(agent, tool, trace_id=tid)
        # The trajectory matches the smoothed-probability math at every step.
        assert span.payload.smoothed_probability == pytest.approx(exp_p)
        assert span.payload.delta == pytest.approx(-exp_pen)
        mirror.append((last if last is not None else START, tool))
        last = tool

    assert scorer.is_quarantined(agent) is True
    assert scorer.score(agent) < cfg.quarantine_threshold
    assert blocked_attempts > 0  # the burst continued after quarantine

    rep = await replay(store, tid)
    ordered = rep.ordered

    # Quarantine fired exactly once.
    quarantines = [s for s in ordered if s.event_type == "AgentQuarantined"]
    assert len(quarantines) == 1

    # Post-quarantine attempts each emit a VISIBLE ToolBlocked("quarantined").
    blocks = [s for s in ordered if s.event_type == "ToolBlocked"]
    assert len(blocks) == blocked_attempts
    assert all(s.payload.blocked_by == "quarantine" for s in blocks)

    # After quarantine the score is frozen: NO TrustUpdated spans follow it.
    q_seq = quarantines[0].seq
    assert not [
        s for s in ordered if s.event_type == "TrustUpdated" and s.seq > q_seq
    ]


async def test_dod_concurrent_updates_have_no_lost_updates() -> None:
    # Fixed-penalty hard signals make the expected trajectory order-independent,
    # so any lost update shows up as a wrong final score / a duplicated
    # previous_score / a missing span. quarantine_threshold=0 keeps quarantine
    # out of the way. SlowStore forces the coroutines to actually interleave.
    cfg = TrustConfig(
        window_size=50,
        starting_score=100,
        quarantine_threshold=0,
        max_transition_penalty=25,
        blocked_call_penalty=2.0,
        injection_detected_penalty=50,
    )
    store = InMemoryForensicStore()
    emitter = SpanEmitter(_SlowStore(store))
    scorer = TrustScorer(emitter, cfg)
    tid = emitter.new_trace_id()
    agent = "racer"
    n = 25

    await asyncio.gather(
        *(
            scorer.record_blocked_call(agent, "send_email", reason="r", trace_id=tid)
            for _ in range(n)
        )
    )

    # No lost updates: all n penalties applied.
    assert scorer.score(agent) == pytest.approx(cfg.starting_score - n * cfg.blocked_call_penalty)

    rep = await replay(store, tid)
    updates = [s for s in rep.ordered if s.event_type == "TrustUpdated"]
    assert len(updates) == n  # every update was recorded

    prev_scores = sorted(s.payload.previous_score for s in updates)
    expected = sorted(cfg.starting_score - cfg.blocked_call_penalty * i for i in range(n))
    assert prev_scores == [pytest.approx(v) for v in expected]
    # Each update read a DISTINCT previous score → none clobbered another.
    assert len({round(p, 6) for p in prev_scores}) == n


async def test_dod_independent_agents_score_separately() -> None:
    # Per-agent locks must not couple distinct agents.
    cfg = load_default_trust_config()
    store = InMemoryForensicStore()
    emitter = SpanEmitter(_SlowStore(store))
    scorer = TrustScorer(emitter, cfg)
    tid = emitter.new_trace_id()

    await asyncio.gather(
        scorer.record_blocked_call("agent-a", "t", reason="r", trace_id=tid),
        scorer.record_injection("agent-b", target="user_prompt", trace_id=tid),
    )
    assert scorer.score("agent-a") == pytest.approx(cfg.starting_score - cfg.blocked_call_penalty)
    assert scorer.score("agent-b") == pytest.approx(
        cfg.starting_score - cfg.injection_detected_penalty
    )
