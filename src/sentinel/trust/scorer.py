"""The Trust Scorer (BUILD_SPEC §Phase 3) — subordinate tier-2 anomaly telemetry.

Mechanism, kept deliberately simple:

* Per agent, keep the last ``window_size`` tool TRANSITIONS ``(from_tool → to_tool)``
  (the first tool of a trace transitions from a ``<start>`` sentinel).
* The probability of an observed transition is the **Laplace (add-one) smoothed**
  conditional ``P(to | from) = (pair_count + 1) / (from_count + V)`` where ``V``
  is the vocabulary size (distinct target tools seen, plus the current target).
  Add-one smoothing is the entire answer to unseen transitions: a never-seen
  transition still gets a non-zero probability ``1/(from_count + V)``.
* A transition is penalized only to the extent its probability falls BELOW
  uniform chance ``1/V``. Define ``relative = P / chance = P · V``. Then
  ``penalty = max_transition_penalty · max(0, 1 − relative)``. So an at-or-above
  chance (expected) transition costs NOTHING — baseline traffic does not erode
  the score — and the most surprising transition costs up to the weight. "Less
  probable → larger penalty," exactly as specified.
* Hard signals (a blocked call, a detected injection) apply FIXED declarative
  penalties from the config. No probability involved.

Score is in [0, 100], starts at ``starting_score``. Below ``quarantine_threshold``
the agent is quarantined: an :class:`AgentQuarantined` span is emitted once, and
every later attempt is refused with a visible :class:`ToolBlocked` ("quarantined")
span — denials never go silent.

Concurrency: each agent has its own :class:`asyncio.Lock`, held across the whole
read → emit → commit sequence. The ``await emit`` sits BETWEEN reading the old
score and committing the new one, so without the lock concurrent updates to one
agent would race (lost updates); the lock serializes them. The in-memory score
is committed only AFTER the TrustUpdated span is durably emitted, so the score
and the forensic log never diverge. Different agents use different locks and run
concurrently.

This is anomaly telemetry + containment, NOT primary prevention — Authorization
(§2B) is the thesis. The implementation is intentionally proportionate to that.
"""
from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from sentinel.forensics.emitter import SpanEmitter
from sentinel.forensics.events import AgentQuarantined, ToolBlocked, TrustUpdated
from sentinel.forensics.span import Span
from sentinel.observability import log_quarantined
from sentinel.trust.config import MAX_SCORE, MIN_SCORE, TrustConfig

# The sentinel "source" for the first tool in a trace (it is never a target, so
# it never enters the vocabulary V).
START: Final[str] = "<start>"


@dataclass(frozen=True)
class TransitionStats:
    """The add-one smoothed model's view of one ``from → to`` transition."""

    probability: float  # P(to | from), Laplace-smoothed
    vocab_size: int     # V: distinct target tools (incl. the current target)
    chance: float       # uniform baseline probability 1/V

    @property
    def relative(self) -> float:
        """``P / chance`` (= P·V): 1.0 means exactly at chance, <1 below chance."""
        return self.probability / self.chance


def transition_stats(
    transitions: Sequence[tuple[str, str]], from_tool: str, to_tool: str
) -> TransitionStats:
    """Compute the Laplace-smoothed stats for ``from_tool → to_tool`` given history.

    Pure function over the window contents — exposed so tests can verify the math
    independently of the scorer's bookkeeping.
    """
    from_count = sum(1 for src, _ in transitions if src == from_tool)
    pair_count = sum(1 for src, dst in transitions if src == from_tool and dst == to_tool)
    vocabulary = {dst for _, dst in transitions}
    vocabulary.add(to_tool)
    vocab_size = max(1, len(vocabulary))
    probability = (pair_count + 1) / (from_count + vocab_size)
    return TransitionStats(
        probability=probability, vocab_size=vocab_size, chance=1.0 / vocab_size
    )


def transition_penalty(stats: TransitionStats, max_penalty: float) -> float:
    """Penalty for a transition: proportional to how far below chance it sits.

    ``max_penalty · max(0, 1 − P/chance)`` — zero for expected (≥ chance)
    transitions, up to ``max_penalty`` for the most surprising ones.
    """
    return max_penalty * max(0.0, 1.0 - stats.relative)


@dataclass
class _AgentState:
    score: float
    transitions: deque[tuple[str, str]]
    last_tool: str | None = None
    quarantined: bool = False


def _clamp(value: float) -> float:
    return max(MIN_SCORE, min(MAX_SCORE, value))


class TrustScorer:
    """Per-agent trust scoring with serialized updates and quarantine."""

    def __init__(self, emitter: SpanEmitter, config: TrustConfig) -> None:
        self._emitter = emitter
        self._config = config
        self._agents: dict[str, _AgentState] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    # --- read-only views (do not create state) -------------------------------

    def score(self, agent_id: str) -> float:
        state = self._agents.get(agent_id)
        return state.score if state is not None else self._config.starting_score

    def is_quarantined(self, agent_id: str) -> bool:
        state = self._agents.get(agent_id)
        return state.quarantined if state is not None else False

    def reset(self, agent_id: str) -> None:
        """Clear an agent's trust state (score back to starting, un-quarantined).

        Administrative; not intended to run concurrently with in-flight updates.
        Drops the per-agent lock too, so repeated reset/short-lived agents (e.g.
        one per live MCP session) don't accumulate lock objects unbounded.
        """
        self._agents.pop(agent_id, None)
        self._locks.pop(agent_id, None)

    # --- internal helpers ----------------------------------------------------

    def _lock(self, agent_id: str) -> asyncio.Lock:
        # setdefault is a single, await-free dict op → atomic within the loop.
        return self._locks.setdefault(agent_id, asyncio.Lock())

    def _state(self, agent_id: str) -> _AgentState:
        state = self._agents.get(agent_id)
        if state is None:
            state = _AgentState(
                score=self._config.starting_score,
                transitions=deque(maxlen=self._config.window_size),
            )
            self._agents[agent_id] = state
        return state

    async def _maybe_quarantine(
        self, state: _AgentState, agent_id: str, trace_id: str, parent_span_id: str | None
    ) -> None:
        if state.quarantined or state.score >= self._config.quarantine_threshold:
            return
        state.quarantined = True
        payload = AgentQuarantined(
            agent_id=agent_id,
            score_at_quarantine=state.score,
            reason=(
                f"trust score {state.score:.2f} fell below quarantine_threshold "
                f"{self._config.quarantine_threshold:.2f}; tool calls refused until reset"
            ),
        )
        log_quarantined(agent_id, trace_id=trace_id, score=state.score)
        await self._emitter.emit(payload, trace_id=trace_id, parent_span_id=parent_span_id)

    # --- update paths --------------------------------------------------------

    async def record_tool_transition(
        self,
        agent_id: str,
        tool_name: str,
        *,
        trace_id: str,
        parent_span_id: str | None = None,
    ) -> Span:
        """Score one observed tool transition and emit its TrustUpdated span."""
        async with self._lock(agent_id):
            state = self._state(agent_id)
            from_tool = state.last_tool if state.last_tool is not None else START
            stats = transition_stats(state.transitions, from_tool, tool_name)
            penalty = transition_penalty(stats, self._config.max_transition_penalty)
            previous = state.score
            new_score = _clamp(previous - penalty)
            reason = (
                f"tool_transition {from_tool}->{tool_name}: "
                f"P={stats.probability:.4f} (add-one smoothed, V={stats.vocab_size}, "
                f"chance=1/{stats.vocab_size}={stats.chance:.4f}); "
                f"penalty=max_transition_penalty*max(0,1-P/chance)="
                f"{self._config.max_transition_penalty:.2f}*max(0,1-{stats.relative:.4f})"
                f"={penalty:.4f}; delta={new_score - previous:.4f}"
            )
            payload = TrustUpdated(
                agent_id=agent_id,
                previous_score=previous,
                new_score=new_score,
                delta=new_score - previous,
                reason=reason,
                smoothed_probability=stats.probability,
            )
            # Emit (await) BEFORE committing in-memory state: this is the race
            # window the per-agent lock closes, and it keeps score ⇄ log consistent.
            span = await self._emitter.emit(
                payload, trace_id=trace_id, parent_span_id=parent_span_id
            )
            state.transitions.append((from_tool, tool_name))
            state.last_tool = tool_name
            state.score = new_score
            await self._maybe_quarantine(state, agent_id, trace_id, parent_span_id)
            return span

    async def _apply_fixed_penalty(
        self,
        agent_id: str,
        penalty: float,
        reason: str,
        *,
        trace_id: str,
        parent_span_id: str | None,
    ) -> Span:
        async with self._lock(agent_id):
            state = self._state(agent_id)
            previous = state.score
            new_score = _clamp(previous - penalty)
            payload = TrustUpdated(
                agent_id=agent_id,
                previous_score=previous,
                new_score=new_score,
                delta=new_score - previous,
                reason=f"{reason}; delta={new_score - previous:.4f}",
                smoothed_probability=None,  # hard signal, not probability-based
            )
            span = await self._emitter.emit(
                payload, trace_id=trace_id, parent_span_id=parent_span_id
            )
            state.score = new_score
            await self._maybe_quarantine(state, agent_id, trace_id, parent_span_id)
            return span

    async def record_blocked_call(
        self,
        agent_id: str,
        tool_name: str,
        *,
        reason: str,
        trace_id: str,
        parent_span_id: str | None = None,
    ) -> Span:
        """Apply the fixed blocked-call penalty (a hard signal from authorization)."""
        weight = self._config.blocked_call_penalty
        detail = (
            f"blocked_call {tool_name}: hard signal "
            f"(blocked_call_penalty={weight:.2f}); reason={reason}"
        )
        return await self._apply_fixed_penalty(
            agent_id, weight, detail, trace_id=trace_id, parent_span_id=parent_span_id
        )

    async def record_injection(
        self,
        agent_id: str,
        *,
        target: str,
        trace_id: str,
        parent_span_id: str | None = None,
    ) -> Span:
        """Apply the fixed injection-detected penalty (a hard signal from Layer 1)."""
        weight = self._config.injection_detected_penalty
        detail = (
            f"injection_detected on {target}: hard signal "
            f"(injection_detected_penalty={weight:.2f})"
        )
        return await self._apply_fixed_penalty(
            agent_id, weight, detail, trace_id=trace_id, parent_span_id=parent_span_id
        )

    async def record_quarantined_block(
        self,
        agent_id: str,
        tool_name: str,
        *,
        trace_id: str,
        parent_span_id: str | None = None,
    ) -> Span:
        """Emit a VISIBLE ToolBlocked for a call refused because of quarantine.

        Does not change the score — the agent is already contained. The proxy
        calls this for every attempt after quarantine so denials stay visible.
        """
        payload = ToolBlocked(
            tool_name=tool_name,
            reason=(
                "agent quarantined: trust score below threshold; "
                "tool calls refused until reset"
            ),
            blocked_by="quarantine",
        )
        async with self._lock(agent_id):
            return await self._emitter.emit(
                payload, trace_id=trace_id, parent_span_id=parent_span_id
            )
