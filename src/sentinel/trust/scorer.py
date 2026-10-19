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
an :class:`AgentQuarantined` span is emitted once. If the scorer ENFORCES
quarantine, every later attempt is refused with a visible :class:`ToolBlocked`
("quarantined") span — denials never go silent. If it does not, the span says
so (``enforced=False``) and calls continue.

Enforcement is off unless the deployment turns it on
(``SENTINEL_ENFORCE_QUARANTINE``). Nothing ever raises a score, so an agent
making only ALLOWED calls drifts below the threshold: measured, 15–21 calls of
varied use, and 40–157 even when 95% of its traffic follows one fixed cycle. As
enforced containment that is an outage generator, not a safeguard, until the
model has recovery and a narrower scope.

Concurrency: each agent has its own :class:`asyncio.Lock`, held across the whole
read → emit → commit sequence. The ``await emit`` sits BETWEEN reading the old
score and committing the new one, so without the lock concurrent updates to one
agent would race (lost updates); the lock serializes them. The in-memory score
is committed only AFTER the store has accepted the TrustUpdated span, so the
score and the forensic log do not diverge in a running process. ("Accepted" is
what each store makes it: SQLite in WAL mode with synchronous=NORMAL survives a
process crash but can lose the last commits to a power cut; the in-memory store
keeps nothing across a restart.) Different agents use different locks and run
concurrently.

This is anomaly telemetry + containment, NOT primary prevention — Authorization
(§2B) is the thesis. The implementation is intentionally proportionate to that.
"""
from __future__ import annotations

import asyncio
from collections import OrderedDict, deque
from collections.abc import Sequence
from dataclasses import dataclass, field
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


# Per-agent trust states kept in memory (see TrustScorer._evict_stale).
_MAX_TRACKED_AGENTS: Final[int] = 10_000
# Per agent, how many recent traces' previous tool is remembered.
_TRACES_PER_AGENT: Final[int] = 64


@dataclass
class _AgentState:
    score: float
    transitions: deque[tuple[str, str]]
    # The previous tool PER TRACE. One field per agent mixed concurrent sessions
    # of the same principal: their interleaved calls made transitions no session
    # took, and those read as anomalies. Bounded to the most recent traces.
    last_tool_by_trace: OrderedDict[str, str] = field(default_factory=OrderedDict)
    quarantined: bool = False
    # The threshold crossing has been recorded (once), enforced or not.
    reported_crossing: bool = False


# (tenant, agent id). A tuple, not a separator-joined string: with
# "tenant<US>agent", a tenant or agent id containing the separator could name
# another pair's state.
_Key = tuple[str | None, str]


def _key(agent_id: str, tenant: str | None) -> _Key:
    """Where an agent's trust state lives: per (tenant, agent).

    Keyed by agent alone, two tenants that used the same agent id shared one
    score, so one could read the other's trust and push its score down (with
    quarantine enforced, quarantine it). Agent ids are not secrets: callers
    choose them for demo runs, and they appear in logs and exports. Without a
    tenant (direct use of the scorer), the agent id alone is the key.
    """
    return (tenant, agent_id)


def _clamp(value: float) -> float:
    return max(MIN_SCORE, min(MAX_SCORE, value))


class TrustScorer:
    """Per-agent trust scoring with serialized updates and quarantine."""

    def __init__(
        self,
        emitter: SpanEmitter,
        config: TrustConfig,
        *,
        enforce: bool = False,
        max_agents: int = _MAX_TRACKED_AGENTS,
    ) -> None:
        self._emitter = emitter
        self._config = config
        # Whether crossing the threshold isolates the agent, or is only recorded.
        self._enforce = enforce
        # Least recently used first, so the cap below evicts the stalest state.
        self._agents: OrderedDict[_Key, _AgentState] = OrderedDict()
        self._locks: dict[_Key, asyncio.Lock] = {}
        self._max_agents = max_agents

    @property
    def enforces_quarantine(self) -> bool:
        return self._enforce

    @property
    def quarantine_threshold(self) -> float:
        return self._config.quarantine_threshold

    # --- read-only views (do not create state) -------------------------------

    def score(self, agent_id: str, *, tenant: str | None = None) -> float:
        state = self._agents.get(_key(agent_id, tenant))
        return state.score if state is not None else self._config.starting_score

    def is_quarantined(self, agent_id: str, *, tenant: str | None = None) -> bool:
        """Whether this agent's calls are being refused. Never true when not enforcing."""
        state = self._agents.get(_key(agent_id, tenant))
        return state.quarantined if state is not None else False

    def crossed_threshold(self, agent_id: str, *, tenant: str | None = None) -> bool:
        """Whether the score has fallen below the threshold, enforced or not."""
        state = self._agents.get(_key(agent_id, tenant))
        return state is not None and (
            state.quarantined or state.score < self._config.quarantine_threshold
        )

    def reset(self, agent_id: str, *, tenant: str | None = None) -> None:
        """Clear an agent's trust state (score back to starting, un-quarantined).

        Administrative; not intended to run concurrently with in-flight updates.
        Drops the per-agent lock too, so repeated reset/short-lived agents (e.g.
        one per live MCP session) don't accumulate lock objects unbounded.
        """
        self._agents.pop(_key(agent_id, tenant), None)
        self._locks.pop(_key(agent_id, tenant), None)

    # --- internal helpers ----------------------------------------------------

    def _lock(self, key: _Key) -> asyncio.Lock:
        # setdefault is a single, await-free dict op → atomic within the loop.
        return self._locks.setdefault(key, asyncio.Lock())

    def _state(self, key: _Key) -> _AgentState:
        state = self._agents.get(key)
        if state is None:
            state = _AgentState(
                score=self._config.starting_score,
                transitions=deque(maxlen=self._config.window_size),
            )
            self._agents[key] = state
            self._evict_stale()
        else:
            self._agents.move_to_end(key)
        return state

    def _evict_stale(self) -> None:
        """Keep at most ``max_agents`` states, dropping the least recently used.

        State used to live for the life of the process, and demo runs and
        anonymous sessions each bring a new agent id. Never evicted: an agent
        that crossed the threshold (dropping it would hand back a clean score,
        and with enforcement on, lift its quarantine) or one with an update in
        flight.
        """
        excess = len(self._agents) - self._max_agents
        if excess <= 0:
            return
        for key in list(self._agents):
            if excess <= 0:
                break
            state = self._agents[key]
            lock = self._locks.get(key)
            if state.reported_crossing or state.quarantined or (lock is not None and lock.locked()):
                continue
            del self._agents[key]
            self._locks.pop(key, None)
            excess -= 1

    async def _maybe_quarantine(
        self,
        state: _AgentState,
        agent_id: str,
        trace_id: str,
        parent_span_id: str | None,
        tenant: str | None = None,
    ) -> None:
        if state.quarantined or state.reported_crossing:
            return
        if state.score >= self._config.quarantine_threshold:
            return
        state.reported_crossing = True
        state.quarantined = self._enforce
        consequence = (
            "tool calls refused until reset"
            if self._enforce
            else "NOT enforced (SENTINEL_ENFORCE_QUARANTINE is off); calls continue"
        )
        payload = AgentQuarantined(
            agent_id=agent_id,
            score_at_quarantine=state.score,
            reason=(
                f"trust score {state.score:.2f} fell below quarantine_threshold "
                f"{self._config.quarantine_threshold:.2f}; {consequence}"
            ),
            enforced=self._enforce,
        )
        log_quarantined(
            agent_id,
            trace_id=trace_id,
            score=state.score,
            enforced=self._enforce,
            tenant=tenant,
        )
        await self._emitter.emit(payload, trace_id=trace_id, parent_span_id=parent_span_id)

    # --- update paths --------------------------------------------------------

    async def record_tool_transition(
        self,
        agent_id: str,
        tool_name: str,
        *,
        trace_id: str,
        parent_span_id: str | None = None,
        tenant: str | None = None,
    ) -> Span:
        """Score one observed tool transition and emit its TrustUpdated span."""
        key = _key(agent_id, tenant)
        async with self._lock(key):
            state = self._state(key)
            from_tool = state.last_tool_by_trace.get(trace_id, START)
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
            state.last_tool_by_trace[trace_id] = tool_name
            state.last_tool_by_trace.move_to_end(trace_id)
            while len(state.last_tool_by_trace) > _TRACES_PER_AGENT:
                state.last_tool_by_trace.popitem(last=False)
            state.score = new_score
            await self._maybe_quarantine(state, agent_id, trace_id, parent_span_id, tenant)
            return span

    async def _apply_fixed_penalty(
        self,
        agent_id: str,
        penalty: float,
        reason: str,
        *,
        trace_id: str,
        parent_span_id: str | None,
        tenant: str | None,
    ) -> Span:
        key = _key(agent_id, tenant)
        async with self._lock(key):
            state = self._state(key)
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
            await self._maybe_quarantine(state, agent_id, trace_id, parent_span_id, tenant)
            return span

    async def record_blocked_call(
        self,
        agent_id: str,
        tool_name: str,
        *,
        reason: str,
        trace_id: str,
        parent_span_id: str | None = None,
        tenant: str | None = None,
    ) -> Span:
        """Apply the fixed blocked-call penalty (a hard signal from authorization)."""
        weight = self._config.blocked_call_penalty
        detail = (
            f"blocked_call {tool_name}: hard signal "
            f"(blocked_call_penalty={weight:.2f}); reason={reason}"
        )
        return await self._apply_fixed_penalty(
            agent_id, weight, detail, trace_id=trace_id, parent_span_id=parent_span_id,
            tenant=tenant,
        )

    async def record_injection(
        self,
        agent_id: str,
        *,
        target: str,
        trace_id: str,
        parent_span_id: str | None = None,
        tenant: str | None = None,
    ) -> Span:
        """Apply the fixed injection-detected penalty (a hard signal from Layer 1)."""
        weight = self._config.injection_detected_penalty
        detail = (
            f"injection_detected on {target}: hard signal "
            f"(injection_detected_penalty={weight:.2f})"
        )
        return await self._apply_fixed_penalty(
            agent_id, weight, detail, trace_id=trace_id, parent_span_id=parent_span_id,
            tenant=tenant,
        )

    async def record_quarantined_block(
        self,
        agent_id: str,
        tool_name: str,
        *,
        trace_id: str,
        parent_span_id: str | None = None,
        tenant: str | None = None,
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
        async with self._lock(_key(agent_id, tenant)):
            return await self._emitter.emit(
                payload, trace_id=trace_id, parent_span_id=parent_span_id
            )
