"""The authorization engine (BUILD_SPEC §2B): deny-overrides + default-deny.

Resolution rules, exactly as specified:

* Rules are deny-only and evaluate IN LISTED ORDER. The FIRST matching
  ``deny_if`` / ``deny_always`` blocks and **short-circuits** — later rules are
  not evaluated, so no later rule can re-allow a denied call.
* A known tool with NO matching deny rule is ALLOWED.
* An UNKNOWN tool (no policy entry) is DEFAULT-DENIED.
* A predicate that cannot be evaluated (missing variable, type error) is
  FAIL-CLOSED to a deny — an unverifiable rule never silently passes.

Every decision produces a complete
:class:`~sentinel.forensics.events.AuthorizationDecided` payload: the policy
version, every rule actually considered (and whether it matched), the provenance
set, taint flag, the matched rule, and a human reason. That payload is both the
forensic record and the dashboard's decision-trace.
"""
from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

from sentinel.authorization.ast import ConditionError
from sentinel.authorization.policy import CompiledPolicy, CompiledRule
from sentinel.forensics.events import AuthorizationDecided, Decision, RuleEvaluation
from sentinel.labels import RETRIEVED_CONTENT, Label, trust_rank

_LOG: Final[logging.Logger] = logging.getLogger("sentinel.authorization.engine")


@dataclass(frozen=True)
class ToolCall:
    """A normalized proposed call: name, typed args, provenance set, and config.

    ``namespace`` is the flat evaluation context predicates resolve against,
    layered by trust — see :meth:`namespace`.
    """

    name: str
    arguments: Mapping[str, object] = field(default_factory=dict)
    provenance: frozenset[Label] = field(default_factory=frozenset)
    config: Mapping[str, object] = field(default_factory=dict)

    @property
    def is_tainted(self) -> bool:
        return RETRIEVED_CONTENT in self.provenance

    @property
    def namespace(self) -> dict[str, object]:
        """The flat evaluation context, layered by TRUST.

        Written least-trusted first, so each layer overwrites the one below it:

        1. **arguments** — chosen by the agent, which may be acting on injected
           content. Untrusted.
        2. **config** — declared by the operator in the policy document.
        3. **provenance** — computed by Whence itself and never supplied.

        The ordering is load-bearing, not stylistic. With arguments written
        LAST, a call carrying an argument named ``allowed_domains`` overwrote the
        operator's allowlist and flipped a DENY to an ALLOW: attacker-selectable
        input decided a deny rule. Trusted values must be written after
        untrusted ones for exactly the same reason provenance is written after
        both.
        """
        ns: dict[str, object] = {}
        ns.update(self.arguments)
        ns.update(self.config)
        ns["effective_provenance"] = self.provenance
        ns["is_tainted"] = self.is_tainted
        return ns


@dataclass(frozen=True)
class AuthorizationResult:
    """Structured verdict — maps 1:1 onto the AuthorizationDecided span."""

    decision: Decision
    reason: str
    effective_provenance: tuple[Label, ...]
    is_tainted: bool
    rules_considered: tuple[RuleEvaluation, ...] = ()
    matched_rule_id: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"


def _sorted_provenance(provenance: frozenset[Label]) -> tuple[Label, ...]:
    # Deterministic, most-trusted-first order for stable spans/UI.
    return tuple(sorted(provenance, key=trust_rank))


class AuthorizationEngine:
    """Evaluates :class:`ToolCall`s against a :class:`CompiledPolicy`."""

    def __init__(self, policy: CompiledPolicy) -> None:
        self._policy = policy

    @property
    def policy_version(self) -> int:
        return self._policy.policy_version

    @property
    def config(self) -> dict[str, object]:
        """Deployment values this tenant's predicates resolve against.

        Comes from the policy document, so callers never have to supply one —
        and cannot accidentally supply the wrong one, which is what happened
        when the live MCP path passed the demo's config.
        """
        return dict(self._policy.config)

    def declassifier_for(self, tool_name: str) -> str | None:
        """The declassification schema policy allows for a tool's output.

        Declassification is a POLICY decision, not a proxy one, so the engine
        owns it alongside authorization: the same document that says what a tool
        may do says whether its output may cross the trust boundary.
        """
        return self._policy.declassifier_for(tool_name)

    def authorize(self, call: ToolCall) -> AuthorizationResult:
        provenance = _sorted_provenance(call.provenance)
        rules = self._policy.rules_for(call.name)

        if rules is None:
            # DEFAULT-DENY: no policy for this tool means it is not permitted.
            return AuthorizationResult(
                decision="DENY",
                reason=f"unknown tool {call.name!r}: default-deny (no policy defined)",
                effective_provenance=provenance,
                is_tainted=call.is_tainted,
                rules_considered=(),
                matched_rule_id=None,
            )

        namespace = call.namespace
        considered: list[RuleEvaluation] = []
        for rule in rules:
            matched, detail = self._evaluate(rule, namespace)
            considered.append(
                RuleEvaluation(
                    rule_id=rule.id, effect="DENY", matched=matched, detail=detail
                )
            )
            if matched:
                # DENY-OVERRIDES: short-circuit. Later rules are NOT evaluated,
                # so they are absent from rules_considered — visible proof in the
                # decision trace that nothing could re-allow this call.
                reason = f"denied by rule {rule.id!r}"
                if detail:
                    reason = f"{reason}: {detail}"
                return AuthorizationResult(
                    decision="DENY",
                    reason=reason,
                    effective_provenance=provenance,
                    is_tainted=call.is_tainted,
                    rules_considered=tuple(considered),
                    matched_rule_id=rule.id,
                )

        return AuthorizationResult(
            decision="ALLOW",
            reason="no deny rule matched",
            effective_provenance=provenance,
            is_tainted=call.is_tainted,
            rules_considered=tuple(considered),
            matched_rule_id=None,
        )

    def _evaluate(
        self, rule: CompiledRule, namespace: Mapping[str, object]
    ) -> tuple[bool, str | None]:
        if rule.deny_always:
            return True, "deny_always"
        assert rule.condition is not None  # guaranteed by the compiler
        try:
            return rule.condition.evaluate(namespace), None
        except ConditionError as exc:
            # Fail-closed: an unevaluable deny predicate becomes a deny, recorded.
            _LOG.warning(
                "fail-closed deny: rule %r could not be evaluated: %s", rule.id, exc
            )
            return True, f"evaluation error (fail-closed deny): {exc}"

    def decision_payload(self, call: ToolCall) -> AuthorizationDecided:
        """Authorize ``call`` and render the AuthorizationDecided forensic span."""
        return to_decision_payload(
            call.name, self._policy.policy_version, self.authorize(call)
        )


def to_decision_payload(
    tool_name: str, policy_version: int, result: AuthorizationResult
) -> AuthorizationDecided:
    """Project an :class:`AuthorizationResult` onto the typed forensic payload."""
    return AuthorizationDecided(
        tool_name=tool_name,
        decision=result.decision,
        policy_version=str(policy_version),
        effective_provenance=list(result.effective_provenance),
        is_tainted=result.is_tainted,
        rules_considered=list(result.rules_considered),
        matched_rule_id=result.matched_rule_id,
        reason=result.reason,
    )
