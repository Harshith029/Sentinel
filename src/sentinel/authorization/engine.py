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

from sentinel.authorization.ast import ConditionError, comparand_names, subject_names
from sentinel.authorization.policy import CompiledPolicy, CompiledRule
from sentinel.forensics.events import AuthorizationDecided, Decision, RuleEvaluation
from sentinel.labels import RETRIEVED_CONTENT, Label, trust_rank

_LOG: Final[logging.Logger] = logging.getLogger("sentinel.authorization.engine")

# Argument fields the proxy's normalizer computes from a call (see
# sentinel.mcp_proxy.proxy.default_normalize), discarding any value the agent
# supplied under the same name.
DERIVED_FIELDS: Final[frozenset[str]] = frozenset(
    {"recipient_domain", "recipient_domains", "url_host"}
)
# Written by the engine itself, after arguments and config (see authorize()).
_COMPUTED: Final[frozenset[str]] = frozenset({"effective_provenance", "is_tainted"})


@dataclass(frozen=True)
class ToolCall:
    """A normalized proposed call: name, typed args, and provenance set.

    ``namespace`` is the flat evaluation context predicates resolve against,
    excluding deployment configuration. The engine supplies configuration from
    its compiled policy; a caller must never be able to supply decision inputs.
    """

    name: str
    arguments: Mapping[str, object] = field(default_factory=dict)
    provenance: frozenset[Label] = field(default_factory=frozenset)
    # Retained as an ignored compatibility field for callers built before policy
    # configuration became engine-owned. It cannot affect authorization.
    config: Mapping[str, object] = field(default_factory=dict, repr=False)

    @property
    def is_tainted(self) -> bool:
        return RETRIEVED_CONTENT in self.provenance

    @property
    def namespace(self) -> dict[str, object]:
        """The flat evaluation context, layered by TRUST.

        Written least-trusted first, so each layer overwrites the one below it:

        1. **arguments** — chosen by the agent, which may be acting on injected
           content. Untrusted.
        2. **provenance** — computed by SENTINEL itself and never supplied.

        Deployment configuration is deliberately absent here: it is owned and
        injected by :class:`AuthorizationEngine`, which prevents an agent or an
        integration caller from supplying a permissive substitute.
        """
        ns: dict[str, object] = {}
        ns.update(self.arguments)
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
        # Per tool: the names its rules compare AGAINST (allowlists, caps).
        # Only the operator's config may supply them; see authorize(). Fields
        # SENTINEL derives are exempt: they describe the call but no agent
        # chooses them, so `"evil.test" in recipient_domains` keeps working.
        self._comparands: dict[str, frozenset[str]] = {}
        for tool, rules in policy.tools.items():
            names: set[str] = set()
            for rule in rules:
                if rule.condition is None:
                    continue
                # Config is layered over arguments, so a config key named like a
                # call field replaces that field for every rule. Nothing said so.
                for name in sorted(subject_names(rule.condition) & policy.config.keys()):
                    _LOG.warning(
                        "policy rule %r reads %r from the policy's config, not from "
                        "the %r call, because config declares that name",
                        rule.id,
                        name,
                        tool,
                    )
                for name in comparand_names(rule.condition) - DERIVED_FIELDS - _COMPUTED:
                    names.add(name)
                    if name not in policy.config:
                        _LOG.warning(
                            "policy rule %r compares against %r, which the policy's "
                            "config does not declare; that rule denies every %r call",
                            rule.id,
                            name,
                            tool,
                        )
            self._comparands[tool] = frozenset(names)

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

        # Policy config is deployment-owned. Never use ``call.config`` here:
        # callers may be agents, integrations, or stale clients and therefore
        # cannot be an authority for a security decision.
        #
        # Nor may the call's own arguments stand in for a comparand. Config is
        # layered over arguments, so when the operator DID declare
        # `allowed_domains` an argument of that name was ignored; when they did
        # NOT (a policy with no config block), the agent's argument was used,
        # and an agent could pass the allowlist that judged it (review
        # AUTHZ-1). Dropping those names makes an undeclared comparand missing,
        # which is a fail-closed deny.
        comparands = self._comparands.get(call.name, frozenset())
        namespace = {k: v for k, v in call.arguments.items() if k not in comparands}
        namespace.update(self._policy.config)
        namespace["effective_provenance"] = call.provenance
        namespace["is_tainted"] = call.is_tainted
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
        except Exception as exc:  # noqa: BLE001 - any failure to evaluate is a deny
            # Fail-closed: an unevaluable deny predicate becomes a deny, recorded.
            # Not only ConditionError: comparing values of the wrong type raises
            # TypeError, and a malformed decimal raises InvalidOperation. Those
            # used to escape the engine, so the call still failed, but with no
            # decision and no block in the forensic record.
            _LOG.warning(
                "fail-closed deny: rule %r could not be evaluated: %s", rule.id, exc
            )
            kind = "" if isinstance(exc, ConditionError) else f"{type(exc).__name__}: "
            return True, f"evaluation error (fail-closed deny): {kind}{exc}"

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
