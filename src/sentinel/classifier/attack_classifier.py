"""Attack classifier (BUILD_SPEC §Phase 8): label a blocked attempt, nothing more.

The classifier's whole world is a single :class:`BlockedAttempt` → one
:class:`AttackLabel`. It has exactly one downstream consumer (the SOC export
panel). It never touches the authorization decision, the trust score, the
severity field, or replay — keeping it scoped is the point (it deepens the AI
story past commodity Prompt-Shields without entangling the core pipeline).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from sentinel.config import Settings

AttackClass = Literal[
    "exfiltration", "privilege_escalation", "instruction_override", "unclassified"
]
ATTACK_CLASSES: Final[tuple[AttackClass, ...]] = (
    "exfiltration",
    "privilege_escalation",
    "instruction_override",
    "unclassified",
)

_CLASSIFIER_RULES: Final[str] = "rule_based"
_CLASSIFIER_AZURE: Final[str] = "azure_openai"

# System prompt for the AZURE MODE classifier — kept here so the one job is auditable.
_AZURE_SYSTEM_PROMPT: Final[str] = (
    "You are a SOC triage classifier. Given a tool call that a security proxy "
    "BLOCKED, respond with exactly one label describing the attempted action: "
    "'exfiltration' (sensitive/tainted data leaving), 'privilege_escalation' "
    "(a destructive or forbidden action), or 'instruction_override' (an action "
    "induced by an injected instruction). Reply with only the label."
)


@dataclass(frozen=True)
class BlockedAttempt:
    """The minimal facts the classifier is allowed to see about a block."""

    tool_name: str
    matched_rule_id: str | None
    blocked_by: str
    reason: str
    is_tainted: bool = False
    injection_detected: bool = False


@dataclass(frozen=True)
class AttackLabel:
    attack_class: AttackClass
    rationale: str
    classifier: str  # which backend produced it


def _rule_label(attempt: BlockedAttempt) -> AttackLabel:
    """Deterministic labelling (DEMO MODE) — classify by the ACTION attempted.

    Action-first (not vector-first) so the SAME attack gets the SAME label
    regardless of whether the Layer-1 shield happened to catch the injection —
    e.g. the hero's blocked ``send_email`` is ``exfiltration`` in both the obvious
    and the evasion variants.
    """
    tool, rule = attempt.tool_name, attempt.matched_rule_id
    if tool in {"delete_record"} or rule == "never" or tool == "transfer_funds":
        return AttackLabel(
            "privilege_escalation",
            "attempted a destructive / forbidden / unauthorized-financial action",
            _CLASSIFIER_RULES,
        )
    if tool == "send_email" or rule in {"block-untrusted-origin", "domain-allowlist"}:
        return AttackLabel(
            "exfiltration",
            "attempted to send sensitive/tainted data to an external recipient",
            _CLASSIFIER_RULES,
        )
    if tool == "get_customer_record" or rule == "user-initiated-only":
        return AttackLabel(
            "exfiltration",
            "attempted to pull sensitive data on an untrusted (tainted) lineage",
            _CLASSIFIER_RULES,
        )
    if attempt.injection_detected or attempt.is_tainted:
        return AttackLabel(
            "instruction_override",
            "action induced by an injected instruction in retrieved content",
            _CLASSIFIER_RULES,
        )
    return AttackLabel("unclassified", "no rule matched", _CLASSIFIER_RULES)


class AttackClassifier:
    """Labels blocked attempts. Mock-deterministic in DEMO MODE, LLM in AZURE MODE."""

    def __init__(
        self,
        *,
        demo_mode: bool = True,
        azure_openai_endpoint: str | None = None,
        azure_openai_deployment: str | None = None,
        azure_openai_api_version: str | None = None,
    ) -> None:
        self._demo_mode = demo_mode
        self._endpoint = azure_openai_endpoint
        self._deployment = azure_openai_deployment
        self._api_version = azure_openai_api_version

    @classmethod
    def from_settings(cls, settings: Settings) -> AttackClassifier:
        return cls(
            demo_mode=settings.demo_mode,
            azure_openai_endpoint=settings.azure_openai_endpoint,
            azure_openai_deployment=settings.azure_openai_deployment,
            azure_openai_api_version=settings.azure_openai_api_version,
        )

    async def classify(self, attempt: BlockedAttempt) -> AttackLabel:
        if self._demo_mode:
            return _rule_label(attempt)
        return await self._classify_azure(attempt)

    async def _classify_azure(self, attempt: BlockedAttempt) -> AttackLabel:
        """AZURE MODE: one chat completion → one label (openai 2.x surface).

        Auth is identity-based (DefaultAzureCredential → managed identity, §6).
        Falls back to the rule label if the model returns something unexpected,
        so the SOC panel never shows a malformed class.
        """
        if not self._endpoint or not self._deployment:
            raise RuntimeError(
                "Azure OpenAI endpoint/deployment not configured; "
                "use DEMO MODE or provide credentials."
            )
        from azure.identity import DefaultAzureCredential, get_bearer_token_provider
        from openai import AsyncAzureOpenAI

        token_provider = get_bearer_token_provider(
            DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default"
        )
        client = AsyncAzureOpenAI(
            azure_endpoint=self._endpoint,
            azure_ad_token_provider=token_provider,
            api_version=self._api_version or "2024-10-21",
        )
        user = (
            f"tool={attempt.tool_name}; matched_rule={attempt.matched_rule_id}; "
            f"blocked_by={attempt.blocked_by}; tainted={attempt.is_tainted}; "
            f"reason={attempt.reason}"
        )
        completion = await client.chat.completions.create(
            model=self._deployment,
            messages=[
                {"role": "system", "content": _AZURE_SYSTEM_PROMPT},
                {"role": "user", "content": user},
            ],
            temperature=0,
            max_tokens=8,
        )
        raw = (completion.choices[0].message.content or "").strip().lower()
        for cls in ATTACK_CLASSES:
            if cls in raw:
                return AttackLabel(cls, "labelled by Azure OpenAI", _CLASSIFIER_AZURE)
        # Model returned something off-script → fall back, but record the backend.
        fallback = _rule_label(attempt)
        return AttackLabel(fallback.attack_class, fallback.rationale, _CLASSIFIER_AZURE)
