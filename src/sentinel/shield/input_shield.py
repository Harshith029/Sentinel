"""InputShield — Layer-1 prompt-injection detection (BUILD_SPEC §5).

Prompt Shields has no first-class Python SDK method, so AZURE MODE calls the
REST surface directly::

    POST {endpoint}/contentsafety/text:shieldPrompt?api-version=2024-09-01
    headers: Ocp-Apim-Subscription-Key: <key>, Content-Type: application/json
    body:    {"userPrompt": "<text>", "documents": ["<doc>", ...]}
    resp:    {"userPromptAnalysis": {"attackDetected": bool},
              "documentsAnalysis": [{"attackDetected": bool}, ...]}

DEMO MODE uses a deterministic local detector. It is DELIBERATELY simple: it
catches the obvious injection markers (a fake ``SYSTEM:`` directive, an "ignore
previous instructions", a plain "email X to <address>") and is EXPECTED to miss
obfuscated variants. That fallibility is the point — it is what lets the hero
demo show the Authorization Engine saving the day when the shield is evaded.

This module FLAGS only. It returns a :class:`ShieldVerdict`; the proxy decides
what to record (an ``InjectionScanned`` span) and how to feed the trust scorer.
Enforcement is never the shield's job — that belongs to Authorization.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final

from sentinel.config import Settings

_SHIELD_MOCK: Final[str] = "mock_prompt_shields"
_SHIELD_AZURE: Final[str] = "azure_prompt_shields"
_API_VERSION: Final[str] = "2024-09-01"

# Deliberately shallow signatures. Layer 1 is meant to be fallible.
_INJECTION_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"(?i)\bsystem\s*:"),  # fake system / role directive
    re.compile(r"(?i)ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above)\s+instructions"),
    # An imperative to email/exfiltrate to a *literal* address.
    re.compile(
        r"(?i)\b(?:e-?mail|send|forward|exfiltrate|leak)\b[^\n]{0,80}?"
        r"[\w.+-]+@[\w-]+\.[\w.-]+"
    ),
)


@dataclass(frozen=True)
class ShieldVerdict:
    """Result of one shield inspection."""

    attack_detected: bool
    shield: str
    detail: str | None = None


def _mock_detect(text: str) -> ShieldVerdict:
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            return ShieldVerdict(
                attack_detected=True,
                shield=_SHIELD_MOCK,
                detail=f"matched injection marker {pattern.pattern!r}",
            )
    return ShieldVerdict(
        attack_detected=False,
        shield=_SHIELD_MOCK,
        detail="no known injection marker matched",
    )


class InputShield:
    """Scans prompts/documents for injection. Mock in DEMO MODE, REST in AZURE MODE."""

    def __init__(
        self,
        *,
        demo_mode: bool = True,
        endpoint: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self._demo_mode = demo_mode
        self._endpoint = endpoint
        self._api_key = api_key

    @classmethod
    def from_settings(cls, settings: Settings) -> InputShield:
        return cls(
            demo_mode=settings.demo_mode,
            endpoint=settings.azure_content_safety_endpoint,
            api_key=settings.azure_content_safety_key,
        )

    async def inspect_user_prompt(self, content: str) -> ShieldVerdict:
        if self._demo_mode:
            return _mock_detect(content)
        analysis = await self._shield_prompt(user_prompt=content, documents=[])
        detected = bool(analysis.get("userPromptAnalysis", {}).get("attackDetected", False))
        return ShieldVerdict(attack_detected=detected, shield=_SHIELD_AZURE)

    async def inspect_document(self, content: str) -> ShieldVerdict:
        if self._demo_mode:
            return _mock_detect(content)
        analysis = await self._shield_prompt(user_prompt="", documents=[content])
        documents = analysis.get("documentsAnalysis") or [{}]
        detected = bool(documents[0].get("attackDetected", False))
        return ShieldVerdict(attack_detected=detected, shield=_SHIELD_AZURE)

    async def _shield_prompt(
        self, *, user_prompt: str, documents: list[str]
    ) -> dict[str, Any]:
        if not self._endpoint or not self._api_key:
            raise RuntimeError(
                "Azure Content Safety endpoint/key not configured; "
                "use DEMO MODE or provide credentials."
            )
        # Lazy import: AZURE MODE only. httpx is present transitively (openai/azure).
        import httpx

        url = (
            f"{self._endpoint.rstrip('/')}"
            f"/contentsafety/text:shieldPrompt?api-version={_API_VERSION}"
        )
        headers = {
            "Ocp-Apim-Subscription-Key": self._api_key,
            "Content-Type": "application/json",
        }
        body = {"userPrompt": user_prompt, "documents": documents}
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, headers=headers, json=body)
            response.raise_for_status()
            data: dict[str, Any] = response.json()
        return data
