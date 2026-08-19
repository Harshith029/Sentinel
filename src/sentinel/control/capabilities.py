"""DEMO MODE vs AZURE MODE capability matrix (BUILD_SPEC §10, §Phase 8).

This is the "Azure is load-bearing" proof made concrete: a matrix naming, for
each capability, what runs in DEMO MODE (degraded) versus what lights up in
AZURE MODE. Flipping ``SENTINEL_DEMO_MODE`` changes which column is active. The
security PIPELINE is identical in both modes — only these integrations degrade.
"""
from __future__ import annotations

from dataclasses import dataclass

from sentinel.config import Settings

# Each row: (key, name, what DEMO MODE provides, what AZURE MODE lights up).
_MATRIX: tuple[tuple[str, str, str, str], ...] = (
    (
        "prompt_shields",
        "Layer-1 injection shield",
        "Deterministic local detector — fallible by design",
        "Azure AI Content Safety · real Prompt Shields",
    ),
    (
        "classifier",
        "Semantic attack classifier",
        "Rule-based SOC labelling",
        "Azure OpenAI classification",
    ),
    (
        "persistence",
        "Forensic persistence",
        "In-memory, LRU-bounded replay store",
        "Azure Cosmos DB · partitioned by trace_id, idempotent, SDK retry",
    ),
    (
        "observability",
        "Observability",
        "Local span log",
        "Azure Monitor · App Insights distributed traces",
    ),
    (
        "agent_driver",
        "Agent driver",
        "Deterministic scripted transcript",
        "Live Foundry Agent Service (real model)",
    ),
    (
        "secrets",
        "Secret resolution",
        "gitignored local .env",
        "Key Vault + managed-identity RBAC (provisioned; secrets bound as env / "
        "Key Vault references at deploy)",
    ),
)


@dataclass(frozen=True)
class Capability:
    key: str
    name: str
    demo: str
    azure: str
    active: str
    degraded: bool


def capability_matrix(settings: Settings) -> list[Capability]:
    demo = settings.demo_mode
    return [
        Capability(
            key=key, name=name, demo=demo_val, azure=azure_val,
            active=(demo_val if demo else azure_val), degraded=demo,
        )
        for (key, name, demo_val, azure_val) in _MATRIX
    ]


def mode_summary(settings: Settings) -> dict[str, object]:
    """The payload the dashboard renders as the DEMO-vs-AZURE delta panel."""
    caps = capability_matrix(settings)
    return {
        "mode": "DEMO MODE" if settings.demo_mode else "AZURE MODE",
        "demo_mode": settings.demo_mode,
        "tagline": (
            "Security pipeline is LIVE and identical to production — only the "
            "integrations below are degraded without Azure."
            if settings.demo_mode
            else "Azure integrations are live."
        ),
        "degraded": [c.name for c in caps if c.degraded],
        "capabilities": [
            {
                "key": c.key, "name": c.name, "demo": c.demo, "azure": c.azure,
                "active": c.active, "degraded": c.degraded,
            }
            for c in caps
        ],
    }
