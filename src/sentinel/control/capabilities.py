"""What each capability is ACTUALLY running on — free backend or paid upgrade.

An earlier version derived every row from ``demo_mode`` alone: flip the flag and
the matrix announced "Azure AI Content Safety", "Azure Cosmos DB" and a "Live
Foundry Agent Service" as active, whether or not any of them was configured. It
also described persistence as an in-memory store when the default is SQLite.
A capability report that reads a boolean instead of the running system is the
exact kind of claim an operator cannot trust.

Each row is now resolved from the component itself where the manager has one
(the shield, the classifier, the store) and from configuration otherwise, and
says whether that backend is free or paid.

The point of saying so: SENTINEL's ENFORCEMENT never depends on a paid service.
Provenance tracking and the authorization engine run locally and identically
everywhere. The paid backends improve detection, labelling, persistence and
telemetry — they are upgrades, not prerequisites.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlparse

from sentinel.config import Settings

_FREE: Final[str] = "free"
_PAID: Final[str] = "paid"


@dataclass(frozen=True)
class Capability:
    """One row: the free option, the paid upgrade, and which one is running."""

    key: str
    name: str
    demo: str  # the FREE option (field name kept for the dashboard's payload)
    azure: str  # the PAID upgrade (ditto)
    active: str  # what is actually running
    degraded: bool  # True when the paid upgrade is NOT the one running
    backend: str  # machine-readable id of what is running
    cost: str  # "free" or "paid"


def _shield_row(settings: Settings, backend: str | None) -> Capability:
    if backend is None:
        from sentinel.shield.input_shield import _resolve_backend

        try:
            backend = _resolve_backend(
                settings.shield_backend,
                demo_mode=settings.demo_mode,
                endpoint=settings.azure_content_safety_endpoint,
                api_key=settings.azure_content_safety_key,
            )
        except ValueError:
            backend = "misconfigured"
    active = {
        "local": "Local heuristic detector",
        "azure": "Azure AI Content Safety · Prompt Shields",
    }.get(backend, "MISCONFIGURED — see SENTINEL_SHIELD")
    return Capability(
        key="prompt_shields",
        name="Layer-1 injection shield",
        demo="Local heuristic detector — flags only; enforcement does not depend on it",
        azure="Azure AI Content Safety · Prompt Shields",
        active=active,
        degraded=backend != "azure",
        backend=backend,
        cost=_PAID if backend == "azure" else _FREE,
    )


def _classifier_row(settings: Settings, backend: str | None) -> Capability:
    if backend is None:
        configured = bool(
            settings.azure_openai_endpoint and settings.azure_openai_deployment
        )
        backend = "azure_openai" if (configured and not settings.demo_mode) else "rules"
    return Capability(
        key="classifier",
        name="Attack classifier (SOC labels)",
        demo="Rule-based labelling",
        azure="Azure OpenAI classification",
        active=(
            "Azure OpenAI classification"
            if backend == "azure_openai"
            else "Rule-based labelling"
        ),
        degraded=backend != "azure_openai",
        backend=backend,
        cost=_PAID if backend == "azure_openai" else _FREE,
    )


def _persistence_row(settings: Settings, store: object | None) -> Capability:
    if store is not None:
        kind = type(store).__name__.lower()
        backend = (
            "cosmos" if "cosmos" in kind
            else "sqlite" if "sqlite" in kind
            else "memory"
        )
    else:
        backend = "cosmos" if settings.azure_cosmos_endpoint else "sqlite"
    active = {
        "cosmos": "Azure Cosmos DB · partitioned by trace_id",
        "sqlite": "SQLite on local disk (SENTINEL_DATA_DIR)",
        "memory": "In-memory (lost on restart)",
    }[backend]
    return Capability(
        key="persistence",
        name="Forensic persistence",
        demo="SQLite on local disk",
        azure="Azure Cosmos DB · partitioned by trace_id",
        active=active,
        degraded=backend != "cosmos",
        backend=backend,
        cost=_PAID if backend == "cosmos" else _FREE,
    )


def _observability_row(settings: Settings) -> Capability:
    azure = bool(settings.applicationinsights_connection_string)
    return Capability(
        key="observability",
        name="Observability",
        demo="Structured local logs",
        azure="Azure Monitor · Application Insights",
        active="Azure Monitor · Application Insights" if azure else "Structured local logs",
        degraded=not azure,
        backend="azure_monitor" if azure else "local_logs",
        cost=_PAID if azure else _FREE,
    )


def _agent_row(settings: Settings) -> Capability:
    """Mirrors ``build_live_model``'s resolution order without building a client."""
    base_url = os.environ.get("OPENAI_BASE_URL")
    model = os.environ.get("OPENAI_MODEL") or "gpt-4o-mini"
    if settings.azure_openai_endpoint and settings.azure_openai_deployment:
        backend, cost = "azure_openai", _PAID
        active = f"Azure OpenAI · {settings.azure_openai_deployment}"
    elif os.environ.get("OPENAI_API_KEY") and not base_url:
        backend, cost = "openai", _PAID
        active = f"OpenAI · {model}"
    elif base_url:
        host = urlparse(base_url).hostname or base_url
        local = host in {"localhost", "127.0.0.1", "::1"}
        backend = "openai_compatible"
        # A local runtime is free; a hosted one depends on the provider's tier.
        cost = _FREE if local else "provider-dependent"
        active = f"OpenAI-compatible endpoint · {host} · {model}"
    else:
        backend, cost = "scripted", _FREE
        active = "Scripted agent (no model configured)"
    return Capability(
        key="agent_driver",
        name="Agent driver",
        demo="Local model via Ollama, or a free hosted tier (OPENAI_BASE_URL)",
        azure="Azure OpenAI / OpenAI",
        active=active,
        degraded=backend in {"scripted", "openai_compatible"},
        backend=backend,
        cost=cost,
    )


def _secrets_row() -> Capability:
    vault = bool(os.environ.get("AZURE_KEY_VAULT_URI"))
    return Capability(
        key="secrets",
        name="Secret resolution",
        demo="Environment variables from the platform's secret store",
        azure="Azure Key Vault + managed identity",
        active="Azure Key Vault URI configured" if vault else "Environment variables",
        degraded=not vault,
        backend="key_vault" if vault else "environment",
        cost=_PAID if vault else _FREE,
    )


def capability_matrix(
    settings: Settings,
    *,
    shield_backend: str | None = None,
    classifier_backend: str | None = None,
    store: object | None = None,
) -> list[Capability]:
    """Every capability, resolved from the running components where available."""
    return [
        _shield_row(settings, shield_backend),
        _classifier_row(settings, classifier_backend),
        _persistence_row(settings, store),
        _observability_row(settings),
        _agent_row(settings),
        _secrets_row(),
    ]


def mode_summary(
    settings: Settings,
    *,
    shield_backend: str | None = None,
    classifier_backend: str | None = None,
    store: object | None = None,
) -> dict[str, object]:
    """The payload the dashboard renders, now describing reality."""
    caps = capability_matrix(
        settings,
        shield_backend=shield_backend,
        classifier_backend=classifier_backend,
        store=store,
    )
    free = [c for c in caps if c.cost == _FREE]
    if settings.demo_mode:
        mode = "DEMO MODE"
        tagline = (
            "Offline demo with synthetic tools. The security pipeline is identical "
            "to production."
        )
    else:
        mode = "PRODUCTION MODE"
        tagline = (
            f"{len(free)} of {len(caps)} capabilities on free backends. "
            "Enforcement never depends on a paid service."
        )
    return {
        "mode": mode,
        "demo_mode": settings.demo_mode,
        "tagline": tagline,
        "degraded": [c.name for c in caps if c.degraded],
        "capabilities": [
            {
                "key": c.key, "name": c.name, "demo": c.demo, "azure": c.azure,
                "active": c.active, "degraded": c.degraded,
                "backend": c.backend, "cost": c.cost,
            }
            for c in caps
        ],
    }
