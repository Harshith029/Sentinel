"""RunManager (BUILD_SPEC §Phase 6) — owns the shared pipeline; runs are isolated.

One manager holds ONE shared set of pipeline dependencies (inner store, the
tee-ing :class:`BroadcastStore`, the seq-assigning emitter, the policy engine,
the trust scorer, the event bus). Each run gets a FRESH ``trace_id`` and a unique
``agent_id``, so concurrent runs interleave in the shared store/bus yet stay
isolated: replay filters by ``trace_id`` and orders by ``(trace_id, seq)``, and
trust accrues per agent.

Runs execute in BACKGROUND tasks so the live monitor (SSE) can stream their spans
as they happen. This is the control plane only — it never routes tool calls;
those are intercepted at the MCP boundary inside :func:`run_demo_session`.
"""
from __future__ import annotations

import asyncio
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import mcp.types as mcp_types

from sentinel.authorization.policy import load_policy
from sentinel.authorization.registry import DEFAULT_TENANT, PolicyRegistry, ReloadResult
from sentinel.classifier import AttackClassifier
from sentinel.classifier.attack_classifier import BlockedAttempt
from sentinel.config import Settings, get_settings
from sentinel.control.capabilities import mode_summary
from sentinel.control.events import BroadcastStore, EventBus
from sentinel.demo.scenario import (
    DEFAULT_CONFIG,
    CustomScenarioSpec,
    ScenarioBuild,
    build_custom_scenario,
    build_scenario_full,
    run_demo_session,
)
from sentinel.forensics.emitter import SpanEmitter
from sentinel.forensics.events import (
    AgentQuarantined,
    AuthorizationDecided,
    InjectionScanned,
    InputReceived,
    ToolBlocked,
)
from sentinel.forensics.replay import TraceReplay, replay
from sentinel.forensics.store import (
    CosmosForensicStore,
    ForensicStore,
    SqliteForensicStore,
)
from sentinel.mcp_proxy.proxy import SentinelProxy
from sentinel.mcp_proxy.router import DownstreamConnection
from sentinel.shield import InputShield
from sentinel.trust.config import load_default_trust_config
from sentinel.trust.scorer import TrustScorer


def _infer_scenario(user_input: str) -> str:
    """Best-effort scenario classification for a restored run record.

    Only used for display in the run index. Authoritative replay is from the
    forensic spans; this just guesses a label from the user prompt because
    the scenario name isn't itself stored as a span.
    """
    text = user_input.lower()
    if "bulk-delete" in text or "permanently remove" in text:
        return "privilege" if "permanently remove" in text else "trust-collapse"
    if "pricing page" in text or "research" in text:
        return "hero-obvious"
    return "restored"


def _build_cosmos_container(settings: Settings) -> Any:  # noqa: ANN401 - SDK container
    """Build the live async Cosmos container client (AZURE MODE).

    Identity-only auth (managed identity via :class:`DefaultAzureCredential`), no
    keys in code (§6). Partition key is ``/trace_id`` (set on the container at
    deploy time). Constructed lazily so the azure SDKs are imported only when
    Cosmos is actually configured. Not exercised offline (needs a live account).
    """
    from azure.cosmos.aio import CosmosClient  # noqa: PLC0415 - Azure-only path
    from azure.identity.aio import DefaultAzureCredential  # noqa: PLC0415

    endpoint = settings.azure_cosmos_endpoint
    assert endpoint is not None  # precondition: only called when configured
    client = CosmosClient(endpoint, DefaultAzureCredential())
    database = client.get_database_client(settings.azure_cosmos_database)
    return database.get_container_client(settings.azure_cosmos_container)


def _build_registry(settings: Settings) -> PolicyRegistry:
    """Load the operator's policy file, or fall back to the bundled example one.

    Governing your own tools requires your own policy; the packaged default only
    describes the example tools, so everything else is default-denied. Failing
    loudly on a bad path is deliberate — silently running the example policy while
    the operator believes theirs is active would be a security surprise.
    """
    if not settings.policy_file:
        return PolicyRegistry.with_default()
    path = Path(settings.policy_file)
    if not path.is_file():
        raise ValueError(
            f"policy file not found: {path} (set SENTINEL_POLICY_FILE / `policy:` "
            "in sentinel.yaml, or run `sentinel scaffold` to generate one)"
        )
    registry = PolicyRegistry()
    registry.register(DEFAULT_TENANT, load_policy(path.read_text(encoding="utf-8")))
    return registry


def _default_store(settings: Settings) -> ForensicStore:
    """The default forensic store, chosen by mode.

    AZURE MODE (``AZURE_COSMOS_ENDPOINT`` set) → distributed
    :class:`CosmosForensicStore` partitioned by ``trace_id``. Otherwise →
    :class:`SqliteForensicStore` under ``$SENTINEL_DATA_DIR`` (or ``./var``), which
    persists across restarts so the dashboard's history survives a reboot. Tests
    pass an explicit :class:`InMemoryForensicStore` so no test writes to disk.
    """
    if settings.azure_cosmos_endpoint:
        return CosmosForensicStore(_build_cosmos_container(settings))
    data_dir = Path(os.environ.get("SENTINEL_DATA_DIR", "var"))
    return SqliteForensicStore(data_dir / "sentinel.db")


@dataclass
class RunRecord:
    """Public, mutable record of one run (``run_id`` is its ``trace_id``)."""

    run_id: str
    trace_id: str
    agent_id: str
    scenario: str
    tenant: str = DEFAULT_TENANT
    status: str = "running"  # running | completed | failed
    error: str | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "trace_id": self.trace_id,
            "agent_id": self.agent_id,
            "scenario": self.scenario,
            "tenant": self.tenant,
            "status": self.status,
            "error": self.error,
        }


class RunManager:
    """Starts/inspects runs over one shared, span-emitting pipeline.

    By default the forensic store is a :class:`SqliteForensicStore` rooted at
    ``${SENTINEL_DATA_DIR:-./var}/sentinel.db`` so runs survive a restart. Tests
    and explicit callers can pass any :class:`ForensicStore` (in-memory,
    :class:`CosmosForensicStore` in AZURE MODE) via ``store=``.
    """

    def __init__(
        self,
        *,
        demo_mode: bool | None = None,
        store: ForensicStore | None = None,
    ) -> None:
        # Mode is driven by SENTINEL_DEMO_MODE (settings) unless overridden, so the
        # capability matrix and every integration agree on the active mode.
        self._settings: Settings = get_settings()
        self._demo_mode = self._settings.demo_mode if demo_mode is None else demo_mode
        self._inner_store: ForensicStore = (
            store if store is not None else _default_store(self._settings)
        )
        self._bus = EventBus()
        self._store = BroadcastStore(self._inner_store, self._bus)
        self._emitter = SpanEmitter(self._store)
        self._registry = _build_registry(self._settings)  # multi-tenant policies
        self._scorer = TrustScorer(self._emitter, load_default_trust_config())
        # Build the shield FROM SETTINGS so AZURE MODE actually carries the
        # Content-Safety endpoint/key (demo_mode alone left it unconfigured).
        self._shield = InputShield.from_settings(self._settings)
        self._classifier = AttackClassifier(
            demo_mode=self._demo_mode,
            azure_openai_endpoint=self._settings.azure_openai_endpoint,
            azure_openai_deployment=self._settings.azure_openai_deployment,
            azure_openai_api_version=self._settings.azure_openai_api_version,
        )
        self._runs: dict[str, RunRecord] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}

    @property
    def bus(self) -> EventBus:
        return self._bus

    @property
    def registry(self) -> PolicyRegistry:
        return self._registry

    def start_scenario(
        self, scenario: str, *, agent_id: str | None = None, tenant: str = DEFAULT_TENANT
    ) -> RunRecord:
        """Start a named scenario as a background run; returns its record at once."""
        build = build_scenario_full(scenario)  # validates the name (raises)
        return self._start(build, scenario=scenario, agent_id=agent_id, tenant=tenant)

    def start_custom(
        self,
        spec: CustomScenarioSpec,
        *,
        agent_id: str | None = None,
        tenant: str = DEFAULT_TENANT,
    ) -> RunRecord:
        """Start a user-supplied attack: their task / URL / page / attacker.

        The pipeline is the IDENTICAL code path the canned scenarios use; only
        the agent transcript and the (mock) downstream's canned pages change.
        """
        build = build_custom_scenario(spec)
        return self._start(build, scenario="custom", agent_id=agent_id, tenant=tenant)

    def _start(
        self,
        build: ScenarioBuild,
        *,
        scenario: str,
        agent_id: str | None,
        tenant: str = DEFAULT_TENANT,
    ) -> RunRecord:
        trace_id = self._emitter.new_trace_id()
        record = RunRecord(
            run_id=trace_id,
            trace_id=trace_id,
            agent_id=agent_id or f"agent-{trace_id[:8]}",
            scenario=scenario,
            tenant=tenant,
        )
        self._runs[trace_id] = record
        task: asyncio.Task[None] = asyncio.create_task(self._execute(record, build))
        self._tasks[trace_id] = task
        return record

    def new_live_proxy(
        self,
        *,
        downstream: DownstreamConnection,
        cache: Sequence[mcp_types.Tool],
        agent_id: str,
        tenant: str = DEFAULT_TENANT,
    ) -> SentinelProxy:
        """Build a per-session proxy for a LIVE MCP connection (Phase 9 gateway).

        The proxy shares THIS manager's emitter / store / scorer / policy
        registry, so a client that connects over real HTTP emits spans into the
        same forensic store and surfaces on the dashboard exactly like a scripted
        scenario. Each call gets a FRESH ``trace_id`` + :class:`RunRecord`
        (``status="running"``, ``scenario="live-mcp"``) — one MCP session == one
        agent task == one trace, the proxy's own contract.

        Fail-closed: raises if the tenant has no registered policy, rather than
        building an unprotected proxy.
        """
        engine = self._registry.engine_for(tenant)
        if engine is None:
            raise ValueError(f"no policy registered for tenant {tenant!r}")
        trace_id = self._emitter.new_trace_id()
        proxy = SentinelProxy(
            downstream=downstream,
            emitter=self._emitter,
            engine=engine,
            scorer=self._scorer,
            agent_id=agent_id,
            trace_id=trace_id,
            authorization_config=DEFAULT_CONFIG,
            input_shield=self._shield,
            tool_schema_cache=cache,
        )
        self._runs[trace_id] = RunRecord(
            run_id=trace_id,
            trace_id=trace_id,
            agent_id=agent_id,
            scenario="live-mcp",
            tenant=tenant,
            status="running",
        )
        return proxy

    def _select_driver(self, build: ScenarioBuild) -> Any:  # noqa: ANN401 - AgentDriver
        """Choose the agent that proposes tool calls for a run.

        Default (product): a REAL LLM when a credential is configured
        (``OPENAI_API_KEY`` / Azure OpenAI). Offline / CI: the deterministic
        scripted transcript from the scenario build, so runs stay reproducible and
        key-free. The security pipeline is identical either way — only the driver
        differs (BUILD_SPEC §10).
        """
        from sentinel.demo.llm_driver import default_agent_driver

        return default_agent_driver(
            task=build.user_input,
            scripted_fallback=build.driver,
            settings=self._settings,
        )

    async def _execute(self, record: RunRecord, build: ScenarioBuild) -> None:
        try:
            # Resolve the tenant's policy at run time → registry hot-reloads take
            # effect for subsequent runs without restart.
            engine = self._registry.engine_for(record.tenant)
            if engine is None:
                raise ValueError(f"no policy registered for tenant {record.tenant!r}")
            await run_demo_session(
                self._select_driver(build),
                user_input=build.user_input,
                demo_mode=self._demo_mode,
                agent_id=record.agent_id,
                authorization_config=build.config,
                store=self._store,
                emitter=self._emitter,
                engine=engine,
                scorer=self._scorer,
                input_shield=self._shield,
                trace_id=record.trace_id,
                extra_pages=build.extra_pages,
                real_web=self._settings.real_web_fetch,
            )
            record.status = "completed"
        except Exception as exc:  # noqa: BLE001 - record failure; never crash the loop
            record.status = "failed"
            record.error = str(exc)

    async def run_baseline(self, build: ScenarioBuild) -> dict[str, Any]:
        """Run a scenario WITHOUT SENTINEL in front and return its observable result.

        For the "before/after" demo: same driver, same downstream tool servers,
        no proxy. The outbox arrives populated (nothing stopped the exfil) and
        no spans are emitted (there is no SENTINEL in this path). The caller —
        the dashboard — shows the two outboxes side-by-side so a viewer can
        FEEL the win, not just read the BLOCKED banner.
        """
        result = await run_demo_session(
            build.driver,
            user_input=build.user_input,
            demo_mode=self._demo_mode,
            agent_id="baseline-no-sentinel",
            authorization_config=build.config,
            extra_pages=build.extra_pages,
            skip_sentinel=True,
        )
        return {
            "outbox": result.outbox,
            "executions": [
                {"tool": name, "arg": str(arg)} for name, arg in result.executions
            ],
        }

    async def join(self, trace_id: str) -> None:
        """Await a run's completion (test/diagnostic helper)."""
        task = self._tasks.get(trace_id)
        if task is not None:
            await task

    def get_run(self, run_id: str) -> RunRecord | None:
        return self._runs.get(run_id)

    def list_runs(self) -> list[RunRecord]:
        return list(self._runs.values())

    async def restore_persisted_runs(self) -> int:
        """Re-hydrate :class:`RunRecord` entries from a persistent store.

        Called at app startup when the backing store survives across restarts
        (currently SQLite). For each previously-recorded trace we reconstruct a
        ``RunRecord`` (status="completed") so the dashboard's run index, audit
        export, and replay endpoints all work after a reboot. The forensic
        spans themselves are already in the store; this just rebuilds the
        minimal in-memory record the control plane keeps per run.
        """
        if not isinstance(self._inner_store, SqliteForensicStore):
            return 0
        trace_ids = await self._inner_store.list_trace_ids()
        restored = 0
        for trace_id in trace_ids:
            if trace_id in self._runs:
                continue
            spans = await self._inner_store.get_spans(trace_id)
            if not spans:
                continue
            scenario = "restored"
            agent_id = f"agent-{trace_id[:8]}"
            for s in spans:
                if isinstance(s.payload, InputReceived):
                    # The user input doesn't tell us the scenario name, but the
                    # control plane only uses scenario for display.
                    scenario = _infer_scenario(s.payload.content)
                    break
            self._runs[trace_id] = RunRecord(
                run_id=trace_id, trace_id=trace_id, agent_id=agent_id,
                scenario=scenario, status="completed",
            )
            restored += 1
        return restored

    async def replay(self, trace_id: str) -> TraceReplay:
        # Deterministic: ordered by (trace_id, seq) from the inner store.
        return await replay(self._inner_store, trace_id)

    def trust(self, agent_id: str) -> dict[str, Any]:
        return {
            "agent_id": agent_id,
            "score": self._scorer.score(agent_id),
            "quarantined": self._scorer.is_quarantined(agent_id),
        }

    def reset(self, agent_id: str) -> dict[str, Any]:
        self._scorer.reset(agent_id)
        return self.trust(agent_id)

    def capabilities(self) -> dict[str, Any]:
        """DEMO-vs-AZURE capability matrix (the 'Azure is load-bearing' delta).

        Carries an explicit UNVERIFIED list. Reporting a service as configured is
        not the same as reporting it as working, and an operator reading this
        endpoint to decide whether a deployment is sound deserves to be told the
        difference rather than left to infer it.
        """
        summary = mode_summary(self._settings)
        summary["deployment_verification"] = {
            "status": "unverified",
            "detail": (
                "The Azure topology has NOT been deployed or smoke-tested. "
                "Container-app wiring and MCP route paths are correct in the "
                "template, but that is not evidence of deployability."
            ),
            "unverified": [
                "key-vault-secret-consumption",
                "content-safety-configuration",
                "openai-configuration",
                "cosmos-data-plane-rbac",
                "readiness-checks",
                "end-to-end-deployment-smoke-test",
            ],
            "tracking": "audit finding F-02",
        }
        return summary

    # --- multi-tenant policy ---------------------------------------------------

    def list_tenants(self) -> list[dict[str, Any]]:
        return [
            {"tenant": t, "policy_version": self._registry.version(t)}
            for t in self._registry.tenants()
        ]

    def reload_policy(self, tenant: str, policy_text: str) -> ReloadResult:
        """Hot-reload a tenant's policy on version bump (raises on malformed)."""
        return self._registry.reload_if_newer(tenant, policy_text)

    # --- SOC audit (the classifier's ONE consumer) -----------------------------

    async def audit(self, trace_id: str) -> list[dict[str, Any]]:
        """Forensic spans as SOC/SIEM JSONL; blocked attempts get a classifier label.

        The semantic classifier touches NOTHING else — severity is computed
        independently here, and the label is attached only to ToolBlocked alerts.
        """
        rep = await self.replay(trace_id)
        injection_detected = any(
            isinstance(s.payload, InjectionScanned) and s.payload.attack_detected
            for s in rep.ordered
        )
        decided: dict[str | None, AuthorizationDecided] = {
            s.parent_span_id: s.payload
            for s in rep.ordered
            if isinstance(s.payload, AuthorizationDecided)
        }
        alerts: list[dict[str, Any]] = []
        for s in rep.ordered:
            p = s.payload
            severity = "info"
            if isinstance(p, ToolBlocked) or (
                isinstance(p, AuthorizationDecided) and p.decision == "DENY"
            ):
                severity = "high"
            elif isinstance(p, AgentQuarantined):
                severity = "critical"
            alert: dict[str, Any] = {
                "timestamp": s.timestamp.isoformat(),
                "source": "SENTINEL",
                "trace_id": s.trace_id,
                "span_id": s.span_id,
                "seq": s.seq,
                "alert_type": s.event_type,
                "severity": severity,
            }
            if isinstance(p, ToolBlocked):
                ctx = decided.get(s.parent_span_id)
                label = await self._classifier.classify(
                    BlockedAttempt(
                        tool_name=p.tool_name,
                        matched_rule_id=p.matched_rule_id,
                        blocked_by=p.blocked_by,
                        reason=p.reason,
                        is_tainted=ctx.is_tainted if ctx is not None else False,
                        injection_detected=injection_detected,
                    )
                )
                alert["attack_class"] = label.attack_class
                alert["attack_rationale"] = label.rationale
                alert["classifier"] = label.classifier
            alerts.append(alert)
        return alerts

    async def aclose(self) -> None:
        """Cancel any still-running background tasks (clean teardown)."""
        for task in self._tasks.values():
            if not task.done():
                task.cancel()
        for task in self._tasks.values():
            # Teardown: drain cancelled/failed tasks; their failures are already
            # captured on the RunRecord, so swallowing here is intentional.
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001, S110
                pass
