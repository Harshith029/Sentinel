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
import functools
import logging
import os
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import mcp.types as mcp_types

from sentinel.authn import tenant_credentials, tenant_policy_paths
from sentinel.authorization.policy import CompiledPolicy, load_default_policy, load_policy
from sentinel.authorization.registry import DEFAULT_TENANT, PolicyRegistry, ReloadResult
from sentinel.classifier import AttackClassifier
from sentinel.classifier.attack_classifier import BlockedAttempt
from sentinel.config import Settings, get_settings
from sentinel.control.capabilities import mode_summary
from sentinel.control.events import BroadcastStore, EventBus
from sentinel.demo.scenario import (
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


def _load_policy_file(path_text: str, *, what: str) -> CompiledPolicy:
    path = Path(path_text)
    if not path.is_file():
        raise ValueError(
            f"{what} not found: {path} (set SENTINEL_POLICY_FILE / `policy:` in "
            "sentinel.yaml, or run `sentinel scaffold` to generate one)"
        )
    return load_policy(path.read_text(encoding="utf-8"))


_LOG = logging.getLogger("sentinel.control.manager")


def build_policy_registry(settings: Settings) -> PolicyRegistry:
    """Give every provisioned tenant a policy, and nobody else.

    * The default tenant gets the deployment policy: the operator's
      ``policy_file``, or the bundled example policy.
    * A tenant named in ``SENTINEL_TENANT_POLICIES`` gets its own file.
    * A tenant with a credential in ``SENTINEL_API_TOKENS`` but no file of its
      own gets the deployment policy. Before this, it got NOTHING, so every run
      in a per-tenant deployment failed with "no policy registered" — tenancy
      that authenticated callers and then could not execute a single action.
    * A tenant with neither a credential nor a file has no policy and is
      refused. That fail-closed behaviour is unchanged.

    Failing loudly on a bad path is deliberate: silently running the example
    policy while the operator believes theirs is active would be a security
    surprise.
    """
    if settings.policy_file:
        deployment = _load_policy_file(settings.policy_file, what="policy file")
    else:
        deployment = load_default_policy()

    registry = PolicyRegistry()
    registry.register(DEFAULT_TENANT, deployment)

    explicit = tenant_policy_paths()
    for tenant, path_text in explicit.items():
        registry.register(
            tenant, _load_policy_file(path_text, what=f"policy file for tenant {tenant!r}")
        )
    for tenant in tenant_credentials():
        if tenant not in explicit and registry.get(tenant) is None:
            registry.register(tenant, deployment)
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


class RunQuotaExceeded(RuntimeError):
    """A tenant already has its maximum number of background runs in flight."""

    def __init__(self, tenant: str, limit: int) -> None:
        super().__init__(
            f"tenant {tenant!r} already has {limit} runs in flight "
            "(SENTINEL_MAX_ACTIVE_RUNS); retry when one finishes"
        )
        self.tenant = tenant
        self.limit = limit


@dataclass
class RunRecord:
    """Public, mutable record of one run (``run_id`` is its ``trace_id``)."""

    run_id: str
    trace_id: str
    agent_id: str
    scenario: str
    # None: restored from before ownership was recorded, so nobody knows whose
    # it is. No tenant matches None, so only the operator can see such a run.
    tenant: str | None = DEFAULT_TENANT
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
        # A store handed in belongs to the caller; one built here is ours to close.
        self._owns_store = store is None
        self._bus = EventBus()
        self._store = BroadcastStore(self._inner_store, self._bus)
        self._emitter = SpanEmitter(self._store)
        self._registry = build_policy_registry(self._settings)  # multi-tenant policies
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
        # Ownership writes in flight; awaited on shutdown so none is lost.
        self._pending_writes: set[asyncio.Task[Any]] = set()
        self._last_purge: float | None = None

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
        # Each run is a background task doing real work. Without a cap one
        # caller could start any number of them — 60 rapid requests put 41 in
        # flight at once — so a tenant gets a bounded share, per tenant, so one
        # tenant saturating its quota does not lock out another.
        limit = self._settings.max_active_runs_per_tenant
        in_flight = sum(
            1 for r in self._runs.values() if r.tenant == tenant and r.status == "running"
        )
        if in_flight >= limit:
            raise RunQuotaExceeded(tenant, limit)
        trace_id = self._emitter.new_trace_id()
        record = RunRecord(
            run_id=trace_id,
            trace_id=trace_id,
            agent_id=agent_id or f"agent-{trace_id[:8]}",
            scenario=scenario,
            tenant=tenant,
        )
        self._runs[trace_id] = record
        self._persist_owner(record)
        task: asyncio.Task[None] = asyncio.create_task(self._execute(record, build))
        self._tasks[trace_id] = task
        task.add_done_callback(functools.partial(self._on_run_done_callback, trace_id))
        return record

    def _on_run_done_callback(self, trace_id: str, _task: asyncio.Task[None]) -> None:
        self._on_run_done(trace_id)

    def _on_run_done(self, trace_id: str) -> None:
        """Drop the finished task's reference and keep the index bounded."""
        self._tasks.pop(trace_id, None)
        self._prune_finished_runs()

    def _prune_finished_runs(self) -> None:
        """Keep at most ``max_retained_runs`` FINISHED runs in the index.

        The run index and the task table used to grow for as long as the
        process lived. Only finished runs are evicted — never one in flight —
        and oldest first. Their spans stay in the forensic store; this bounds
        the in-memory index, not the evidence.
        """
        limit = self._settings.max_retained_runs
        finished = [tid for tid, r in self._runs.items() if r.status != "running"]
        for tid in finished[: max(0, len(finished) - limit)]:
            del self._runs[tid]

    def new_live_proxy(
        self,
        *,
        downstream: DownstreamConnection,
        cache: Sequence[mcp_types.Tool],
        agent_id: str,
        tenant: str = DEFAULT_TENANT,
        catalogue_gate: Callable[[str], str | None] | None = None,
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
            # The TENANT'S OWN config, from their policy document. This used
            # to be sentinel.demo.scenario.DEFAULT_CONFIG, so every live MCP
            # session over the wire — the product path — was authorized against
            # the demo's `allowed_domains: ["corp.example"]` and `max_amount`.
            # An operator had no way to set it, so their allowlist rules either
            # permitted a domain they never approved or fail-closed on every key
            # the demo dict happened not to contain.
            authorization_config=engine.config,
            input_shield=self._shield,
            tool_schema_cache=cache,
            catalogue_gate=catalogue_gate,
        )
        self._runs[trace_id] = RunRecord(
            run_id=trace_id,
            trace_id=trace_id,
            agent_id=agent_id,
            scenario="live-mcp",
            tenant=tenant,
            status="running",
        )
        self._persist_owner(self._runs[trace_id])
        return proxy

    def _persist_owner(self, record: RunRecord) -> None:
        """Record in the persistent store which tenant a new run belongs to.

        Fire-and-track rather than awaited, because runs start from synchronous
        code; :meth:`aclose` waits for any write still in flight.
        """
        store = self._inner_store
        if not isinstance(store, SqliteForensicStore) or record.tenant is None:
            return
        task = asyncio.create_task(
            store.put_run(
                record.trace_id, tenant=record.tenant,
                agent_id=record.agent_id, scenario=record.scenario,
            )
        )
        self._pending_writes.add(task)
        task.add_done_callback(self._pending_writes.discard)
        self._maybe_purge()

    def _maybe_purge(self) -> None:
        """Apply the retention policy at most once a day, driven by activity."""
        now = time.monotonic()
        if self._last_purge is not None and now - self._last_purge < 86_400:
            return
        self._last_purge = now
        task = asyncio.create_task(self.purge_expired())
        self._pending_writes.add(task)
        task.add_done_callback(self._pending_writes.discard)

    async def purge_expired(self) -> list[str]:
        """Delete traces past ``SENTINEL_FORENSIC_RETENTION_DAYS`` (0 = keep all).

        Runs in flight are never touched. The run index forgets purged runs,
        so it cannot offer a replay of a trace that no longer exists.
        """
        days = self._settings.forensic_retention_days
        store = self._inner_store
        if days == 0 or not isinstance(store, SqliteForensicStore):
            return []
        cutoff = datetime.now(UTC) - timedelta(days=days)
        running = frozenset(t for t, r in self._runs.items() if r.status == "running")
        purged = await store.purge_older_than(cutoff, keep=running)
        for trace_id in purged:
            self._runs.pop(trace_id, None)
        if purged:
            _LOG.info(
                "retention: deleted %d trace(s) older than %d day(s)", len(purged), days
            )
        return purged

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
            engine = (
                self._registry.engine_for(record.tenant)
                if record.tenant is not None
                else None
            )
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

    def finish_live_run(self, trace_id: str, *, status: str = "completed") -> None:
        """Move a live MCP run out of ``running`` when its transport is done.

        Live runs were opened ``status="running"`` and never transitioned, so
        every MCP session a deployment had ever served sat in the run index as
        permanently in-flight. An operator reading that index could not tell an
        active agent from one that disconnected days ago, which is exactly the
        question the index exists to answer.

        Idempotent and safe from a finalizer: it only ever moves a run OUT of
        ``running``, so a late call cannot resurrect or relabel a run that some
        other path already completed.
        """
        record = self._runs.get(trace_id)
        if record is not None and record.status == "running":
            record.status = status
            self._prune_finished_runs()

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
        if self._last_purge is None:
            self._last_purge = time.monotonic()
            await self.purge_expired()  # never restore what retention deletes
        trace_ids = await self._inner_store.list_trace_ids()
        owners = await self._inner_store.run_owners()
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
            # Ownership comes from what was recorded when the run started. A
            # trace with no record predates that (or was written by something
            # else) and is attributed to NOBODY rather than to the default
            # tenant: guessing an owner either hides a tenant's history from
            # it or shows it to someone else.
            owner = owners.get(trace_id)
            tenant: str | None = None
            if owner is not None:
                tenant, agent_id, scenario = owner
            self._runs[trace_id] = RunRecord(
                run_id=trace_id, trace_id=trace_id, agent_id=agent_id,
                scenario=scenario, tenant=tenant, status="completed",
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
        # Resolved from the RUNNING components, not inferred from demo_mode.
        summary = mode_summary(
            self._settings,
            shield_backend=self._shield.backend,
            classifier_backend=self._classifier.backend,
            store=self._inner_store,
        )
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
        """Clean shutdown: stop runs, finish pending writes, close the store."""
        # Snapshot: finishing tasks remove themselves from _tasks, so iterating
        # the live dict while awaiting would change it mid-loop.
        tasks = list(self._tasks.values())
        for task in tasks:
            if not task.done():
                task.cancel()
        for task in tasks:
            # Teardown: drain cancelled/failed tasks; their failures are already
            # captured on the RunRecord, so swallowing here is intentional.
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001, S110
                pass
        # Ownership records and retention are writes, not work to abandon: a
        # run whose owner was never recorded restores as nobody's.
        for write in list(self._pending_writes):
            try:
                await write
            except Exception:  # noqa: BLE001 - shutdown must not stop on one write
                _LOG.exception("pending forensic-store write failed at shutdown")
        close = getattr(self._inner_store, "close", None)
        if self._owns_store and callable(close):
            close()
            self._owns_store = False  # aclose may be called more than once
