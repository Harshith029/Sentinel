"""Quarantine is recorded, not enforced, unless the operator turns it on (review F3).

The trust score only ever falls. Measured against the real scorer with only
ALLOWED calls: varied use crossed the quarantine threshold within 15–21 calls,
and even 95%-repetitive traffic within 40–157. One flagged page (−50) plus one
blocked call (−30) crosses it at once. Enforced, that cut off legitimate agents,
and with them every agent sharing the credential.
"""
from __future__ import annotations

import random
from pathlib import Path

import mcp.types as mcp_types
import pytest

from sentinel.config import get_settings, reset_settings_cache
from sentinel.control.manager import RunManager
from sentinel.forensics.replay import replay
from sentinel.forensics.store import InMemoryForensicStore
from sentinel.mcp_proxy.content import result_text

_TOOLS = ("search", "read_doc", "summarize", "create_ticket", "list_files")


class _Downstream:
    def __init__(self) -> None:
        self.calls = 0

    async def call_tool(
        self, name: str, arguments: dict[str, object]
    ) -> mcp_types.CallToolResult:
        self.calls += 1
        return mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text="ok")], isError=False
        )


@pytest.fixture
def _permissive_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "policy_version: 1\ntools:\n"
        + "".join(f"  {tool}:\n    rules: []\n" for tool in _TOOLS),
        encoding="utf-8",
    )
    monkeypatch.setenv("SENTINEL_POLICY_FILE", str(policy))
    reset_settings_cache()


def test_quarantine_enforcement_is_off_by_default() -> None:
    assert get_settings().enforce_quarantine is False


@pytest.mark.usefixtures("_permissive_policy")
async def test_sustained_allowed_traffic_is_never_cut_off() -> None:
    manager = RunManager(store=InMemoryForensicStore())
    downstream = _Downstream()
    try:
        proxy = manager.new_live_proxy(
            downstream=downstream, cache=(), agent_id="agent-steady"  # type: ignore[arg-type]
        )
        await proxy.start(user_input="work through the backlog")
        rng = random.Random(7)  # noqa: S311 - a reproducible traffic mix, not crypto
        for _ in range(200):
            result = await proxy.handle_call(rng.choice(_TOOLS), {})
            assert result.isError is False, result_text(result)
        assert downstream.calls == 200

        # The crossing is still on record, marked as not enforced.
        rep = await replay(manager._inner_store, proxy.trace_id)  # noqa: SLF001
        crossings = [s.payload for s in rep.ordered if s.event_type == "AgentQuarantined"]
        assert len(crossings) == 1
        assert crossings[0].enforced is False  # type: ignore[attr-defined]
        trust = manager.trust("agent-steady")
        assert trust["quarantined"] is False
        assert trust["below_threshold"] is True
        assert trust["quarantine_enforced"] is False
    finally:
        await manager.aclose()


@pytest.mark.usefixtures("_permissive_policy")
async def test_an_operator_can_turn_enforcement_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_ENFORCE_QUARANTINE", "1")
    reset_settings_cache()
    manager = RunManager(store=InMemoryForensicStore())
    try:
        proxy = manager.new_live_proxy(
            downstream=_Downstream(), cache=(), agent_id="agent-enforced"  # type: ignore[arg-type]
        )
        await proxy.start(user_input="work through the backlog")
        rng = random.Random(7)  # noqa: S311 - a reproducible traffic mix, not crypto
        refused = None
        for i in range(200):
            result = await proxy.handle_call(rng.choice(_TOOLS), {})
            if result.isError:
                refused = i
                break
        assert refused is not None, "enforcement on, but the agent was never cut off"
        assert manager.trust("agent-enforced")["quarantined"] is True
    finally:
        await manager.aclose()
