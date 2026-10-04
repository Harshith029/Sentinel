"""Operator approval of a reviewed tool definition, by fingerprint (review F10).

The catalogue scanner is a heuristic. Measured with the local detector: three
of four ordinary descriptions were flagged ("Send an email to a recipient, e.g.
user@example.com.", "Query the ticketing system: returns open issues.",
"Forward the message to ops-team@company.com for triage."), and in strict mode
(the default) SENTINEL then refused to start. The only way past was turning
strict mode off for every tool. An approval accepts one EXACT definition: if
the tool changes, the approval stops matching and the tool is flagged again.
"""
from __future__ import annotations

import mcp.types as mcp_types
import pytest

from sentinel.catalogue import fingerprint_tool, parse_approvals
from sentinel.demo.preflight import PreflightError, preflight
from sentinel.shield import InputShield

SHIELD = InputShield(demo_mode=True)


def _tool(name: str, description: str) -> mcp_types.Tool:
    return mcp_types.Tool(
        name=name, description=description, inputSchema={"type": "object", "properties": {}}
    )


ORDINARY = (
    _tool("send_email", "Send an email to a recipient, e.g. user@example.com."),
    _tool("list_issues", "Query the ticketing system: returns open issues."),
    _tool("forward", "Forward the message to ops-team@company.com for triage."),
)
PLAIN = _tool("fetch_page", "Fetch a web page and return its text.")


class _Downstream:
    def __init__(self, *tools: mcp_types.Tool) -> None:
        self._tools = list(tools)

    async def list_tools(self) -> mcp_types.ListToolsResult:
        return mcp_types.ListToolsResult(tools=self._tools)


def _approve(*tools: mcp_types.Tool) -> dict[str, str]:
    return {tool.name: fingerprint_tool(tool) for tool in tools}


async def test_ordinary_descriptions_are_flagged_and_the_refusal_says_how_to_approve() -> None:
    with pytest.raises(PreflightError) as refused:
        await preflight(_Downstream(*ORDINARY, PLAIN), required_tools=[], shield=SHIELD)
    message = str(refused.value)
    assert "catalogue_approvals:" in message
    for tool in ORDINARY:
        assert f"{tool.name}: {fingerprint_tool(tool)}" in message
    assert "fetch_page" not in message  # nothing flagged, nothing to approve


async def test_approving_the_exact_definitions_lets_it_start() -> None:
    cache = await preflight(
        _Downstream(*ORDINARY, PLAIN), required_tools=[], shield=SHIELD,
        approved=_approve(*ORDINARY),
    )
    assert cache.names == {"send_email", "list_issues", "forward", "fetch_page"}
    assert cache.findings == ()
    # Approved is not forgotten: the findings are still reported.
    assert {f.tool_name for f in cache.acknowledged} == {t.name for t in ORDINARY}


async def test_a_changed_definition_is_flagged_again() -> None:
    approved = _approve(*ORDINARY)
    changed = _tool("send_email", "Send an email to a recipient, e.g. admin@example.com.")
    with pytest.raises(PreflightError, match="has changed since") as refused:
        await preflight(
            _Downstream(changed, *ORDINARY[1:]), required_tools=[], shield=SHIELD,
            approved=approved,
        )
    assert f"send_email: {fingerprint_tool(changed)}" in str(refused.value)


async def test_an_approval_covers_only_its_own_tool() -> None:
    with pytest.raises(PreflightError) as refused:
        await preflight(
            _Downstream(*ORDINARY), required_tools=[], shield=SHIELD,
            approved=_approve(ORDINARY[0]),
        )
    assert "send_email:" not in str(refused.value).split("catalogue_approvals:")[1]
    assert "list_issues" in str(refused.value)


async def test_flag_only_mode_keeps_approved_and_unapproved_apart() -> None:
    cache = await preflight(
        _Downstream(*ORDINARY), required_tools=[], shield=SHIELD, strict=False,
        approved=_approve(ORDINARY[0]),
    )
    assert [f.tool_name for f in cache.acknowledged] == ["send_email"]
    assert {f.tool_name for f in cache.findings} == {"list_issues", "forward"}


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("{not json", "not valid JSON"),
        ('["send_email"]', "must be an object"),
        ('{"send_email": "abc123"}', "64-character hex"),
        ('{"send_email": "' + "z" * 64 + '"}', "64-character hex"),
    ],
)
def test_malformed_approvals_are_an_error(raw: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_approvals(raw)


def test_approvals_parse_and_normalize() -> None:
    fingerprint = fingerprint_tool(ORDINARY[0])
    assert parse_approvals(None) == {}
    assert parse_approvals("  ") == {}
    assert parse_approvals(f'{{"send_email": "{fingerprint.upper()}"}}') == {
        "send_email": fingerprint
    }
