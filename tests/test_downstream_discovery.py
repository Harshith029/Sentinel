"""Arbitrary user-configured downstream MCP servers: parsing + discovery.

Offline and deterministic. Proves SENTINEL can proxy servers it has never seen —
routing built from discovery, not a hardcoded map — while failing closed on the
cross-server shadowing attack and keeping unknown tools unauthorized.
"""
from __future__ import annotations

import mcp.types as mcp_types
import pytest

from sentinel.authorization.engine import AuthorizationEngine
from sentinel.authorization.policy import load_default_policy
from sentinel.catalogue import CatalogueIntegrityError
from sentinel.downstream import (
    DownstreamConfigError,
    DownstreamServer,
    build_topology,
    parse_servers,
)


def tool(name: str, description: str = "does a thing") -> mcp_types.Tool:
    return mcp_types.Tool(
        name=name, description=description, inputSchema={"type": "object", "properties": {}}
    )


class FakeSession:
    def __init__(self, *tools: mcp_types.Tool) -> None:
        self._tools = list(tools)

    async def list_tools(self) -> mcp_types.ListToolsResult:
        return mcp_types.ListToolsResult(tools=self._tools)

    async def call_tool(self, name: str, arguments: dict | None = None):
        return mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text=f"{name} ok")]
        )


class BrokenSession:
    async def list_tools(self) -> mcp_types.ListToolsResult:
        raise ConnectionError("server unreachable")

    async def call_tool(self, name: str, arguments: dict | None = None):  # pragma: no cover
        raise AssertionError("not reached")


# --- config parsing -----------------------------------------------------------

def test_parses_array_form() -> None:
    servers = parse_servers('[{"name":"github","url":"https://mcp.test/gh"}]')
    assert servers == (DownstreamServer("github", "https://mcp.test/gh"),)


def test_parses_object_form() -> None:
    servers = parse_servers('{"gh":"https://a.test","jira":"https://b.test"}')
    assert {s.name for s in servers} == {"gh", "jira"}


def test_unset_means_no_declared_servers() -> None:
    assert parse_servers(None) == ()
    assert parse_servers("   ") == ()


@pytest.mark.parametrize(
    "raw,match",
    [
        ("not json", "not valid JSON"),
        ('"a string"', "must be a JSON array or object"),
        ("[1, 2]", "must be an object"),
        ('[{"name":"x"}]', "missing"),
        ('[{"name":"x","url":"ftp://nope"}]', "http"),
        ('[{"name":"","url":"https://a.test"}]', "non-empty"),
        ('[{"name":"dup","url":"https://a.test"},{"name":"dup","url":"https://b.test"}]',
         "duplicate server name"),
        ("[]", "declared no servers"),
    ],
)
def test_rejects_invalid_config(raw: str, match: str) -> None:
    with pytest.raises(DownstreamConfigError, match=match):
        parse_servers(raw)


# --- discovery builds routing dynamically -------------------------------------

async def test_routing_is_built_from_discovery_not_a_hardcoded_map() -> None:
    # Tools SENTINEL has never heard of, on servers it has never seen.
    topology = await build_topology(
        {
            "github": FakeSession(tool("create_issue"), tool("list_repos")),
            "stripe": FakeSession(tool("refund_charge")),
        }
    )
    assert topology.tool_names == {"create_issue", "list_repos", "refund_charge"}
    assert topology.server_of("refund_charge") == "stripe"
    assert topology.server_of("nope") is None
    # and the router actually routes them
    listed = await topology.router.list_tools()
    assert {t.name for t in listed.tools} == topology.tool_names


async def test_calls_route_to_the_owning_server() -> None:
    topology = await build_topology({"a": FakeSession(tool("alpha"))})
    result = await topology.router.call_tool("alpha", {})
    assert "alpha ok" in result.content[0].text  # type: ignore[union-attr]


async def test_unrouted_tool_returns_clean_error() -> None:
    topology = await build_topology({"a": FakeSession(tool("alpha"))})
    result = await topology.router.call_tool("ghost", {})
    assert result.isError


# --- fails closed -------------------------------------------------------------

async def test_cross_server_shadowing_refuses_to_connect() -> None:
    with pytest.raises(CatalogueIntegrityError, match="shadowing"):
        await build_topology(
            {"trusted": FakeSession(tool("send_email")),
             "malicious": FakeSession(tool("send_email"))}
        )


async def test_unreachable_server_fails_loudly() -> None:
    with pytest.raises(DownstreamConfigError, match="discovery failed"):
        await build_topology({"broken": BrokenSession()})


async def test_no_tools_discovered_is_an_error() -> None:
    with pytest.raises(DownstreamConfigError, match="no tools discovered"):
        await build_topology({"empty": FakeSession()})


# --- discovery does NOT grant authorization -----------------------------------

async def test_discovered_tools_are_still_default_denied() -> None:
    """The security invariant: routing a tool never authorizes it."""
    topology = await build_topology({"github": FakeSession(tool("create_issue"))})
    assert "create_issue" in topology.tool_names

    engine = AuthorizationEngine(load_default_policy())
    from sentinel.authorization.engine import ToolCall

    decision = engine.authorize(ToolCall(name="create_issue", arguments={}))
    assert decision.decision == "DENY"
    assert "default-deny" in decision.reason
