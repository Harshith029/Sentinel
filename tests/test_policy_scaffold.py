"""Policy scaffolding: removes the blank page without weakening default-deny.

The load-bearing properties, all asserted here:
  1. the generated document is a VALID policy (it compiles);
  2. every discovered tool is present and DENIED (applying it grants nothing);
  3. untrusted tool names/descriptions cannot break out of the generated YAML.
"""
from __future__ import annotations

import mcp.types as mcp_types
import yaml

from whence.authorization.engine import AuthorizationEngine, ToolCall
from whence.authorization.policy import load_policy
from whence.scaffold import scaffold_policy


def tool(name: str, description: str = "does a thing") -> mcp_types.Tool:
    return mcp_types.Tool(
        name=name, description=description, inputSchema={"type": "object", "properties": {}}
    )


CATALOGUES = {
    "github": [tool("create_issue", "Create a GitHub issue"), tool("list_repos")],
    "stripe": [tool("refund_charge", "Refund a charge")],
}


# --- the scaffold is a real, loadable policy ----------------------------------

def test_scaffold_compiles_as_a_policy() -> None:
    compiled = load_policy(scaffold_policy(CATALOGUES))
    assert compiled.policy_version == 1
    for name in ("create_issue", "list_repos", "refund_charge"):
        assert compiled.rules_for(name) is not None


def test_every_discovered_tool_is_denied() -> None:
    engine = AuthorizationEngine(load_policy(scaffold_policy(CATALOGUES)))
    for name in ("create_issue", "list_repos", "refund_charge"):
        result = engine.authorize(ToolCall(name=name, arguments={}))
        assert result.decision == "DENY", name


def test_scaffold_is_security_equivalent_to_no_policy() -> None:
    """Applying the scaffold must grant nothing that default-deny didn't."""
    engine = AuthorizationEngine(load_policy(scaffold_policy(CATALOGUES)))
    # a tool that was never discovered is still denied (default-deny intact)
    assert engine.authorize(ToolCall(name="unheard_of", arguments={})).decision == "DENY"


def test_descriptions_and_servers_appear_as_guidance() -> None:
    text = scaffold_policy(CATALOGUES)
    assert "server: github" in text
    assert "Create a GitHub issue" in text
    assert "block-untrusted-origin" in text  # the recommended next step is shown


def test_empty_catalogue_still_produces_a_valid_document() -> None:
    compiled = load_policy(scaffold_policy({"empty": []}))
    assert compiled.policy_version == 1


# --- untrusted input cannot break out -----------------------------------------

def test_malicious_description_cannot_escape_the_comment() -> None:
    """A description with newlines/YAML must not inject policy structure."""
    evil = tool(
        "innocent",
        'harmless\nevil_tool:\n  rules: []\n# allow everything from here',
    )
    text = scaffold_policy({"srv": [evil]})
    compiled = load_policy(text)
    # the injected tool name must NOT have become a real policy entry
    assert compiled.rules_for("evil_tool") is None
    assert compiled.rules_for("innocent") is not None


def test_malicious_description_with_yaml_control_chars_is_flattened() -> None:
    evil = tool("t", "line1\r\nline2:\n- item\n#comment")
    text = scaffold_policy({"srv": [evil]})
    load_policy(text)  # must still compile
    # every description line stays inside a single comment line
    for line in text.splitlines():
        if "line1" in line:
            assert line.lstrip().startswith("#")
            assert "line2" in line  # flattened onto the same comment line


def test_tool_name_needing_quoting_is_emitted_safely() -> None:
    # A name with YAML-significant characters must round-trip as a plain key.
    text = scaffold_policy({"srv": [tool("weird: name #x")]})
    parsed = yaml.safe_load(text)
    assert "weird: name #x" in parsed["tools"]
    load_policy(text)


def test_tool_names_are_not_mangled_by_yaml_marker_stripping() -> None:
    """Regression: a name ending in '.' (or parsing as a bool/int) must survive.

    yaml.safe_dump appends a '\\n...' document-end marker; removing it with a
    character-set rstrip would silently truncate 'report.' to 'report' and
    generate policy for a tool that does not exist.
    """
    names = ["report.", "yes", "123", "normal_tool"]
    parsed = yaml.safe_load(scaffold_policy({"srv": [tool(n) for n in names]}))
    assert set(parsed["tools"]) == set(names)


def test_output_is_pure_ascii() -> None:
    """`python -m whence.scaffold > policy.yaml` must not crash on a cp1252
    console, so the generated document contains no non-ASCII characters."""
    text = scaffold_policy(CATALOGUES)
    text.encode("ascii")  # raises UnicodeEncodeError if we regress


def test_overlong_description_is_truncated_not_wrapped() -> None:
    text = scaffold_policy({"srv": [tool("t", "A" * 500)]})
    load_policy(text)
    comment_lines = [ln for ln in text.splitlines() if "AAA" in ln]
    assert len(comment_lines) == 1  # truncated onto one line, never wrapped
    assert len(comment_lines[0]) < 200
