"""Generate a starter policy from the tools discovered on an operator's servers.

The onboarding problem: Whence default-denies any tool with no policy entry —
correct, but it means a freshly-connected operator faces a blank YAML file and a
proxy that refuses everything. This module removes the blank page **without
weakening the security model**:

* every discovered tool is emitted **explicitly denied**, exactly matching the
  engine's default-deny, so generating and applying a scaffold changes nothing
  about what is permitted;
* each entry carries the tool's own description (as a comment) plus commented
  starting rules, so the operator edits rather than invents;
* nothing is inferred. We never guess that a tool is "safe", "read-only" or
  "high-risk" — risk classification is an operator declaration, not something a
  generator may assume (BUILD_SPEC §13 cut adaptive rule suggestion for this
  reason; inert scaffolding is deliberately on the other side of that line).

**Untrusted input warning.** Tool names and descriptions come from downstream
servers and are therefore attacker-controlled (see :mod:`whence.catalogue`).
They are embedded in generated YAML, so this module must not let them break out:
descriptions are flattened to a single line and comment-escaped, and names are
emitted through a YAML dumper rather than string interpolation. A description
containing newlines, ``#``, or YAML syntax cannot alter the generated policy's
structure — proven by tests.
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Final

import mcp.types as mcp_types
import yaml

# Predicate cheat-sheet shown in the header so the operator does not have to go
# hunting for the grammar. These mirror whence.authorization.parser exactly.
_PREDICATE_HELP: Final[tuple[str, ...]] = (
    "RETRIEVED_CONTENT in effective_provenance   # data came from untrusted content",
    "effective_provenance != {USER}              # anything not purely user-originated",
    "recipient_domain not in allowed_domains     # argument allowlist",
    "amount >= max_amount                        # numeric cap",
)

# Collapse anything that could escape a single-line YAML comment.
_UNSAFE_COMMENT = re.compile(r"[\r\n  ]+")
_MAX_COMMENT = 120


def _comment_safe(text: str) -> str:
    """Flatten untrusted text so it cannot escape a one-line YAML comment."""
    flattened = _UNSAFE_COMMENT.sub(" ", text).strip()
    if len(flattened) > _MAX_COMMENT:
        flattened = flattened[: _MAX_COMMENT - 3].rstrip() + "..."
    return flattened


def _yaml_key(name: str) -> str:
    """Emit a tool name as a safe YAML key (quoted/escaped as needed)."""
    # yaml.safe_dump handles quoting for names with ':', '#', spaces, or names
    # that would otherwise parse as bools/ints ('yes', '123').
    dumped = yaml.safe_dump(name, default_flow_style=True).strip()
    # It appends a "..." document-end marker after a plain scalar. Strip it as a
    # SUFFIX: rstrip("\n...") is a character set and would eat a legitimate
    # trailing dot (a tool literally named "report." must stay "report.").
    marker = "\n..."
    if dumped.endswith(marker):
        dumped = dumped[: -len(marker)]
    return dumped.strip()


def scaffold_policy(
    catalogues: Mapping[str, Sequence[mcp_types.Tool]], *, policy_version: int = 1
) -> str:
    """Render a deny-everything starter policy for the discovered catalogues.

    The result is a VALID policy document (it loads through
    :func:`~whence.authorization.policy.load_policy`) in which every tool is
    explicitly denied. Applying it is a no-op security-wise; editing it is how the
    operator grants access.
    """
    lines: list[str] = [
        "# Whence policy scaffold - generated from your discovered MCP tools.",
        "#",
        "# EVERY tool below is DENIED. That mirrors Whence's default-deny (a tool",
        "# with no policy entry is refused), so applying this file as-is changes",
        "# nothing. To permit a tool, replace its `deny_always` rule with the",
        "# conditions under which it should be REFUSED - rules are deny-only, and a",
        "# call is allowed when no deny rule matches.",
        "#",
        "# Predicates you can use in `deny_if`:",
        *(f"#   {help_line}" for help_line in _PREDICATE_HELP),
        "#",
        "# Descriptions below are quoted from the downstream servers and are NOT",
        "# trusted - read them, do not assume they are accurate.",
        "",
        f"policy_version: {policy_version}",
    ]

    # `tools:` with nothing under it parses as null, not an empty mapping — emit
    # an explicit `{}` so a scaffold for an empty catalogue is still valid policy.
    if not any(catalogues.get(server) for server in catalogues):
        lines.append("tools: {}")
        return "\n".join(lines).rstrip() + "\n"
    lines.append("tools:")

    for server in sorted(catalogues):
        tools = sorted(catalogues[server], key=lambda t: t.name)
        if not tools:
            continue
        lines.append("")
        lines.append(f"  # --- server: {_comment_safe(server)} " + "-" * 24)
        for tool in tools:
            description = _comment_safe(tool.description or "(no description)")
            lines.append(f"  # {_comment_safe(tool.name)} - {description}")
            lines.append(f"  {_yaml_key(tool.name)}:")
            lines.append("    rules:")
            lines.append("      - id: not-yet-reviewed")
            lines.append("        deny_always: true")
            lines.append("      # Recommended once reviewed - delete the rule above and")
            lines.append("      # uncomment this to allow the tool EXCEPT on tainted data:")
            lines.append("      # - id: block-untrusted-origin")
            lines.append('      #   deny_if: "RETRIEVED_CONTENT in effective_provenance"')
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _main() -> int:  # pragma: no cover - thin CLI wrapper
    """Connect to the declared servers and print a starter policy to stdout.

    Usage::

        WHENCE_MCP_SERVERS='[{"name":"gh","url":"https://..."}]' \\
            python -m whence.scaffold > my-policy.yaml
    """
    import asyncio
    import sys
    from contextlib import AsyncExitStack

    from whence.config import get_settings
    from whence.downstream import connect_downstream, parse_servers

    # Our own template is pure ASCII, but a downstream server's descriptions may
    # not be. Force UTF-8 so `... > policy.yaml` cannot die on a cp1252 console.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    servers = parse_servers(get_settings().mcp_servers)
    if not servers:
        print(
            "No downstream servers declared. Set WHENCE_MCP_SERVERS, e.g.\n"
            '  WHENCE_MCP_SERVERS=\'[{"name":"gh","url":"https://mcp.example/gh"}]\'',
            file=sys.stderr,
        )
        return 2

    async def run() -> str:
        async with AsyncExitStack() as stack:
            topology = await connect_downstream(servers, stack)
            return scaffold_policy(topology.catalogues)
        raise AssertionError("unreachable")  # pragma: no cover

    print(asyncio.run(run()))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
