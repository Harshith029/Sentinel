# Quick start

This guide puts SENTINEL in front of MCP servers you already run. To watch it
refuse an attack first, without any servers of your own, see
[Try the demo](./demo).

## Requirements

- Python 3.11 or later.
- MCP servers that speak the **streamable HTTP** transport. SENTINEL does not
  proxy stdio servers yet (see [limitations](./limitations)).

## 1. Install

```bash
pip install "sentinel-prox>=0.2.2"
```

::: danger Never install 0.1.x
The 0.1.x releases are insecure: an open `/mcp` endpoint, overridable policy
config, and unredacted forensics. Always install 0.2.2 or later.
:::

For the exact dependency set CI tests against, install from a checkout with
`pip install . -c versions.lock`.

## 2. Declare your servers

```bash
sentinel init
```

This writes `sentinel.yaml`. List your MCP servers under `servers:`:

```yaml
servers:
  - name: github
    url: https://mcp.example/gh
policy: ./policy.yaml
host: 127.0.0.1
port: 8765
dashboard: false
catalogue_strict: true
```

`sentinel.yaml` accepts an `api_token`, so keep it out of version control.
`sentinel init` warns you if the file sits in a git repository and is not
ignored. Prefer putting the token in the environment.

## 3. Set a credential

SENTINEL is fail-closed. With no credential configured it answers every data
route with `503` rather than serving openly.

```bash
export SENTINEL_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

This token is what your agent presents. To replace policies or clear
quarantines through the API you also need a separate operator token,
`SENTINEL_ADMIN_TOKEN`. See [Authentication](./authentication).

## 4. Check, then scaffold a policy

```bash
sentinel check
```

`check` runs the startup checks `serve` would run, without serving. It
connects to each server, vets its tool catalogue, prints a fingerprint for
each tool, and exits non-zero if `serve` would fail. On a first run it reports
that the policy file is missing.

Every tool is denied until a policy says otherwise, so generate a starting
point from the tools SENTINEL discovered:

```bash
sentinel scaffold > policy.yaml
```

The scaffold lists every discovered tool explicitly denied, with its
description and a recommended starting rule, so you edit rather than invent.
See [Writing policy](./policy).

::: tip A flagged tool description
The poisoning scan is a heuristic and also flags ordinary descriptions. After
reviewing a flagged tool, approve that exact definition with
`catalogue_approvals` and the fingerprint `sentinel check` printed, rather
than turning strict mode off.
:::

## 5. Serve

```bash
sentinel serve
```

SENTINEL now listens on `http://127.0.0.1:8765/mcp`. Each decision is logged
as it happens:

```text
23:16:40 INFO    ALLOW  get_customer_record  [trace 2ad33998e093]
23:16:40 INFO    ALLOW  web_fetch  [trace 2ad33998e093]
23:16:40 WARNING BLOCK  send_email  rule=block-untrusted-origin  [trace 2ad33998e093]
```

## 6. Point your agent at SENTINEL

Your agent needs no code changes. Give it SENTINEL's endpoint instead of your
servers' endpoints, with the token as a bearer credential. With the official
MCP Python SDK:

```python
import asyncio
import os

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def main() -> None:
    headers = {"authorization": f"Bearer {os.environ['SENTINEL_API_TOKEN']}"}
    async with httpx.AsyncClient(headers=headers) as http, streamable_http_client(
        "http://127.0.0.1:8765/mcp", http_client=http
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print(sorted(t.name for t in tools.tools))


asyncio.run(main())
```

A refused call comes back as a tool error (`isError=True`) whose text starts
with `SENTINEL blocked`.

Then make the topology enforce it: put your tool servers on a network that
**only** SENTINEL can reach, so the agent has no path around the proxy. See
[Deployment](./deployment).

## Next steps

- [Writing policy](./policy): guard your outbound and high-risk tools.
- [How it works](./how-it-works): what taint is and how it clears.
- [Status and limitations](./limitations): read before production.
