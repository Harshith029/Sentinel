# Authentication

SENTINEL is **fail-closed**. With no credential configured, and without an
explicit `SENTINEL_ALLOW_ANONYMOUS=1`, every data route answers `503` instead
of serving openly. Forgetting to configure authentication is not the same as
choosing to have none.

With a credential configured, every route except `/healthz` needs it, reads
included:

```http
Authorization: Bearer <token>
```

## Agent credentials

| Variable | Use |
|---|---|
| `SENTINEL_API_TOKEN` | One token for a single-tenant deployment |
| `SENTINEL_API_TOKENS` | A JSON map of tenant to token, such as `{"acme": "...", "globex": "..."}` |

Each token authenticates as its tenant, and runs, events, live streams and
MCP sessions are scoped to that tenant. A tenant named in a request body is a
claim, and it is refused when it contradicts the credential.

Agent identity is derived from the credential, so an agent's trust score and
an enforced quarantine survive a reconnect (within one process).

Generate a token with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## The operator credential

`SENTINEL_ADMIN_TOKEN` is the **only** credential that can administer:

- replace a tenant's policy (`POST /tenants/{tenant}/policy`);
- clear a quarantine (`POST /agents/{agent}/reset`).

Agent credentials never can, because an agent that could administer could
switch off its own guardrails. Keep the admin token away from agents.
Without it nobody can administer, single-token deployments included, and
`sentinel check` and `sentinel serve` say so.

## Policy per tenant

`SENTINEL_TENANT_POLICIES` maps a tenant to its own policy file:

```bash
SENTINEL_TENANT_POLICIES='{"acme": "policies/acme.yaml"}'
```

A tenant without an entry uses the deployment policy (`SENTINEL_POLICY_FILE`).

## Anonymous mode

`SENTINEL_ALLOW_ANONYMOUS=1` runs with **no authentication**. It exists for the
local demo, whose tools are in-memory mocks. Never use it in front of real
tools or on a network: anyone who can reach `/mcp` can drive the tools behind
it.

Even then, an anonymous instance:

- answers only to `localhost`, `127.0.0.1` and `[::1]`, which defeats DNS
  rebinding. List any other host name it must answer to in
  `SENTINEL_ALLOWED_HOSTS`;
- refuses state-changing requests from other sites, so a web page cannot
  drive it through your browser.

## What other tenants can see

Some state is shared across tenants. Event ids on `/events` come from one
global counter, so a tenant can infer how busy the deployment is, and
`/downstream` and `/capabilities` describe the whole deployment to any
authenticated caller.
