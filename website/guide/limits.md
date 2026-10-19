# Resource limits

Every per-request and per-tenant resource is capped, so one caller cannot
exhaust the service. The defaults sit well above normal use and only affect
abuse. Leave a variable blank for its default; a value that is not a whole
number is a startup error.

| Setting | Default | Over the limit |
|---|---|---|
| `SENTINEL_MAX_BODY_BYTES` | 4 MiB | `413`. Chunked bodies are counted as they stream |
| `SENTINEL_RATE_LIMIT_PER_MINUTE` | 600 | `429` with `Retry-After`. `0` disables it |
| `SENTINEL_MAX_ACTIVE_RUNS` | 8 per tenant | `429` with `Retry-After` |
| `SENTINEL_MAX_RETAINED_RUNS` | 1000 | The oldest *finished* run leaves the run index. Its spans stay in the forensic store |
| `SENTINEL_MAX_SSE_SUBSCRIBERS` | 100 per tenant | `503`. Use `/events` polling instead |
| `SENTINEL_MAX_RESULT_BYTES` | 1 MiB | The tool result is withheld and the agent gets an error. The call is still recorded |
| `SENTINEL_DOWNSTREAM_TIMEOUT_SECONDS` | 30 | Applies per downstream operation (connect and initialize, tool listing, one tool call). A timed-out call returns an error to the agent and is recorded like any other result. Raise it for tools that run longer |
| MCP sessions on `/mcp` | 512 per tenant (fixed) | `initialize` is answered with a JSON-RPC error. Open sessions are never evicted to make room |

`GET /events` returns at most 1000 events per call, with `next_since` to
resume.

## How the rate limit is keyed

The rate limit is keyed by **tenant** for a valid credential, and by **client
address** for everything else, including invalid credentials and anonymous
traffic. Inventing a new token for each request therefore does not buy a new
budget.

Behind a reverse proxy, the client address is the proxy's unless uvicorn
trusts it. Set `FORWARDED_ALLOW_IPS` to the proxy's address or CIDR, and never
to `*` on a host clients can reach directly. Until you configure it, all
unauthenticated callers share one budget.

## Counters are per process

These counters live in process memory. Two replicas give a tenant twice the
budget. Enforce a global limit at the load balancer if you need one.
