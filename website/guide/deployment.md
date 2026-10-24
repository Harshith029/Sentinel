# Deployment

Nothing here needs a paid service or a cloud account. Enforcement runs
locally; the paid integrations are optional upgrades (see
[Free and paid backends](./backends)).

## The rule that makes it work

Put your tool servers on an internal network reachable **only** by SENTINEL.
That topology is what makes interception impossible to bypass: an agent that
can reach a tool server directly can skip the proxy.

## Self-host with Docker Compose

[`deploy/compose.yaml`](https://github.com/Harshith029/Sentinel/blob/main/deploy/compose.yaml)
runs SENTINEL with a required token, forensic history on a named volume,
loopback-only binding and a health check.

```bash
python -c "import secrets; print('SENTINEL_API_TOKEN=' + secrets.token_urlsafe(32))" > .env
docker compose -f deploy/compose.yaml --env-file .env up -d --build
curl http://127.0.0.1:8765/healthz
```

Start from a `.env` that holds only what this deployment needs. Copying
`.env.example` brings its local-development values with it, including
`SENTINEL_DEMO_MODE=1`, and the service then reports itself as a demo.

Point your agent at `http://127.0.0.1:8765/mcp` with
`Authorization: Bearer <your token>`. Declare your MCP servers with
`SENTINEL_MCP_SERVERS` and mount a policy (`sentinel scaffold` writes one);
the comments in `compose.yaml` show how.

This setup was verified locally with Docker:

- with no `SENTINEL_API_TOKEN` in `.env`, compose refuses to start and names
  the variable;
- with it, the container is healthy, runs as uid 10001, and `/healthz` reports
  production mode;
- `/runs` answers `401` without the token and `200` with it;
- a run's history and its tenant survive the container being destroyed and
  recreated.

**If only your own machine uses it, stop here.** Running SENTINEL next to the
agent is the simplest and most secure setup: nothing is exposed to the
network.

## Reaching it from other machines

Keep the tool servers reachable only by SENTINEL, and give SENTINEL a way in.
These are free options we know of; neither has been tested with SENTINEL yet.

| Option | Cost | Notes |
|---|---|---|
| Tailscale (private network) | Free personal plan | Agents on other machines reach SENTINEL over the tailnet, with nothing public. Tailscale Funnel can publish it over HTTPS if you must |
| Oracle Cloud Always Free VM | Free; a card is needed at sign-up for verification | An always-on ARM VM with a persistent disk. Run the compose file on it |

Whatever sits in front must pass streaming responses (Server-Sent Events)
through unbuffered: MCP's streamable HTTP transport uses them.

### Behind a reverse proxy

The rate limit is keyed by client address for unauthenticated traffic. Behind
a reverse proxy that address is the proxy's unless uvicorn trusts it, so set
`FORWARDED_ALLOW_IPS` to the proxy's address or CIDR. Never set it to `*` on a
host clients can reach directly: uvicorn would then take the client-supplied
`X-Forwarded-For` at face value.

### Platforms that assign the port

The image listens on `$PORT` (default 8765), so platforms that set `PORT`
work without changes. `sentinel serve --port` still overrides it.

## Run one replica

Trust scores, MCP sessions, the event feed and the run index live in process
memory, and policies replaced through the API are saved in that instance's
`SENTINEL_DATA_DIR`. Two replicas share none of it, and each enforces its own
rate limits. Run one instance, and enforce any global limit at the load
balancer.

## Azure Container Apps (optional, untested)

[`deploy/main.bicep`](https://github.com/Harshith029/Sentinel/blob/main/deploy/main.bicep)
describes an Azure topology: SENTINEL as the only external ingress, the tool
servers internal-only, Key Vault with RBAC, and Cosmos DB for spans.

::: warning Never deployed
CI compiles the template on every change, which shows it is valid, not that
it deploys or works. If you deploy it, please
[report what happened](https://github.com/Harshith029/Sentinel/issues).
:::

The demo tool servers it deploys have no authentication of their own. What
keeps them behind SENTINEL is internal-only ingress, so anything else running
in the same Container Apps environment can reach them directly. Put nothing
else there.

## What CI proves about the image

On every push and pull request, CI builds `deploy/Dockerfile`, starts it, and
fails unless it is healthy, answers `503` on a data route with no credential
configured, and does not run as root. It also installs the built wheel into a
clean environment and runs it from outside the source tree.
