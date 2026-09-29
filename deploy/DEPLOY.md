# SENTINEL — deployment

Nothing here needs a paid service or a cloud account. SENTINEL's enforcement runs
locally; the paid integrations (Azure Content Safety, Azure OpenAI, Cosmos DB) are
optional upgrades with free defaults (see the README, *Running at zero cost*).

SENTINEL is fail-closed: with no credential configured, and without an explicit
`SENTINEL_ALLOW_ANONYMOUS=1`, every data route answers **503** instead of serving
openly. Each option below says which of the two it uses.

## 1. Try the demo locally

```bash
docker build -t sentinel -f deploy/Dockerfile .
docker run --rm -p 127.0.0.1:8765:8765 -e SENTINEL_ALLOW_ANONYMOUS=1 sentinel
# open http://localhost:8765 and click "Launch attack"
```

Or from a checkout: `make install`, then `make dashboard`.

Anonymous mode is fine here: the tools are in-memory mocks with no side effects,
and the port is bound to loopback. Never use it in front of real tools.

## 2. Self-host for real (free, on any machine)

[`compose.yaml`](./compose.yaml) runs the same image with a required token,
forensic history on a named volume, loopback-only binding and a health check.

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"   # put this in .env as SENTINEL_API_TOKEN
docker compose -f deploy/compose.yaml --env-file .env up -d --build
curl http://127.0.0.1:8765/healthz        # {"status":"ok","mode":"PRODUCTION MODE"}
```

Point your agent at `http://127.0.0.1:8765/mcp` with
`Authorization: Bearer <your token>`. Declare your own MCP servers with
`SENTINEL_MCP_SERVERS` and mount a policy (`sentinel scaffold` writes one); see the
comments in `compose.yaml`.

Verified locally with Docker before this file was written:

- no `SENTINEL_API_TOKEN` in `.env`: compose refuses to start and names the variable;
- with it: container healthy, runs as uid 10001, `/healthz` reports production mode;
- `/runs` answers 401 without the token and 200 with it;
- a run's history (18 spans) and its tenant survive the container being destroyed
  and recreated.

**If only your own machine uses it, stop here.** Running SENTINEL next to the agent
is the simplest and most secure setup: nothing is exposed to the network.

## 3. Reaching it from other machines

Keep the tool servers reachable only by SENTINEL, and give SENTINEL a way in:

| Option | Cost | Notes | Tested by us |
|---|---|---|---|
| Tailscale (private network) | Free personal plan | Agents on other machines reach SENTINEL over the tailnet; nothing public. Tailscale Funnel can publish it over HTTPS if you must. | No |
| Oracle Cloud Always Free VM | Free; card needed at sign-up for verification | An always-on ARM VM with a persistent disk; run the compose file on it. | No |
| Render free web service | Free, no card | [`render.yaml`](../render.yaml) deploys the **public demo** (anonymous, mock tools). Sleeps when idle and loses its disk on redeploy: a demo, not a place to keep forensic history. | Deployed previously; not re-checked for this change |

Whatever sits in front must pass streaming responses (Server-Sent Events) through
unbuffered: MCP's streamable HTTP transport uses them.

Checked and **not** free as of September 2026: Hugging Face Docker Spaces (creating
one needs a paid plan, per Hugging Face's Spaces documentation). AWS, Azure and GCP
need a card, and their free credits expire.

### Platforms that assign the port

The image listens on `$PORT` (default 8765), so platforms that set `PORT` (Render,
Koyeb, Cloud Run and similar) work without changes. `sentinel serve --port` still
overrides it; `sentinel serve` otherwise uses `PORT`, then `port:` in
`sentinel.yaml`, then 8765.

## 4. Azure Container Apps (optional, untested)

`deploy/main.bicep` describes an Azure topology: SENTINEL as the only external
ingress, the tool servers internal-only, Key Vault with RBAC, Cosmos DB for spans.
**It has never been deployed.** CI compiles it on every change (`az bicep build`),
which shows the template is valid, not that it deploys or works. If you do
deploy it, please report what happened.

```bash
az group create -n sentinel-rg -l eastus
az acr create -n <acr> -g sentinel-rg --sku Basic
az acr build -r <acr> -t sentinel:1.0 -f deploy/Dockerfile .
az deployment group create -g sentinel-rg -f deploy/main.bicep \
  -p image=<acr>.azurecr.io/sentinel:1.0 demoMode=false
```

## What CI proves about the image

On every push and pull request, CI builds `deploy/Dockerfile`, starts it, and fails
unless it is healthy, answers 503 on a data route with no credential configured,
and does not run as root. It also installs the built wheel into a clean
environment and runs it from outside the source tree.
