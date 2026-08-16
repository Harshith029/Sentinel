# Whence — deployment

## Local bring-up (fresh clone → whole system up, DEMO MODE)

**Option A — Docker (no Python needed):**
```bash
docker build -t whence -f deploy/Dockerfile .
docker run --rm -p 8765:8765 whence
# open http://localhost:8765  →  click "Launch attack"
```

**Option B — venv:**
```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"   # (Linux/macOS: .venv/bin/python)
make dashboard                                     # serves http://127.0.0.1:8765
```

Either way the **whole system** comes up in DEMO MODE: the Whence proxy, the
control plane, the dashboard, and the three mock tool servers (in-memory MCP
transport). The security pipeline (provenance → authorization → trust → forensics)
is identical to production — only the integrations in the capability matrix degrade.

## Azure Container Apps (real-cloud mode)

`deploy/main.bicep` provisions the full topology. Build/push the image to ACR,
then deploy:

```bash
az group create -n whence-rg -l eastus
az acr create -n <acr> -g whence-rg --sku Basic
az acr build -r <acr> -t whence:1.0 -f deploy/Dockerfile .
az deployment group create -g whence-rg -f deploy/main.bicep \
  -p image=<acr>.azurecr.io/whence:1.0 demoMode=false
```

What the bicep encodes (the parts that matter):

| Concern | How it is enforced |
|---|---|
| **Topology / thesis** | `whencey` has `ingress.external = true` (the ONLY public endpoint). The three `whence-tools-*` apps have `ingress.external = false` — **no external ingress**, reachable only inside the ACA environment, i.e. only by Whence. |
| **Autoscale** | KEDA **HTTP-concurrency** scaler on the proxy (`name: http-concurrency`, `concurrentRequests: 50`). |
| **Identity** | `identity: SystemAssigned` on the proxy + a Key Vault **Secrets User** RBAC role assignment to that principal (explicit, not implicit). |
| **Secrets** | Key Vault with `enableRbacAuthorization: true`; Cosmos with `disableLocalAuth: true` (identity-only). |
| **Persistence** | Cosmos SQL container `spans` partitioned by `/trace_id`; idempotent upserts + default SDK retry are in the app's `CosmosForensicStore`. |

Flip the banner: `demoMode=true` ⇒ the dashboard's **Deployment mode** panel shows
the degraded column active; `demoMode=false` ⇒ the Azure column lights up.

## Honest status (per the spec's fail-loudly rule)

This repository was built and verified **offline, with no Azure subscription**.
Therefore:

- **Verified against the real SDKs (not stale):** the Azure OpenAI classifier
  surface (`openai==2.38.0` `AsyncAzureOpenAI` + `azure-identity`
  `get_bearer_token_provider`), the Foundry `MCPTool` registration
  (`azure-ai-projects==2.0.0`, constructed successfully), and the Content Safety
  `shieldPrompt` REST shape (§5). The image builds and the bicep is valid IaC.
- **NOT executed end-to-end here:** a live Foundry agent run, live Prompt Shields
  calls, live Azure OpenAI calls, and the live MCP-over-HTTP transport between the
  proxy and the internal tool-server apps. These require a live subscription +
  credentials and the HTTP-MCP exposure of Whence's MCP server.

The stage demo runs on **DEMO MODE**, which is fully exercised (219+ tests, the
hero attack verified in a real browser). Only the agent **driver** differs between
modes; the provenance/authorization/trust/forensic pipeline is the identical code
path.
