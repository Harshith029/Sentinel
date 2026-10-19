# Free and paid backends

Nothing in SENTINEL requires a paid service. Enforcement (provenance tracking
and the authorization engine) runs locally and is identical everywhere. The
paid integrations improve detection, labelling and storage. They are
upgrades, not prerequisites.

| Capability | Free default | Optional paid upgrade |
|---|---|---|
| Enforcement (provenance and policy) | Built in | None needed |
| Layer-1 injection shield | Local heuristic detector (`SENTINEL_SHIELD=local`) | Azure AI Content Safety Prompt Shields |
| Attack classifier (labels on blocked calls) | Rule-based | Azure OpenAI |
| Forensic persistence | SQLite on local disk | Azure Cosmos DB |
| Demo agent model | Ollama locally, or any OpenAI-compatible endpoint via `OPENAI_BASE_URL` | OpenAI or Azure OpenAI |
| Hosting | Any Docker host, including your own machine | Azure Container Apps |

`GET /capabilities` reports which backend each capability is actually running
on, so you never have to guess.

## Why a simpler shield does not weaken enforcement

The Layer-1 shield only *flags*; it never blocks. The authorization engine
refuses a tainted action whether or not anything flagged the text that tainted
it. A free local detector therefore changes what gets flagged and how an
agent's trust score moves, not what gets refused.

## Configuring the Azure services

| Service | Variables |
|---|---|
| Content Safety | `SENTINEL_SHIELD=azure` (or `auto`, which uses Azure when configured), `AZURE_CONTENT_SAFETY_ENDPOINT`, `AZURE_CONTENT_SAFETY_KEY` |
| Azure OpenAI | `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_DEPLOYMENT`, `AZURE_OPENAI_API_VERSION`. Authenticates with `DefaultAzureCredential` |
| Cosmos DB | `AZURE_COSMOS_ENDPOINT`, `AZURE_COSMOS_DATABASE`, `AZURE_COSMOS_CONTAINER`, and `pip install "sentinel-prox[cosmos]"` |

SENTINEL does not export telemetry to Application Insights. Blocks,
quarantines and injection flags are structured log lines on stdout; use
`--log-format json` for a log shipper.
