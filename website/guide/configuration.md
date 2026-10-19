# Configuration

SENTINEL reads a config file (`sentinel.yaml` by default), environment
variables, and `sentinel serve` flags.

## Precedence

**CLI flag > environment variable > config file > default.**

A container can therefore override a checked-in file. An environment variable
set to an empty string counts as unset.

## The config file

`sentinel init` writes a starter file. It accepts only the keys below, and an
unknown key is an error.

| Key | Environment variable | Meaning |
|---|---|---|
| `servers` | `SENTINEL_MCP_SERVERS` | Your MCP servers: a list of `{name, url}`. As an environment variable, JSON: a list, or an object mapping name to URL |
| `policy` | `SENTINEL_POLICY_FILE` | Path to your policy file |
| `catalogue_strict` | `SENTINEL_CATALOGUE_STRICT` | Refuse catalogues containing injection markers, and refuse calls to a tool that changed after approval. Default `true` |
| `catalogue_approvals` | `SENTINEL_CATALOGUE_APPROVALS` | Reviewed tool definitions to accept despite a flag: a map of tool name to the fingerprint `sentinel check` prints |
| `downstream_timeout_seconds` | `SENTINEL_DOWNSTREAM_TIMEOUT_SECONDS` | Limit per downstream operation (connect and initialize, tool listing, one tool call). Default `30` |
| `api_token` | `SENTINEL_API_TOKEN` | The agent credential. Prefer the environment variable, so the file holds no secret |
| `real_web_fetch` | `SENTINEL_REAL_WEB_FETCH` | Demo only: lets the bundled `web` tool make real, SSRF-guarded HTTP requests instead of serving canned pages |
| `host`, `port` | `--host`, `--port` | Where to listen. Default `127.0.0.1:8765`. The port comes from `--port`, then the `PORT` environment variable, then the file |
| `dashboard` | `--dashboard`, `SENTINEL_DASHBOARD` | Serve the bundled demo dashboard. Default `false`: its routes answer `404` |
| `log_level` | `--log-level` | `DEBUG`, `INFO`, `WARNING` or `ERROR`. Default `INFO` |
| `log_format` | `--log-format` | `text` for a terminal, `json` for a log aggregator. Default `text` |

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

::: warning Keep secrets out of the file
`sentinel.yaml` accepts an `api_token`, so a committed copy publishes a
credential. `sentinel init` warns when the file is inside a git repository and
not ignored.
:::

## Environment-only settings

Every other setting is read from the environment alone.
[`.env.example`](https://github.com/Harshith029/Sentinel/blob/main/.env.example)
documents each one.

| Area | Variables | See |
|---|---|---|
| Authentication | `SENTINEL_API_TOKENS`, `SENTINEL_ADMIN_TOKEN`, `SENTINEL_TENANT_POLICIES`, `SENTINEL_ALLOW_ANONYMOUS`, `SENTINEL_ALLOWED_HOSTS` | [Authentication](./authentication) |
| Catalogue checks | `SENTINEL_CATALOGUE_RECHECK_SECONDS` (default 300; `0` re-checks only when an agent lists tools) | [How it works](./how-it-works#catalogue-integrity) |
| Quarantine | `SENTINEL_ENFORCE_QUARANTINE` (default off: crossings are recorded only) | [How it works](./how-it-works#_3-contain-trust-score-and-quarantine) |
| Forensic store | `SENTINEL_DATA_DIR` (default `./var`), `SENTINEL_FORENSIC_RETENTION_DAYS` (default 90) | [Logs and forensics](./forensics) |
| Resource limits | `SENTINEL_MAX_*`, `SENTINEL_RATE_LIMIT_PER_MINUTE`, `FORWARDED_ALLOW_IPS` | [Resource limits](./limits) |
| Layer-1 shield | `SENTINEL_SHIELD` (`auto`, `local` or `azure`), `AZURE_CONTENT_SAFETY_ENDPOINT`, `AZURE_CONTENT_SAFETY_KEY` | [Free and paid backends](./backends) |
| Optional Azure services | `AZURE_OPENAI_*`, `AZURE_COSMOS_*` | [Free and paid backends](./backends) |
| Demo | `SENTINEL_DEMO_MODE`, `SENTINEL_DASHBOARD`, `SENTINEL_AGENT_DRIVER`, `OPENAI_*` | [Try the demo](./demo) |

A limit that is not a whole number is a startup error, not a silent fallback.

## Commands

| Command | What it does |
|---|---|
| `sentinel init [--force]` | Write a starter `sentinel.yaml`. `--force` overwrites an existing file |
| `sentinel check` | Validate the config, connect to every server and vet its catalogue, print tool fingerprints, and report authentication and policy problems. Exits non-zero if `serve` would fail |
| `sentinel scaffold` | Print a starter policy for the tools discovered on your servers |
| `sentinel serve` | Run the proxy. Flags: `--host`, `--port`, `--dashboard`, `--log-level`, `--log-format` |

To read a config file other than `sentinel.yaml`, pass `-c` (or `--config`)
before the command: `sentinel -c prod.yaml serve`.
