# Logs and forensics

SENTINEL records every decision twice: as a log line where you are already
looking, and as an immutable span in the forensic store.

## Decision logs

Blocks are logged at `WARNING` and allowed calls at `INFO`. Each line carries
the `trace_id` that ties it to the full forensic record:

```text
23:16:40 INFO    ALLOW  get_customer_record  [trace 2ad33998e093]
23:16:40 INFO    ALLOW  web_fetch  [trace 2ad33998e093]
23:16:40 WARNING BLOCK  send_email  rule=block-untrusted-origin  [trace 2ad33998e093]
```

- `sentinel serve --log-format json` emits one JSON object per line for a log
  aggregator.
- `--log-level WARNING` narrows the output to refusals and quarantines.

::: tip Tool arguments are never logged
The payloads SENTINEL inspects are the secrets it exists to protect. Writing
them to a log would move a secret from a blocked call into a plaintext file
that ships off-box, which is the exfiltration that was just prevented. The
decision is logged; the data stays in the access-controlled forensic store. A
test asserts that the demo's synthetic SSN and API key never appear in log
output.
:::

## Runs, replay and export

Each MCP session SENTINEL proxies is recorded as a run. With the agent's
credential you can:

| Request | Returns |
|---|---|
| `GET /runs` | The runs your tenant owns |
| `GET /runs/{run_id}` | One run |
| `GET /runs/{run_id}/replay` | The run's spans, replayed from the forensic store |
| `GET /runs/{run_id}/audit` | The run's alerts as JSON. Blocked calls carry an attack-class label |
| `GET /runs/{run_id}/audit?format=jsonl` | The same alerts as a JSONL download, one per line, for a SIEM |
| `GET /events?since=N` | Events after cursor `N`, at most 1000 per call, with `next_since` to resume |
| `GET /events/stream` | The same events as a live Server-Sent Events stream |

Spans are immutable: re-emitting an identical span is a no-op, and a differing
one is rejected.

Each policy reload through the API is a run too (scenario `policy-change`),
holding one `PolicyChanged` span: the outcome, the versions, and the SHA-256
of the submitted policy. Its audit export is graded `medium`.

## The forensic store

The default store is SQLite at `${SENTINEL_DATA_DIR:-./var}/sentinel.db`.

**Retention.** A trace is deleted, whole, once its newest span is older than
`SENTINEL_FORENSIC_RETENTION_DAYS` (default 90; `0` keeps everything). The
purge runs the first time runs are listed or started after startup, then at
most once a day while runs are being started, so an idle service purges
nothing. Runs in flight are never deleted. Set the window to what your audit
obligations require.

**Ownership.** Each run's tenant is recorded when it starts, so after a
restart every tenant sees its own history and no one else's. History written
by a version before that has no recorded owner. It is shown only to the
operator (`SENTINEL_ADMIN_TOKEN`) rather than guessed at.

**Encryption at rest.** SENTINEL does not encrypt the database. Tool arguments
and results are redacted before they are written, but tool names, decisions
and timings are stored in the clear. Put `SENTINEL_DATA_DIR` on an encrypted
volume.

**Backup.** A clean shutdown checkpoints the write-ahead log, so the `.db`
file of a stopped service is complete on its own. While it runs, copy it with
SQLite's online backup rather than a file copy, because the newest writes can
still be in `sentinel.db-wal`:

```bash
sqlite3 sentinel.db ".backup copy.db"
```

Back up `${SENTINEL_DATA_DIR}/policies/` with it: it holds the policies
replaced through the API, which a restart restores from there.

## Cosmos DB (optional)

Set `AZURE_COSMOS_ENDPOINT` to store spans in Azure Cosmos DB instead. It needs
the `cosmos` extra:

```bash
pip install "sentinel-prox[cosmos]"
```

Cosmos support is partial. Spans are stored and replayable, but run ownership,
the run index after a restart, and retention purging exist only for SQLite.
Retention in Cosmos is the container's time-to-live (`defaultTtl`), which you
set on the container; SENTINEL does not purge Cosmos itself.
