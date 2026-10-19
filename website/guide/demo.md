# Try the demo

SENTINEL bundles a demo that runs the whole pipeline on a scripted attack, on
your own machine. It shows what a refusal looks like. It is **not** the
product surface: real deployments leave the dashboard off.

## Run it

::: code-group

```bash [pip]
pip install "sentinel-prox>=0.2.2"
SENTINEL_ALLOW_ANONYMOUS=1 sentinel serve --dashboard
```

```bash [Docker]
docker build -t sentinel -f deploy/Dockerfile .
docker run --rm -p 127.0.0.1:8765:8765 \
  -e SENTINEL_ALLOW_ANONYMOUS=1 -e SENTINEL_DASHBOARD=1 sentinel
```

```bash [From a checkout]
make install
make dashboard
```

:::

Open <http://localhost:8765> and launch the attack.

Anonymous mode is fine here: the demo's tools are in-memory mocks with no side
effects, and SENTINEL listens on loopback. **Never** use anonymous mode in
front of real tools. Without `SENTINEL_ALLOW_ANONYMOUS=1` (or a token) the
dashboard loads, but every data route answers `503`, because SENTINEL is
fail-closed.

## What you are watching

A poisoned web page induces the agent to email a synthetic customer record to
an attacker.

1. The agent looks up the customer record. The bundled policy marks the
   records service's output as trusted (`trusted_output`), so the lookup
   alone taints nothing.
2. The agent fetches the page. Its content is labelled `RETRIEVED_CONTENT`.
3. The Layer-1 filter **misses** the obfuscated instruction. The page is
   written to slip past the local detector's patterns, so the miss is staged
   on purpose.
4. The agent tries to email the record to the attacker. Authorization refuses
   it, because the action's lineage includes the page.

The attacker's domain is also outside the bundled allowlist, a second and
independent reason for the same refusal. The tests show that an email to an
allowed address is refused after the page, and allowed without it. Without the
page, the agent never attempts the email.

All demo data is synthetic. The record is a labelled fake (SSN `000-00-0000`,
a non-functional `sk-synthetic-DO-NOT-USE` key), and `send_email` writes to an
in-memory sink. Nothing is ever sent.

## With a real model

The demo agent is a real LLM whenever a credential is present: set
`OPENAI_API_KEY`, or `AZURE_OPENAI_ENDPOINT` and `AZURE_OPENAI_DEPLOYMENT`.
With no credential it falls back to a deterministic scripted transcript, so
CI needs no keys.

For a free local model, point `OPENAI_BASE_URL` at any OpenAI-compatible
endpoint, such as Ollama:

```bash
ollama serve && ollama pull llama3.2
export OPENAI_BASE_URL=http://localhost:11434/v1 OPENAI_MODEL=llama3.2
```

`OPENAI_API_KEY` is sent to whatever `OPENAI_BASE_URL` names, so never pair a
real OpenAI key with another provider's URL. `SENTINEL_AGENT_DRIVER` chooses
the driver explicitly: `auto` (the default), `scripted`, or `llm`.

## Drive it from code

The [examples](https://github.com/Harshith029/Sentinel/tree/main/examples)
connect a real MCP client to the demo over HTTP, run a live model against it,
and send your own custom attack through the REST API.
