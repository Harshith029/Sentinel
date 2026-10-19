# Frequently asked questions

## Does my agent need code changes?

No. To your agent, SENTINEL is an ordinary MCP server. Point its MCP endpoint
at SENTINEL (`http://127.0.0.1:8765/mcp` by default) instead of at your tool
servers, and give it a bearer token. Then make sure the tool servers are
reachable only from SENTINEL.

## Is this a prompt-injection filter?

Not mainly. SENTINEL does screen text with a Layer-1 detector, but that
detector only flags. What refuses an attack is the authorization engine,
which judges each action by where its data came from. An injection that no
filter catches is still refused if the action it causes has untrusted
lineage and your policy guards that tool.

## Why not just use a content filter?

Content filters judge the words, and attackers can reword, encode or
obfuscate an instruction until it slips through. The provenance of an action
does not change with wording: an email built after reading a web page carries
that page's label however the page was written.

## Which MCP servers can it protect?

Servers that speak the streamable HTTP transport. SENTINEL does not proxy
stdio servers yet, and has no per-server credentials or OAuth. See
[Status and limitations](./guide/limitations).

## Will it block my legitimate workflows?

It can, by design. Every tool result is untrusted by default, so a flow like
"look up the customer, then email them" is denied when the email tool has a
taint rule. Mark tools whose output nobody outside can influence as
`trusted_output: true`, or declassify values that fit a strict schema. See
[Writing policy](./guide/policy#trusted-output).

## Does it need Azure or any paid service?

No. Enforcement, the local injection detector, the rule-based classifier and
the SQLite forensic store are all free and local. Azure Content Safety, Azure
OpenAI and Cosmos DB are optional upgrades. See
[Free and paid backends](./guide/backends).

## Is the dashboard the product?

No. The dashboard is a demo of the pipeline on synthetic data, and it is off
unless you pass `--dashboard`. The product is the proxy, its policy and its
forensic record.

## Is it ready for production?

It is beta. Enforcement, catalogue integrity and authentication are tested,
but there are real limitations: taint is tracked per MCP session, state lives
in one process, and the Azure template has never been deployed. Read
[Status and limitations](./guide/limitations) and decide for your threat
model.

## Does it log my data?

No tool arguments are ever logged. Logs carry the decision, the tool name,
the rule and a trace id. Arguments and results are redacted before they reach
the forensic store.

## Why is the package called `sentinel-prox`?

`sentinel` and the obvious variants were already taken on PyPI. The import
package and the command are both `sentinel`.

## How do I report a vulnerability?

Privately, not in a public issue. See the
[security policy](https://github.com/Harshith029/Sentinel/blob/main/SECURITY.md).
