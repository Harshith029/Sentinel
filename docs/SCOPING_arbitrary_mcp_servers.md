# Scoping: proxying arbitrary user-configured MCP servers

Decision material for the product conversation. **No code has been written for this** —
the codebase is frozen on this topic pending the decision.

Premise (from the product correction): Whence should not ship email/record tools.
It secures the operator's **own** downstream MCP servers. The bundled `web` / `email` /
`records` servers are examples/demos, not product surface.

---

## 1. What already generalizes (no work needed)

| Component | Status |
|---|---|
| `DownstreamConnection` protocol | Already generic — any `list_tools`/`call_tool` speaker satisfies it |
| `ToolRouter` | Already generic — takes `Mapping[tool_name -> ClientSession]`; nothing demo-specific |
| MCP-over-HTTP client connection | Already real and tested (`_connect_remote_downstream`) |
| The whole security pipeline | Already general — proven on novel tools and arbitrary inputs |
| Unknown tools | Already **default-denied** by the authorization engine |

The plumbing is ~80% there. The blockers are three hardcoded couplings, below.

## 2. The three hardcoded couplings that block it

1. **`tool_servers.py:74` — `TOOL_TO_SERVER`**
   A fixed dict of the 4 demo tools → 3 demo server keys. Routing is built from this,
   so only those tools can be routed.
2. **`mcp_gateway.py:205` — `required_keys = set(TOOL_TO_SERVER.values())`**
   Remote mode *hard-requires* URLs for exactly `web`, `email`, `records`, and refuses
   to boot otherwise. An operator with one server (or five, differently named) cannot start.
3. **`mcp_gateway.py:175` — `preflight(required_tools=REQUIRED_TOOLS)`**
   Boot fails unless the downstream exposes those exact 4 tool names.

All three assume *our* demo topology. Replacing them with discovery is mechanical.

## 3. The real product question (not plumbing): policy authoring

This is what the advisor conversation should actually be about.

**Unknown tools are default-denied.** That is a core safety property and must not change.
But it means: an operator who connects their own MCP servers gets **every tool denied**
until they author policy for their own tool catalog. So the product must answer:

> How does an operator go from "connected my servers" to "a working policy" without
> either (a) hand-writing YAML for every tool, or (b) us weakening default-deny?

Options (not mutually exclusive):

- **A. Explicit policy authoring.** Operator writes rules per tool. *Safest, highest friction.*
  Fits the existing versioned/multi-tenant policy registry with zero new concepts.
- **B. Discovery-assisted scaffolding.** On connect, enumerate the catalogue and generate a
  starter policy that denies everything, with per-tool stubs to fill in. *Keeps default-deny;
  removes the blank-page problem.* Note: BUILD_SPEC §13 deliberately cut "adaptive rule
  suggestion" — scaffolding is inert text generation, not adaptive inference, but the line
  is worth being explicit about.
- **C. Tool classification.** Operator tags tools by risk (read / write / high-risk), and
  ships default rule templates per class. *Lowest friction; the classification becomes the
  new trust boundary, so it must be operator-declared, never inferred.*

**Recommendation to discuss:** A as the floor (it already works), B as the usability layer.
C is a bigger product bet and can wait.

## 4. Implementation sketch (if the decision is "build it")

Roughly a day, low risk, additive:

1. **Config**: replace `WHENCE_TOOLS_{WEB,EMAIL,RECORDS}_URL` with a list of downstream
   servers (`WHENCE_MCP_SERVERS` as JSON/YAML, or a config file: `[{name, url}]`).
   Keep the old three vars working as a deprecated alias so nothing breaks.
2. **Discovery**: on connect, `list_tools()` each server and build the `tool -> session`
   routing map dynamically. Replaces `TOOL_TO_SERVER`.
3. **Conflicts**: two servers exposing the same tool name needs a documented rule
   (first-wins, namespacing, or refuse-to-boot). *Refuse-to-boot is the safe default —
   silent shadowing of a tool is a security problem.*
4. **Preflight**: change `required_tools` from a fixed set to "whatever discovery found",
   keeping the health-check and schema cache.
5. **Demo servers**: move `web`/`email`/`records` behind an explicit "examples" flag so
   "these are demos" is unambiguous in the product.

## 5. Open questions for the advisor

1. Is the product **the proxy alone** (operator brings all tools), or proxy + a small set of
   blessed reference integrations?
2. Who authors policy — the operator, or do we ship starter templates? (§3)
3. Multi-tenant: is one Whence instance per operator, or one instance serving many
   tenants' downstream servers? The policy registry already supports per-tenant namespacing,
   but *connection* topology currently assumes one downstream set per process.
4. Does the hosted demo keep the example servers, while the distributed product ships without them?

## 6. What NOT to do (settled)

- Do **not** ship real `send_email` / `get_customer_record` tools — Whence is not a tool vendor.
- Do **not** weaken default-deny to make onboarding smoother.
- Do **not** infer tool risk automatically (see §3-C: operator-declared only).
