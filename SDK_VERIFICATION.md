# Whence — SDK Verification (Phase 0 artifact)

This file records facts CONFIRMED against the actually-installed SDKs in
`versions.lock`, per BUILD_SPEC §3 / Phase 0 kickoff item 4. It is the live
counterpart to spec §3/§6, which intentionally carries placeholders. The spec
itself is NOT mutated — drift goes here.

Verification environment:

| Field | Value |
| ----- | ----- |
| Python | 3.11.9 (Windows 11, x64) |
| Date verified | 2026-05-29 |
| Venv | `.venv/` at repo root |
| Method | Direct `inspect` / `pkgutil.walk_packages` of the installed packages |

---

## 1. `McpTool` import path — **SPEC DRIFT — FAIL LOUDLY**

> Spec §3 / §6: "exact import path of `McpTool` (do NOT assume `azure.ai.projects.models`)"

**Confirmed result (azure-ai-projects 2.0.0):**

- The class spelling is **`MCPTool`** (all caps), NOT `McpTool` (camel). The
  kickoff and BUILD_SPEC use the camel spelling; that name does not exist in
  the installed package.
- The class lives at `azure.ai.projects.models.MCPTool`
  (exported through the `models` namespace; defined in
  `azure.ai.projects.models._models`).
- Walked the entire `azure.ai.projects` package tree: there is no `McpTool`
  symbol anywhere. The only MCP-prefixed types are:
  - `MCPTool`
  - `MCPToolFilter`
  - `MCPToolRequireApproval`
  - `ToolChoiceMCP`

**Action taken:** code uses `MCPTool` (all caps). The spec's `McpTool` is
treated as a documentation typo. We do NOT silently rename — any spec quote in
code comments preserves the spec spelling and notes the drift inline.

```python
# CORRECT (works in azure-ai-projects==2.0.0):
from azure.ai.projects.models import MCPTool, MCPToolFilter, MCPToolRequireApproval

# WRONG (matches spec text, but ImportError at runtime):
# from azure.ai.projects.models import McpTool
```

---

## 2. `require_approval` location — confirmed on `MCPTool`

> Spec §3 / §6: "exact object/field where `require_approval` is set"

**Confirmed result:**

- `require_approval` is a field on **`MCPTool` itself** (not on
  `AIProjectClient`, not on a separate registration call).
- Per the SDK docstring, it accepts one of three types:
  - `MCPToolRequireApproval` (structured: lists of `always` / `never` tool
    filters, each an `MCPToolFilter` with `tool_names: list[str]`)
  - `Literal["always"]` — string literal
  - `Literal["never"]` — string literal

Spec §6 sets `require_approval="never"` — confirmed valid.

Sample wire output (from `MCPTool(...).as_dict()`):

```json
{
  "server_label": "whence",
  "server_url": "http://localhost:8765/mcp",
  "allowed_tools": ["web_fetch", "send_email", "..."],
  "require_approval": "never",
  "type": "mcp"
}
```

---

## 3. `allowed_tools=[]` semantics — **partially confirmed; explicit enumeration is mandatory**

> Spec §3 / §6: "whether `allowed_tools=[]` means all-tools or no-tools"
> §6: "ENUMERATE proxied tools explicitly — do NOT rely on `allowed_tools=[]`
> meaning 'all'"

**What inspection of the installed SDK confirms:**

- `allowed_tools` is a public field on `MCPTool`.
- Its declared type is `list[str] | MCPToolFilter`. The wire shape is either a
  bare JSON array of tool names or a structured filter object with `tool_names`
  + `read_only`.
- An empty list **does serialize** to `"allowed_tools": []` on the wire
  (confirmed via `MCPTool(allowed_tools=[]).as_dict()`); the SDK does NOT
  reject it client-side.

**What inspection CANNOT confirm (and we will NOT guess):**

- Whether the Foundry / Agent Service server INTERPRETS an empty list as
  "allow none" or "allow all". The local SDK does not document this; it is a
  server-side decision that varies across surfaces and could change between
  service revisions. Confirming would require a live call against a Foundry
  project endpoint, which is out of scope for Phase 0.

**Decision (binding for all later phases):**

We MUST always pass an explicit non-empty list of tool names to
`allowed_tools`, matching spec §6 ("ENUMERATE proxied tools explicitly").
Whence therefore registers the exact tool set it intends the protected agent
to reach. Any future code path that wants "all tools" must pass the full list —
never `[]`. A linter / runtime assertion in Phase 4 enforces this.

---

## 4. `AIProjectClient` entry point — confirmed

> Spec §3 / §6: "azure-ai-projects 2.0: `AIProjectClient(endpoint=PROJECT_ENDPOINT, credential=DefaultAzureCredential())`"

**Confirmed result:**

- `from azure.ai.projects import AIProjectClient` resolves to the 2.0.0 client.
- Public methods include `close`, `get_openai_client`, `send_request`.
- `get_openai_client()` returns an authenticated `openai.OpenAI` instance:
  - `base_url` defaults to `<project_endpoint>/openai/v1`
  - `api_key` defaults to a bearer-token provider scoped to
    `https://ai.azure.com/.default`
  - Both can be overridden via kwargs.

The spec's `AIProjectClient(endpoint=..., credential=DefaultAzureCredential())`
shape is consistent with the installed signature.

---

## 5. `azure-ai-agents` (deprecated per spec §3) — confirmed absent

> Spec §3: "azure-ai-agents is DEPRECATED — do not use."

**Confirmed result:** `importlib.import_module('azure.ai.agents')` raises
`ModuleNotFoundError`. No code path imports it; nothing transitive pulled it
in. Matches spec intent.

---

## 6. `mcp` Python SDK — confirmed

| Item | Value |
| ---- | ----- |
| Distribution version | `mcp==1.27.1` |
| Server entry point | `mcp.server.fastmcp.FastMCP` (re-exported by `mcp.server`) |
| Client session | `mcp.ClientSession` (also at `mcp.client.session.ClientSession`) |
| Stdio transports | `mcp.stdio_server`, `mcp.stdio_client` (top-level) |
| Core message types | `CallToolRequest`, `ListToolsResult`, `Tool`, `JSONRPCRequest`, `JSONRPCResponse`, `McpError`, etc. |

Phase 1's thin proxy skeleton + Phase 4's full proxy will use these symbols
directly.

---

## 7. `openai` client — confirmed

| Item | Value |
| ---- | ----- |
| Distribution version | `openai==2.38.0` (exact pin per spec §3) |
| Client class | `openai.OpenAI` |
| Acquisition (Foundry) | `AIProjectClient.get_openai_client()` |

---

## 8. Summary of facts vs. spec

| Spec assertion | Status | Note |
| -------------- | ------ | ---- |
| `McpTool` import path is in `azure.ai.projects.models` | **DRIFT** | Path correct; spelling is `MCPTool`, not `McpTool` |
| `require_approval` is set on the MCP tool registration object | CONFIRMED | Lives on `MCPTool` |
| `require_approval="never"` is a valid literal | CONFIRMED | SDK declares `Literal["never"]` |
| `allowed_tools=[]` meaning ambiguous | UNRESOLVED at client | Server interprets; spec mandates explicit enumeration anyway |
| `AIProjectClient(endpoint=..., credential=...)` constructor shape | CONFIRMED | |
| `get_openai_client()` returns authenticated OpenAI client | CONFIRMED | |
| `azure-ai-agents` deprecated → not used | CONFIRMED | Not installed |
| Exact pin set for runtime resolution | CONFIRMED | See `versions.lock` |

---

*Generated during Phase 0. Re-run on any dep bump that touches `azure-ai-projects`,
`mcp`, or `openai`. If a future verification flips any "CONFIRMED" to "DRIFT",
update this file and fail loudly — do not silently adapt code.*
