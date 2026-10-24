# Writing policy

A SENTINEL policy is a YAML document that decides, for each tool, which calls
to refuse. It is parsed into a typed condition tree when it loads, and a
malformed policy is rejected before it can match anything.

## Start from the scaffold

```bash
sentinel scaffold > policy.yaml
```

The scaffold contains every tool SENTINEL discovered on your servers,
explicitly denied, with its description and a recommended starting rule.
Edit it rather than writing a policy from scratch, then point `policy:` in
`sentinel.yaml` (or `SENTINEL_POLICY_FILE`) at it.

## Shape of a policy

```yaml
policy_version: 1
config:
  allowed_domains: ["corp.example"]
  max_amount: 1000
tools:
  send_email:
    rules:
      - id: block-untrusted-origin
        deny_if: "RETRIEVED_CONTENT in effective_provenance"
      - id: domain-allowlist
        deny_if: "recipient_domain not in allowed_domains"
  delete_record:
    rules:
      - id: never
        deny_always: true
```

| Key | Meaning |
|---|---|
| `policy_version` | An integer you bump when the policy changes. It is recorded with each decision |
| `config` | The values your rules compare against: allowlists, limits |
| `tools.<name>.rules` | The deny rules for one tool. Each has an `id` and exactly one of `deny_if` (a predicate) or `deny_always: true` |
| `tools.<name>.trusted_output` | `true` labels this tool's results `SYSTEM` instead of `RETRIEVED_CONTENT` |
| `tools.<name>.declassify.schema` | Clears taint from this tool's output when it validates against a named schema |

Unknown keys, duplicate YAML keys and duplicate rule ids are all errors.

## How rules combine

- Rules are **deny-only**. A call is allowed when no deny rule matches.
- They are evaluated in order, and the first match denies (deny-overrides).
- A tool that does not appear in `tools` is **denied by default**.
- A predicate that cannot be evaluated denies.

## Predicates

A `deny_if` predicate supports:

- comparisons: `==`, `!=`, `<`, `>=`, `in`, `not in`;
- `and`, `or`, `not`, and parentheses;
- set literals such as `{USER}` or `{USER, SYSTEM}`;
- string and number literals, and `true` / `false`;
- the call's provenance (`effective_provenance`), the tool's arguments by
  name, and values from `config`.

```yaml
- id: user-only
  deny_if: "effective_provenance != {USER}"
- id: cap
  deny_if: "amount >= max_amount"
- id: non-negative
  deny_if: "amount < 0"
```

Some rules of the language:

- There is no `null`.
- A predicate may nest at most 64 levels. Use a set for long lists of
  alternatives.
- Numbers must be finite. A numeric string compares as a number, and a
  boolean never equals a number.

### The right-hand side comes from `config`

In a comparison, the left side describes the call and the right side is what
you allow. A variable on the right (`allowed_domains`, `max_amount`) is read
from `config` only, **never** from the call's arguments, so an agent cannot
supply its own allowlist.

If you forget to declare such a variable in `config`, the rule denies every
call rather than reading it from the arguments, and SENTINEL logs a warning
naming the rule when the policy loads.

### Derived fields

SENTINEL derives some fields from the call so you can write rules about them
directly:

| Field | Derived from |
|---|---|
| `recipient_domains` | Every recipient domain across the `to`, `cc`, `bcc`, `recipient` and `recipients` arguments, parsed from the address itself, so a display name cannot disguise it |
| `recipient_domain` | The one domain all those recipients share. When they span several domains, or an address cannot be parsed, it is a value no allowlist contains, so an allowlist rule denies |
| `url_host` | The canonical HTTP(S) host of the `url` argument |

These are always SENTINEL's own values: an argument with the same name is
discarded. Derived fields may appear on either side of a comparison, so
`"evil.test" in recipient_domains` works.

## Guard every outbound tool

A tool without rules can carry tainted data out. The bundled example policy
treats `web_fetch` as an outbound capability and constrains its host:

```yaml
config:
  allowed_fetch_hosts: ["corp.example", "example.com"]
tools:
  web_fetch:
    rules:
      - id: fetch-host-allowlist
        deny_if: "url_host not in allowed_fetch_hosts"
```

Add equivalent rules for every outbound tool you introduce. There is no
general notion of an outbound "sink" yet.

## Trusted output

By default every tool result is `RETRIEVED_CONTENT`, which means a benign flow
like "look up the customer, then email them" is denied when the email tool
has a taint rule. If a tool's output cannot be influenced by anyone outside,
mark it trusted:

```yaml
tools:
  get_customer_record:
    trusted_output: true
    rules:
      - id: user-initiated-only
        deny_if: "RETRIEVED_CONTENT in effective_provenance"
```

Only do this for a tool whose output nobody outside can write to, such as
your own records service.

## Declassification

Declassification clears taint from a specific tool's output when it validates
against a strict schema. The schema registry is closed:

| Schema | Accepts |
|---|---|
| `decimal_amount` | A plain decimal amount |
| `iso_date` | A strict ISO date |

```yaml
tools:
  read_price:
    declassify:
      schema: decimal_amount
    rules: []
```

See [How it works](./how-it-works#declassification-the-one-way-taint-clears)
for the guarantees.

## Policy per tenant

Each tenant can have its own policy through `SENTINEL_TENANT_POLICIES`, a JSON
map of tenant to policy file. A tenant without an entry uses the deployment
policy.

## Replacing a policy at runtime

The operator can replace a tenant's policy without a restart:

```bash
curl -X POST http://127.0.0.1:8765/tenants/acme/policy \
  -H "Authorization: Bearer $SENTINEL_ADMIN_TOKEN" \
  -H "content-type: application/json" \
  -d "$(jq -Rs '{policy: .}' policy.yaml)"
```

- **Only a newer `policy_version` replaces the active one.** A same or older
  version is ignored, so a stale push cannot downgrade a tenant. A policy that
  does not load is refused with `400`, and the active one stays.
- **It survives a restart.** An applied policy is saved under
  `${SENTINEL_DATA_DIR}/policies/` before it takes effect. If it cannot be
  saved, nothing changes and the request fails with `500`. At startup, a saved
  policy replaces the configured one only if its version is higher, so to go
  back to your file, give the file a higher `policy_version`.
- **Every reload is recorded.** Applied, ignored, rejected or failed, each
  becomes a `PolicyChanged` record in that tenant's history (listed under
  `GET /runs`), with the submitted version and the SHA-256 of the submitted
  text, and a `POLICY` line in the security log. A request without the admin
  token is refused with `403` before it gets that far.

A saved policy that cannot be read, or no longer loads, stops `sentinel serve`
and `sentinel check` with an error naming the file. Repair the file or delete
it.
