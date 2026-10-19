# Security policy

SENTINEL is a security tool, so a vulnerability in it can leave the agents
behind it unprotected. Thank you for reporting one responsibly.

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x (latest release) | Yes |
| 0.1.x | **No.** These releases are insecure (open `/mcp`, overridable policy config, unredacted forensics). Upgrade to the latest 0.2.x |

Fixes land in the latest release. There are no backports to older versions.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a
vulnerability.**

Report it privately through GitHub:
[**Report a vulnerability**](https://github.com/Harshith029/Sentinel/security/advisories/new)
(the *Security* tab, then *Report a vulnerability*).

Please include:

- the SENTINEL version (`pip show sentinel-prox`) and how it is configured;
- what an attacker can do, and what they need first (network access, an agent
  credential, control of a tool's output, and so on);
- steps or a proof of concept that reproduce it, using synthetic data only.

## What to expect

This is a volunteer-maintained project, so these are goals rather than
guarantees:

- an acknowledgement within 7 days;
- an assessment, and a plan or a fix, as soon as the issue is understood;
- credit in the advisory and the changelog, unless you would rather stay
  anonymous.

Please give us a reasonable time to release a fix before you disclose the
issue publicly. We will publish a GitHub security advisory when it is fixed.

## Scope

In scope: anything that lets an action through that the policy should refuse,
bypasses authentication or tenant isolation, leaks redacted data, or corrupts
the forensic record. The security invariants in
[CONTRIBUTING.md](./CONTRIBUTING.md#security-invariants--do-not-regress-these)
are a good map of what SENTINEL promises.

SENTINEL deliberately draws a threat-model boundary. Provenance is tracked per
message and tool result (not per token), enforcement is at the action layer
(not the model's reasoning), and the proxy and policy store are trusted. The
[known limitations](https://harshith029.github.io/Sentinel/guide/limitations)
are documented and are not vulnerabilities in themselves. Reports about them
are still welcome as issues or discussions.

The bundled demo (the dashboard, its mock tools and synthetic data) is not a
production surface, but a flaw that would also affect a real deployment is in
scope.
