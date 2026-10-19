## What and why

<!-- What this changes, and the problem it solves. Link the issue: "Fixes #123". -->

## Security invariants

<!--
SENTINEL is a security proxy: the bar is "does this preserve the guarantees".
See the list in CONTRIBUTING.md. If this change touches one, explain why it
still holds. Never open a PR that discloses an unfixed vulnerability; report it
privately first (SECURITY.md).
-->

- [ ] This change does not weaken a security invariant, or the PR explains why it is still safe.

## Checklist

- [ ] Tests cover the change. A security fix includes a test that fails without the fix.
- [ ] `python -m pytest`, `python -m ruff check src tests` and `python -m mypy src` pass locally.
- [ ] Docs are updated where behaviour changed (README, `website/`, `.env.example`).
- [ ] `CHANGELOG.md` has an entry under *Unreleased* for a user-visible change.
