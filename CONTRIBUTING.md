# Contributing to SENTINEL

Thanks for your interest. SENTINEL is a security proxy, so the bar for changes is
"does this preserve the guarantees" more than "does it work".

## Setup

```bash
git clone https://github.com/Harshith029/Sentinel.git
cd Sentinel
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]" -c versions.lock   # Windows: .venv\Scripts\python.exe
.venv/bin/pre-commit install
```

Install with `-c versions.lock`. Without it your environment drifts from CI and the
container — a floating dependency once broke a production deploy, and the pin is how
we stop that recurring.

## Before you open a PR

```bash
.venv/bin/python -m pytest          # all tests must pass
.venv/bin/python -m ruff check src tests
.venv/bin/python -m mypy src        # strict; no new ignores without a reason
```

CI runs the same three plus `gitleaks`, on Python 3.11.

## Security invariants — do not regress these

These are the product. A change that weakens one needs an explicit argument in the PR,
not a passing test suite.

1. **No `eval`/`exec`.** Policy predicates compile to a typed AST and are tree-walked.
2. **Provenance is a set over transitive ancestry**, computed by a real cycle-safe
   walk — never a cached flag or the label of the most recent node.
3. **Fail closed.** Unknown tools are default-denied; an unevaluable predicate denies;
   a malformed or cyclic lineage counts as tainted; a colliding tool name refuses to serve.
4. **The sanitizer is not launderable.** A cleared value has empty `derived_from`;
   recombining it with a tainted sibling re-taints.
5. **Interception is topological.** Every agent→tool path goes through
   `SentinelProxy._intercept`. The non-bypassability test compares downstream
   executions against emitted spans — keep it green.
6. **Forensic spans are immutable.** An identical re-emit is a no-op; a differing one
   is rejected.
7. **Discovery is not authorization.** Connecting a server never grants permission to
   its tools.

## Testing expectations

- Every behaviour change ships with a test. Security fixes ship with a test that
  *fails* without the fix.
- Tests must run offline and deterministically: no network, no API keys, no real
  models. Use the existing fakes (`FakeAsyncCosmosContainer`, `SusceptibleStubModel`,
  `httpx.MockTransport`) as the pattern.
- Cover the negative case too. A check that never fires is as useless as one that
  never fires correctly — most modules here test both "detects the attack" and "does
  not false-positive on benign input".

## Style

- Python 3.11+, full type hints, Pydantic v2 models for anything crossing a boundary.
- Comments explain *why*, not *what* — especially for security decisions, where the
  reasoning is the part a future reader can't reconstruct.
- Keep `ruff` and `mypy --strict` clean.

## Publishing a release (maintainers)

Releases are automated by `.github/workflows/release.yml`, which runs lint, types and
tests, builds, checks the tag matches `pyproject.toml`, and publishes to PyPI via
**Trusted Publishing** — GitHub proves the workflow's identity over OIDC, so no API
token is stored in the repo.

One-time setup on PyPI (before the first upload), at
<https://pypi.org/manage/account/publishing/>:

| Field | Value |
|---|---|
| PyPI Project Name | `sentinel-proxy` |
| Owner | `Harshith029` |
| Repository name | `Sentinel` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

Then, to cut a release:

```bash
# 1. bump the version in pyproject.toml and add a CHANGELOG entry
# 2. commit, then tag with the SAME version prefixed by v
git tag -a v0.1.1 -m "..." && git push origin v0.1.1
```

**A version number can never be reused on PyPI**, even after deletion — so dry-run on
TestPyPI first if unsure. Push tags individually; never `git push --tags`.

## Reporting a vulnerability

Please **do not** open a public issue for a security vulnerability in SENTINEL
itself. Open a GitHub security advisory on the repository, or contact the maintainer
privately, and allow time for a fix before disclosure.

Note the deliberate threat-model boundary in the README: message-level (not
token-level) provenance, action-layer (not cognition) enforcement, and a trusted proxy
and policy store. Reports outside that boundary are still welcome as discussion, but
they aren't vulnerabilities in the implementation.
