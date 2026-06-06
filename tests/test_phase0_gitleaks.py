"""Phase 0 DoD: gitleaks blocks a planted fake secret.

The kickoff explicitly requires PROOF that the gitleaks pre-commit hook
intercepts a planted key. The gitleaks pre-commit hook runs
`gitleaks protect --staged`, so to exercise the real code path we:

1. Write a planted-secret file inside the repo.
2. `git add` it (staged content is what gitleaks scans).
3. Invoke `pre-commit run gitleaks`.
4. Assert the run failed (non-zero) AND reported a leak.
5. Unstage and delete the file regardless of outcome.

Using a GitHub PAT shape (`ghp_<36>`) because gitleaks's `github-pat` rule is
explicit and not masked by the default allowlist (which silently ignores
several AWS `EXAMPLE` patterns).
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PRECOMMIT_CONFIG = REPO_ROOT / ".pre-commit-config.yaml"


def _pre_commit_executable() -> str:
    venv_bin = Path(sys.executable).parent
    for c in (venv_bin / "pre-commit.exe", venv_bin / "pre-commit"):
        if c.is_file():
            return str(c)
    return "pre-commit"


def _git_executable() -> str:
    found = shutil.which("git")
    if not found:
        pytest.skip("git not on PATH")
    return found


def _make_planted_pat() -> str:
    """Assemble a fake GitHub PAT at runtime.

    The contiguous `ghp_<36>` literal NEVER appears in this source file —
    it is built from split string parts. That keeps gitleaks from
    (correctly) flagging this very test source as a secret. The runtime
    value DOES match `github-pat`; gitleaks catches it on the planted file,
    which is what this test asserts.
    """
    prefix = "gh" + "p_"
    body = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z7"
    return prefix + body


@pytest.fixture()
def staged_planted_secret() -> Iterator[Path]:
    """Plant + stage a fake credential, yield path, then unstage + delete.

    Teardown runs unconditionally so a failed assertion does NOT leave the
    secret in the index. We MUST NOT leak a planted credential into git
    history — that is the very thing this test exists to prevent.
    """
    planted = REPO_ROOT / "_phase0_planted_secret_DELETE_ME.txt"
    fake_pat = _make_planted_pat()
    planted.write_text(
        f"# Phase 0 test — PLANTED fake credential to prove gitleaks blocks.\n"
        f"GITHUB_TOKEN = {fake_pat!r}\n",
        encoding="utf-8",
    )

    git = _git_executable()
    try:
        subprocess.run(  # noqa: S603
            [git, "add", "--force", str(planted)],
            cwd=str(REPO_ROOT),
            check=True,
            capture_output=True,
        )
        yield planted
    finally:
        # Always unstage so the planted credential cannot be committed.
        subprocess.run(  # noqa: S603
            [git, "restore", "--staged", str(planted)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            check=False,
        )
        planted.unlink(missing_ok=True)


def test_gitleaks_blocks_planted_secret(staged_planted_secret: Path) -> None:
    assert PRECOMMIT_CONFIG.is_file(), "Phase 0 must ship a .pre-commit-config.yaml"

    proc = subprocess.run(  # noqa: S603
        [_pre_commit_executable(), "run", "gitleaks"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=180,
    )

    assert proc.returncode != 0, (
        "gitleaks did NOT block the planted secret.\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )

    combined = (proc.stdout + "\n" + proc.stderr).lower()
    assert "gitleaks" in combined or "secret" in combined, combined
    assert any(
        marker in combined for marker in ("failed", "leak", "finding", "secrets found")
    ), combined


def test_pre_commit_hook_is_installed() -> None:
    """`.git/hooks/pre-commit` exists after `pre-commit install` ran."""
    hook = REPO_ROOT / ".git" / "hooks" / "pre-commit"
    assert hook.is_file(), (
        "Run `pre-commit install` (Phase 0 step); .git/hooks/pre-commit is "
        "missing, so commits are NOT actually being scanned."
    )
    content = hook.read_text(encoding="utf-8", errors="ignore")
    assert "pre-commit" in content.lower()
