#!/usr/bin/env python
"""CI guard: the installed environment must agree with ``versions.lock``.

``versions.lock`` is an exact ``pip freeze``. CI installs *with it as a
constraints file* so the environment is reproducible; this script then fails
loudly on any genuine version **conflict** (a package installed at a version
different from the lock).

Platform-specific pins are tolerated. ``versions.lock`` was generated on Windows,
so it records packages such as ``pywin32`` and ``colorama`` that are simply not
installed on a Linux runner. Their *absence* is expected — only a co-installed
package pinned to the *wrong version* is real drift.

Run from the repo root: ``python scripts/check_versions_lock.py``.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def pins(text: str) -> dict[str, str]:
    """Parse ``name==version`` lines into a normalized {name: version} map."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "==" in line:
            name, version = line.split("==", 1)
            # Normalize so e.g. ``pydantic_core`` and ``pydantic-core`` match.
            out[name.lower().replace("_", "-")] = version
    return out


def main() -> int:
    lock_path = Path("versions.lock")
    if not lock_path.is_file():
        raise SystemExit("versions.lock not found (run from the repo root)")

    lock = pins(lock_path.read_text(encoding="utf-8"))
    frozen = subprocess.run(
        [sys.executable, "-m", "pip", "freeze", "--exclude-editable"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    got = pins(frozen)

    conflicts = {n: (lock[n], got[n]) for n in lock if n in got and got[n] != lock[n]}
    if conflicts:
        for name, (want, have) in sorted(conflicts.items()):
            print(f"  DRIFT {name}: lock={want} installed={have}")
        raise SystemExit(f"versions.lock drift: {len(conflicts)} version conflict(s)")

    absent = sorted(n for n in lock if n not in got)
    print(
        f"versions.lock OK: {len(lock)} pins, 0 conflicts, "
        f"{len(absent)} platform-only absence(s) tolerated: {absent}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
