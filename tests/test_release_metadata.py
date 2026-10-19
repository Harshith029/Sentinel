"""What users are told to install is what this repository builds (review F1, F28).

The README said `pip install sentinel` and its badges pointed at
pypi.org/project/sentinel: an unrelated project by another author. This
distribution is `sentinel-prox`. A text substitution during a rename caused it,
and nothing checked, so these checks run in CI from now on.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

import sentinel

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
DISTRIBUTION = PYPROJECT["project"]["name"]


def _read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


# The project site's pages (not website/node_modules, which holds other
# projects' markdown).
SITE_PAGES = tuple(
    str(p.relative_to(ROOT))
    for pattern in ("website/*.md", "website/guide/*.md")
    for p in sorted(ROOT.glob(pattern))
)


def test_the_site_pages_are_found() -> None:
    assert "website/guide/quick-start.md" in {p.replace("\\", "/") for p in SITE_PAGES}


def test_every_pip_install_in_the_docs_names_this_distribution() -> None:
    for doc in ("README.md", "CONTRIBUTING.md", "deploy/DEPLOY.md", *SITE_PAGES):
        for match in re.finditer(r"pip(?:x)? install ([^\s`#]+)", _read(doc)):
            # Quoted requirements (`"sentinel-prox>=0.2.2"`, `"sentinel-prox[cosmos]"`)
            # are checked by their project name, which is everything before the
            # version specifier or extras.
            target = match.group(1).strip("\"'")
            if target.startswith(("-", ".")):
                continue  # flags, editable installs, local paths
            name = re.match(r"[A-Za-z0-9_.-]+", target)
            assert name is not None and name.group(0) == DISTRIBUTION, f"{doc}: `{match.group(0)}`"


def test_pypi_links_point_at_this_distribution() -> None:
    for doc in ("README.md", "CONTRIBUTING.md", *SITE_PAGES):
        for project in re.findall(r"pypi\.org/project/([A-Za-z0-9_.-]+)", _read(doc)):
            assert project == DISTRIBUTION, f"{doc} links to pypi.org/project/{project}"
        for project in re.findall(r"img\.shields\.io/pypi/[a-z]+/([A-Za-z0-9_.-]+)", _read(doc)):
            assert project == DISTRIBUTION, f"{doc} badge for {project}"


def test_the_trusted_publisher_table_names_this_distribution() -> None:
    row = next(
        line for line in _read("CONTRIBUTING.md").splitlines()
        if line.startswith("| PyPI Project Name")
    )
    assert f"`{DISTRIBUTION}`" in row


def test_the_package_reports_the_version_it_was_built_as() -> None:
    assert sentinel.__version__ == PYPROJECT["project"]["version"]
