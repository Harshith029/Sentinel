"""SENTINEL — provenance-aware MCP security proxy.

See README.md for the architecture, threat model, and quick start.
"""
from importlib.metadata import PackageNotFoundError, version

# One source of truth: the installed distribution's version, which comes from
# pyproject.toml. A literal here had drifted to 0.1.0 while the package was 0.2.0.
try:
    __version__ = version("sentinel-prox")
except PackageNotFoundError:  # running from a source tree that is not installed
    __version__ = "0+unknown"
