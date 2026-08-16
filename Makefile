# Whence developer Makefile.
#
# Targets are intentionally tiny shims — the real logic is in pyproject.toml,
# pre-commit config, and CI. `make test` is the canonical entry point Phase 0
# DoD cares about.

PY ?= .venv/Scripts/python.exe
PRE_COMMIT ?= .venv/Scripts/pre-commit.exe
ifeq ($(OS),Windows_NT)
	PY := .venv/Scripts/python.exe
	PRE_COMMIT := .venv/Scripts/pre-commit.exe
else
	PY := .venv/bin/python
	PRE_COMMIT := .venv/bin/pre-commit
endif

.PHONY: help test test-unit lint typecheck install hooks gitleaks-scan clean dashboard serve

help:
	@echo "Whence — developer targets"
	@echo ""
	@echo "  make install       — create .venv and install dev extras"
	@echo "  make hooks         — install the pre-commit git hook"
	@echo "  make test          — run pytest (this is the Phase 0 DoD entry point)"
	@echo "  make lint          — ruff check"
	@echo "  make typecheck     — mypy"
	@echo "  make dashboard     — serve the control plane + dashboard on :8765 (REST demo)"
	@echo "  make serve         — serve the FULL product incl. the /mcp wire gateway on :8765"
	@echo "  make gitleaks-scan — pre-commit run gitleaks --all-files"
	@echo "  make clean         — remove caches and build artifacts"

dashboard:  ## Phase 7: serve the live dashboard + control plane at http://127.0.0.1:8765
	$(PY) -m uvicorn whence.control.app:create_app --factory --host 127.0.0.1 --port 8765

serve:  ## Phase 9: serve the dashboard + control plane + REAL /mcp wire transport
	$(PY) -m uvicorn whence.control.app:create_gateway_app --factory --host 127.0.0.1 --port 8765

install:
	python -m venv .venv
	$(PY) -m pip install --upgrade pip setuptools wheel
	$(PY) -m pip install -e ".[dev]"

hooks:
	$(PRE_COMMIT) install
	$(PRE_COMMIT) install-hooks

test:
	$(PY) -m pytest

test-unit: test  ## alias for clarity in CI

lint:
	$(PY) -m ruff check src tests

typecheck:
	$(PY) -m mypy src

gitleaks-scan:
	$(PRE_COMMIT) run gitleaks --all-files

clean:
	-rm -rf .pytest_cache .ruff_cache .mypy_cache build dist *.egg-info
	-find . -type d -name __pycache__ -exec rm -rf {} +
