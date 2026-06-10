# SENTINEL container image (BUILD_SPEC §Phase 8).
#
# One image serves three roles via the run command:
#   * SENTINEL proxy + control plane + dashboard  (default CMD, external ingress)
#   * a mock tool server                          (CMD: python -m sentinel.demo.toolserver_main)
# In Azure Container Apps the tool-server replicas run with INTERNAL ingress only.
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SENTINEL_DEMO_MODE=1

WORKDIR /app

# Install the package (deps resolve to the pins recorded in versions.lock).
COPY pyproject.toml README.md versions.lock ./
COPY src ./src
RUN python -m pip install --upgrade pip setuptools wheel \
 && python -m pip install .

# Run as non-root. /data is the writable home of the SQLite forensic store —
# /app is root-owned, so the default ./var path would fail for uid 10001.
RUN useradd --create-home --uid 10001 sentinel \
 && mkdir -p /data && chown sentinel /data
ENV SENTINEL_DATA_DIR=/data
USER sentinel

EXPOSE 8765

# Default role: the FULL product — control plane + dashboard + the real /mcp wire
# gateway (create_gateway_app), so the deployed app is the same thing `make serve`
# runs locally. Gate /mcp with SENTINEL_API_TOKEN on any public deploy.
CMD ["python", "-m", "uvicorn", "sentinel.control.app:create_gateway_app", \
     "--factory", "--host", "0.0.0.0", "--port", "8765"]
