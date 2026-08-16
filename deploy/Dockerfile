# Whence container image (BUILD_SPEC §Phase 8).
#
# One image serves three roles via the run command:
#   * Whence proxy + control plane + dashboard  (default CMD, external ingress)
#   * a mock tool server                          (CMD: python -m whence.demo.toolserver_main)
# In Azure Container Apps the tool-server replicas run with INTERNAL ingress only.
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    WHENCE_DEMO_MODE=1

WORKDIR /app

# Install the package PINNED to versions.lock.
#
# `-c versions.lock` is load-bearing, not decorative: pyproject declares floors
# (e.g. `mcp>=1.2`), so a plain `pip install .` silently resolves to whatever is
# newest at build time. That is exactly how this image broke in production — a
# newer `mcp` dropped `create_connected_server_and_client_session` and the
# container crashed on import. Constraints only bind packages that are actually
# installed, so the Windows-only entries in the lock (pywin32, colorama) are
# simply ignored on this Linux base image. Same mechanism CI uses.
COPY pyproject.toml README.md versions.lock ./
COPY src ./src
RUN python -m pip install --upgrade pip setuptools wheel \
 && python -m pip install . -c versions.lock

# Run as non-root. /data is the writable home of the SQLite forensic store —
# /app is root-owned, so the default ./var path would fail for uid 10001.
RUN useradd --create-home --uid 10001 whence \
 && mkdir -p /data && chown whence /data
ENV WHENCE_DATA_DIR=/data
USER whence

EXPOSE 8765

# Default role: the FULL product — control plane + dashboard + the real /mcp wire
# gateway (create_gateway_app), so the deployed app is the same thing `make serve`
# runs locally. Gate /mcp with WHENCE_API_TOKEN on any public deploy.
# Run through the CLI (the product interface), so a mounted /app/whence.yaml is
# honoured exactly as it is locally: `docker run -v $(pwd)/whence.yaml:/app/whence.yaml`.
# Without one it serves with defaults, which is what the hosted demo does.
CMD ["whence", "serve", "--host", "0.0.0.0", "--port", "8765"]
