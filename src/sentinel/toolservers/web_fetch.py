"""Real ``web_fetch`` — fetch arbitrary URLs safely (Layer 1a generalization).

The demo's ``web_fetch`` returns canned pages. This one performs a REAL HTTP GET
against any user-supplied URL, so the agent can research pages the system has never
seen — and the fetched bytes flow into the provenance/taint engine exactly like any
other ``RETRIEVED_CONTENT``.

A ``web_fetch`` inside a *security* proxy is itself an SSRF liability, so the
fetcher is guarded up front and fails CLOSED:

* only ``http`` / ``https`` schemes;
* the target host is resolved and every candidate IP is rejected if it is
  private, loopback, link-local (this also covers the ``169.254.169.254`` cloud
  metadata endpoint), reserved, multicast, or unspecified — unless
  ``allow_private`` is explicitly set (tests / trusted internal use);
* redirects are followed manually and **each hop is re-validated** (an open
  redirect to ``http://10.0.0.1`` is blocked on the second hop, not the first);
* the body is size-capped by streaming (a huge response cannot exhaust memory),
  with a per-request timeout;
* non-text content is summarized rather than returned as binary noise;
* any transport/DNS error becomes a returned error string — the tool never raises.

The HTTP client and the DNS resolver are injectable so the guards and the happy
path are unit-testable without real network access.

Known limitation (documented, not hidden): validation resolves the host and then
the client connects, so a DNS-rebinding attacker could in principle return a public
IP at validation and a private IP at connect (TOCTOU). Pinning the validated IP into
the connection is a follow-up hardening; for now the resolver check plus scheme and
redirect re-validation cover the common SSRF vectors.
"""
from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

import httpx

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

_USER_AGENT: Final[str] = "SENTINEL-web-fetch/1.0 (+https://github.com/Harshith029/SENTINEL)"
_TEXTUAL_HINTS: Final[tuple[str, ...]] = (
    "text/", "json", "xml", "html", "javascript", "csv", "yaml",
)

Resolver = Callable[[str], Sequence[str]]


@dataclass(frozen=True)
class FetchResult:
    """Outcome of one fetch. ``error`` is None on success; ``text`` is the body."""

    url: str
    status: int | None
    content_type: str | None
    text: str
    truncated: bool
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def as_tool_output(self) -> str:
        """The string the MCP tool returns (still treated as RETRIEVED_CONTENT).

        On failure the error is returned as text rather than raised, so the agent
        (and the taint engine) still see a well-formed, untrusted result.
        """
        if self.error is not None:
            return f"[web_fetch error for {self.url}] {self.error}"
        return self.text


def _default_resolve(host: str) -> list[str]:
    """Resolve ``host`` to the set of candidate IP strings (A and AAAA)."""
    return [str(info[4][0]) for info in socket.getaddrinfo(host, None)]


def _ip_is_blocked(ip_text: str) -> bool:
    ip = ipaddress.ip_address(ip_text)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local  # covers 169.254.169.254 cloud metadata
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_target(url: str, *, allow_private: bool, resolve: Resolver) -> str | None:
    """Return an error string if ``url`` must be refused, else ``None`` (allowed)."""
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError, ValueError):
        return "invalid URL"
    if parsed.scheme not in ("http", "https"):
        return f"blocked scheme {parsed.scheme!r}: only http/https allowed"
    host = parsed.host
    if not host:
        return "URL has no host"
    if allow_private:
        return None
    # Host may be an IP literal (no DNS) or a name (resolve it).
    try:
        candidates: Sequence[str] = [str(ipaddress.ip_address(host))]
    except ValueError:
        try:
            candidates = resolve(host)
        except (socket.gaierror, OSError) as exc:
            return f"DNS resolution failed for {host!r}: {exc}"
        if not candidates:
            return f"no addresses resolved for {host!r}"
    blocked = sorted({ip for ip in candidates if _ip_is_blocked(ip)})
    if blocked:
        return f"blocked private/internal address {blocked} for host {host!r}"
    return None


def _summarize_binary(content_type: str, size: int) -> str:
    return f"[non-text content: {content_type or 'unknown'}, {size} bytes not returned]"


async def fetch_url(
    url: str,
    *,
    timeout: float = 10.0,
    max_bytes: int = 2_000_000,
    max_redirects: int = 3,
    allow_private: bool = False,
    client: httpx.AsyncClient | None = None,
    resolve: Resolver = _default_resolve,
) -> FetchResult:
    """Fetch ``url`` with SSRF/size/timeout guards. Never raises — errors returned."""
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(follow_redirects=False, timeout=timeout)
    try:
        current = url
        for _hop in range(max_redirects + 1):
            blocked = validate_target(current, allow_private=allow_private, resolve=resolve)
            if blocked is not None:
                return FetchResult(current, None, None, "", False, blocked)
            try:
                async with client.stream(
                    "GET", current, headers={"User-Agent": _USER_AGENT}
                ) as resp:
                    if resp.is_redirect and "location" in resp.headers:
                        current = str(httpx.URL(current).join(resp.headers["location"]))
                        await resp.aclose()
                        continue
                    ctype = resp.headers.get("content-type", "")
                    body = bytearray()
                    truncated = False
                    async for chunk in resp.aiter_bytes():
                        body.extend(chunk)
                        if len(body) >= max_bytes:
                            truncated = True
                            del body[max_bytes:]
                            break
                    is_text = any(h in ctype.lower() for h in _TEXTUAL_HINTS) or not ctype
                    if is_text:
                        text = bytes(body).decode(resp.encoding or "utf-8", errors="replace")
                    else:
                        text = _summarize_binary(ctype, len(body))
                    return FetchResult(
                        str(resp.url), resp.status_code, ctype, text, truncated, None
                    )
            except httpx.HTTPError as exc:
                return FetchResult(
                    current, None, None, "", False,
                    f"fetch error: {type(exc).__name__}: {exc}",
                )
        return FetchResult(url, None, None, "", False, f"too many redirects (> {max_redirects})")
    finally:
        if owns_client:
            await client.aclose()


def build_web_server() -> FastMCP:
    """A FastMCP ``web`` server whose ``web_fetch`` performs a REAL fetch.

    Drop-in replacement for the demo's mock ``web`` server: same tool name and
    signature, so it sits behind the proxy unchanged. Imported lazily so the
    package has no hard dependency on ``mcp.server.fastmcp`` at import time.
    """
    from mcp.server.fastmcp import FastMCP

    web = FastMCP("web")

    @web.tool()
    async def web_fetch(url: str) -> str:
        """Fetch a web page over HTTP(S) and return its text (guarded)."""
        result = await fetch_url(url)
        return result.as_tool_output()

    return web
