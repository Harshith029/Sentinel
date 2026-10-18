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
* for public hostnames, the validated address is pinned into the actual HTTP
  connection while the original host remains the HTTP ``Host`` header and TLS
  SNI name, closing DNS-rebinding between validation and connect;
* redirects are followed manually and **each hop is re-validated** (an open
  redirect to ``http://10.0.0.1`` is blocked on the second hop, not the first);
* the body is size-capped by streaming (a huge response cannot exhaust memory),
  with a per-request timeout;
* non-text content is summarized rather than returned as binary noise;
* any transport/DNS error becomes a returned error string — the tool never raises.

The HTTP client and the DNS resolver are injectable so the guards and the happy
path are unit-testable without real network access.

"""

from __future__ import annotations

import asyncio
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
    "text/",
    "json",
    "xml",
    "html",
    "javascript",
    "csv",
    "yaml",
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


@dataclass(frozen=True)
class _PinnedTarget:
    """One validated target, with its public DNS answer pinned for connection."""

    request_url: httpx.URL
    headers: dict[str, str]
    extensions: dict[str, object]


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
        # RFC 6598 shared address space is not reported as private by every
        # supported Python ipaddress release. It is routable inside provider
        # networks, including cloud metadata services, so web_fetch must never
        # treat it as a public destination.
        or ip in ipaddress.ip_network("100.64.0.0/10")
    )


def _prepare_target(url: str, *, allow_private: bool, resolve: Resolver) -> _PinnedTarget | str:
    """Validate a target and pin a public hostname to its checked address."""
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError, ValueError):
        return "invalid URL"
    if parsed.scheme not in ("http", "https"):
        return f"blocked scheme {parsed.scheme!r}: only http/https allowed"
    try:
        host = parsed.host
    except UnicodeError:  # idna.IDNAError is a UnicodeError; it escaped before
        return "invalid URL host"
    if not host:
        return "URL has no host"
    if parsed.username or parsed.password:
        return "URL userinfo is not allowed"
    if allow_private:
        # This is an explicit trusted-internal-use escape hatch. Keep the
        # requested URL intact rather than attempting to impose the public SSRF
        # policy on it.
        return _PinnedTarget(parsed, {"User-Agent": _USER_AGENT}, {})
    # Host may be an IP literal (no DNS) or a name (resolve it).
    try:
        candidates: Sequence[str] = [str(ipaddress.ip_address(host))]
    except ValueError:
        try:
            candidates = resolve(host)
        except UnicodeError:  # a label too long or empty, raised while encoding
            return "invalid URL host"
        except (socket.gaierror, OSError) as exc:
            return f"DNS resolution failed for {host!r}: {exc}"
        if not candidates:
            return f"no addresses resolved for {host!r}"
    blocked = sorted({ip for ip in candidates if _ip_is_blocked(ip)})
    if blocked:
        return f"blocked private/internal address {blocked} for host {host!r}"

    # IP literals are already their own pinned endpoint. For DNS names, use one
    # checked answer as the request destination. HTTP/1.1 virtual hosting still
    # needs the original authority; HTTPS additionally needs it for certificate
    # verification and SNI. httpcore (under httpx) honors ``sni_hostname`` when
    # opening TLS, while the socket target comes from request_url's IP address.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        request_url = parsed.copy_with(host=candidates[0])
        authority = parsed.netloc.decode("ascii")
        extensions: dict[str, object] = {}
        if parsed.scheme == "https":
            extensions["sni_hostname"] = host
        return _PinnedTarget(
            request_url,
            {"User-Agent": _USER_AGENT, "Host": authority},
            extensions,
        )
    return _PinnedTarget(parsed, {"User-Agent": _USER_AGENT}, {})


def validate_target(url: str, *, allow_private: bool, resolve: Resolver) -> str | None:
    """Return an error string if ``url`` must be refused, else ``None`` (allowed)."""
    prepared = _prepare_target(url, allow_private=allow_private, resolve=resolve)
    return prepared if isinstance(prepared, str) else None


def _summarize_binary(content_type: str, size: int) -> str:
    return f"[non-text content: {content_type or 'unknown'}, {size} bytes not returned]"


async def fetch_url(
    url: str,
    *,
    timeout: float = 10.0,
    deadline: float = 30.0,
    max_bytes: int = 2_000_000,
    max_redirects: int = 3,
    allow_private: bool = False,
    client: httpx.AsyncClient | None = None,
    resolve: Resolver = _default_resolve,
) -> FetchResult:
    """Fetch ``url`` with SSRF/size/timeout guards. Never raises — errors returned.

    ``timeout`` bounds each network operation (connect, one read); ``deadline``
    bounds the whole fetch, redirects included. Without it, a server sending a
    byte just inside ``timeout`` kept a fetch going indefinitely.
    """
    try:
        async with asyncio.timeout(deadline):
            return await _fetch(
                url,
                timeout=timeout,
                max_bytes=max_bytes,
                max_redirects=max_redirects,
                allow_private=allow_private,
                client=client,
                resolve=resolve,
            )
    except TimeoutError:
        return FetchResult(url, None, None, "", False, f"fetch exceeded its {deadline:g}s deadline")
    except Exception as exc:  # noqa: BLE001 - "never raises" is this function's contract
        return FetchResult(url, None, None, "", False, f"fetch error: {type(exc).__name__}")


async def _fetch(
    url: str,
    *,
    timeout: float,
    max_bytes: int,
    max_redirects: int,
    allow_private: bool,
    client: httpx.AsyncClient | None,
    resolve: Resolver,
) -> FetchResult:
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(follow_redirects=False, timeout=timeout)
    try:
        current = url
        for _hop in range(max_redirects + 1):
            # In a thread: the default resolver is blocking getaddrinfo, which
            # stalled every session on the shared event loop while it ran.
            prepared = await asyncio.to_thread(
                _prepare_target, current, allow_private=allow_private, resolve=resolve
            )
            if isinstance(prepared, str):
                return FetchResult(current, None, None, "", False, prepared)
            try:
                async with client.stream(
                    "GET",
                    prepared.request_url,
                    headers=prepared.headers,
                    extensions=prepared.extensions,
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
                    return FetchResult(current, resp.status_code, ctype, text, truncated, None)
            except httpx.HTTPError as exc:
                return FetchResult(
                    current,
                    None,
                    None,
                    "",
                    False,
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
