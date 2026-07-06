"""Real web_fetch: SSRF guards, streaming caps, redirect re-validation, errors.

Uses httpx.MockTransport + an injected resolver, so every case is deterministic
and offline. These prove the tool operates on ARBITRARY urls while failing closed
on the internal-network vectors an SSRF attacker would reach for.
"""
from __future__ import annotations

import httpx
import pytest

from sentinel.toolservers.web_fetch import FetchResult, fetch_url, validate_target


def _resolver(mapping: dict[str, list[str]]):
    def resolve(host: str) -> list[str]:
        return mapping.get(host, [])
    return resolve


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)


PUBLIC = _resolver({"public.test": ["93.184.216.34"], "evil.test": ["10.0.0.5"]})


# --- SSRF: refuse internal targets, up front, before any request ---------------

@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/secret",           # loopback literal
        "http://169.254.169.254/latest/meta", # cloud metadata (link-local)
        "http://[::1]/",                       # ipv6 loopback
        "http://10.0.0.5/",                    # private literal
        "http://192.168.1.1/",                 # private literal
    ],
)
async def test_blocks_internal_ip_literals(url: str) -> None:
    result = await fetch_url(url, resolve=PUBLIC)
    assert not result.ok
    assert "blocked" in result.error.lower()


async def test_blocks_private_via_dns() -> None:
    # A public-looking hostname that resolves to a private address is still blocked.
    result = await fetch_url("http://evil.test/", resolve=PUBLIC)
    assert not result.ok and "10.0.0.5" in result.error


async def test_rejects_non_http_scheme() -> None:
    result = await fetch_url("file:///etc/passwd", resolve=PUBLIC)
    assert not result.ok and "scheme" in result.error


async def test_rejects_unresolvable_host() -> None:
    result = await fetch_url("http://nope.invalid/", resolve=PUBLIC)
    assert not result.ok and "resolved" in result.error


# --- happy path over an arbitrary public URL -----------------------------------

async def test_fetches_public_text() -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html"}, content=b"<h1>hi</h1>")

    async with _client(handler) as c:
        result = await fetch_url("http://public.test/page", resolve=PUBLIC, client=c)
    assert result.ok and result.status == 200
    assert result.text == "<h1>hi</h1>" and not result.truncated


# --- redirects are re-validated at every hop -----------------------------------

async def test_redirect_to_private_is_blocked_on_second_hop() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.host == "public.test"  # the private hop must NEVER be requested
        return httpx.Response(302, headers={"location": "http://10.0.0.1/internal"})

    async with _client(handler) as c:
        result = await fetch_url("http://public.test/redir", resolve=PUBLIC, client=c)
    assert not result.ok and "blocked" in result.error.lower()


# --- resource limits ------------------------------------------------------------

async def test_size_cap_truncates() -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"A" * 5000)

    async with _client(handler) as c:
        result = await fetch_url("http://public.test/big", resolve=PUBLIC, client=c, max_bytes=100)
    assert result.ok and result.truncated and len(result.text) == 100


async def test_non_text_is_summarized_not_returned() -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "image/png"}, content=b"\x89PNG\r\n")

    async with _client(handler) as c:
        result = await fetch_url("http://public.test/img", resolve=PUBLIC, client=c)
    assert result.ok and "non-text content" in result.text and "image/png" in result.text


# --- failures never raise -------------------------------------------------------

async def test_transport_error_is_returned_not_raised() -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    async with _client(handler) as c:
        result = await fetch_url("http://public.test/down", resolve=PUBLIC, client=c)
    assert not result.ok and "fetch error" in result.error


async def test_as_tool_output_wraps_error_as_text() -> None:
    err = FetchResult("http://x/", None, None, "", False, "boom")
    assert err.as_tool_output().startswith("[web_fetch error")


# --- validate_target is a pure, reusable guard ---------------------------------

def test_validate_target_allows_public_and_blocks_private() -> None:
    assert validate_target("http://public.test/", allow_private=False, resolve=PUBLIC) is None
    assert validate_target("http://127.0.0.1/", allow_private=False, resolve=PUBLIC) is not None
    # allow_private bypass (trusted internal use) skips the IP check
    assert validate_target("http://127.0.0.1/", allow_private=True, resolve=PUBLIC) is None
