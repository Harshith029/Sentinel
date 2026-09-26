"""Request-level resource bounds: body size and per-caller rate (audit F-05/F-06).

Both are ASGI middleware rather than FastAPI dependencies so they sit in front of
EVERYTHING the app serves, including the ``/mcp`` mount — a dependency would
only guard the control-plane routes, and a body has already been read by the
time a dependency runs.

Before this, a single request could make the server buffer and JSON-parse any
amount of data (a 40 MB body to ``/runs/custom`` was read in full and only then
rejected by validation), and nothing limited how fast one caller could hit it.
"""
from __future__ import annotations

import time
from collections import OrderedDict
from typing import Final

from starlette.datastructures import Headers
from starlette.requests import cookie_parser
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sentinel.authn import SESSION_COOKIE, bearer_credential, is_admin, resolve_tenant
from sentinel.config import get_settings

# Paths a load balancer or a browser must reach without being throttled.
_UNLIMITED_PATHS: Final[frozenset[str]] = frozenset({"/healthz", "/"})
# Buckets are per caller; cap how many we remember so the limiter cannot itself
# become the unbounded structure it exists to prevent.
_MAX_TRACKED_CALLERS: Final[int] = 10_000


async def _reject(send: Send, status: int, detail: str, *, retry_after: int | None = None) -> None:
    headers = [(b"content-type", b"application/json")]
    if retry_after is not None:
        headers.append((b"retry-after", str(retry_after).encode()))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    body = ('{"detail":"' + detail.replace('"', "'") + '"}').encode()
    await send({"type": "http.response.body", "body": body})


class BodySizeLimit:
    """Refuse request bodies above ``SENTINEL_MAX_BODY_BYTES`` with 413.

    A declared ``Content-Length`` over the limit is refused before a single body
    byte is read. A body without one (chunked) is counted as it streams and cut
    off the moment it crosses the limit, so a client cannot dodge the check by
    simply not declaring a length.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        limit = get_settings().max_body_bytes
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None:
            try:
                if int(declared) > limit:
                    await _reject(send, 413, f"request body exceeds {limit} bytes")
                    return
            except ValueError:
                await _reject(send, 400, "malformed Content-Length")
                return

        received = 0
        started = False
        over = False

        async def counting_receive() -> Message:
            nonlocal received, over
            if over:
                return {"type": "http.disconnect"}  # read no more of the body
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # Tell the app the client went away rather than raising
                    # through it: frameworks catch errors raised while reading a
                    # body and turn them into a 400, which would hide the reason.
                    over = True
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal started
            if over and not started:
                return  # the app's reply to a truncated body is not the answer
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        await self._app(scope, counting_receive, guarded_send)
        if over and not started:
            await _reject(send, 413, f"request body exceeds {limit} bytes")


class RateLimit:
    """Token bucket per caller: ``SENTINEL_RATE_LIMIT_PER_MINUTE`` requests/minute.

    A caller presenting a VALID credential is keyed by the tenant it
    authenticates as, so one tenant exhausting its budget cannot starve another.
    Everyone else — no credential, or one that matches nothing — is keyed by
    client address.

    Keying by whatever credential a request carries would be wrong: a client
    could send a different made-up token on every request and get a fresh
    bucket each time. That would leave unthrottled exactly the traffic a limiter
    most needs to catch — someone guessing credentials, or anyone at all in
    anonymous mode, where no token is checked.

    Behind a reverse proxy the client address is the proxy's unless uvicorn is
    told to trust it (``FORWARDED_ALLOW_IPS``); see the README.
    Over the limit is 429 with ``Retry-After``.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app
        # caller -> (tokens, last refill time); ordered so the oldest is evicted.
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

    @staticmethod
    def _caller(scope: Scope) -> str:
        headers = Headers(scope=scope)
        presented = bearer_credential(headers) or cookie_parser(
            headers.get("cookie", "")
        ).get(SESSION_COOKIE, "")
        if presented:
            tenant = resolve_tenant(presented)
            if tenant is not None:
                return f"t:{tenant}"
            if is_admin(presented):
                return "admin"
        client = scope.get("client") or ("unknown", 0)
        return f"a:{client[0]}"

    def _allow(self, caller: str, per_minute: int) -> tuple[bool, int]:
        now = time.monotonic()
        capacity = float(per_minute)
        rate = per_minute / 60.0
        tokens, last = self._buckets.pop(caller, (capacity, now))
        tokens = min(capacity, tokens + (now - last) * rate)
        allowed = tokens >= 1.0
        if allowed:
            tokens -= 1.0
        self._buckets[caller] = (tokens, now)
        while len(self._buckets) > _MAX_TRACKED_CALLERS:
            self._buckets.popitem(last=False)
        retry_after = 0 if allowed else max(1, int((1.0 - tokens) / rate) + 1)
        return allowed, retry_after

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        per_minute = get_settings().rate_limit_per_minute
        if scope["type"] != "http" or per_minute == 0 or scope["path"] in _UNLIMITED_PATHS:
            await self._app(scope, receive, send)
            return
        allowed, retry_after = self._allow(self._caller(scope), per_minute)
        if not allowed:
            await _reject(send, 429, "rate limit exceeded", retry_after=retry_after)
            return
        await self._app(scope, receive, send)
