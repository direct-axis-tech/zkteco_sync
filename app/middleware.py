"""Security middleware for the public HTTP surface.

Two independent concerns, kept apart because they fail differently:
``SecurityHeadersMiddleware`` never rejects a request, it only decorates the
response; ``MaxBodySizeMiddleware`` can reject a request outright and must do
so as the body streams in, not after Starlette has buffered all of it into
memory to find out it was too big.
"""

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app import config

log = logging.getLogger(__name__)

# Devices are dumb ADMS clients, not browsers: they neither parse nor benefit
# from CSP or HSTS, and this is the one publicly-reachable surface where an
# unexpected header could make firmware misbehave. Leave their responses
# exactly as before.
_DEVICE_PREFIX = "/iclock"

_PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=()"

# Same-origin SPA build with no CDN scripts, no inline <style>/<script>, no
# third-party fonts or frames — verified empirically against the production
# build (see D4 report). object-src/base-uri/frame-ancestors are added on
# top of default-src for defense in depth against the classic CSP-bypass
# corners, even though default-src would already cover them.
_CSP = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"

# Devices never see this (see _DEVICE_PREFIX above); on the browser-facing
# surface it only goes out once Apache is actually terminating TLS.
_HSTS = "max-age=31536000; includeSubDomains"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = _PERMISSIONS_POLICY

        if not request.url.path.startswith(_DEVICE_PREFIX):
            response.headers["Content-Security-Policy"] = _CSP
            if config.IS_PRODUCTION:
                response.headers["Strict-Transport-Security"] = _HSTS

        return response


_BODY_TOO_LARGE = b"Request body too large"


class _BodyTooLarge(Exception):
    pass


class MaxBodySizeMiddleware:
    """Pure ASGI (not BaseHTTPMiddleware) so an oversized body is caught as
    it streams in. Content-Length is checked up front as a fast path; a
    client that lies about it, or omits it and streams instead, is still
    caught chunk by chunk before it reaches a route handler.
    """

    def __init__(self, app: ASGIApp, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                if int(declared) > self.max_bytes:
                    await self._reject(send)
                    return
            except ValueError:
                pass  # Malformed header — fall through to the streaming check.

        total = 0
        response_started = False

        async def guarded_receive() -> Message:
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body") or b"")
                if total > self.max_bytes:
                    raise _BodyTooLarge()
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, guarded_receive, guarded_send)
        except _BodyTooLarge:
            if response_started:
                # The handler already began replying before the limit was
                # hit — nothing safe left to do but let the connection die
                # rather than attempt to send a second response.
                raise
            await self._reject(send)

    @staticmethod
    async def _reject(send: Send) -> None:
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(_BODY_TOO_LARGE)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": _BODY_TOO_LARGE, "more_body": False})
