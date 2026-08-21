"""Security middleware for the public HTTP surface.

Three independent concerns, kept apart because they fail differently:
``SecurityHeadersMiddleware`` never rejects a request, it only decorates the
response; ``MaxBodySizeMiddleware`` can reject a request outright and must do
so as the body streams in, not after Starlette has buffered all of it into
memory to find out it was too big; ``SpaNavigationMiddleware`` answers a
request itself instead of routing it, and so must be extremely conservative
about which requests it claims.
"""

import logging
import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse
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


# --------------------------------------------------------------------------
# SPA navigation vs API content negotiation
# --------------------------------------------------------------------------
#
# /devices, /employees, /attendance and /users are real API routes returning
# 200 JSON, so a 404-triggered history fallback cannot work: nothing 404s.
# The two callers are told apart by intent instead of by path.
#
#   default              -> the page
#   with the XHR flag    -> JSON
#
# The positive signal is the flag frontend/src/api.js puts on every single
# call (X-Requested-With: XMLHttpRequest). The negative signal is that the
# request also has to look like a real top-level browser navigation, so that
# a caller which simply doesn't know about the flag — curl, a cron script,
# any existing consumer of the documented REST API — keeps getting JSON.

_XHR_HEADER = "x-requested-with"
_XHR_VALUE = "xmlhttprequest"

# Sec-Fetch-Mode is a forbidden header name: browsers set it on every request
# and page JavaScript cannot override it, so "navigate" is a signal the SPA's
# own fetch() calls could not produce even if the flag above were dropped.
# Only browsers old enough to omit Sec-Fetch-* entirely fall through to the
# Accept sniff below.
_NAV_MODES = {"navigate"}

_SAFE_METHODS = {"GET", "HEAD"}

# StaticFiles owns everything under here plus anything that looks like a
# file. favicon.svg and icons.svg are covered by the extension test.
_ASSET_PREFIX = "/assets/"


def _accept_quality(accept: str, media_type: str) -> float:
    """Quality this Accept header gives ``media_type`` **explicitly**.

    A bare ``*/*`` deliberately scores 0: that is what curl and every other
    non-browser client sends, and it must never be read as asking for HTML.
    """
    best = 0.0
    for part in accept.split(","):
        bits = part.strip().split(";")
        if bits[0].strip().lower() != media_type:
            continue
        quality = 1.0
        for param in bits[1:]:
            name, _, value = param.partition("=")
            if name.strip().lower() == "q":
                try:
                    quality = float(value.strip())
                except ValueError:
                    quality = 0.0
        best = max(best, quality)
    return best


def _is_navigation(headers) -> bool:
    mode = headers.get("sec-fetch-mode")
    accept = headers.get("accept", "")
    html = _accept_quality(accept, "text/html")
    json_ = _accept_quality(accept, "application/json")

    if mode is not None:
        # Modern browser. Anything other than a top-level navigation
        # (fetch/XHR arrive as cors|same-origin|no-cors) is not ours. The
        # Accept test is kept as an escape hatch so an operator poking at the
        # API from a browser-based client with an explicit
        # Accept: application/json still gets JSON.
        return mode.lower() in _NAV_MODES and json_ <= html

    # Pre-Sec-Fetch browser: the only thing left to go on is a stated
    # preference for HTML over JSON.
    return html > 0 and html >= json_


class SpaNavigationMiddleware(BaseHTTPMiddleware):
    """Serve the SPA shell for browser navigations; route everything else.

    Sits inside SecurityHeadersMiddleware so the shell it returns picks up
    the same CSP and friends as any other document response.
    """

    def __init__(self, app: ASGIApp, index_html: str):
        super().__init__(app)
        self.index_html = index_html

    async def dispatch(self, request: Request, call_next):
        if not self._claims(request):
            return await call_next(request)

        # A backend-only checkout has no build to serve — fall through to
        # whatever the app would have done rather than 500.
        if not os.path.isfile(self.index_html):
            return await call_next(request)

        # The cache headers are load-bearing, not hygiene. /employees is both
        # a page and an API route, and the two are told apart by *headers*
        # rather than by URL. FileResponse's default ETag/Last-Modified with
        # no Vary tells the browser those two responses are interchangeable,
        # so the shell HTML cached from the navigation gets replayed to the
        # page's own fetch('/employees') — which then fails to parse as JSON
        # and renders an empty list. Observed: a hard reload of /employees
        # showing "0 employees" while the API itself was answering perfectly.
        #
        # `no-store` is what fixes it; `Vary` states the actual dependency for
        # any cache in between. Nothing is lost by not caching the shell: it
        # is a few hundred bytes and every asset it references is content-
        # hashed and cached normally.
        return FileResponse(self.index_html, headers={
            "Cache-Control": "no-store",
            "Vary": "X-Requested-With, Sec-Fetch-Mode, Accept",
        })

    def _claims(self, request: Request) -> bool:
        # The single most dangerous line in this file. Devices are embedded
        # ADMS clients: they send no XHR flag, no Sec-Fetch-*, and no Accept
        # worth the name, so every later test would happily hand one of them
        # an HTML page — which stops attendance collection site-wide, with no
        # error anywhere. Checked first, before any header is looked at.
        if request.url.path.startswith(_DEVICE_PREFIX):
            return False

        if request.method not in _SAFE_METHODS:
            return False

        headers = request.headers
        if headers.get(_XHR_HEADER, "").lower() == _XHR_VALUE:
            return False

        path = request.url.path
        if path.startswith(_ASSET_PREFIX) or "." in path.rsplit("/", 1)[-1]:
            return False

        return _is_navigation(headers)
