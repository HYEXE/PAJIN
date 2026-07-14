"""Static, same-origin Web Console responses with a locked-down browser policy."""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
from typing import Literal

from fastapi.responses import HTMLResponse, Response

type ConsoleAsset = Literal["index.html", "app.css", "app.js"]

_ASSET_MEDIA_TYPES: dict[ConsoleAsset, str] = {
    "index.html": "text/html",
    "app.css": "text/css",
    "app.js": "text/javascript",
}
_BASE_HEADERS = {
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": (
        "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()"
    ),
}
_CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'none'",
        "script-src 'self'",
        "script-src-attr 'none'",
        "style-src 'self'",
        "style-src-attr 'none'",
        "connect-src 'self'",
        "img-src 'none'",
        "font-src 'none'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
        "worker-src 'none'",
    )
)


@lru_cache(maxsize=3)
def _asset_text(name: ConsoleAsset) -> str:
    return files("pajin.control_plane.web").joinpath(name).read_text(encoding="utf-8")


def console_index_response() -> HTMLResponse:
    return HTMLResponse(
        _asset_text("index.html"),
        headers={**_BASE_HEADERS, "Content-Security-Policy": _CONTENT_SECURITY_POLICY},
    )


def console_asset_response(name: Literal["app.css", "app.js"]) -> Response:
    return Response(
        _asset_text(name),
        media_type=_ASSET_MEDIA_TYPES[name],
        headers=_BASE_HEADERS,
    )
