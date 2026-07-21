"""Run the PAJIN Control Plane API server."""

from __future__ import annotations

import os

import uvicorn

_DEFAULT_LIMIT_CONCURRENCY = 256


def _limit_concurrency_from_env() -> int:
    raw = os.environ.get("PAJIN_CP_LIMIT_CONCURRENCY", str(_DEFAULT_LIMIT_CONCURRENCY))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("PAJIN_CP_LIMIT_CONCURRENCY must be an integer") from exc
    if not 1 <= value <= 100_000:
        raise ValueError("PAJIN_CP_LIMIT_CONCURRENCY must be between 1 and 100000")
    return value


def main() -> None:
    uvicorn.run(
        "pajin.control_plane.api:create_app",
        factory=True,
        host=os.environ.get("PAJIN_CP_HOST", "127.0.0.1"),
        port=int(os.environ.get("PAJIN_CP_PORT", "8090")),
        limit_concurrency=_limit_concurrency_from_env(),
        proxy_headers=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()
