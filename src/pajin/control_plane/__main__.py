"""Run the PAJIN Control Plane API server."""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    uvicorn.run(
        "pajin.control_plane.api:create_app",
        factory=True,
        host=os.environ.get("PAJIN_CP_HOST", "127.0.0.1"),
        port=int(os.environ.get("PAJIN_CP_PORT", "8090")),
        proxy_headers=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()
