"""Deterministic synthetic target for the PAJIN CTF Web local lab."""

from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

CHALLENGE_ID = "web-backup-lab"
FLAG = "PAJIN{fixed_web_backup_lab}"
BACKUP_PATH = "/backup/config.json.bak"


def read_backup(*, profile: str) -> tuple[int, dict[str, Any]]:
    if profile == "vulnerable":
        return HTTPStatus.OK, {
            "challengeId": CHALLENGE_ID,
            "synthetic": True,
            "configuration": "training-only",
            "flag": FLAG,
        }
    if profile == "hardened":
        return HTTPStatus.NOT_FOUND, {
            "challengeId": CHALLENGE_ID,
            "synthetic": True,
            "error": "backup artifact not deployed",
        }
    raise ValueError("unsupported PAJIN_CTF_WEB_LAB_PROFILE")


class Handler(BaseHTTPRequestHandler):
    server_version = "PAJINCTFWebLab/1.0"

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/health" and not parsed.query:
            self._json(HTTPStatus.OK, {"status": "healthy", "synthetic": True})
            return
        if parsed.path != BACKUP_PATH or parsed.query:
            self._json(
                HTTPStatus.NOT_FOUND,
                {"challengeId": CHALLENGE_ID, "synthetic": True, "error": "not found"},
            )
            return
        profile = os.environ.get("PAJIN_CTF_WEB_LAB_PROFILE", "vulnerable")
        try:
            status, payload = read_backup(profile=profile)
            self._json(status, payload)
        except ValueError as exc:
            self._json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"challengeId": CHALLENGE_ID, "synthetic": True, "error": str(exc)},
            )

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
