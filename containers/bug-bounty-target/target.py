"""Deterministic synthetic API for the PAJIN Bug Bounty local lab."""

from __future__ import annotations

import json
import os
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

SYNTHETIC_USERS = [
    {"id": 1, "handle": "lab-alpha"},
    {"id": 2, "handle": "lab-beta"},
]
FALSE_CONTROL = "1' AND '1'='2"
BOOLEAN_PROBE = "1' OR '1'='1"


def lookup(identifier: str, *, profile: str) -> tuple[int, dict[str, Any]]:
    if profile not in {"vulnerable", "hardened"}:
        raise ValueError("unsupported PAJIN_BUG_BOUNTY_LAB_PROFILE")
    if profile == "hardened" and not identifier.isascii():
        return HTTPStatus.BAD_REQUEST, _response([], "rejected-non-ascii")
    if profile == "hardened" and not identifier.isdigit():
        return HTTPStatus.BAD_REQUEST, _response([], "rejected-invalid-identifier")

    if identifier == BOOLEAN_PROBE and profile == "vulnerable":
        return HTTPStatus.OK, _response(SYNTHETIC_USERS, "unsafe-boolean-expression")
    if identifier == FALSE_CONTROL:
        return HTTPStatus.OK, _response([], "false-control")
    if identifier.isdigit():
        user_id = int(identifier)
        records = [user for user in SYNTHETIC_USERS if user["id"] == user_id]
        return HTTPStatus.OK, _response(records, "parameterized-identifier")
    return HTTPStatus.OK, _response([], "unmatched-input")


def _response(records: list[dict[str, Any]], query_mode: str) -> dict[str, Any]:
    return {
        "synthetic": True,
        "recordCount": len(records),
        "records": records,
        "queryMode": query_mode,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "PAJINBugBountyLab/1.0"

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/health":
            self._json(HTTPStatus.OK, {"status": "healthy", "synthetic": True})
            return
        if parsed.path != "/v1/users/lookup":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found", "synthetic": True})
            return
        if len(self.path) > 512:
            self._json(
                HTTPStatus.REQUEST_URI_TOO_LONG,
                {"error": "request URI too long", "synthetic": True, "recordCount": 0},
            )
            return
        identifiers = parse_qs(parsed.query, keep_blank_values=True).get("id", [])
        if len(identifiers) != 1:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": "exactly one id is required", "synthetic": True, "recordCount": 0},
            )
            return
        profile = os.environ.get("PAJIN_BUG_BOUNTY_LAB_PROFILE", "vulnerable")
        try:
            status, response = lookup(identifiers[0], profile=profile)
            self._json(status, response)
        except ValueError:
            self._json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "lab configuration is invalid", "synthetic": True, "recordCount": 0},
            )

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        del size
        request_path = getattr(self, "path", None)
        if not isinstance(request_path, str):
            return
        path = urlsplit(request_path).path
        event = {
            "event": "pajin.synthetic-http-response",
            "method": self.command,
            "path": path,
            "status": int(code) if isinstance(code, int) else code,
        }
        sys.stdout.write(json.dumps(event, separators=(",", ":"), sort_keys=True) + "\n")
        sys.stdout.flush()

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
