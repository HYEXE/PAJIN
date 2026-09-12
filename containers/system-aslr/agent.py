"""Fixed-file, pinned-client mTLS System agent. No shell, arbitrary paths or target writes."""

from __future__ import annotations

import base64
import json
import os
import re
import ssl
import stat
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import cast


def read_aslr() -> bytes:
    fd = os.open(
        "/proc/sys/kernel/randomize_va_space",
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
    )
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("unsupported kernel interface")
        # procfs reports zero st_size. Bound the actual reads and require two stable observations.
        content = os.read(fd, 3)
        os.lseek(fd, 0, os.SEEK_SET)
        if content not in (b"0\n", b"1\n", b"2\n") or os.read(fd, 3) != content:
            raise ValueError("unsupported or changing ASLR setting")
        return content
    finally:
        os.close(fd)


class Agent(HTTPServer):
    def __init__(self, config: dict[str, str], context: ssl.SSLContext) -> None:
        self.config, self.context = config, context
        self.consumed: set[str] = set()
        super().__init__(("0.0.0.0", 8443), Handler)

    def get_request(self) -> tuple[ssl.SSLSocket, tuple[str, int]]:
        stream, address = super().get_request()
        stream.settimeout(3)
        try:
            return self.context.wrap_socket(stream, server_side=True), address
        except BaseException:
            stream.close()
            raise


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        # Avoid paths, headers and credential material in server logs.
        return

    def finish_status(self, code: int, content: bytes = b"") -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:
        server = cast(Agent, self.server)
        peer = cast(ssl.SSLSocket, self.connection).getpeercert(binary_form=True)
        if peer is None or sha256(peer).hexdigest() != server.config["client_cert_sha256"]:
            self.finish_status(403)
            return
        request_ids = self.headers.get_all("X-PAJIN-Request-ID", [])
        if (
            self.path != "/v1/aslr"
            or len(request_ids) != 1
            or re.fullmatch(r"tool_[a-f0-9]{32}", request_ids[0]) is None
            or self.headers.get("Transfer-Encoding") is not None
            or self.headers.get("Content-Length", "0") != "0"
        ):
            self.finish_status(400)
            return
        request_id = request_ids[0]
        if request_id in server.consumed:
            self.finish_status(409)
            return
        if len(server.consumed) >= 1024:
            self.finish_status(503)
            return
        server.consumed.add(request_id)
        try:
            content = read_aslr()
        except (OSError, ValueError):
            self.finish_status(422)
            return
        result = {
            "schema": "pajin.sys-004.agent-read/v1",
            "requestId": request_id,
            "instance": server.config["instance"],
            "agentSha256": sha256(Path(__file__).read_bytes()).hexdigest(),
            "source": "/proc/sys/kernel/randomize_va_space",
            "fileSha256": sha256(content).hexdigest(),
            "fileBytes": len(content),
            "fileBase64": base64.b64encode(content).decode(),
        }
        self.finish_status(200, json.dumps(result, sort_keys=True, separators=(",", ":")).encode())


def main() -> None:
    config = json.loads(Path("/credentials/agent.json").read_text())
    if (
        os.getuid() != 65532
        or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", config["instance"]) is None
        or re.fullmatch(r"[a-f0-9]{64}", config["client_cert_sha256"]) is None
    ):
        raise ValueError("invalid agent deployment")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations("/credentials/ca.pem")
    context.load_cert_chain("/credentials/server.pem", "/credentials/server-key.pem")
    with Agent(config, context) as server:
        server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
