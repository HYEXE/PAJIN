"""Case-ID-only passive TCP banner emitter for the NET-002 fixture Target."""

from __future__ import annotations

import json
import socket
import sys
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Final

LISTEN_HOST: Final = "0.0.0.0"
LISTEN_PORT: Final = 18_080
MAX_PENDING_CONNECTIONS: Final = 8

CASE_BANNERS: Final[Mapping[str, bytes]] = MappingProxyType(
    {
        "network-fixture:ftp-known-positive": b"220 PAJIN FTP service ready\r\n",
        "network-fixture:imap-known-positive": b"* OK PAJIN IMAP4rev1 service ready\r\n",
        "network-fixture:pop3-known-positive": b"+OK PAJIN POP3 service ready\r\n",
        "network-fixture:smtp-known-positive": b"220 PAJIN ESMTP service ready\r\n",
        "network-fixture:ssh-known-positive": b"SSH-2.0-PAJINFixture\r\n",
        "network-fixture:unknown-negative-control": b"PAJIN UNKNOWN PROTOCOL\r\n",
    }
)


def selected_case(argv: Sequence[str]) -> tuple[str, bytes]:
    """Accept exactly one code-owned case ID and no caller-selected configuration."""

    if len(argv) != 2:
        raise ValueError("the Network fixture requires exactly one case ID")
    case_id = argv[1]
    try:
        return case_id, CASE_BANNERS[case_id]
    except KeyError as exc:
        raise ValueError("the Network fixture case ID is not registered") from exc


def _emit_event(event: str, *, case_id: str, sequence: int | None = None) -> None:
    payload: dict[str, object] = {
        "event": event,
        "caseId": case_id,
        "port": LISTEN_PORT,
    }
    if sequence is not None:
        payload["sequence"] = sequence
    sys.stdout.write(
        json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n"
    )
    sys.stdout.flush()


def serve(case_id: str, banner: bytes) -> None:
    """Send the fixed banner immediately after accept and never read client bytes."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((LISTEN_HOST, LISTEN_PORT))
        listener.listen(MAX_PENDING_CONNECTIONS)
        _emit_event("ready", case_id=case_id)
        sequence = 0
        while True:
            connection, _peer = listener.accept()
            with connection:
                connection.sendall(banner)
            sequence += 1
            _emit_event("banner-emitted", case_id=case_id, sequence=sequence)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        case_id, banner = selected_case(sys.argv if argv is None else argv)
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        return 2
    serve(case_id, banner)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
