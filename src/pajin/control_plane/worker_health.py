"""Container health check for the PAJIN Worker daemon status file."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pajin.control_plane.worker import WorkerDaemonStatus


def main() -> None:
    path = Path(os.environ.get("PAJIN_DAEMON_STATUS_PATH", "/tmp/pajin-worker-status.json"))
    status = WorkerDaemonStatus.model_validate_json(path.read_text(encoding="utf-8"))
    if status.state not in {"starting", "idle", "running"}:
        raise SystemExit(f"Worker daemon is not ready: {status.state}")
    last_contact = status.last_contact_at
    if last_contact.tzinfo is None:
        last_contact = last_contact.replace(tzinfo=UTC)
    if datetime.now(UTC) - last_contact > timedelta(seconds=30):
        raise SystemExit("Worker daemon status is stale")


if __name__ == "__main__":
    main()
