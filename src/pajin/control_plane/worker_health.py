"""Container health check for the PAJIN Worker daemon status file."""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

from pajin.control_plane.daemon_runtime import validate_health_timestamp
from pajin.control_plane.status_file import (
    default_worker_status_path,
    read_status_file,
)
from pajin.control_plane.worker import WorkerDaemonStatus

_MAX_AGE = timedelta(seconds=30)


def main() -> None:
    path = Path(os.environ.get("PAJIN_DAEMON_STATUS_PATH", str(default_worker_status_path())))
    try:
        status = WorkerDaemonStatus.model_validate_json(
            read_status_file(path, owner_label="Worker")
        )
    except (OSError, ValueError) as exc:
        raise SystemExit("Worker daemon status is unavailable or invalid") from exc
    expected_worker_id = os.environ.get("PAJIN_WORKER_ID")
    if not expected_worker_id or status.worker_id != expected_worker_id:
        raise SystemExit("Worker daemon status identity does not match configuration")
    if status.state not in {"starting", "idle", "running"}:
        raise SystemExit(f"Worker daemon is not ready: {status.state}")
    validate_health_timestamp(
        status.last_contact_at,
        owner="Worker daemon",
        max_age=_MAX_AGE,
    )


if __name__ == "__main__":
    main()
