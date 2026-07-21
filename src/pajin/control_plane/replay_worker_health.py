"""Container health check for the dedicated Replay Worker status file."""

from __future__ import annotations

import math
import os
from datetime import timedelta
from pathlib import Path

from pajin.control_plane.daemon_runtime import validate_health_timestamp
from pajin.control_plane.replay_worker import ReplayWorkerStatus
from pajin.control_plane.status_file import (
    default_replay_worker_status_path,
    read_status_file,
)

_MAX_HEALTH_AGE_SECONDS = 300.0


def _max_age_seconds() -> float:
    raw = os.environ.get("PAJIN_REPLAY_HEALTH_MAX_AGE_SECONDS", "30")
    try:
        value = float(raw)
    except ValueError as exc:
        raise SystemExit("Replay Worker health age is not numeric") from exc
    if not math.isfinite(value) or not 0 < value <= _MAX_HEALTH_AGE_SECONDS:
        raise SystemExit("Replay Worker health age must be between 0 and 300 seconds")
    return value


def main() -> None:
    path = Path(
        os.environ.get(
            "PAJIN_REPLAY_STATUS_PATH",
            str(default_replay_worker_status_path()),
        )
    )
    try:
        status = ReplayWorkerStatus.model_validate_json(
            read_status_file(path, owner_label="Replay Worker")
        )
    except (OSError, ValueError) as exc:
        raise SystemExit("Replay Worker status is unavailable or invalid") from exc
    expected_worker_id = os.environ.get("PAJIN_REPLAY_WORKER_ID")
    expected_profile = os.environ.get("PAJIN_REPLAY_EXECUTOR_PROFILE")
    if (
        not expected_worker_id
        or status.worker_id != expected_worker_id
        or not expected_profile
        or status.executor_profile != expected_profile
    ):
        raise SystemExit("Replay Worker status identity does not match configuration")
    if status.state not in {"starting", "idle", "running", "finalizing"}:
        raise SystemExit(f"Replay Worker is not ready: {status.state}")
    validate_health_timestamp(
        status.last_contact_at,
        owner="Replay Worker",
        max_age=timedelta(seconds=_max_age_seconds()),
    )


if __name__ == "__main__":
    main()
