from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pajin.control_plane import replay_worker_health, worker_health
from pajin.control_plane.daemon_runtime import float_env, integer_env, required_env
from pajin.control_plane.replay_worker import ReplayWorkerConfig, ReplayWorkerStatus
from pajin.control_plane.worker import WorkerDaemonConfig, WorkerDaemonStatus


def _write(path: Path, payload: str) -> None:
    path.write_text(payload, encoding="utf-8")


def test_worker_health_binds_identity_and_rejects_future_timestamp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "worker-status.json"
    monkeypatch.setenv("PAJIN_DAEMON_STATUS_PATH", str(path))
    monkeypatch.setenv("PAJIN_WORKER_ID", "worker-expected")
    status = WorkerDaemonStatus(
        worker_id="worker-expected",
        state="idle",
        last_contact_at=datetime.now(UTC),
    )
    _write(path, status.model_dump_json())
    worker_health.main()

    _write(
        path,
        status.model_copy(
            update={"last_contact_at": datetime.now(UTC) + timedelta(days=365)}
        ).model_dump_json(),
    )
    with pytest.raises(SystemExit, match="future"):
        worker_health.main()

    _write(
        path,
        status.model_copy(update={"worker_id": "worker-other"}).model_dump_json(),
    )
    with pytest.raises(SystemExit, match="identity"):
        worker_health.main()


def test_replay_worker_health_binds_identity_profile_and_age_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "replay-worker-status.json"
    monkeypatch.setenv("PAJIN_REPLAY_STATUS_PATH", str(path))
    monkeypatch.setenv("PAJIN_REPLAY_WORKER_ID", "replay-worker-expected")
    monkeypatch.setenv("PAJIN_REPLAY_EXECUTOR_PROFILE", "kisa-exact-v1")
    status = ReplayWorkerStatus(
        worker_id="replay-worker-expected",
        executor_profile="kisa-exact-v1",
        state="idle",
        last_contact_at=datetime.now(UTC),
    )
    _write(path, status.model_dump_json())
    replay_worker_health.main()

    _write(
        path,
        status.model_copy(
            update={"last_contact_at": datetime.now(UTC) + timedelta(days=365)}
        ).model_dump_json(),
    )
    with pytest.raises(SystemExit, match="future"):
        replay_worker_health.main()

    _write(
        path,
        status.model_copy(update={"worker_id": "replay-worker-other"}).model_dump_json(),
    )
    with pytest.raises(SystemExit, match="identity"):
        replay_worker_health.main()

    _write(path, status.model_dump_json())
    monkeypatch.setenv("PAJIN_REPLAY_EXECUTOR_PROFILE", "wrong-profile")
    with pytest.raises(SystemExit, match="identity"):
        replay_worker_health.main()

    monkeypatch.setenv("PAJIN_REPLAY_EXECUTOR_PROFILE", "kisa-exact-v1")
    monkeypatch.setenv("PAJIN_REPLAY_HEALTH_MAX_AGE_SECONDS", "1e308")
    with pytest.raises(SystemExit, match="between 0 and 300"):
        replay_worker_health.main()


def test_worker_health_bounds_status_bytes_and_rejects_symlinks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker_path = tmp_path / "worker-status.json"
    replay_path = tmp_path / "replay-status.json"
    oversized = "x" * (64 * 1024 + 1)
    _write(worker_path, oversized)
    _write(replay_path, oversized)
    monkeypatch.setenv("PAJIN_DAEMON_STATUS_PATH", str(worker_path))
    monkeypatch.setenv("PAJIN_REPLAY_STATUS_PATH", str(replay_path))

    with pytest.raises(SystemExit, match="unavailable or invalid"):
        worker_health.main()
    with pytest.raises(SystemExit, match="unavailable or invalid"):
        replay_worker_health.main()

    victim = tmp_path / "victim.json"
    _write(victim, "{}")
    worker_path.unlink()
    replay_path.unlink()
    worker_path.symlink_to(victim)
    replay_path.symlink_to(victim)

    with pytest.raises(SystemExit, match="unavailable or invalid"):
        worker_health.main()
    with pytest.raises(SystemExit, match="unavailable or invalid"):
        replay_worker_health.main()


@pytest.mark.parametrize(
    "overrides",
    [
        {"retry_base_seconds": 2, "retry_max_seconds": 1},
        {"cancellation_grace_seconds": 5, "cancellation_force_seconds": 5},
    ],
)
def test_worker_daemon_configs_reject_inverted_retry_and_cleanup_bounds(
    overrides: dict[str, float],
) -> None:
    with pytest.raises(ValueError):
        WorkerDaemonConfig(worker_id="worker-bounds", kinds=["campaign"], **overrides)
    with pytest.raises(ValueError):
        ReplayWorkerConfig(worker_id="replay-worker-bounds", **overrides)


@pytest.mark.parametrize("raw", [" 5", "+5", "05", "5.0", "nan", "inf"])
def test_daemon_integer_environment_is_canonical(
    raw: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAJIN_TEST_INTEGER", raw)
    with pytest.raises(RuntimeError, match=r"invalid|canonical integer"):
        integer_env("PAJIN_TEST_INTEGER", 5, owner="Test Worker")


@pytest.mark.parametrize("raw", ["nan", "inf", "-inf", " 5"])
def test_daemon_float_environment_is_finite_and_whitespace_exact(
    raw: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAJIN_TEST_FLOAT", raw)
    with pytest.raises(RuntimeError):
        float_env("PAJIN_TEST_FLOAT", 5, owner="Test Worker")


@pytest.mark.parametrize("raw", ["", " ", "token\n", " token"])
def test_daemon_required_environment_rejects_ambiguous_values(
    raw: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAJIN_TEST_REQUIRED", raw)
    with pytest.raises(RuntimeError, match="missing or invalid"):
        required_env("PAJIN_TEST_REQUIRED", owner="Test Worker")
