from hashlib import sha256
from pathlib import Path

import pytest

from pajin.domain.manifest import load_manifest
from pajin.domain.models import CampaignManifest
from scripts.ci_sharding import (
    DurationRecorder,
    assign_duration_shards,
    canonical_nodeid,
    load_durations,
)


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("CI sharding")
    group.addoption(
        "--ci-shard-index",
        action="store",
        type=int,
        default=None,
        dest="ci_shard_index",
        help="zero-based CI shard index; requires --ci-shard-total",
    )
    group.addoption(
        "--ci-shard-total",
        action="store",
        type=int,
        default=None,
        dest="ci_shard_total",
        help="total number of CI shards; requires --ci-shard-index",
    )
    group.addoption(
        "--ci-shard-durations",
        default=None,
        help="measured duration profile for deterministic balanced shard placement",
    )
    group.addoption(
        "--ci-duration-output",
        default=None,
        help="write setup/call/teardown durations as scheduling hints",
    )


def _canonical_ci_nodeid(nodeid: str) -> str:
    return canonical_nodeid(nodeid)


def pytest_configure(config: pytest.Config) -> None:
    if output := config.getoption("ci_duration_output"):
        config.pluginmanager.register(
            DurationRecorder(Path(output), config.rootpath), "pajin-duration-recorder"
        )


def _ci_shard_for_nodeid(nodeid: str, shard_total: int) -> int:
    if shard_total <= 0:
        raise ValueError("shard_total must be positive")
    digest = sha256(_canonical_ci_nodeid(nodeid).encode("utf-8")).digest()
    return int.from_bytes(digest, byteorder="big") % shard_total


def _validate_ci_shard_options(
    shard_index: int | None,
    shard_total: int | None,
) -> tuple[int, int] | None:
    if shard_index is None and shard_total is None:
        return None
    if shard_index is None or shard_total is None:
        raise pytest.UsageError("--ci-shard-index and --ci-shard-total must be provided together")
    if shard_total <= 0:
        raise pytest.UsageError("--ci-shard-total must be greater than zero")
    if shard_index < 0 or shard_index >= shard_total:
        raise pytest.UsageError(
            "--ci-shard-index must be greater than or equal to zero and less than --ci-shard-total"
        )
    return shard_index, shard_total


def _configured_ci_shard(config: pytest.Config) -> tuple[int, int] | None:
    return _validate_ci_shard_options(
        config.getoption("ci_shard_index"),
        config.getoption("ci_shard_total"),
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    shard = _configured_ci_shard(config)
    duration_path = config.getoption("ci_shard_durations")
    if shard is None:
        if duration_path:
            raise pytest.UsageError("--ci-shard-durations requires a complete shard selection")
        return

    shard_index, shard_total = shard
    assignments: dict[str, int] | None = None
    if duration_path:
        try:
            assignments = assign_duration_shards(
                (item.nodeid for item in items),
                load_durations(Path(duration_path)),
                shard_total,
            )
        except (OSError, ValueError) as exc:
            raise pytest.UsageError("CI duration profile cannot be loaded or assigned") from exc
    selected: list[pytest.Item] = []
    deselected: list[pytest.Item] = []
    for item in items:
        destination = (
            assignments[_canonical_ci_nodeid(item.nodeid)]
            if assignments is not None
            else _ci_shard_for_nodeid(item.nodeid, shard_total)
        )
        (selected if destination == shard_index else deselected).append(item)

    items[:] = selected
    if deselected:
        config.hook.pytest_deselected(items=deselected)


@pytest.fixture
def sample_campaign() -> CampaignManifest:
    return load_manifest(Path("examples/ai-redteam.yaml"))
