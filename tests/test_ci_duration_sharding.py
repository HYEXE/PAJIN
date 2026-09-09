from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import pytest_collection_modifyitems
from test_main_ci_sharding import _Config, _Item

from scripts.ci_sharding import assign_duration_shards, load_durations, main, write_durations


def test_measured_shards_spread_long_cases_and_ignore_collection_order() -> None:
    durations = {
        f"tests/test_cost.py::test_case[{index}]": duration
        for index, duration in enumerate([100, 99, 98, 3, 2, 1])
    }
    placements = assign_duration_shards(durations, durations, 3)
    assert placements == assign_duration_shards(reversed(durations), durations, 3)
    assert len({placements[nodeid] for nodeid in list(durations)[:3]}) == 3
    costs = [
        sum(seconds for nodeid, seconds in durations.items() if placements[nodeid] == index)
        for index in range(3)
    ]
    assert max(costs) == 101


def test_measured_shards_cover_known_unknown_and_skipped_tests_once(tmp_path: Path) -> None:
    items = [_Item(f"tests/test_cost.py::test_case[{index}]") for index in range(100)]
    path = tmp_path / "durations.json"
    write_durations(path, {item.nodeid: float(index) for index, item in enumerate(items[:50])}, {})
    selected = []
    for shard in range(24):
        current = list(items)
        pytest_collection_modifyitems(_Config(shard, 24, str(path)), current)
        selected.extend(item.nodeid for item in current)
    assert sorted(selected) == sorted(item.nodeid for item in items)
    assert len(set(selected)) == len(items)


@pytest.mark.parametrize("value", [True, -1, "2", float("nan"), float("inf"), 86_401, 10**400])
def test_invalid_duration_measurements_fail_configuration(tmp_path: Path, value: object) -> None:
    path = tmp_path / "durations.json"
    path.write_text(json.dumps({"version": 1, "durations": {"tests/a.py::test_a": value}}))
    with pytest.raises(ValueError, match="measurement"):
        load_durations(path)
    with pytest.raises(pytest.UsageError, match="duration profile"):
        pytest_collection_modifyitems(_Config(0, 2, str(path)), [_Item("tests/a.py::test_a")])


@pytest.mark.parametrize(
    "raw",
    [
        '{"version":true,"durations":{}}',
        '{"version":1,"durations":{"a":1,"a":2}}',
        '{"version":1,"durations":{"tests\\\\a.py::test_a":1}}',
    ],
)
def test_profiles_reject_ambiguous_identity_or_version(tmp_path: Path, raw: str) -> None:
    path = tmp_path / "durations.json"
    path.write_text(raw)
    with pytest.raises(ValueError):
        load_durations(path)


def test_requested_profile_is_never_silently_replaced_with_hash_assignment(tmp_path: Path) -> None:
    with pytest.raises(pytest.UsageError):
        pytest_collection_modifyitems(_Config(0, 2, str(tmp_path / "missing")), [_Item("a")])
    with pytest.raises(pytest.UsageError, match="complete shard"):
        pytest_collection_modifyitems(_Config(None, None, str(tmp_path / "missing")), [_Item("a")])
    with pytest.raises(ValueError, match="unique"):
        assign_duration_shards(["a", "a"], {}, 2)


def test_profile_round_trip_retains_long_adversarial_parameter_ids(tmp_path: Path) -> None:
    nodeid = "tests/test_input.py::test_limit[" + "x" * 65_537 + "]"
    path = tmp_path / "duration.json"
    write_durations(path, {nodeid: 0.1}, {})
    durations = load_durations(path)
    assert durations == {nodeid: 0.1}
    assert assign_duration_shards([nodeid], durations, 24) == {nodeid: 0}


def test_profile_merge_rejects_overlapping_measurements(tmp_path: Path, monkeypatch) -> None:
    first, second, output = [tmp_path / name for name in ("a.json", "b.json", "output.json")]
    write_durations(first, {"a": 1}, {})
    write_durations(second, {"a": 2}, {})
    monkeypatch.setattr(
        sys, "argv", ["ci_sharding", str(first), str(second), "--output", str(output)]
    )
    with pytest.raises(SystemExit) as failure:
        main()
    assert failure.value.code == 2
    assert not output.exists()
    write_durations(second, {"b": 2}, {})
    main()
    assert load_durations(output) == {"a": 1, "b": 2}


def test_real_pytest_reports_complete_duration_without_changing_test_status(tmp_path: Path) -> None:
    output = tmp_path / "duration.json"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests/test_security_domain_taxonomy.py",
            "-k",
            "test_registered_taxonomy_is_exact_content_addressed_classification_only",
            "--ci-duration-output",
            str(output),
        ],
        cwd=Path(__file__).parents[1],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    durations = load_durations(output)
    assert len(durations) == 1
    assert next(iter(durations.values())) > 0
    metadata = json.loads(output.read_text())["metadata"]
    assert metadata["exitStatus"] == 0
    assert metadata["selectedTests"] == metadata["reportedTests"] == 1
    assert metadata["schedulingHintOnly"] is True
