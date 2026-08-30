from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml
from conftest import (
    _canonical_ci_nodeid,
    _ci_shard_for_nodeid,
    _validate_ci_shard_options,
    pytest_collection_modifyitems,
)

_WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml"


@dataclass(frozen=True)
class _Item:
    nodeid: str


class _DeselectHook:
    def __init__(self) -> None:
        self.calls: list[list[_Item]] = []

    def pytest_deselected(self, *, items: list[_Item]) -> None:
        self.calls.append(list(items))


class _Config:
    def __init__(self, shard_index: int | None, shard_total: int | None) -> None:
        self._options = {
            "ci_shard_index": shard_index,
            "ci_shard_total": shard_total,
        }
        self.hook = _DeselectHook()

    def getoption(self, name: str) -> int | None:
        return self._options[name]


def _workflow() -> dict[str, object]:
    value = yaml.load(_WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(value, dict)
    return value


def _named_steps(job: dict[str, object]) -> dict[str, dict[str, Any]]:
    steps = job["steps"]
    assert isinstance(steps, list)
    return {
        step["name"]: step
        for step in steps
        if isinstance(step, dict) and isinstance(step.get("name"), str)
    }


def test_ci_shard_assignment_is_deterministic_and_uses_the_full_canonical_nodeid() -> None:
    nodeid = "tests/test_example.py::test_case[param::identifier]"

    assert _ci_shard_for_nodeid(nodeid, 8) == 3
    assert _ci_shard_for_nodeid(nodeid, 8) == _ci_shard_for_nodeid(nodeid, 8)
    assert _ci_shard_for_nodeid("tests/test_example.py::test_case[other]", 8) == 5


def test_ci_shard_canonicalizes_only_the_nodeid_path() -> None:
    windows_nodeid = r"tests\nested\test_example.py::test_case[param\value::suffix]"

    assert _canonical_ci_nodeid(windows_nodeid) == (
        r"tests/nested/test_example.py::test_case[param\value::suffix]"
    )
    assert _ci_shard_for_nodeid(windows_nodeid, 8) == _ci_shard_for_nodeid(
        r"tests/nested/test_example.py::test_case[param\value::suffix]",
        8,
    )


def test_eight_ci_shards_are_disjoint_and_cover_every_collected_item() -> None:
    all_items = [
        _Item(f"tests/test_{number:03}.py::test_case[param-{number}]") for number in range(256)
    ]
    selected_by_shard: list[set[str]] = []

    for shard_index in range(8):
        items = list(all_items)
        config = _Config(shard_index, 8)

        pytest_collection_modifyitems(config, items)

        selected = {item.nodeid for item in items}
        selected_by_shard.append(selected)
        assert config.hook.calls == [[item for item in all_items if item.nodeid not in selected]]

    assert set.union(*selected_by_shard) == {item.nodeid for item in all_items}
    for shard_index, selected in enumerate(selected_by_shard):
        assert selected
        assert all(
            selected.isdisjoint(other)
            for other_index, other in enumerate(selected_by_shard)
            if shard_index != other_index
        )


@pytest.mark.parametrize(
    ("shard_index", "shard_total"),
    [
        (None, 8),
        (0, None),
        (0, 0),
        (0, -1),
        (-1, 8),
        (8, 8),
    ],
)
def test_invalid_or_incomplete_ci_shard_options_raise_usage_error(
    shard_index: int | None,
    shard_total: int | None,
) -> None:
    with pytest.raises(pytest.UsageError):
        _validate_ci_shard_options(shard_index, shard_total)


def test_default_ci_shard_options_are_a_no_op() -> None:
    items = [_Item("tests/test_example.py::test_case")]
    original = list(items)
    config = _Config(None, None)

    pytest_collection_modifyitems(config, items)

    assert items == original
    assert config.hook.calls == []


def test_main_ci_workflow_separates_quality_from_eight_test_shards() -> None:
    workflow = _workflow()
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    assert set(jobs) == {"quality", "tests"}

    quality = jobs["quality"]
    tests = jobs["tests"]
    assert isinstance(quality, dict)
    assert isinstance(tests, dict)
    assert quality["runs-on"] == "ubuntu-24.04"
    assert quality["timeout-minutes"] == "60"
    assert tests["runs-on"] == "ubuntu-24.04"
    assert tests["timeout-minutes"] == "90"
    assert tests["strategy"] == {
        "fail-fast": "false",
        "matrix": {"shard": [str(shard) for shard in range(8)]},
    }

    expected_common_steps = {
        "Check out repository",
        "Set up Python",
        "Set up uv",
        "Install locked dependencies",
    }
    quality_steps = _named_steps(quality)
    test_steps = _named_steps(tests)
    assert set(quality_steps) == expected_common_steps | {"Lint", "Type check"}
    assert set(test_steps) == expected_common_steps | {"Test"}

    for steps in (quality_steps, test_steps):
        assert steps["Check out repository"]["uses"] == (
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
        )
        assert steps["Set up Python"]["uses"] == (
            "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
        )
        assert steps["Set up Python"]["with"] == {"python-version-file": ".python-version"}
        assert steps["Set up uv"]["uses"] == (
            "astral-sh/setup-uv@11f9893b081a58869d3b5fccaea48c9e9e46f990"
        )
        assert steps["Set up uv"]["with"] == {
            "version": "0.11.28",
            "enable-cache": "true",
            "cache-dependency-glob": "uv.lock",
        }
        assert steps["Install locked dependencies"]["run"] == "uv sync --locked --all-extras"

    assert quality_steps["Lint"]["run"] == "uv run --locked ruff check src tests containers"
    assert quality_steps["Type check"]["run"] == "uv run --locked mypy src"
    assert test_steps["Test"]["run"] == (
        "uv run --locked pytest --ci-shard-index ${{ matrix.shard }} "
        "--ci-shard-total 8 --durations=25"
    )
