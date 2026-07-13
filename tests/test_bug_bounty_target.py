import importlib.util
from http import HTTPStatus
from pathlib import Path
from types import ModuleType


def _load_target() -> ModuleType:
    path = Path("containers/bug-bounty-target/target.py")
    spec = importlib.util.spec_from_file_location("pajin_bug_bounty_lab_target", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_vulnerable_lab_exposes_only_the_fixed_synthetic_boolean_signal() -> None:
    target = _load_target()

    baseline_status, baseline = target.lookup("1", profile="vulnerable")
    control_status, control = target.lookup(target.FALSE_CONTROL, profile="vulnerable")
    probe_status, probe = target.lookup(target.BOOLEAN_PROBE, profile="vulnerable")

    assert baseline_status is HTTPStatus.OK
    assert baseline["recordCount"] == 1
    assert control_status is HTTPStatus.OK
    assert control["recordCount"] == 0
    assert probe_status is HTTPStatus.OK
    assert probe["recordCount"] == 2
    assert all(item["synthetic"] is True for item in (baseline, control, probe))
    assert {record["handle"] for record in probe["records"]} == {"lab-alpha", "lab-beta"}


def test_hardened_lab_rejects_non_numeric_probe_and_preserves_baseline() -> None:
    target = _load_target()

    baseline_status, baseline = target.lookup("1", profile="hardened")
    probe_status, probe = target.lookup(target.BOOLEAN_PROBE, profile="hardened")

    assert baseline_status is HTTPStatus.OK
    assert baseline["recordCount"] == 1
    assert probe_status is HTTPStatus.BAD_REQUEST
    assert probe["recordCount"] == 0
    assert probe["synthetic"] is True
