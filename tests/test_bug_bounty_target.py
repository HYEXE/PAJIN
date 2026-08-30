import importlib.util
from http import HTTPStatus
from pathlib import Path
from types import ModuleType

import pytest


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


def test_target_access_log_is_canonical_query_free_jsonl(
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _load_target()
    handler = object.__new__(target.Handler)
    handler.path = "/v1/users/lookup?id=do-not-log"
    handler.command = "GET"

    handler.log_request(200)

    assert capsys.readouterr().out == (
        '{"event":"pajin.synthetic-http-response","method":"GET",'
        '"path":"/v1/users/lookup","status":200}\n'
    )


def test_target_access_log_ignores_preparse_error_without_path(
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _load_target()
    handler = object.__new__(target.Handler)
    handler.command = None

    handler.log_request(400)

    assert capsys.readouterr().out == ""
