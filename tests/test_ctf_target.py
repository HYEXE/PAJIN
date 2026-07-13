import importlib.util
from http import HTTPStatus
from pathlib import Path
from types import ModuleType


def _load_target() -> ModuleType:
    path = Path("containers/ctf-web-target/target.py")
    spec = importlib.util.spec_from_file_location("pajin_ctf_web_lab_target", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_vulnerable_ctf_web_lab_exposes_only_the_synthetic_flag_artifact() -> None:
    target = _load_target()

    status, payload = target.read_backup(profile="vulnerable")

    assert status is HTTPStatus.OK
    assert payload["challengeId"] == "web-backup-lab"
    assert payload["synthetic"] is True
    assert payload["flag"] == "PAJIN{fixed_web_backup_lab}"


def test_hardened_ctf_web_lab_removes_the_backup_artifact() -> None:
    target = _load_target()

    status, payload = target.read_backup(profile="hardened")

    assert status is HTTPStatus.NOT_FOUND
    assert payload["synthetic"] is True
    assert "flag" not in payload
