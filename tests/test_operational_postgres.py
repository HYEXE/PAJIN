from __future__ import annotations

from hashlib import sha256

import pytest

from scripts.operational_postgres import OwnedPostgres, require_checkpoint, run


@pytest.mark.parametrize("changed", ["db.dump", "state.json"])
def test_independent_checkpoint_rejects_changed_archive_or_expected_rows(tmp_path, changed):
    (tmp_path / "db.dump").write_bytes(b"bounded archive")
    (tmp_path / "state.json").write_bytes(b"independently retained rows")
    pin = {
        "archive_sha256": sha256((tmp_path / "db.dump").read_bytes()).hexdigest(),
        "state_sha256": sha256((tmp_path / "state.json").read_bytes()).hexdigest(),
    }
    require_checkpoint(tmp_path, pin)
    (tmp_path / changed).write_bytes(b"substituted state")
    with pytest.raises(ValueError, match="independent checkpoint"):
        require_checkpoint(tmp_path, pin)


def test_runner_refuses_existing_output_before_creating_resources(tmp_path):
    with pytest.raises(FileExistsError):
        run(tmp_path)


@pytest.mark.parametrize("changed", ["owner", "identity"])
def test_resource_replacement_is_not_mutation_authority(tmp_path, monkeypatch, changed):
    import json

    import scripts.operational_postgres as module

    lab = OwnedPostgres(tmp_path)
    lab.container_id = "original"
    item = {
        "Id": "other" if changed == "identity" else "original",
        "Config": {"Labels": {module.LABEL: "other" if changed == "owner" else lab.owner}},
    }
    calls = []

    def inspect_only(args):
        calls.append(args)
        return json.dumps([item]).encode()

    monkeypatch.setattr(module, "command", inspect_only)
    with pytest.raises(ValueError, match=r"ownership|identity"):
        lab.crash_restart("unused")
    assert calls == [["docker", "container", "inspect", "original"]]
