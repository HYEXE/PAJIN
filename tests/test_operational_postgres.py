from __future__ import annotations

import io
import tarfile
from hashlib import sha256

import pytest

from scripts.operational_postgres import OwnedPostgres, require_checkpoint, run


def test_private_tls_transfer_does_not_depend_on_host_file_ownership(tmp_path, monkeypatch):
    import scripts.operational_postgres as module

    expected = {name: f"private-{name}".encode() for name in (
        "server.crt", "server.key", "pg_hba.conf"
    )}

    def tls_files(directory):
        for name, content in expected.items():
            (directory / name).write_bytes(content)
            (directory / name).chmod(0o600)

    commands = []

    def command(args, **kwargs):
        commands.append((args, kwargs))
        if args[:3] == ["docker", "run", "-d"]:
            raise RuntimeError("stop before database startup")
        return b""

    monkeypatch.setattr(module, "tls_files", tls_files)
    monkeypatch.setattr(module, "command", command)
    with pytest.raises(RuntimeError, match="stop before"):
        OwnedPostgres(tmp_path).start()
    args, options = commands[1]
    assert "-i" in args and not any("/input" in value for value in args)
    assert [args[i + 1] for i, value in enumerate(args) if value == "--cap-add"] == ["CHOWN"]
    assert args[args.index("--network") + 1] == "none"
    with tarfile.open(fileobj=io.BytesIO(options["stdin"])) as archive:
        assert archive.getnames() == list(expected)
        for member in archive.getmembers():
            assert member.uid == member.gid == 0 and member.mode == 0o600
            assert archive.extractfile(member).read() == expected[member.name]


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
