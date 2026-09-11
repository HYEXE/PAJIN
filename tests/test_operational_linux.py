from __future__ import annotations

import json

import pytest

import scripts.operational_linux as module

IMAGE = "sha256:" + "a" * 64


@pytest.mark.parametrize("image", ["runtime:latest", "a" * 64, "sha256:" + "g" * 64])
def test_linux_probe_requires_immutable_runtime_image(tmp_path, image):
    with pytest.raises(ValueError, match="image ID"):
        module.LinuxLab(tmp_path, image, IMAGE)


def test_linux_probe_never_reuses_existing_output(tmp_path):
    with pytest.raises(FileExistsError):
        module.run(tmp_path, runtime_image=IMAGE, worker_image=IMAGE)


@pytest.mark.parametrize("change", ["owner", "identity", "running"])
def test_cold_checkpoint_refuses_replaced_or_running_writer(tmp_path, monkeypatch, change):
    lab = module.LinuxLab(tmp_path, IMAGE, IMAGE)
    lab.containers["host"] = "original"
    calls = []

    def inspect(args):
        calls.append(args)
        return json.dumps([{
            "Id": "other" if change == "identity" else "original",
            "Config": {"Labels": {module.LABEL: "other" if change == "owner" else lab.owner}},
            "State": {"Running": change == "running", "Pid": 1 if change == "running" else 0},
        }]).encode()

    monkeypatch.setattr(module, "command", inspect)
    with pytest.raises(ValueError, match=r"ownership|identity|writers stopped"):
        lab.require_stopped()
    assert calls == [["docker", "container", "inspect", "original"]]


def test_normal_writer_stop_waits_for_exit_and_rechecks_pid(tmp_path, monkeypatch):
    lab = module.LinuxLab(tmp_path, IMAGE, IMAGE)
    calls = []

    def command(args):
        calls.append(args)
        if args[1] == "stop":
            return b"original\n"
        running = len(calls) == 1
        return json.dumps([{
            "Id": "original", "Config": {"Labels": {module.LABEL: lab.owner}},
            "State": {"Running": running, "Pid": 123 if running else 0},
        }]).encode()

    monkeypatch.setattr(module, "command", command)
    lab.stop("original")
    assert calls == [
        ["docker", "container", "inspect", "original"],
        ["docker", "stop", "--time", "3", "original"],
        ["docker", "container", "inspect", "original"],
    ]


@pytest.mark.parametrize("value", [b"0\n", b"998\n", b"31415\n"])
def test_fixture_reads_daemon_socket_group_without_changing_host_permissions(
    tmp_path, monkeypatch, value
):
    lab = module.LinuxLab(tmp_path, IMAGE, IMAGE)
    calls = []
    monkeypatch.setattr(module, "command", lambda args: calls.append(args) or value)
    assert lab.socket_group() == value.decode().strip()
    args = calls[0]
    assert args[:3] == ["docker", "run", "--rm"]
    assert "/var/run/docker.sock:/var/run/docker.sock:ro" in args
    assert args[args.index("--network") + 1] == "none"
    assert args[args.index("--cap-drop") + 1] == "ALL"
    assert "--cap-add" not in args and "chmod" not in args[-1]


@pytest.mark.parametrize("value", [b"", b"-1", b"4294967295", b"0\n999", b"private text"])
def test_fixture_socket_group_has_no_default_on_invalid_observation(tmp_path, monkeypatch, value):
    lab = module.LinuxLab(tmp_path, IMAGE, IMAGE)
    monkeypatch.setattr(module, "command", lambda args: value)
    with pytest.raises(ValueError, match="numeric GID"):
        lab.socket_group()


def test_both_trusted_controller_paths_use_observed_nonzero_group(tmp_path, monkeypatch):
    from scripts import hybrid_operations_rehearsal as hybrid
    from scripts.operational_postgres import OwnedPostgres

    lab = module.LinuxLab(tmp_path, IMAGE, IMAGE)
    lab.volumes = {name: name for name in ("state-source", "control-source", "evidence")}
    lab.envs["source"] = tmp_path / "fixture.env"
    pg = OwnedPostgres(tmp_path)
    pg.container_id = "owned-postgres"
    calls = []
    monkeypatch.setattr(lab, "socket_group", lambda: "31415")
    monkeypatch.setattr(lab, "inspect", lambda *args: {
        "State": {"Running": True}, "Image": IMAGE,
    })
    monkeypatch.setattr(module, "command", lambda args: calls.append(args) or b"owned-controller")
    monkeypatch.setattr(hybrid, "command", lambda args: calls.append(args) or b"owned-controller")
    lab.start(pg, role="source", name="source", init_process=True)
    rehearsal = hybrid.Rehearsal(tmp_path, IMAGE, IMAGE)
    rehearsal.labs.append(lab)
    rehearsal.controller(lab, pg, "source")
    assert len(calls) == 2
    assert all(args[args.index("--group-add") + 1] == "31415" for args in calls)
