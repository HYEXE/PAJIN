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
