"""A failed measurement preserves diagnostics without claiming a complete comparison."""

import json
import subprocess
from pathlib import Path

import pytest

from scripts import profile_graph_history_readers as profiler


def test_child_failure_preserves_partial_evidence_and_releases_successful_copies(
    tmp_path, monkeypatch, capsys
):
    outputs = []

    def run(command, **kwargs):
        output = Path(command[command.index("--output") + 1])
        output.mkdir()
        (output / "graph.db").write_bytes(b"owned synthetic fixture copy")
        outputs.append(output)
        failed = len(outputs) == 2
        return subprocess.CompletedProcess(
            command,
            1 if failed else 0,
            stdout=b"" if failed else b'{"sample": "completed"}',
            stderr=b"child diagnostic retained\n" if failed else b"",
        )

    monkeypatch.setattr(profiler.subprocess, "run", run)
    result = tmp_path / "result.json"
    with pytest.raises(subprocess.CalledProcessError):
        profiler.measure(tmp_path / "fixtures", tmp_path / "source", result, repetitions=3)
    partial = json.loads(result.with_suffix(".partial.json").read_bytes())
    assert partial["complete"] is False and len(partial["results"]) == 1
    assert not result.exists()
    assert not (outputs[0] / "graph.db").exists()
    assert (outputs[1] / "graph.db").read_bytes() == b"owned synthetic fixture copy"
    assert outputs[1].with_suffix(".stderr.log").read_bytes() == b"child diagnostic retained\n"
    assert "child diagnostic retained" in capsys.readouterr().err
