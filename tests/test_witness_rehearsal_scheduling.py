"""Keep independent crash stress outside the existing short-lived approval window."""

import json

import pytest

from scripts import witness_checkpoint_rehearsal as witness
from scripts.hybrid_operations_rehearsal import Rehearsal
from scripts.independent_checkpoint_rehearsal import AnchoredRehearsal


def test_slow_independent_restart_probe_cannot_expire_recovery_approval(tmp_path, monkeypatch):
    elapsed = [0]
    order = []
    exercise = witness.WitnessedRehearsal(tmp_path, "runtime", "worker")
    exercise.witness_volume = "owned-witness"
    exercise.controllers = ["source", "recovery"]
    monkeypatch.setattr(AnchoredRehearsal, "check_restored", lambda *args: None)
    monkeypatch.setattr(exercise, "execute", lambda *args: b"")

    def command(args, **kwargs):
        if args[:2] == ["docker", "inspect"]:
            return json.dumps([{"Mounts": [{
                "Name": "owned-witness", "RW": False, "Destination": "/witness",
            }]}]).encode()
        assert "checkpoint_witness_process_probe.py" in " ".join(args)
        assert kwargs["timeout"] == 1200
        elapsed[0] += 600  # valid cumulative duration; each child still has its own bound
        order.append("independent-crash-stress")
        return b'{"complete":true,"cycles":32}'

    def restore_then_resume(self):
        self.check_restored("recovery", {})
        # Existing product approval intents expire after five minutes. No expiry is extended.
        assert elapsed[0] < 300, "independent stress consumed the recovery approval window"
        order.append("approved-continuation")

    monkeypatch.setattr(witness, "command", command)
    monkeypatch.setattr(Rehearsal, "run", restore_then_resume)
    exercise.run()
    assert order == ["approved-continuation", "independent-crash-stress"]
    assert "32-fresh-process-head-verification-cycles" in exercise.checks
    assert exercise.phase == "complete"


def test_late_crash_probe_failure_keeps_the_rehearsal_incomplete(tmp_path, monkeypatch):
    exercise = witness.WitnessedRehearsal(tmp_path, "runtime", "worker")
    exercise.controllers = ["recovery"]
    monkeypatch.setattr(Rehearsal, "run", lambda self: None)
    monkeypatch.setattr(
        witness, "command", lambda *args, **kwargs: b'{"complete":false,"cycles":31}'
    )
    with pytest.raises(ValueError, match="crash probe is incomplete"):
        exercise.run()
    assert exercise.phase == "witness-process-crash"
    assert "32-fresh-process-head-verification-cycles" not in exercise.checks
