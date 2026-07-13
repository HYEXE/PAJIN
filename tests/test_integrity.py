import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import pajin.cli as cli
from pajin.runtime.store import (
    RunIntegrityError,
    RunIntegritySeal,
    RunStore,
    verify_run_integrity,
)


def _sealed_run(tmp_path: Path) -> tuple[RunStore, RunIntegritySeal]:
    store = RunStore.create(tmp_path, "integrity-test")
    store.write_json("campaign.json", {"name": "integrity-test"})
    evidence = store.write_json(
        "evidence/request-1.json",
        {
            "request": {
                "request_id": "request-1",
                "tool_id": "test.probe",
            },
            "workerJob": {"executionId": "execution-1"},
            "result": {"success": True},
        },
    )
    store.append_event("campaign.started", {"campaign": "integrity-test"})
    store.append_event(
        "tool.completed",
        {"requestId": "request-1", "evidence": evidence},
    )
    store.append_event("campaign.completed", {"report": "report.md"})
    store.write_text("report.md", "# Integrity test")
    return store, store.seal()


def test_run_seal_binds_artifacts_events_and_evidence_provenance(tmp_path: Path) -> None:
    store, seal = _sealed_run(tmp_path)

    verification = verify_run_integrity(store.path)

    assert verification.valid
    assert verification.run_id == store.run_id
    assert verification.seal_count == 1
    assert verification.artifact_count == 3
    assert verification.event_count == 3
    assert verification.root_digest == seal.root_digest
    evidence = next(item for item in seal.artifacts if item.path == "evidence/request-1.json")
    assert evidence.provenance is not None
    assert evidence.provenance.request_id == "request-1"
    assert evidence.provenance.tool_id == "test.probe"
    assert evidence.provenance.execution_id == "execution-1"
    assert len(evidence.provenance.event_ids) == 1


def test_integrity_rejects_changed_and_missing_sealed_artifacts(tmp_path: Path) -> None:
    changed_store, _ = _sealed_run(tmp_path / "changed")
    campaign = changed_store.path / "campaign.json"
    campaign.write_text('{"name":"tampered"}\n', encoding="utf-8")

    with pytest.raises(RunIntegrityError, match="sealed Run artifact changed"):
        verify_run_integrity(changed_store.path)
    with pytest.raises(RunIntegrityError, match="cannot be overwritten"):
        changed_store.write_json("campaign.json", {"name": "rewritten"})

    missing_store, _ = _sealed_run(tmp_path / "missing")
    (missing_store.path / "report.md").unlink()
    with pytest.raises(RunIntegrityError, match="sealed Run artifact is missing"):
        verify_run_integrity(missing_store.path)


def test_integrity_rejects_unsealed_file_addition(tmp_path: Path) -> None:
    store, _ = _sealed_run(tmp_path)
    (store.path / "unexpected.txt").write_text("not sealed\n", encoding="utf-8")

    with pytest.raises(RunIntegrityError, match="Run contains unsealed artifacts"):
        verify_run_integrity(store.path)


def test_integrity_rejects_audit_event_reordering(tmp_path: Path) -> None:
    store, _ = _sealed_run(tmp_path)
    lines = store.events_path.read_text(encoding="utf-8").splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    store.events_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(RunIntegrityError, match="event sequence is not contiguous"):
        verify_run_integrity(store.path)


def test_integrity_extension_chains_new_artifacts_to_previous_root(tmp_path: Path) -> None:
    store, first = _sealed_run(tmp_path)
    extension_path = store.write_json("derived/assessment.json", {"status": "complete"})
    store.append_event("assessment.completed", {"assessment": extension_path})

    second = store.seal()
    verification = verify_run_integrity(store.path)

    assert second.sequence == 2
    assert second.previous_root_digest == first.root_digest
    assert [item.path for item in second.artifacts] == ["derived/assessment.json"]
    assert verification.seal_count == 2
    assert verification.artifact_count == 4
    assert verification.event_count == 4
    seals = [
        RunIntegritySeal.model_validate_json(line)
        for line in store.integrity_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [item.root_digest for item in seals] == [first.root_digest, second.root_digest]


def test_evidence_verify_cli_reports_root_and_fails_closed_on_tamper(tmp_path: Path) -> None:
    store, seal = _sealed_run(tmp_path)
    runner = CliRunner()

    valid = runner.invoke(cli.app, ["evidence-verify", str(store.path)])

    assert valid.exit_code == 0, valid.output
    assert "VALID" in valid.output
    assert seal.root_digest in valid.output

    events = [
        json.loads(line) for line in store.events_path.read_text(encoding="utf-8").splitlines()
    ]
    events[1]["payload"]["requestId"] = "tampered-request"
    store.events_path.write_text(
        "\n".join(json.dumps(item, separators=(",", ":")) for item in events) + "\n",
        encoding="utf-8",
    )
    invalid = runner.invoke(cli.app, ["evidence-verify", str(store.path)])

    assert invalid.exit_code == 1
    assert "verification failed" in invalid.output
