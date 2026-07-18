from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest
from kisa_control_plane_support import (
    KISAControlPlaneSource,
    _tree_identity,
    build_kisa_control_plane_source,
)

from pajin.control_plane.kisa_derivation import (
    KISA_CONFIRMATION_MAX_ATTEMPTS,
    KISA_CONFIRMATION_POLICY_VERSION,
    KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
    derive_kisa_confirmation_batch,
)
from pajin.control_plane.models import ArtifactRef
from pajin.domain.replay import ReplayCompilation, ReplayPurpose
from pajin.replay.tickets import canonical_replay_compilation_bytes, replay_context_digest
from pajin.runtime.store import AuditEvent, RunStore, verify_run_integrity

NOW = datetime(2026, 7, 18, 8, 0, tzinfo=UTC)


def test_derives_stable_canonical_compilations_from_only_the_sealed_source(
    tmp_path: Path,
) -> None:
    source = build_kisa_control_plane_source(tmp_path / "source", scenario_count=3)
    replay_ids = tuple(f"run_{index:032x}" for index in range(1, 4))

    first_ids = iter(replay_ids)
    first = derive_kisa_confirmation_batch(
        source_root=source.path,
        artifact_ref=source.artifact_ref,
        replay_run_id_factory=lambda: next(first_ids),
        clock=lambda: NOW,
    )
    second_ids = iter(replay_ids)
    second = derive_kisa_confirmation_batch(
        source_root=source.path,
        artifact_ref=source.artifact_ref,
        replay_run_id_factory=lambda: next(second_ids),
        clock=lambda: NOW,
    )

    assert first == second
    assert first.campaign_name == source.campaign.metadata.name
    assert first.candidate_run_id == source.artifact_ref.run_id
    assert first.source_root_digest == source.artifact_ref.integrity_root_digest
    assert first.purpose is ReplayPurpose.CONFIRMATION
    assert first.policy_version == KISA_CONFIRMATION_POLICY_VERSION
    assert first.used_tool_calls == 6
    assert first.required_tool_calls == 6
    assert first.max_tool_calls == 12
    assert [item.candidate_id for item in first.items] == sorted(
        item.candidate_id for item in first.items
    )
    assert [item.replay_run_id for item in first.items] == list(replay_ids)
    assert len(first.items) == 3
    for item in first.items:
        assert item.required_attempts == KISA_CONFIRMATION_REQUIRED_ATTEMPTS
        assert item.max_attempts == KISA_CONFIRMATION_MAX_ATTEMPTS
        assert item.candidate_digest == replay_context_digest(item.candidate)
        assert item.contract_digest == replay_context_digest(item.contract)
        assert item.grant_digest == replay_context_digest(item.compilation.grant)
        assert item.canonical_compilation == canonical_replay_compilation_bytes(item.compilation)
        assert item.compilation_digest == sha256(item.canonical_compilation).hexdigest()
        assert ReplayCompilation.model_validate_json(item.canonical_compilation) == (
            item.compilation
        )
        assert not hasattr(item, "ticket")


def test_rejects_artifact_ref_or_raw_worker_evidence_substitution(tmp_path: Path) -> None:
    source = build_kisa_control_plane_source(tmp_path / "source", scenario_count=1)
    mismatched_ref = source.artifact_ref.model_copy(update={"integrity_root_digest": "f" * 64})
    with pytest.raises(ValueError, match="ArtifactRef does not bind"):
        derive_kisa_confirmation_batch(
            source_root=source.path,
            artifact_ref=mismatched_ref,
            clock=lambda: NOW,
        )

    evidence_path = next((source.path / "evidence").glob("*.json"))
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    raw = json.loads(evidence["workerResult"]["stdout"])
    raw["turns"][0]["response"]["message"]["content"] = "forged refusal"
    evidence["workerResult"]["stdout"] = json.dumps(raw, separators=(",", ":"))
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    rebound = _reseal_and_rebind(source)

    with pytest.raises(ValueError, match="source transcript does not support"):
        derive_kisa_confirmation_batch(
            source_root=rebound.path,
            artifact_ref=rebound.artifact_ref,
            clock=lambda: NOW,
        )


def test_rejects_candidate_decision_and_capability_authority_substitution(
    tmp_path: Path,
) -> None:
    candidate_source = build_kisa_control_plane_source(
        tmp_path / "candidate-source",
        scenario_count=1,
    )
    candidates_path = candidate_source.path / "candidate-findings.json"
    candidates = json.loads(candidates_path.read_text(encoding="utf-8"))
    candidates[0]["claim"]["finding_id"] = "finding_forged_authority"
    candidates[0]["claim"]["title"] = "Caller-authored Candidate title"
    candidates_path.write_text(json.dumps(candidates), encoding="utf-8")
    candidate_source = _reseal_and_rebind(candidate_source)

    with pytest.raises(ValueError, match="trusted producer output"):
        derive_kisa_confirmation_batch(
            source_root=candidate_source.path,
            artifact_ref=candidate_source.artifact_ref,
            clock=lambda: NOW,
        )

    decision_source = build_kisa_control_plane_source(
        tmp_path / "decision-source",
        scenario_count=1,
    )
    decisions_path = decision_source.path / "validation-decisions.json"
    decisions = json.loads(decisions_path.read_text(encoding="utf-8"))
    decisions[0]["method"] = "legacy-validator"
    decisions_path.write_text(json.dumps(decisions), encoding="utf-8")
    decision_source = _reseal_and_rebind(decision_source)

    with pytest.raises(ValueError, match="Decision differs from trusted validation output"):
        derive_kisa_confirmation_batch(
            source_root=decision_source.path,
            artifact_ref=decision_source.artifact_ref,
            clock=lambda: NOW,
        )

    capability_source = build_kisa_control_plane_source(
        tmp_path / "capability-source",
        scenario_count=1,
    )
    capabilities_path = capability_source.path / "capabilities.json"
    capabilities = json.loads(capabilities_path.read_text(encoding="utf-8"))
    for record in capabilities:
        record["revoked"] = True
        record["revoke_reason"] = "test authority revocation"
    capabilities_path.write_text(json.dumps(capabilities), encoding="utf-8")
    capability_source = _reseal_and_rebind(capability_source)

    with pytest.raises(ValueError, match="Validator capability lineage"):
        derive_kisa_confirmation_batch(
            source_root=capability_source.path,
            artifact_ref=capability_source.artifact_ref,
            clock=lambda: NOW,
        )


@pytest.mark.parametrize(
    ("field", "forged_value"),
    [
        ("validator_id", "agent:validator:attacker"),
        ("decision_id", "decision_forged_authority"),
        ("decision_summary", "FORGED semantic validation summary"),
        ("checks", []),
        ("decided_at", "2000-01-01T00:00:00Z"),
    ],
)
def test_rejects_resealed_noncanonical_validation_decision_fields(
    tmp_path: Path,
    field: str,
    forged_value: object,
) -> None:
    source = build_kisa_control_plane_source(
        tmp_path / field,
        scenario_count=1,
    )
    decisions_path = source.path / "validation-decisions.json"
    decisions = json.loads(decisions_path.read_text(encoding="utf-8"))
    decisions[0][field] = forged_value
    decisions_path.write_text(json.dumps(decisions), encoding="utf-8")
    source = _reseal_and_rebind(source)

    with pytest.raises(ValueError, match="sealed KISA Decision"):
        derive_kisa_confirmation_batch(
            source_root=source.path,
            artifact_ref=source.artifact_ref,
            clock=lambda: NOW,
        )


def test_rejects_rehashed_validator_completion_before_decision_events(tmp_path: Path) -> None:
    source = build_kisa_control_plane_source(
        tmp_path / "validator-event-order",
        scenario_count=1,
    )
    decision = json.loads((source.path / "validation-decisions.json").read_text(encoding="utf-8"))[
        0
    ]
    graph = json.loads((source.path / "task-graph.json").read_text(encoding="utf-8"))
    validation_task_id = next(
        task_id
        for task_id, task in graph["tasks"].items()
        if task["title"] == "Independently validate candidate findings"
    )
    events = [
        AuditEvent.model_validate_json(line)
        for line in (source.path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    task_succeeded = next(
        event
        for event in events
        if event.event_type == "task.succeeded"
        and event.payload == {"taskId": validation_task_id, "error": None}
    )
    validator_completed = next(
        event
        for event in events
        if event.event_type == "agent.completed"
        and event.payload.get("agentId") == decision["validator_id"]
    )
    moved_event_ids = {task_succeeded.event_id, validator_completed.event_id}
    reordered = [event for event in events if event.event_id not in moved_event_ids]
    decision_start = next(
        index
        for index, event in enumerate(reordered)
        if event.event_type == "candidate.finding.created"
        and event.payload.get("decisionId") == decision["decision_id"]
    )
    reordered[decision_start:decision_start] = [task_succeeded, validator_completed]
    _write_rehashed_events(source.path / "events.jsonl", reordered)
    source = _reseal_and_rebind(source)

    with pytest.raises(ValueError, match="Decisions do not precede Validator completion"):
        derive_kisa_confirmation_batch(
            source_root=source.path,
            artifact_ref=source.artifact_ref,
            clock=lambda: NOW,
        )


def test_rejects_aggregate_budget_exhaustion_and_versioned_validation(
    tmp_path: Path,
) -> None:
    understated_source = build_kisa_control_plane_source(
        tmp_path / "understated-budget-source",
        scenario_count=1,
    )
    understated_budget_path = understated_source.path / "budget.json"
    understated_budget = json.loads(understated_budget_path.read_text(encoding="utf-8"))
    understated_budget["toolCalls"] = 0
    understated_budget_path.write_text(json.dumps(understated_budget), encoding="utf-8")
    understated_source = _reseal_and_rebind(understated_source)

    with pytest.raises(ValueError, match="tool-call usage differs from execution lineage"):
        derive_kisa_confirmation_batch(
            source_root=understated_source.path,
            artifact_ref=understated_source.artifact_ref,
            clock=lambda: NOW,
        )

    budget_source = build_kisa_control_plane_source(
        tmp_path / "budget-source",
        scenario_count=3,
    )
    budget_path = budget_source.path / "budget.json"
    budget = json.loads(budget_path.read_text(encoding="utf-8"))
    budget["maxToolCalls"] = 11
    budget_path.write_text(json.dumps(budget), encoding="utf-8")
    campaign_path = budget_source.path / "campaign.json"
    campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
    campaign["spec"]["budgets"]["maxToolCalls"] = 11
    campaign_path.write_text(json.dumps(campaign), encoding="utf-8")
    budget_source = _reseal_and_rebind(budget_source)

    with pytest.raises(ValueError, match="aggregate Campaign tool-call budget"):
        derive_kisa_confirmation_batch(
            source_root=budget_source.path,
            artifact_ref=budget_source.artifact_ref,
            clock=lambda: NOW,
        )

    versioned_source = build_kisa_control_plane_source(
        tmp_path / "versioned-source",
        scenario_count=1,
    )
    versioned = versioned_source.path / "validation" / "v1alpha1"
    versioned.mkdir(parents=True)
    (versioned / "index.json").write_text("{}\n", encoding="utf-8")
    versioned_source = _reseal_and_rebind(versioned_source)

    with pytest.raises(ValueError, match="already-versioned validation projection"):
        derive_kisa_confirmation_batch(
            source_root=versioned_source.path,
            artifact_ref=versioned_source.artifact_ref,
            clock=lambda: NOW,
        )


def _write_rehashed_events(path: Path, events: list[AuditEvent]) -> None:
    previous_hash: str | None = None
    encoded: list[str] = []
    for sequence, event in enumerate(events, start=1):
        pending = event.model_copy(
            update={
                "sequence": sequence,
                "previous_hash": previous_hash,
                "event_hash": "0" * 64,
            }
        )
        finalized = pending.model_copy(update={"event_hash": pending.computed_hash()})
        encoded.append(finalized.model_dump_json())
        previous_hash = finalized.event_hash
    path.write_text("\n".join(encoded) + "\n", encoding="utf-8")


def _reseal_and_rebind(source: KISAControlPlaneSource) -> KISAControlPlaneSource:
    (source.path / "run-integrity.jsonl").unlink()
    seal = RunStore(run_id=source.artifact_ref.run_id, path=source.path).seal()
    content_digest, byte_length = _tree_identity(source.path)
    ref = ArtifactRef(
        **source.artifact_ref.model_dump(
            exclude={"content_digest", "byte_length", "integrity_root_digest"}
        ),
        content_digest=content_digest,
        byte_length=byte_length,
        integrity_root_digest=seal.root_digest,
    )
    assert verify_run_integrity(source.path).root_digest == seal.root_digest
    return KISAControlPlaneSource(
        path=source.path,
        artifact_ref=ref,
        campaign=source.campaign,
    )
