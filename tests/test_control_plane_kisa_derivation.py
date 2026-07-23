from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest
from kisa_control_plane_support import (
    KISAControlPlaneSource,
    _tree_identity,
    build_kisa_control_plane_retest_sources,
    build_kisa_control_plane_source,
)

import pajin.control_plane.kisa_derivation as kisa_derivation
import pajin.modes.ai_redteam.replay as ai_redteam_replay
import pajin.workflow.validation as finding_validation
from pajin.control_plane.kisa_derivation import (
    KISA_CONFIRMATION_MAX_ATTEMPTS,
    KISA_CONFIRMATION_POLICY_VERSION,
    KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
    KISA_RETEST_POLICY_VERSION,
    derive_kisa_confirmation_batch,
    derive_kisa_retest_batch,
)
from pajin.control_plane.models import ArtifactRef
from pajin.domain.replay import ReplayCompilation, ReplayPurpose
from pajin.replay.tickets import canonical_replay_compilation_bytes, replay_context_digest
from pajin.runtime.store import AuditEvent, RunStore, verify_run_integrity


def test_derives_stable_canonical_compilations_from_only_the_sealed_source(
    tmp_path: Path,
) -> None:
    source = build_kisa_control_plane_source(tmp_path / "source", scenario_count=3)
    capabilities = json.loads((source.path / "capabilities.json").read_text(encoding="utf-8"))
    assert capabilities and all(record["revoked"] is True for record in capabilities)
    replay_ids = tuple(f"run_{index:032x}" for index in range(1, 4))

    first_ids = iter(replay_ids)
    first = derive_kisa_confirmation_batch(
        source_root=source.path,
        artifact_ref=source.artifact_ref,
        replay_run_id_factory=lambda: next(first_ids),
        clock=lambda: source.compilation_time,
    )
    second_ids = iter(replay_ids)
    second = derive_kisa_confirmation_batch(
        source_root=source.path,
        artifact_ref=source.artifact_ref,
        replay_run_id_factory=lambda: next(second_ids),
        clock=lambda: source.compilation_time,
    )

    assert first == second
    assert first.campaign_name == source.campaign.metadata.name
    assert first.candidate_run_id == source.artifact_ref.run_id
    assert first.source_root_digest == source.artifact_ref.integrity_root_digest
    assert first.purpose is ReplayPurpose.CONFIRMATION
    assert first.policy_version == KISA_CONFIRMATION_POLICY_VERSION
    assert first.used_tool_calls == 6
    assert first.required_tool_calls == 6
    assert first.max_tool_calls == 24
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


def test_derives_negative_retest_from_exact_baseline_and_parent_sources(
    tmp_path: Path,
) -> None:
    sources = build_kisa_control_plane_retest_sources(
        tmp_path / "retest-sources",
        baseline_producer_run_id=f"run_{'a' * 32}",
        retest_producer_run_id=f"run_{'b' * 32}",
    )
    replay_run_id = f"run_{'c' * 32}"

    derived = derive_kisa_retest_batch(
        source_root=sources.baseline.path,
        artifact_ref=sources.baseline.artifact_ref,
        retest_root=sources.retest.path,
        retest_artifact_ref=sources.retest.artifact_ref,
        replay_run_id_factory=lambda: replay_run_id,
        clock=lambda: sources.retest.compilation_time,
    )

    assert derived.purpose is ReplayPurpose.REMEDIATION_RETEST
    assert derived.policy_version == KISA_RETEST_POLICY_VERSION
    assert derived.artifact_ref == sources.baseline.artifact_ref
    assert derived.retest_artifact_ref == sources.retest.artifact_ref
    assert derived.capacity_artifact_ref == sources.retest.artifact_ref
    assert derived.required_tool_calls == 2
    assert len(derived.items) == 1
    item = derived.items[0]
    assert item.replay_run_id == replay_run_id
    assert item.compilation.spec.binding.purpose is ReplayPurpose.REMEDIATION_RETEST
    context = item.compilation.validation_packet.retest_context
    assert context is not None
    assert context.retest_run_id == sources.retest.artifact_ref.run_id
    assert (
        context.retest_source_root_digest
        == sources.retest.artifact_ref.integrity_root_digest
    )


@pytest.mark.parametrize("malformation", ["duplicate-key", "nan", "deep-nesting"])
def test_rejects_ambiguous_or_resource_hostile_sealed_json(
    tmp_path: Path,
    malformation: str,
) -> None:
    source = build_kisa_control_plane_source(
        tmp_path / malformation,
        scenario_count=1,
    )
    budget_path = source.path / "budget.json"
    budget = json.loads(budget_path.read_text(encoding="utf-8"))
    if malformation == "duplicate-key":
        serialized = json.dumps(budget, separators=(",", ":"))
        field = f'"toolCalls":{budget["toolCalls"]}'
        assert field in serialized
        malformed = serialized.replace(field, f"{field},{field}", 1)
    elif malformation == "nan":
        budget["costUsd"] = float("nan")
        malformed = json.dumps(budget, separators=(",", ":"))
        assert "NaN" in malformed
    else:
        nested: object = None
        for _ in range(70):
            nested = [nested]
        budget["nested"] = nested
        malformed = json.dumps(budget, separators=(",", ":"))
    budget_path.write_text(malformed, encoding="utf-8")
    source = _reseal_and_rebind(source)

    with pytest.raises(ValueError, match=r"could not be read: budget\.json"):
        derive_kisa_confirmation_batch(
            source_root=source.path,
            artifact_ref=source.artifact_ref,
            clock=lambda: source.compilation_time,
        )


def test_rejects_oversized_sealed_gateway_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = build_kisa_control_plane_source(tmp_path / "oversized", scenario_count=1)
    monkeypatch.setattr(kisa_derivation, "_MAX_KISA_SOURCE_EVIDENCE_BYTES", 64)

    with pytest.raises(ValueError, match="artifact could not be loaded"):
        derive_kisa_confirmation_batch(
            source_root=source.path,
            artifact_ref=source.artifact_ref,
            clock=lambda: source.compilation_time,
        )


def test_rejects_source_substitution_between_snapshot_phases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = build_kisa_control_plane_source(tmp_path / "substitution", scenario_count=1)
    original_loader = kisa_derivation.load_verified_run_artifacts
    load_count = 0

    def substitute_after_preliminary_snapshot(*args: object, **kwargs: object) -> object:
        nonlocal load_count
        snapshot = original_loader(*args, **kwargs)
        load_count += 1
        if load_count == 1:
            run_summary_path = source.path / "run.json"
            run_summary_path.write_text(
                run_summary_path.read_text(encoding="utf-8") + " ",
                encoding="utf-8",
            )
            _reseal_and_rebind(source)
        return snapshot

    monkeypatch.setattr(
        kisa_derivation,
        "load_verified_run_artifacts",
        substitute_after_preliminary_snapshot,
    )

    with pytest.raises(ValueError, match="changed during replay derivation"):
        derive_kisa_confirmation_batch(
            source_root=source.path,
            artifact_ref=source.artifact_ref,
            clock=lambda: source.compilation_time,
        )
    assert load_count == 2


def test_reuses_pinned_snapshot_for_replay_context_and_validation_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = build_kisa_control_plane_source(tmp_path / "pinned", scenario_count=1)

    def reject_reopen(*args: object, **kwargs: object) -> object:
        raise AssertionError("sealed source artifact was reopened by pathname")

    monkeypatch.setattr(ai_redteam_replay._SealedRunReader, "open", reject_reopen)
    monkeypatch.setattr(
        finding_validation,
        "load_bounded_strict_json",
        reject_reopen,
    )

    batch = derive_kisa_confirmation_batch(
        source_root=source.path,
        artifact_ref=source.artifact_ref,
        clock=lambda: source.compilation_time,
    )

    assert len(batch.items) == 1


def test_rejects_artifact_ref_or_raw_worker_evidence_substitution(tmp_path: Path) -> None:
    source = build_kisa_control_plane_source(tmp_path / "source", scenario_count=1)
    mismatched_ref = source.artifact_ref.model_copy(update={"integrity_root_digest": "f" * 64})
    with pytest.raises(ValueError, match="ArtifactRef does not bind"):
        derive_kisa_confirmation_batch(
            source_root=source.path,
            artifact_ref=mismatched_ref,
            clock=lambda: source.compilation_time,
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
            clock=lambda: rebound.compilation_time,
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
            clock=lambda: candidate_source.compilation_time,
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
            clock=lambda: decision_source.compilation_time,
        )

    capability_source = build_kisa_control_plane_source(
        tmp_path / "capability-source",
        scenario_count=1,
    )
    capabilities_path = capability_source.path / "capabilities.json"
    capabilities = json.loads(capabilities_path.read_text(encoding="utf-8"))
    capabilities[0]["revoked"] = False
    capabilities[0]["revoke_reason"] = None
    capabilities_path.write_text(json.dumps(capabilities), encoding="utf-8")
    capability_source = _reseal_and_rebind(capability_source)

    with pytest.raises(ValueError, match="live revocation state"):
        derive_kisa_confirmation_batch(
            source_root=capability_source.path,
            artifact_ref=capability_source.artifact_ref,
            clock=lambda: capability_source.compilation_time,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "source-run",
        "validator",
        "task",
        "candidate",
        "claim-digest",
        "evidence",
        "evidence-omitted",
        "findings-omitted",
        "finding-semantics",
        "semantic-disagreement",
    ],
)
def test_requires_exact_sealed_validator_owned_assessment(
    tmp_path: Path,
    mutation: str,
) -> None:
    source = build_kisa_control_plane_source(
        tmp_path / mutation,
        scenario_count=1,
    )
    output_path = source.path / "validator-output.json"
    if mutation == "missing":
        output_path.unlink()
    else:
        output = json.loads(output_path.read_text(encoding="utf-8"))
        assessment = output["assessments"][0]
        if mutation == "source-run":
            output["sourceRunId"] = f"run_{'f' * 32}"
        elif mutation == "validator":
            output["validatorId"] = "agent:validator:foreign"
        elif mutation == "task":
            output["validationTaskId"] = "task_foreign_validation"
        elif mutation == "candidate":
            assessment["candidate_id"] = "candidate_foreign"
        elif mutation == "claim-digest":
            assessment["claim_digest"] = "0" * 64
        elif mutation == "evidence":
            assessment["supporting_evidence"] = ["evidence/foreign.json"]
        elif mutation == "evidence-omitted":
            assessment["supporting_evidence"] = []
        elif mutation == "findings-omitted":
            output["findings"] = []
        elif mutation == "finding-semantics":
            output["findings"][0]["summary"] = "A different claim was validated."
        else:
            assessment["supports_claim"] = False
            assessment["reason_code"] = "validator-disagreed"
            assessment["supporting_evidence"] = []
        output_path.write_text(json.dumps(output), encoding="utf-8")
    source = _reseal_and_rebind(source)

    with pytest.raises(
        ValueError,
        match=(
            r"Validator|validator-output|artifact could not be loaded|Decision differs|"
            r"requires evidence|validated Finding|supporting assessment"
        ),
    ):
        derive_kisa_confirmation_batch(
            source_root=source.path,
            artifact_ref=source.artifact_ref,
            clock=lambda: source.compilation_time,
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
            clock=lambda: source.compilation_time,
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
            clock=lambda: source.compilation_time,
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
            clock=lambda: understated_source.compilation_time,
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
            clock=lambda: budget_source.compilation_time,
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
            clock=lambda: versioned_source.compilation_time,
        )


def test_rejects_unconsumed_historical_source_capability(tmp_path: Path) -> None:
    source = build_kisa_control_plane_source(tmp_path / "unconsumed", scenario_count=1)
    capabilities_path = source.path / "capabilities.json"
    capabilities = json.loads(capabilities_path.read_text(encoding="utf-8"))
    for record in capabilities:
        grant = record["grant"]
        if "ai.chat-probe" in grant["tools"]:
            record["remaining_calls"] = grant["max_calls"]
    capabilities_path.write_text(json.dumps(capabilities), encoding="utf-8")
    source = _reseal_and_rebind(source)

    with pytest.raises(ValueError, match="lineage was not consumed"):
        derive_kisa_confirmation_batch(
            source_root=source.path,
            artifact_ref=source.artifact_ref,
            clock=lambda: source.compilation_time,
        )


def test_rejects_source_capability_revoked_before_worker_completion(tmp_path: Path) -> None:
    source = build_kisa_control_plane_source(tmp_path / "early-revoke", scenario_count=1)
    candidate = json.loads((source.path / "candidate-findings.json").read_text(encoding="utf-8"))[0]
    request_id = candidate["source_request_ids"][0]
    evidence = json.loads((source.path / f"evidence/{request_id}.json").read_text(encoding="utf-8"))
    agent_id = evidence["request"]["agent_id"]
    capabilities = json.loads((source.path / "capabilities.json").read_text(encoding="utf-8"))
    grant_id = next(
        record["grant"]["grant_id"]
        for record in capabilities
        if record["grant"]["subject"] == agent_id
    )
    events_path = source.path / "events.jsonl"
    events = [AuditEvent.model_validate_json(line) for line in events_path.read_text().splitlines()]
    revocation = next(
        event
        for event in events
        if event.event_type == "capability.revoked"
        and grant_id in event.payload.get("revokedGrantIds", [])
    )
    reordered = [event for event in events if event.event_id != revocation.event_id]
    completion_index = next(
        index
        for index, event in enumerate(reordered)
        if event.event_type == "worker.completed" and event.payload.get("requestId") == request_id
    )
    reordered.insert(completion_index, revocation)
    _write_rehashed_events(events_path, reordered)
    source = _reseal_and_rebind(source)

    with pytest.raises(ValueError, match="revoked before execution completed"):
        derive_kisa_confirmation_batch(
            source_root=source.path,
            artifact_ref=source.artifact_ref,
            clock=lambda: source.compilation_time,
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
        compilation_time=source.compilation_time,
    )
