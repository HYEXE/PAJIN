from __future__ import annotations

import json
import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

import pajin.cli as cli
import pajin.reporting.sarif as sarif
from pajin.domain.models import Finding, FindingSeverity
from pajin.domain.validation import (
    CandidateFinding,
    ConfirmationBasis,
    FindingDisposition,
    FindingValidationSet,
    ReplayConfirmationLineage,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
    VersionedConfirmedFindingSet,
    VersionedValidationDecisionSet,
    VersionedValidationIndex,
)
from pajin.runtime.store import RunStore, verify_run_integrity
from pajin.workflow.validation_artifacts import (
    VERSIONED_VALIDATION_DECISIONS_PATH,
    VERSIONED_VALIDATION_FINDINGS_PATH,
    VERSIONED_VALIDATION_INDEX_PATH,
    VERSIONED_VALIDATION_REPORT_PATH,
    write_validation_artifacts,
)

NOW = datetime(2026, 8, 11, 9, 0, tzinfo=UTC)


def _finding(
    *,
    finding_id: str = "finding_sarif_1",
    severity: FindingSeverity = FindingSeverity.HIGH,
    threat_class: str = "M03",
    validated: bool = False,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title="Confirmed access control weakness",
        severity=severity,
        threat_class=threat_class,
        target="https://operator:secret@target.example/v1/chat?token=secret-target-token",
        summary="An independently replayed request crossed the expected access boundary.",
        impact="A scoped test identity reached another test tenant.",
        affected_component="tenant retrieval endpoint",
        root_cause="secret-root-cause-detail",
        reproduction=["secret-reproduction-step"],
        evidence=["evidence/secret-evidence-path.json"],
        remediation=["Bind retrieval to the authenticated tenant identity."],
        confidence=0.95,
        validated=validated,
    )


def _sealed_validation_run(tmp_path: Path) -> RunStore:
    store = RunStore.create(tmp_path, "sarif-export-test")
    candidate = CandidateFinding(
        candidate_id="candidate_sarif_1",
        claim=_finding(),
        source="trusted-core:candidate-producer",
        source_agent_id="trusted-core:test-producer",
        source_request_ids=["request_source_1"],
        created_at=NOW,
    )
    source_decision = ValidationDecision(
        decision_id="decision_source_1",
        candidate_id=candidate.candidate_id,
        validator_id="agent:semantic-validator:1",
        method=ValidationMethod.HYBRID_LEGACY_GATE,
        disposition=FindingDisposition.NEEDS_REVIEW,
        reason_codes=[ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING],
        decision_summary="Independent reproduction has not run.",
        supporting_evidence=[],
        contradicting_evidence=[],
        replay_request_ids=[],
        checks=[],
        decided_at=NOW,
    )
    source_validation = FindingValidationSet(
        candidates=[candidate],
        decisions=[source_decision],
        confirmed_findings=[],
    )
    store.append_event("test.source-validation.created", {})
    write_validation_artifacts(store, source_validation)
    store.write_json("findings.json", [])
    source_seal = store.seal()

    lineage = ReplayConfirmationLineage(
        replay_run_id="run_replay_sarif_1",
        replay_outcome_id="replay-outcome_sarif_1",
        replay_request_ids=["request_replay_1"],
        replay_evidence=["evidence/request_replay_1.json"],
        oracle_result_id="oracle-result_sarif_1",
        ticket_id="ticket_sarif_1",
        candidate_source_root_digest=source_seal.root_digest,
        artifact_set_digest="a" * 64,
        artifact_seal_root_digest="b" * 64,
        receipt_seal_root_digest="c" * 64,
        verified_at=NOW,
    )
    confirmed_decision = ValidationDecision(
        decision_id="decision_replay_1",
        supersedes_decision_id=source_decision.decision_id,
        candidate_id=candidate.candidate_id,
        validator_id="trusted-core:confirmed-gate",
        method=ValidationMethod.RESTRICTED_REPLAY_GATE,
        disposition=FindingDisposition.CONFIRMED,
        confirmation_basis=ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY,
        reason_codes=[ValidationReasonCode.INDEPENDENT_REPRODUCTION_CONFIRMED],
        decision_summary="A verified independent replay supported the exact claim.",
        supporting_evidence=[],
        contradicting_evidence=[],
        replay_request_ids=lineage.replay_request_ids,
        replay_outcome_ids=[lineage.replay_outcome_id],
        replay_lineage=[lineage],
        checks=[],
        decided_at=NOW,
    )
    confirmed_finding = candidate.claim.model_copy(update={"validated": True})
    index = VersionedValidationIndex(
        sourceRunId=store.run_id,
        candidateSourceRootDigest=source_seal.root_digest,
        confirmationSemantics="verified-independent-replay",
        dispositions={
            FindingDisposition.CONFIRMED: [candidate.candidate_id],
            FindingDisposition.NEEDS_REVIEW: [],
            FindingDisposition.INCONCLUSIVE: [],
            FindingDisposition.REJECTED_OBJECTIVE: [],
        },
        confirmedCandidateIds=[candidate.candidate_id],
        generatedAt=NOW,
    )
    store.write_json(
        VERSIONED_VALIDATION_DECISIONS_PATH,
        VersionedValidationDecisionSet(
            sourceRunId=store.run_id,
            decisions=[confirmed_decision],
        ).model_dump(mode="json", by_alias=True),
    )
    store.write_json(
        VERSIONED_VALIDATION_FINDINGS_PATH,
        VersionedConfirmedFindingSet(
            sourceRunId=store.run_id,
            confirmationSemantics="verified-independent-replay",
            findings=[confirmed_finding],
        ).model_dump(mode="json", by_alias=True),
    )
    store.write_text(VERSIONED_VALIDATION_REPORT_PATH, "# Independently replayed findings\n")
    store.write_json(
        VERSIONED_VALIDATION_INDEX_PATH,
        index.model_dump(mode="json", by_alias=True),
    )
    store.append_event("test.versioned-validation.created", {})
    store.seal()
    return store


def test_verified_sarif_export_is_deterministic_bound_and_minimized(tmp_path: Path) -> None:
    store = _sealed_validation_run(tmp_path)
    authority = verify_run_integrity(store.path)

    first = sarif.load_verified_sarif_export(
        store.path,
        expected_run_id=store.run_id,
        expected_root_digest=authority.root_digest,
    )
    second = sarif.load_verified_sarif_export(
        store.path,
        expected_run_id=store.run_id,
        expected_root_digest=authority.root_digest,
    )

    assert first == second
    assert first.finding_count == 1
    document = json.loads(first.content)
    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    result = run["results"][0]
    assert result["level"] == "error"
    assert result["message"]["text"].startswith("An independently replayed request")
    assert result["partialFingerprints"]["pajinFinding/v1"]
    assert result["properties"]["targetDigest"]
    authority_properties = run["properties"]["pajin"]
    assert authority_properties["sourceRunId"] == store.run_id
    assert authority_properties["sourceRootDigest"] == authority.root_digest
    assert authority_properties["sourceFindingSetDigest"] == first.finding_set_digest
    assert authority_properties["externalDeliveryPerformed"] is False
    assert authority_properties["deliveryReceiptAuthority"] is False
    assert authority_properties["issueMutationAuthority"] is False
    assert authority_properties["siemIngestAuthority"] is False
    assert authority_properties["soarActionAuthority"] is False
    for excluded in (
        "secret-target-token",
        "operator:secret",
        "secret-root-cause-detail",
        "secret-reproduction-step",
        "secret-evidence-path",
    ):
        assert excluded not in first.content

    output = tmp_path / "exports" / "findings.sarif"
    persisted = sarif.write_verified_sarif_export(first, output)
    assert persisted == output.resolve()
    assert output.read_text(encoding="utf-8") == first.content
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600
    assert verify_run_integrity(store.path).root_digest == authority.root_digest


def test_sarif_export_rejects_legacy_confirmation_semantics(tmp_path: Path) -> None:
    store = RunStore.create(tmp_path, "legacy-sarif-export-test")
    finding = _finding(validated=True)
    candidate = CandidateFinding(
        candidate_id="candidate_legacy_sarif_1",
        claim=finding.model_copy(update={"validated": False}),
        source="trusted-core:candidate-producer",
        source_agent_id="trusted-core:test-producer",
        source_request_ids=["request_legacy_1"],
        created_at=NOW,
    )
    decision = ValidationDecision(
        decision_id="decision_legacy_1",
        candidate_id=candidate.candidate_id,
        validator_id="agent:legacy-validator:1",
        method=ValidationMethod.HYBRID_LEGACY_GATE,
        disposition=FindingDisposition.CONFIRMED,
        reason_codes=[ValidationReasonCode.VALIDATOR_CONFIRMED],
        decision_summary="Legacy semantic validation confirmed the claim.",
        supporting_evidence=[],
        contradicting_evidence=[],
        replay_request_ids=[],
        checks=[],
        decided_at=NOW,
    )
    validation = FindingValidationSet(
        candidates=[candidate],
        decisions=[decision],
        confirmed_findings=[finding],
    )
    store.append_event("test.legacy-validation.created", {})
    write_validation_artifacts(store, validation)
    store.write_json("findings.json", [finding.model_dump(mode="json")])
    store.seal()
    authority = verify_run_integrity(store.path)

    with pytest.raises(ValueError, match="requires verified independent replay"):
        sarif.load_verified_sarif_export(
            store.path,
            expected_run_id=store.run_id,
            expected_root_digest=authority.root_digest,
        )


def test_sarif_export_rejects_wrong_or_stale_source_root(tmp_path: Path) -> None:
    store = _sealed_validation_run(tmp_path)
    authority = verify_run_integrity(store.path)

    with pytest.raises(ValueError, match="root digest differs"):
        sarif.load_verified_sarif_export(
            store.path,
            expected_run_id=store.run_id,
            expected_root_digest="f" * 64,
        )

    store.write_json("later-phase.json", {"phase": "later"})
    store.append_event("test.later-phase.created", {})
    store.seal()
    with pytest.raises(ValueError, match="root digest differs"):
        sarif.load_verified_sarif_export(
            store.path,
            expected_run_id=store.run_id,
            expected_root_digest=authority.root_digest,
        )


def test_sarif_writer_never_mutates_the_source_run(tmp_path: Path) -> None:
    store = _sealed_validation_run(tmp_path)
    authority = verify_run_integrity(store.path)
    exported = sarif.load_verified_sarif_export(
        store.path,
        expected_run_id=store.run_id,
        expected_root_digest=authority.root_digest,
    )

    with pytest.raises(ValueError, match="outside the immutable source Run"):
        sarif.write_verified_sarif_export(exported, store.path / "export.sarif")


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX symbolic-link semantics")
def test_sarif_writer_rejects_a_symbolic_link_leaf(tmp_path: Path) -> None:
    store = _sealed_validation_run(tmp_path)
    authority = verify_run_integrity(store.path)
    exported = sarif.load_verified_sarif_export(
        store.path,
        expected_run_id=store.run_id,
        expected_root_digest=authority.root_digest,
    )
    outside = tmp_path / "outside.sarif"
    outside.write_text("must remain unchanged", encoding="utf-8")
    output = tmp_path / "linked-output.sarif"
    output.symlink_to(outside)

    with pytest.raises(ValueError, match="symbolic link"):
        sarif.write_verified_sarif_export(exported, output)

    assert outside.read_text(encoding="utf-8") == "must remain unchanged"


def test_sarif_writer_rejects_corrupt_content_before_replacing_output(tmp_path: Path) -> None:
    store = _sealed_validation_run(tmp_path)
    authority = verify_run_integrity(store.path)
    exported = sarif.load_verified_sarif_export(
        store.path,
        expected_run_id=store.run_id,
        expected_root_digest=authority.root_digest,
    )
    output = tmp_path / "existing.sarif"
    output.write_text("keep existing output", encoding="utf-8")

    with pytest.raises(ValueError, match="differs from its verified digest"):
        sarif.write_verified_sarif_export(
            replace(exported, content=exported.content + " "),
            output,
        )

    assert output.read_text(encoding="utf-8") == "keep existing output"


@pytest.mark.parametrize(
    ("severity", "expected_level"),
    [
        (FindingSeverity.SAFE, "note"),
        (FindingSeverity.LOW, "note"),
        (FindingSeverity.MEDIUM, "warning"),
        (FindingSeverity.HIGH, "error"),
        (FindingSeverity.CRITICAL, "error"),
    ],
)
def test_sarif_severity_mapping_is_explicit(
    tmp_path: Path,
    severity: FindingSeverity,
    expected_level: str,
) -> None:
    exported = sarif._build_sarif_export(
        source_run_path=tmp_path,
        source_run_id="run_sarif_mapping_1",
        source_root_digest="a" * 64,
        findings=[_finding(severity=severity, validated=True)],
    )

    assert json.loads(exported.content)["runs"][0]["results"][0]["level"] == expected_level


def test_sarif_export_rejects_unsafe_display_text(tmp_path: Path) -> None:
    finding = _finding(validated=True).model_copy(update={"title": "forged\u202eexe"})

    with pytest.raises(ValueError, match="unsafe Unicode controls"):
        sarif._build_sarif_export(
            source_run_path=tmp_path,
            source_run_id="run_sarif_unsafe_1",
            source_root_digest="a" * 64,
            findings=[finding],
        )


def test_sarif_export_rejects_an_unbounded_finding_set(tmp_path: Path) -> None:
    findings = [
        _finding(finding_id=f"finding_sarif_{index}", validated=True) for index in range(1_001)
    ]

    with pytest.raises(ValueError, match="1000-Finding limit"):
        sarif._build_sarif_export(
            source_run_path=tmp_path,
            source_run_id="run_sarif_oversized_1",
            source_root_digest="a" * 64,
            findings=findings,
        )


def test_sarif_cli_writes_local_artifact_without_delivery(tmp_path: Path) -> None:
    store = _sealed_validation_run(tmp_path)
    authority = verify_run_integrity(store.path)
    output = tmp_path / "cli-export.sarif"

    result = CliRunner().invoke(
        cli.app,
        [
            "sarif-export",
            str(store.path),
            "--output",
            str(output),
            "--expected-run-id",
            store.run_id,
            "--expected-root-digest",
            authority.root_digest,
        ],
    )

    assert result.exit_code == 0, result.output
    assert output.is_file()
    assert "NOT PERFORMED" in result.output
    assert authority.root_digest[:16] in result.output


def test_sarif_cli_fails_closed_without_creating_output(tmp_path: Path) -> None:
    store = _sealed_validation_run(tmp_path)
    output = tmp_path / "must-not-exist.sarif"

    result = CliRunner().invoke(
        cli.app,
        [
            "sarif-export",
            str(store.path),
            "--output",
            str(output),
            "--expected-run-id",
            store.run_id,
            "--expected-root-digest",
            "f" * 64,
        ],
    )

    assert result.exit_code == 1
    assert "SARIF export failed" in result.output
    assert not output.exists()
