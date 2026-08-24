from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_cloud_provider_admission import NOW, _Context, _context

from pajin.capabilities.cloud_inventory import CloudReadOnlyOperation
from pajin.domain.models import CampaignManifest
from pajin.workflow.cloud_policy_replay_benchmark import (
    CloudPolicyArtifactAttestor,
    CloudPolicyArtifactBundle,
    CloudPolicyArtifactSourceInputs,
    CloudPolicyBenchmarkFixtureProfile,
    CloudPolicyBenchmarkGroundTruthClass,
    CloudPolicyDecision,
    CloudPolicyEffect,
    CloudPolicyExactRule,
    CloudPolicyFreshCredentialReplayValidation,
    CloudPolicyQuery,
    CloudPolicyReplayBenchmarkError,
    CloudPolicyReplayBenchmarkGate,
    CloudPolicyReplayComparison,
    cloud_policy_artifact_bundle_bytes,
    derive_cloud_policy_sanitized_artifact,
    evaluate_cloud_policy_artifact,
    registered_cloud_policy_benchmark_fixture_profile,
)
from pajin.workflow.cloud_provider_admission import (
    CloudProviderObservationAdmission,
    load_verified_cloud_provider_observation_source,
)

ARTIFACT_REFERENCE = "evidence/cloud-policy-artifact.json"
QUERY = CloudPolicyQuery(
    principal="principal:policy-reader",
    action="cloud:read-policy",
    resource="resource:policy-document",
)
ALLOW = CloudPolicyExactRule(
    ruleId="rule:allow-policy-reader",
    effect=CloudPolicyEffect.ALLOW,
    principal=QUERY.principal,
    action=QUERY.action,
    resource=QUERY.resource,
)
DENY = CloudPolicyExactRule(
    ruleId="rule:deny-policy-reader",
    effect=CloudPolicyEffect.DENY,
    principal=QUERY.principal,
    action=QUERY.action,
    resource=QUERY.resource,
)
UNRELATED_ALLOW = CloudPolicyExactRule(
    ruleId="rule:unrelated-allow",
    effect=CloudPolicyEffect.ALLOW,
    principal="principal:other-reader",
    action=QUERY.action,
    resource=QUERY.resource,
)


@dataclass(frozen=True, slots=True)
class _AdmittedPolicy:
    context: _Context
    admission: CloudProviderObservationAdmission
    artifact_inputs: CloudPolicyArtifactSourceInputs
    bundle: CloudPolicyArtifactBundle
    artifact_path: Path


async def _admitted_policy(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    run_id: str,
    request_id: str,
    execution_id: str,
    rules: tuple[CloudPolicyExactRule, ...],
    operation: CloudReadOnlyOperation = CloudReadOnlyOperation.POLICY,
) -> _AdmittedPolicy:
    context = await _context(
        tmp_path,
        sample_campaign,
        operation=operation,
        run_id=run_id,
        request_id=request_id,
        execution_id=execution_id,
        response_body=b'{"policy":"sanitized-out-of-band"}',
    )
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    admission = context.gate.admit(context.source_inputs, candidate)
    source = load_verified_cloud_provider_observation_source(
        context.source_inputs,
        graph_store=context.graph_store,
        trust_anchor=context.trust_anchor,
    )
    artifact = derive_cloud_policy_sanitized_artifact(
        source=source,
        admission=admission,
        rules=rules,
        query=QUERY,
        sanitized_at=NOW + timedelta(seconds=21),
    )
    bundle = CloudPolicyArtifactAttestor.from_private_key_bytes(
        active_key_id=context.trust_anchor.keys[0].key_id,
        private_key=context.private_key,
        trust_anchor=context.trust_anchor,
    ).attest(artifact)
    artifact_path = context.source_inputs.source_root / ARTIFACT_REFERENCE
    artifact_path.write_bytes(cloud_policy_artifact_bundle_bytes(bundle))
    return _AdmittedPolicy(
        context=context,
        admission=admission,
        artifact_inputs=CloudPolicyArtifactSourceInputs(
            source_root=context.source_inputs.source_root,
            artifact_reference=ARTIFACT_REFERENCE,
        ),
        bundle=bundle,
        artifact_path=artifact_path,
    )


def _bind(
    source: _AdmittedPolicy, replay: _AdmittedPolicy
) -> CloudPolicyFreshCredentialReplayValidation:
    return CloudPolicyReplayBenchmarkGate(
        trust_anchor=source.context.trust_anchor
    ).bind_fresh_credential_replay(
        source.context.source_inputs,
        source.admission,
        source.artifact_inputs,
        replay.context.source_inputs,
        replay.admission,
        replay.artifact_inputs,
        source_graph_store=source.context.graph_store,
        replay_graph_store=replay.context.graph_store,
    )


@pytest.mark.asyncio
async def test_fresh_credential_replay_binds_exact_policy_and_decision_match(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = await _admitted_policy(
        tmp_path / "source",
        sample_campaign,
        run_id="run_20260824T140000Z_a1b2c3d4",
        request_id="tool_cloud_policy_source",
        execution_id="cloud-execution:policy-source",
        rules=(ALLOW,),
    )
    replay = await _admitted_policy(
        tmp_path / "replay",
        sample_campaign,
        run_id="run_20260824T140100Z_b1c2d3e4",
        request_id="tool_cloud_policy_replay",
        execution_id="cloud-execution:policy-replay",
        rules=(ALLOW,),
    )

    validation = _bind(source, replay)

    assert validation.comparison is CloudPolicyReplayComparison.INPUT_AND_DECISION_MATCHED
    assert validation.state == "fresh-credential-policy-input-and-decision-match"
    assert validation.source_execution.evaluation.decision is CloudPolicyDecision.ALLOW
    assert validation.policy_input_matched is True
    assert validation.decision_matched is True
    assert validation.source_execution.action_permit.permit_id != (
        validation.replay_execution.action_permit.permit_id
    )
    assert validation.source_execution.preparation.credential_lease.lease_id_fingerprint != (
        validation.replay_execution.preparation.credential_lease.lease_id_fingerprint
    )
    assert validation.source_execution.execution_id != validation.replay_execution.execution_id
    assert validation.source_execution.policy_artifact.artifact_id != (
        validation.replay_execution.policy_artifact.artifact_id
    )
    assert validation.provider_policy_semantics_confirmed is False
    assert validation.effective_permission_confirmed is False
    assert validation.benchmark_measurement_observed is False
    assert validation.profile_validation_floor_satisfied is False
    assert validation.finding_authority is False
    assert validation.replay_authorized is False
    assert validation.execution_authorized is False
    serialized = json.dumps(validation.model_dump(mode="json", by_alias=True), sort_keys=True)
    assert "sanitized-out-of-band" not in serialized
    assert source.context.raw_lease_id not in serialized
    assert replay.context.raw_lease_id not in serialized
    assert (
        CloudPolicyFreshCredentialReplayValidation.model_validate(
            validation.model_dump(mode="json", by_alias=True)
        )
        == validation
    )


@pytest.mark.asyncio
async def test_replay_distinguishes_input_change_from_decision_change(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = await _admitted_policy(
        tmp_path / "source",
        sample_campaign,
        run_id="run_20260824T141000Z_c1d2e3f4",
        request_id="tool_cloud_policy_change_source",
        execution_id="cloud-execution:policy-change-source",
        rules=(ALLOW,),
    )
    same_decision = await _admitted_policy(
        tmp_path / "same-decision",
        sample_campaign,
        run_id="run_20260824T141100Z_d1e2f3a4",
        request_id="tool_cloud_policy_same_decision",
        execution_id="cloud-execution:policy-same-decision",
        rules=tuple(sorted((ALLOW, UNRELATED_ALLOW), key=lambda item: item.rule_id)),
    )
    changed_decision = await _admitted_policy(
        tmp_path / "changed-decision",
        sample_campaign,
        run_id="run_20260824T141200Z_e1f2a3b4",
        request_id="tool_cloud_policy_changed_decision",
        execution_id="cloud-execution:policy-changed-decision",
        rules=tuple(sorted((ALLOW, DENY), key=lambda item: item.rule_id)),
    )

    same = _bind(source, same_decision)
    changed = _bind(source, changed_decision)

    assert same.comparison is CloudPolicyReplayComparison.INPUT_CHANGED_DECISION_MATCHED
    assert same.state == "fresh-credential-policy-input-changed-decision-match"
    assert same.policy_input_matched is False
    assert same.decision_matched is True
    assert changed.comparison is CloudPolicyReplayComparison.DECISION_CHANGED
    assert changed.state == "fresh-credential-policy-decision-changed"
    assert changed.replay_execution.evaluation.decision is CloudPolicyDecision.EXPLICIT_DENY
    assert changed.provider_policy_semantics_confirmed is False
    assert changed.finding_authority is False


@pytest.mark.asyncio
async def test_replay_rejects_reused_authority_and_swapped_artifact(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = await _admitted_policy(
        tmp_path / "source",
        sample_campaign,
        run_id="run_20260824T142000Z_f1a2b3c4",
        request_id="tool_cloud_policy_reuse_source",
        execution_id="cloud-execution:policy-reuse-source",
        rules=(ALLOW,),
    )
    replay = await _admitted_policy(
        tmp_path / "replay",
        sample_campaign,
        run_id="run_20260824T142100Z_a2b3c4d5",
        request_id="tool_cloud_policy_reuse_replay",
        execution_id="cloud-execution:policy-reuse-replay",
        rules=(ALLOW,),
    )

    with pytest.raises(CloudPolicyReplayBenchmarkError, match="failed closed"):
        _bind(source, source)

    bad_reference = CloudPolicyArtifactSourceInputs(
        source_root=replay.context.source_inputs.source_root,
        artifact_reference="../cloud-policy-artifact.json",
    )
    with pytest.raises(CloudPolicyReplayBenchmarkError, match="failed closed"):
        CloudPolicyReplayBenchmarkGate(
            trust_anchor=source.context.trust_anchor
        ).bind_fresh_credential_replay(
            source.context.source_inputs,
            source.admission,
            source.artifact_inputs,
            replay.context.source_inputs,
            replay.admission,
            bad_reference,
            source_graph_store=source.context.graph_store,
            replay_graph_store=replay.context.graph_store,
        )

    replay.artifact_path.write_bytes(cloud_policy_artifact_bundle_bytes(source.bundle))
    with pytest.raises(CloudPolicyReplayBenchmarkError, match="failed closed"):
        _bind(source, replay)


@pytest.mark.asyncio
async def test_artifact_signature_tamper_fails_before_policy_comparison(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = await _admitted_policy(
        tmp_path / "source",
        sample_campaign,
        run_id="run_20260824T143000Z_b2c3d4e5",
        request_id="tool_cloud_policy_tamper_source",
        execution_id="cloud-execution:policy-tamper-source",
        rules=(ALLOW,),
    )
    replay = await _admitted_policy(
        tmp_path / "replay",
        sample_campaign,
        run_id="run_20260824T143100Z_c2d3e4f5",
        request_id="tool_cloud_policy_tamper_replay",
        execution_id="cloud-execution:policy-tamper-replay",
        rules=(ALLOW,),
    )
    payload = json.loads(replay.artifact_path.read_text(encoding="utf-8"))
    signature = payload["signatureBase64url"]
    payload["signatureBase64url"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    replay.artifact_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(CloudPolicyReplayBenchmarkError, match="signature verification"):
        _bind(source, replay)


def test_exact_evaluator_enforces_deny_override_and_implicit_negative() -> None:
    profile = registered_cloud_policy_benchmark_fixture_profile()

    assert profile.state == "registered-fixture-ground-truth-not-provisioned-or-measured"
    assert [case.fixture_id for case in profile.cases] == sorted(
        case.fixture_id for case in profile.cases
    )
    assert {case.ground_truth_class for case in profile.cases} == {
        CloudPolicyBenchmarkGroundTruthClass.KNOWN_ALLOW,
        CloudPolicyBenchmarkGroundTruthClass.EXPLICIT_DENY,
        CloudPolicyBenchmarkGroundTruthClass.NEGATIVE_CONTROL,
    }
    assert [case.expected_decision for case in profile.cases] == [
        CloudPolicyDecision.ALLOW,
        CloudPolicyDecision.EXPLICIT_DENY,
        CloudPolicyDecision.IMPLICIT_DENY,
    ]
    assert profile.disposable_environment_required is True
    assert profile.cleanup_evidence_required is True
    assert profile.provider_account_provisioned is False
    assert profile.emulator_provisioned is False
    assert profile.credential_lease_acquired is False
    assert profile.replay_evidence_bound is False
    assert profile.benchmark_measurement_observed is False
    assert profile.profile_validation_floor_satisfied is False
    assert profile.execution_authorized is False
    assert (
        CloudPolicyBenchmarkFixtureProfile.model_validate(
            profile.model_dump(mode="json", by_alias=True)
        )
        == profile
    )

    mutated = profile.model_dump(mode="json", by_alias=True)
    mutated["profileId"] = ""
    mutated["profileDigest"] = ""
    mutated["cases"][0]["expectedDecision"] = "explicit-deny"
    with pytest.raises(ValidationError, match="Ground Truth"):
        CloudPolicyBenchmarkFixtureProfile.model_validate(mutated)


@pytest.mark.asyncio
async def test_inventory_source_cannot_be_promoted_to_policy_artifact(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = await _context(
        tmp_path,
        sample_campaign,
        operation=CloudReadOnlyOperation.INVENTORY,
        run_id="run_20260824T144000Z_d2e3f4a5",
        request_id="tool_cloud_inventory_not_policy",
        execution_id="cloud-execution:inventory-not-policy",
    )
    candidate = context.gate.prepare_candidate(context.source_inputs, context.graph_binding)
    admission = context.gate.admit(context.source_inputs, candidate)
    source = load_verified_cloud_provider_observation_source(
        context.source_inputs,
        graph_store=context.graph_store,
        trust_anchor=context.trust_anchor,
    )

    with pytest.raises(CloudPolicyReplayBenchmarkError, match="failed closed"):
        derive_cloud_policy_sanitized_artifact(
            source=source,
            admission=admission,
            rules=(ALLOW,),
            query=QUERY,
            sanitized_at=NOW + timedelta(seconds=21),
        )


@pytest.mark.asyncio
async def test_replay_and_artifact_markers_reject_authority_escalation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = await _admitted_policy(
        tmp_path / "source",
        sample_campaign,
        run_id="run_20260824T145000Z_e2f3a4b5",
        request_id="tool_cloud_policy_marker_source",
        execution_id="cloud-execution:policy-marker-source",
        rules=(ALLOW,),
    )
    replay = await _admitted_policy(
        tmp_path / "replay",
        sample_campaign,
        run_id="run_20260824T145100Z_f2a3b4c5",
        request_id="tool_cloud_policy_marker_replay",
        execution_id="cloud-execution:policy-marker-replay",
        rules=(ALLOW,),
    )
    validation = _bind(source, replay)

    escalated = validation.model_dump(mode="json", by_alias=True)
    escalated["validationId"] = ""
    escalated["validationDigest"] = ""
    escalated["effectivePermissionConfirmed"] = True
    with pytest.raises(ValidationError, match="authority markers"):
        CloudPolicyFreshCredentialReplayValidation.model_validate(escalated)

    artifact_payload = source.bundle.artifact.model_dump(mode="json", by_alias=True)
    artifact_payload["artifactId"] = ""
    artifact_payload["artifactDigest"] = ""
    artifact_payload["providerPolicySemanticsConfirmed"] = True
    with pytest.raises(ValidationError, match="authority markers"):
        source.bundle.artifact.__class__.model_validate(artifact_payload)

    empty_payload = source.bundle.artifact.model_dump(mode="json", by_alias=True)
    empty_payload["artifactId"] = ""
    empty_payload["artifactDigest"] = ""
    empty_payload["rules"] = []
    empty_artifact = source.bundle.artifact.__class__.model_validate(empty_payload)
    assert evaluate_cloud_policy_artifact(empty_artifact).decision is (
        CloudPolicyDecision.IMPLICIT_DENY
    )

    duplicate_payload = source.bundle.artifact.model_dump(mode="json", by_alias=True)
    duplicate_payload["artifactId"] = ""
    duplicate_payload["artifactDigest"] = ""
    duplicate_rule = duplicate_payload["rules"][0].copy()
    duplicate_rule["ruleId"] = "rule:duplicate-policy-reader"
    duplicate_payload["rules"] = sorted(
        [*duplicate_payload["rules"], duplicate_rule],
        key=lambda rule: rule["ruleId"],
    )
    with pytest.raises(ValidationError, match="uniquely sorted"):
        source.bundle.artifact.__class__.model_validate(duplicate_payload)

    assert (
        evaluate_cloud_policy_artifact(source.bundle.artifact).decision is CloudPolicyDecision.ALLOW
    )
