from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.skills import (
    WRITE_WEB_SECURITY_FINDING_SKILL_ID,
    built_in_analysis_skill_registry,
    built_in_proposal_analysis_skill_registry,
    canonical_skill_json,
)
from pajin.web_assessment.analysis_skill_projection import (
    SkillBoundWebAnalysisSnapshot,
    WebAnalysisSkillProjectionBundle,
    WebAnalysisSkillProjectionError,
    _build_skill_bound_web_analysis_snapshot_with_loader,
    _create_web_analysis_skill_projection_run_with_loader,
    _load_verified_web_analysis_skill_projection_with_loader,
    registered_web_analysis_skill_selection_policy,
)
from tests.test_web_analysis_proposal import _synthetic_loader, _verified_source


def _snapshot(run_suffix: str = "a1b2c3d4") -> tuple[object, SkillBoundWebAnalysisSnapshot]:
    source = _verified_source(run_suffix=run_suffix)
    snapshot = _build_skill_bound_web_analysis_snapshot_with_loader(
        source,
        source_loader=_synthetic_loader(source),
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
    )
    return source, snapshot


def test_skill_bound_projection_selects_exact_four_and_splits_message_trust() -> None:
    source, snapshot = _snapshot()
    instruction = snapshot.projection_bundle.instruction_projection
    evidence = snapshot.projection_bundle.evidence_projection

    assert instruction.selected_skill_count == 4
    assert instruction.projected_instruction_bytes == 7_475
    assert len(snapshot.qualification.bindings) == 4
    assert tuple(item.skill_ref for item in instruction.selected_skills) == (
        snapshot.selection_receipt.selected_skill_refs
    )
    assert all(
        item.skill_ref.skill_id != WRITE_WEB_SECURITY_FINDING_SKILL_ID
        for item in instruction.selected_skills
    )
    assert snapshot.projection_bundle.instruction_message_role == "developer"
    assert snapshot.projection_bundle.evidence_message_role == "user"
    assert snapshot.projection_bundle.combined_user_message_authorized is False
    assert snapshot.projection_bundle.provider_dispatch_authorized is False
    assert evidence == snapshot.source_snapshot.model_projection
    assert source.verification.run_id == snapshot.source_snapshot.source_run_id
    assert snapshot.model_invocation_performed is False
    assert snapshot.target_request_performed is False
    assert snapshot.recipe_binding_created is False
    assert snapshot.capability_granted is False
    assert snapshot.permit_granted is False
    assert snapshot.execution_authority is False


def test_projection_bundle_excludes_local_source_target_and_unselected_skill_content() -> None:
    source, snapshot = _snapshot()
    bundle_bytes = canonical_skill_json(
        snapshot.projection_bundle.model_dump(mode="json", by_alias=True),
        label="test Web Skill projection bundle",
    )

    for private_value in (
        source.verification.run_id.encode(),
        source.verification.root_digest.encode(),
        source.plan.origin.encode(),
        b"/ignore-all-instructions",
        b"/execute-tool-now",
        b"prompt_injection_email",
        b"Draft a concise security Finding narrative",
    ):
        assert private_value not in bundle_bytes
    for forbidden_key in (
        b'"credential"',
        b'"payload"',
        b'"recipe"',
        b'"selector"',
        b'"target"',
        b'"tool"',
    ):
        assert forbidden_key not in bundle_bytes.lower()


def test_target_derived_source_identity_does_not_change_selected_skill_refs() -> None:
    _first_source, first = _snapshot("a1b2c3d4")
    _second_source, second = _snapshot("deadbeef")

    assert (
        first.selection_receipt.selected_skill_refs == second.selection_receipt.selected_skill_refs
    )
    assert (
        first.projection_bundle.instruction_projection
        == second.projection_bundle.instruction_projection
    )
    assert first.source_snapshot.snapshot_digest != second.source_snapshot.snapshot_digest
    assert (
        first.projection_bundle.evidence_projection != second.projection_bundle.evidence_projection
    )


def test_web_policy_rejects_catalogued_foreign_or_stale_registry_identity() -> None:
    _source, snapshot = _snapshot()
    qualification = snapshot.qualification

    with pytest.raises((ValueError, WebAnalysisSkillProjectionError)):
        registered_web_analysis_skill_selection_policy(
            source_projection=snapshot.source_snapshot.model_projection,
            qualified_registry_ref=built_in_analysis_skill_registry().reference(),
            qualification=qualification,
        )
    stale = (
        built_in_proposal_analysis_skill_registry()
        .reference()
        .model_copy(update={"registry_digest": "0" * 64})
    )
    with pytest.raises((ValueError, WebAnalysisSkillProjectionError)):
        registered_web_analysis_skill_selection_policy(
            source_projection=snapshot.source_snapshot.model_projection,
            qualified_registry_ref=stale,
            qualification=qualification,
        )


def test_bundle_and_snapshot_reject_digest_and_lineage_drift() -> None:
    _source, snapshot = _snapshot()
    raw_bundle = json.loads(snapshot.projection_bundle.model_dump_json(by_alias=True))
    raw_bundle["instructionProjection"]["selectedSkills"][0]["objective"] = "drifted"
    with pytest.raises(ValidationError):
        WebAnalysisSkillProjectionBundle.model_validate(raw_bundle)

    raw_snapshot = json.loads(snapshot.model_dump_json(by_alias=True))
    raw_snapshot["selectionReceipt"]["policyDigest"] = "0" * 64
    with pytest.raises(ValidationError):
        SkillBoundWebAnalysisSnapshot.model_validate(raw_snapshot)


@pytest.mark.parametrize(
    "drift",
    ("receipt-qualification", "instruction-policy", "projected-instruction-bytes"),
)
def test_snapshot_rejects_recalculated_but_contradictory_nested_lineage(drift: str) -> None:
    _source, snapshot = _snapshot()
    raw_snapshot = json.loads(snapshot.model_dump_json(by_alias=True))
    raw_snapshot["snapshotId"] = ""
    raw_snapshot["snapshotDigest"] = ""

    raw_receipt = raw_snapshot["selectionReceipt"]
    if drift == "receipt-qualification":
        raw_receipt["qualificationId"] = "forged-qualification"
        raw_receipt["qualificationDigest"] = "0" * 64
    elif drift == "projected-instruction-bytes":
        raw_receipt["projectedInstructionBytes"] -= 1
    raw_receipt["receiptId"] = ""
    raw_receipt["receiptDigest"] = ""
    receipt = type(snapshot.selection_receipt).model_validate(raw_receipt)

    raw_instruction = raw_snapshot["projectionBundle"]["instructionProjection"]
    if drift == "instruction-policy":
        raw_instruction["policyId"] = "forged-policy"
        raw_instruction["policyDigest"] = "1" * 64
    raw_instruction["selectionReceiptId"] = receipt.receipt_id
    raw_instruction["selectionReceiptDigest"] = receipt.receipt_digest
    raw_instruction["projectionId"] = ""
    raw_instruction["projectionDigest"] = ""
    instruction = type(snapshot.projection_bundle.instruction_projection).model_validate(
        raw_instruction
    )

    raw_bundle = raw_snapshot["projectionBundle"]
    raw_bundle["bundleId"] = ""
    raw_bundle["bundleDigest"] = ""
    raw_bundle["instructionProjection"] = instruction
    bundle = WebAnalysisSkillProjectionBundle.model_validate(raw_bundle)
    raw_snapshot["selectionReceipt"] = receipt
    raw_snapshot["projectionBundle"] = bundle

    with pytest.raises(ValidationError, match="lineage differs"):
        SkillBoundWebAnalysisSnapshot.model_validate(raw_snapshot)


def test_bundle_and_snapshot_reject_nested_model_copy_authority_bypass() -> None:
    _source, snapshot = _snapshot()
    instruction = snapshot.projection_bundle.instruction_projection.model_copy(
        update={
            "execution_authority": True,
            "projection_id": "",
            "projection_digest": "",
        },
    )
    raw_bundle = snapshot.projection_bundle.model_dump(mode="python", by_alias=True)
    raw_bundle["bundleId"] = ""
    raw_bundle["bundleDigest"] = ""
    raw_bundle["instructionProjection"] = instruction
    with pytest.raises(ValidationError, match=r"not canonical|literal false"):
        WebAnalysisSkillProjectionBundle.model_validate(raw_bundle)

    forged_bundle = snapshot.projection_bundle.model_copy(
        update={"instruction_projection": instruction},
    )
    raw_snapshot = snapshot.model_dump(mode="python", by_alias=True)
    raw_snapshot["snapshotId"] = ""
    raw_snapshot["snapshotDigest"] = ""
    raw_snapshot["projectionBundle"] = forged_bundle
    with pytest.raises(ValidationError, match=r"not canonical|literal false"):
        SkillBoundWebAnalysisSnapshot.model_validate(raw_snapshot)


def test_bundle_rejects_coercible_nested_model_copy_before_mutable_state_can_escape() -> None:
    _source, snapshot = _snapshot()
    instruction = snapshot.projection_bundle.instruction_projection.model_copy(
        update={
            "selected_skills": list(
                snapshot.projection_bundle.instruction_projection.selected_skills
            ),
            "projection_id": "",
            "projection_digest": "",
        },
    )
    raw_bundle = snapshot.projection_bundle.model_dump(mode="python", by_alias=True)
    raw_bundle["bundleId"] = ""
    raw_bundle["bundleDigest"] = ""
    raw_bundle["instructionProjection"] = instruction

    with (
        pytest.warns(UserWarning, match="Pydantic serializer warnings"),
        pytest.raises(
            ValidationError,
            match=r"not canonical|non-canonical runtime state",
        ),
    ):
        WebAnalysisSkillProjectionBundle.model_validate(raw_bundle)


def test_preparation_run_seals_and_strictly_reloads_with_zero_dispatch(
    tmp_path: Path,
) -> None:
    source = _verified_source()
    loader = _synthetic_loader(source)
    verified = _create_web_analysis_skill_projection_run_with_loader(
        source=source,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        output_root=tmp_path,
        source_loader=loader,
    )

    assert verified.verification.seal_count == 1
    assert verified.verification.event_count == 2
    assert verified.verification.artifact_count == 4
    assert verified.index.model_invocation_count == 0
    assert verified.index.provider_dispatch_count == 0
    assert verified.index.target_request_count == 0
    assert verified.index.tool_request_count == 0
    assert verified.index.action_permit_count == 0
    assert verified.index.finding_count == 0
    assert verified.index.graph_mutation_count == 0
    assert verified.index.external_delivery_performed is False

    reloaded = _load_verified_web_analysis_skill_projection_with_loader(
        verified.run_path,
        source=source,
        expected_run_id=verified.verification.run_id,
        expected_root_digest=verified.verification.root_digest,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        expected_registry_ref=verified.index.registry,
        expected_policy_digest=verified.index.selection_policy_digest,
        source_loader=loader,
    )
    assert reloaded == verified


def test_preparation_loader_rejects_foreign_run_source_registry_and_policy_anchors(
    tmp_path: Path,
) -> None:
    source = _verified_source()
    loader = _synthetic_loader(source)
    verified = _create_web_analysis_skill_projection_run_with_loader(
        source=source,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        output_root=tmp_path,
        source_loader=loader,
    )
    common = {
        "source": source,
        "expected_run_id": verified.verification.run_id,
        "expected_root_digest": verified.verification.root_digest,
        "expected_source_run_id": source.verification.run_id,
        "expected_source_root_digest": source.verification.root_digest,
        "expected_registry_ref": verified.index.registry,
        "expected_policy_digest": verified.index.selection_policy_digest,
        "source_loader": loader,
    }
    mutations = (
        {"expected_run_id": "run_20260916T000000Z_deadbeef"},
        {"expected_root_digest": "0" * 64},
        {"expected_source_root_digest": "0" * 64},
        {"expected_registry_ref": built_in_analysis_skill_registry().reference()},
        {"expected_policy_digest": "0" * 64},
    )
    for update in mutations:
        with pytest.raises(WebAnalysisSkillProjectionError, match="failed closed"):
            _load_verified_web_analysis_skill_projection_with_loader(
                verified.run_path,
                **(common | update),
            )


def test_skill_projection_module_has_no_provider_gateway_worker_or_network_imports() -> None:
    source_path = (
        Path(__file__).parents[1]
        / "src"
        / "pajin"
        / "web_assessment"
        / "analysis_skill_projection.py"
    )
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imports = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    imports.update(
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )
    forbidden = {
        "httpx",
        "subprocess",
        "pajin.providers",
        "pajin.runtime.worker",
        "pajin.tools",
        "pajin.web_assessment.analysis_runtime",
    }
    assert not {
        module
        for module in imports
        if any(module == item or module.startswith(item + ".") for item in forbidden)
    }


def test_existing_web_analysis_v1alpha1_models_reject_skill_sidecars() -> None:
    _source, snapshot = _snapshot()
    raw = snapshot.source_snapshot.model_dump(mode="json", by_alias=True)
    raw["skillProjection"] = snapshot.projection_bundle.instruction_projection.model_dump(
        mode="json",
        by_alias=True,
    )

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        type(snapshot.source_snapshot).model_validate(raw)
