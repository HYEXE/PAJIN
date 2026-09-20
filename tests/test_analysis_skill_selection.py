from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from pajin.domain.orchestration import AgentRole
from pajin.skills import (
    WRITE_WEB_SECURITY_FINDING_SKILL_ID,
    AnalysisSkillSelectionPolicy,
    SkillDefinitionError,
    SkillDefinitionRegistry,
    SkillLifecycleStage,
    SkillSelectionError,
    build_analysis_skill_instruction_projection_from_code_owned_policy,
    built_in_analysis_skill_registry,
    built_in_proposal_analysis_skill_registry,
    canonical_skill_json,
    qualify_proposal_only_skill_registry,
    resolve_installed_analysis_skill_registry,
    select_analysis_skills_from_code_owned_policy,
)

_CATALOGUED_REGISTRY_DIGEST = "4ca94d3a34ae73f6e468656901151f20da2ec582e314e9f56afff25722412898"
_PROPOSAL_REGISTRY_DIGEST = "88c3cf4d3127c1b8ef4cad1c57c7049277cb53a94c36e9aa660de60a71406343"
_QUALIFICATION_DIGEST = "65c98f083ecb6d5c7e32cf8620e5f3efd528911f21451993e3e79cd19536e4e6"
_SELECTION_POLICY_DIGEST = "a8a379cef12b5ee6999255b50921508089ac83a8152cf722dec8a2d94aa921d5"
_INSTRUCTION_PROJECTION_DIGEST = "5a1ae9195458bae3a07f98e6d88f8f8ee7bc175327d66b5aee980340c53a00c3"


def _selection_authority() -> tuple[object, object, object, AnalysisSkillSelectionPolicy]:
    predecessor = built_in_analysis_skill_registry()
    registry = built_in_proposal_analysis_skill_registry()
    qualification = qualify_proposal_only_skill_registry(
        predecessor_registry=predecessor,
        qualified_registry=registry,
    )
    allowed = tuple(binding.qualified for binding in qualification.bindings)
    definitions = tuple(registry.resolve(reference).definition for reference in allowed)
    policy = AnalysisSkillSelectionPolicy(
        policyId="",
        policyDigest="",
        registry=registry.reference(),
        qualificationId=qualification.qualification_id,
        qualificationDigest=qualification.qualification_digest,
        allowedSkillRefs=allowed,
        agentRole=AgentRole.PLANNER,
        domainClassification=definitions[0].domain_classifications[0],
        surfaceType="web.http-operation",
        allowedHypothesisIds=tuple(
            sorted({item for definition in definitions for item in definition.hypothesis_types})
        ),
        maxSelectedSkills=4,
        maxProjectedInstructionBytes=32 * 1024,
        selectionBasis="code-owned-metadata-intersection",
        targetContentUsedForSelection=False,
        modelSelectedSkills=False,
        scopeExpansionAuthority=False,
        recipeBindingAuthority=False,
        capabilityAuthority=False,
        permitAuthority=False,
        executionAuthority=False,
    )
    return predecessor, registry, qualification, policy


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for item in value.values() for key in _all_keys(item)}
    if isinstance(value, list):
        return {key for item in value for key in _all_keys(item)}
    return set()


def test_proposal_registry_is_exact_cumulative_and_preserves_catalogued_identity() -> None:
    predecessor, registry, qualification, _policy = _selection_authority()

    assert predecessor.reference().registry_version == "1.0.0"
    assert predecessor.registry_digest == _CATALOGUED_REGISTRY_DIGEST
    assert registry.reference().registry_version == "1.1.0"
    assert registry.registry_digest == _PROPOSAL_REGISTRY_DIGEST
    assert len(registry.references()) == 9
    assert len(qualification.bindings) == 4
    assert qualification.qualification_digest == _QUALIFICATION_DIGEST
    assert all(
        registry.resolve(binding.predecessor).definition.lifecycle_stage
        is SkillLifecycleStage.CATALOGUED
        for binding in qualification.bindings
    )
    assert all(
        registry.resolve(binding.qualified).definition.lifecycle_stage
        is SkillLifecycleStage.PROPOSAL_ONLY
        for binding in qualification.bindings
    )
    finding = tuple(
        item
        for item in registry.definitions()
        if item.skill_id == WRITE_WEB_SECURITY_FINDING_SKILL_ID
    )
    assert len(finding) == 1
    assert finding[0].skill_version == "1.0.0"
    assert finding[0].lifecycle_stage is SkillLifecycleStage.CATALOGUED


def test_installed_registry_resolution_is_exact_without_latest_or_substitution() -> None:
    predecessor, registry, _qualification, _policy = _selection_authority()

    assert resolve_installed_analysis_skill_registry(predecessor.reference()).reference() == (
        predecessor.reference()
    )
    assert resolve_installed_analysis_skill_registry(registry.reference()).reference() == (
        registry.reference()
    )
    wrong = registry.reference().model_copy(update={"registry_digest": "0" * 64})
    with pytest.raises(ValueError, match="exact installed"):
        resolve_installed_analysis_skill_registry(wrong)
    with pytest.raises(SkillDefinitionError, match="exact semantic version"):
        SkillDefinitionRegistry(
            tuple(predecessor.resolve(item) for item in predecessor.references()),
            registry_version="latest",
        )
    hidden = registry.reference().model_copy(update={"registryDigest": "0" * 64})
    with pytest.raises(SkillDefinitionError, match="undeclared model state"):
        resolve_installed_analysis_skill_registry(hidden)


def test_qualification_rejects_self_consistent_uninstalled_registry() -> None:
    predecessor = built_in_analysis_skill_registry()
    installed = built_in_proposal_analysis_skill_registry()
    foreign = SkillDefinitionRegistry(
        tuple(installed.resolve(item) for item in installed.references()),
        registry_version="9.9.9",
    )

    with pytest.raises(SkillSelectionError, match="failed closed"):
        qualify_proposal_only_skill_registry(
            predecessor_registry=predecessor,
            qualified_registry=foreign,
        )


def test_selection_returns_only_four_qualified_pre_execution_skills() -> None:
    _predecessor, registry, qualification, policy = _selection_authority()

    receipt, selected = select_analysis_skills_from_code_owned_policy(
        registry=registry,
        qualification=qualification,
        policy=policy,
    )
    projection = build_analysis_skill_instruction_projection_from_code_owned_policy(
        registry=registry,
        qualification=qualification,
        policy=policy,
        receipt=receipt,
    )

    assert receipt.considered_skill_count == 4
    assert receipt.selected_skill_count == 4
    assert receipt.projected_instruction_bytes == 7_475
    assert tuple(item.definition.reference() for item in selected) == receipt.selected_skill_refs
    assert (
        tuple(item.skill_ref for item in projection.selected_skills) == receipt.selected_skill_refs
    )
    assert all(item.required_evidence_satisfied is False for item in projection.selected_skills)
    assert receipt.required_evidence_satisfaction_claimed is False
    assert projection.developer_message_eligible is True
    assert policy.policy_digest == _SELECTION_POLICY_DIGEST
    assert projection.projection_digest == _INSTRUCTION_PROJECTION_DIGEST
    assert projection.user_evidence_message_embedded is False
    assert all(
        item.skill_ref.skill_id != WRITE_WEB_SECURITY_FINDING_SKILL_ID
        for item in projection.selected_skills
    )

    encoded = canonical_skill_json(
        projection.model_dump(mode="json", by_alias=True),
        label="test Skill instruction projection",
    )
    assert b"Draft a concise security Finding narrative" not in encoded
    assert b"juice shop" not in encoded.lower()


def test_selection_rejects_catalogued_unqualified_and_digest_substituted_refs() -> None:
    predecessor, registry, qualification, policy = _selection_authority()
    catalogued_ref = predecessor.references()[0]
    raw = policy.model_dump(mode="json", by_alias=True)
    raw["policyId"] = ""
    raw["policyDigest"] = ""
    raw["allowedSkillRefs"][0] = catalogued_ref.model_dump(mode="json", by_alias=True)
    forged_policy = AnalysisSkillSelectionPolicy.model_validate(raw)
    with pytest.raises(SkillSelectionError, match="failed closed"):
        select_analysis_skills_from_code_owned_policy(
            registry=registry,
            qualification=qualification,
            policy=forged_policy,
        )

    raw = policy.model_dump(mode="json", by_alias=True)
    raw["policyId"] = ""
    raw["policyDigest"] = ""
    raw["allowedSkillRefs"][0]["instructionDigest"] = "0" * 64
    forged_policy = AnalysisSkillSelectionPolicy.model_validate(raw)
    with pytest.raises(SkillSelectionError, match="failed closed"):
        select_analysis_skills_from_code_owned_policy(
            registry=registry,
            qualification=qualification,
            policy=forged_policy,
        )


def test_selection_rejects_role_hypothesis_count_and_byte_budget_mismatch() -> None:
    _predecessor, registry, qualification, policy = _selection_authority()

    for update in (
        {"agent_role": AgentRole.REPORTER, "policy_digest": ""},
        {"allowed_hypothesis_ids": ("pajin.example.unrelated",), "policy_digest": ""},
        {"max_selected_skills": 3, "policy_digest": ""},
        {"max_projected_instruction_bytes": 7_474, "policy_digest": ""},
    ):
        changed = policy.model_copy(update=update)
        with pytest.raises(SkillSelectionError, match="failed closed"):
            select_analysis_skills_from_code_owned_policy(
                registry=registry,
                qualification=qualification,
                policy=changed,
            )


def test_selection_revalidates_model_copy_and_requires_literal_budget_integers() -> None:
    _predecessor, registry, qualification, policy = _selection_authority()

    hidden_stale = policy.model_copy(update={"max_selected_skills": 3})
    with pytest.raises(SkillSelectionError, match="failed closed"):
        select_analysis_skills_from_code_owned_policy(
            registry=registry,
            qualification=qualification,
            policy=hidden_stale,
        )

    hidden_alias_state = policy.model_copy(update={"executionAuthority": True})
    with pytest.raises(SkillSelectionError, match="failed closed"):
        select_analysis_skills_from_code_owned_policy(
            registry=registry,
            qualification=qualification,
            policy=hidden_alias_state,
        )

    raw = policy.model_dump(mode="json", by_alias=True)
    raw["policyId"] = ""
    raw["policyDigest"] = ""
    raw["maxSelectedSkills"] = True
    with pytest.raises(ValidationError):
        AnalysisSkillSelectionPolicy.model_validate(raw)


def test_selection_rejects_cyclic_model_copy_state_without_hanging() -> None:
    _predecessor, registry, qualification, policy = _selection_authority()
    cyclic_refs: list[object] = []
    cyclic_refs.append(cyclic_refs)
    forged_policy = policy.model_copy(update={"allowed_skill_refs": cyclic_refs})

    with pytest.raises(SkillSelectionError, match="failed closed"):
        select_analysis_skills_from_code_owned_policy(
            registry=registry,
            qualification=qualification,
            policy=forged_policy,
        )


@pytest.mark.parametrize("use_installed_predecessor", [False, True])
def test_selection_rejects_self_consistent_forged_qualification(
    use_installed_predecessor: bool,
) -> None:
    predecessor, registry, qualification, policy = _selection_authority()
    raw_qualification = qualification.model_dump(mode="json", by_alias=True)
    raw_qualification["qualificationId"] = ""
    raw_qualification["qualificationDigest"] = ""
    raw_qualification["bindings"] = raw_qualification["bindings"][:1]
    if not use_installed_predecessor:
        raw_qualification["predecessorRegistry"] = {
            "registryId": "pajin.analysis-skills",
            "registryVersion": "0.0.1",
            "registryDigest": "2" * 64,
        }
    forged_qualification = type(qualification).model_validate(raw_qualification)

    raw_policy = policy.model_dump(mode="json", by_alias=True)
    raw_policy["policyId"] = ""
    raw_policy["policyDigest"] = ""
    raw_policy["qualificationId"] = forged_qualification.qualification_id
    raw_policy["qualificationDigest"] = forged_qualification.qualification_digest
    raw_policy["allowedSkillRefs"] = [
        forged_qualification.bindings[0].qualified.model_dump(mode="json", by_alias=True)
    ]
    forged_policy = AnalysisSkillSelectionPolicy.model_validate(raw_policy)

    with pytest.raises(SkillSelectionError, match="failed closed"):
        select_analysis_skills_from_code_owned_policy(
            registry=registry,
            qualification=forged_qualification,
            policy=forged_policy,
        )

    assert predecessor.reference() == qualification.predecessor_registry


def test_selected_projection_contains_no_execution_or_target_fields() -> None:
    _predecessor, registry, qualification, policy = _selection_authority()
    receipt, _selected = select_analysis_skills_from_code_owned_policy(
        registry=registry,
        qualification=qualification,
        policy=policy,
    )
    projection = build_analysis_skill_instruction_projection_from_code_owned_policy(
        registry=registry,
        qualification=qualification,
        policy=policy,
        receipt=receipt,
    )
    raw = projection.model_dump(mode="json", by_alias=True)

    assert not (
        _all_keys(raw)
        & {
            "callable",
            "command",
            "credential",
            "groundTruth",
            "importPath",
            "payload",
            "permit",
            "recipe",
            "route",
            "scope",
            "selector",
            "target",
            "tool",
        }
    )
    assert raw["executionAuthority"] is False
    assert raw["capabilityAuthority"] is False
    assert raw["permitAuthority"] is False
    assert raw["graphAdmissionAuthority"] is False
    assert raw["findingAuthority"] is False
    assert raw["reportDeliveryAuthority"] is False


def test_selection_and_projection_are_deterministic_and_digest_bound() -> None:
    _predecessor, registry, qualification, policy = _selection_authority()
    first_receipt, _ = select_analysis_skills_from_code_owned_policy(
        registry=registry,
        qualification=qualification,
        policy=policy,
    )
    second_receipt, _ = select_analysis_skills_from_code_owned_policy(
        registry=registry,
        qualification=qualification,
        policy=policy,
    )
    first = build_analysis_skill_instruction_projection_from_code_owned_policy(
        registry=registry,
        qualification=qualification,
        policy=policy,
        receipt=first_receipt,
    )
    second = build_analysis_skill_instruction_projection_from_code_owned_policy(
        registry=registry,
        qualification=qualification,
        policy=policy,
        receipt=second_receipt,
    )

    assert first_receipt == second_receipt
    assert first == second
    raw = json.loads(first.model_dump_json(by_alias=True))
    raw["selectedSkills"][0]["objective"] = "drifted"
    with pytest.raises(ValidationError, match="digest differs"):
        type(first).model_validate(raw)
