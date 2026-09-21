from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

import pytest
from pydantic import ValidationError

from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.tools.ai import ChatRole
from pajin.web_assessment.analysis_skill_compact import (
    COMPACT_SKILL_BOUND_GLOBAL_SAFETY_INSTRUCTION,
    COMPACT_SKILL_BOUND_SYSTEM_SENTINEL,
    COMPACT_SKILL_BOUND_USER_SENTINEL,
    CompactSkillBoundWebAnalysisError,
    CompactSkillBoundWebAnalysisProjection,
    build_compact_skill_bound_web_analysis_chat_request,
    build_compact_skill_bound_web_analysis_projection,
)
from pajin.web_assessment.analysis_skill_invocation import (
    SkillBoundWebAnalysisProposalDraft,
)
from tests.test_web_analysis_skill_projection import _snapshot


def _prepared():
    _source, snapshot = _snapshot()
    projection = build_compact_skill_bound_web_analysis_projection(snapshot)
    chat = build_compact_skill_bound_web_analysis_chat_request(snapshot)
    return snapshot, projection, chat


def _keys(value: object) -> set[str]:
    if isinstance(value, Mapping):
        return {str(key) for key in value} | {
            nested for item in value.values() for nested in _keys(item)
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return {nested for item in value for nested in _keys(item)}
    return set()


def test_compact_projection_and_request_are_deterministic_and_capacity_bounded() -> None:
    snapshot, first, first_chat = _prepared()
    second = build_compact_skill_bound_web_analysis_projection(snapshot)
    second_chat = build_compact_skill_bound_web_analysis_chat_request(snapshot)

    assert first == second
    assert first_chat == second_chat
    assert first.projection_digest == second.projection_digest
    assert first.system_message.safety == COMPACT_SKILL_BOUND_GLOBAL_SAFETY_INSTRUCTION
    assert first.system_message.sentinel == COMPACT_SKILL_BOUND_SYSTEM_SENTINEL
    assert first.user_message.sentinel == COMPACT_SKILL_BOUND_USER_SENTINEL
    assert len(first.system_message_digest) == len(first.user_message_digest) == 64
    for field_name in (
        "provider_dispatch_authority",
        "target_request_authority",
        "scope_expansion_authority",
        "tool_request_authority",
        "capability_authority",
        "permit_authority",
        "execution_authority",
        "graph_admission_authority",
        "finding_authority",
        "report_delivery_authority",
        "automatic_redispatch_authority",
    ):
        assert getattr(first, field_name) is False
    request_bytes = canonical_json_bytes(
        first_chat.model_dump(mode="json", by_alias=True),
        label="test compact Skill-bound request",
    )
    assert len(request_bytes) <= 65_536


def test_compact_request_has_exact_roles_parameters_and_legacy_schema() -> None:
    _snapshot_value, projection, chat = _prepared()

    assert [message.role for message in chat.messages] == [ChatRole.SYSTEM, ChatRole.USER]
    system = json.loads(chat.messages[0].content or "")
    user = json.loads(chat.messages[1].content or "")
    assert set(system) == {"safety", "u", "instructionProjectionDigest", "selectedSkills"}
    assert all(
        set(skill)
        == {
            "skillId",
            "version",
            "hypothesisIds",
            "objective",
            "evidenceRequirements",
            "falsePositiveControls",
        }
        for skill in system["selectedSkills"]
    )
    assert set(user) == {"pi", "pd", "t", "u", "a", "d", "p", "e"}
    assert user["t"] is True
    assert len(user["d"]) == 3
    assert len(user["p"]) == 2
    assert chat.stream is False
    assert chat.tools == []
    assert chat.tool_choice == "none"
    assert chat.max_completion_tokens == 1024
    assert chat.temperature == 0.0
    assert chat.top_p == 1.0
    assert chat.seed == 0
    assert chat.parallel_tool_calls is False
    assert chat.response_format is not None
    schema_definition = chat.response_format.json_schema
    assert schema_definition.name == "skill_bound_web_analysis_proposal_draft"
    assert schema_definition.strict is True
    serialized = schema_definition.model_dump(mode="json", by_alias=True)
    assert serialized["schema"] == SkillBoundWebAnalysisProposalDraft.model_json_schema(
        mode="validation", by_alias=True
    )
    assert projection.user_message.original_projection_digest == (
        projection.lineage.evidence_projection_digest
    )


def test_compact_projection_preserves_full_snapshot_lineage_and_exact_alias_mapping() -> None:
    snapshot, projection, _chat = _prepared()
    source = snapshot.source_snapshot
    lineage = projection.lineage
    assert lineage.model_dump(mode="json", by_alias=True) == {
        "skillBoundSnapshotDigest": snapshot.snapshot_digest,
        "sourceSnapshotDigest": source.snapshot_digest,
        "sourceRootDigest": source.source_root_digest,
        "sourceIndexDigest": source.source_index_digest,
        "sourcePlanDigest": source.source_plan_digest,
        "sourceDiscoveryEvidenceDigest": source.source_discovery_evidence_digest,
        "sourceDiscoveryPlanDigest": source.source_discovery_plan_digest,
        "sourceDiscoveryResultDigest": source.source_discovery_result_digest,
        "profileRegistryDigest": source.profile_registry_digest,
        "profileDigest": source.profile_digest,
        "adapterCatalogDigest": source.adapter_catalog_digest,
        "diagnosticCatalogDigest": source.diagnostic_catalog_digest,
        "diagnosticBundleDigest": source.diagnostic_bundle_digest,
        "adapterImplementationDigest": source.adapter_implementation_digest,
        "executorImplementationDigest": source.executor_implementation_digest,
        "pathBuilderImplementationDigest": source.path_builder_implementation_digest,
        "registryDigest": snapshot.selection_receipt.registry.registry_digest,
        "qualificationDigest": snapshot.qualification.qualification_digest,
        "selectionPolicySchemaDigest": snapshot.qualification.selection_policy_schema_digest,
        "instructionProjectionSchemaDigest": (
            snapshot.qualification.instruction_projection_schema_digest
        ),
        "selectionPolicyDigest": snapshot.selection_policy.policy_digest,
        "selectionReceiptDigest": snapshot.selection_receipt.receipt_digest,
        "projectionBundleDigest": snapshot.projection_bundle.bundle_digest,
        "instructionProjectionDigest": (
            snapshot.projection_bundle.instruction_projection.projection_digest
        ),
        "evidenceProjectionDigest": source.model_projection.projection_digest,
    }

    aliases = {
        item.alias: item.catalog_entry_id for item in projection.user_message.catalog_aliases
    }
    original = source.model_projection
    assert [aliases[item.catalog_alias] for item in projection.user_message.diagnostics] == [
        item.catalog_entry_id for item in original.diagnostics
    ]
    assert [aliases[item.catalog_alias] for item in projection.user_message.paths] == [
        item.catalog_entry_id for item in original.attack_paths
    ]
    for compact, exact in zip(
        projection.user_message.evidence_signals,
        original.evidence_signals,
        strict=True,
    ):
        assert tuple(sorted(aliases[item] for item in compact.supports)) == (
            exact.supports_catalog_entries
        )


@pytest.mark.parametrize(
    "mutation",
    ("tamper", "reorder", "alias-map", "extra", "authority", "python-field-name"),
)
def test_compact_projection_rejects_tamper_reorder_extra_and_authority(mutation: str) -> None:
    _snapshot_value, projection, _chat = _prepared()
    raw = json.loads(projection.model_dump_json(by_alias=True))
    if mutation == "tamper":
        raw["userMessage"]["pd"] = "0" * 64
    elif mutation == "reorder":
        raw["userMessage"]["d"].reverse()
    elif mutation == "alias-map":
        aliases = raw["userMessage"]["a"]
        aliases[0]["id"], aliases[1]["id"] = aliases[1]["id"], aliases[0]["id"]
    elif mutation == "extra":
        raw["userMessage"]["payload"] = "forbidden"
    elif mutation == "authority":
        raw["executionAuthority"] = True
    else:
        raw["execution_authority"] = raw.pop("executionAuthority")
    with pytest.raises(ValidationError):
        CompactSkillBoundWebAnalysisProjection.model_validate(raw)

    hidden = projection.model_copy(update={"execution_authority": True})
    with pytest.raises(CompactSkillBoundWebAnalysisError):
        build_compact_skill_bound_web_analysis_chat_request(hidden)


def test_model_visible_content_omits_repeated_and_executable_material() -> None:
    _snapshot_value, _projection, chat = _prepared()
    content = [json.loads(message.content or "") for message in chat.messages]
    keys = _keys(content)
    assert keys.isdisjoint(
        {
            "workflowSteps",
            "safetyConstraints",
            "requiredEvidenceTypes",
            "provenance",
            "target",
            "targets",
            "route",
            "routes",
            "payload",
            "payloads",
            "credential",
            "credentials",
            "action",
            "actions",
        }
    )
    assert "skillDigest" not in keys
    assert "instructionDigest" not in keys
    assert "inputSchemaDigest" not in keys
    assert "outputSchemaDigest" not in keys
