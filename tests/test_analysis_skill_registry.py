from __future__ import annotations

import ast
from hashlib import sha256
from operator import delitem
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.skills import (
    ASSESS_WEB_OBJECT_ACCESS_SKILL_ID,
    ASSESS_WEB_SQLI_SKILL_ID,
    ASSESS_WEB_XSS_SKILL_ID,
    COMPOSE_WEB_ATTACK_PATH_SKILL_ID,
    WRITE_WEB_SECURITY_FINDING_SKILL_ID,
    RegisteredSkill,
    SkillDefinition,
    SkillDefinitionError,
    SkillDefinitionRef,
    SkillDefinitionRegistry,
    SkillInstructionBundle,
    SkillLifecycleStage,
    SkillProvenance,
    SkillSourceKind,
    built_in_analysis_skill_registry,
    canonical_skill_json,
    skill_schema_digest,
)

_DIGEST_A = sha256(b"a").hexdigest()
_EXPECTED_REGISTRY_DIGEST = "4ca94d3a34ae73f6e468656901151f20da2ec582e314e9f56afff25722412898"
_EXPECTED_SKILL_IDS = (
    ASSESS_WEB_OBJECT_ACCESS_SKILL_ID,
    ASSESS_WEB_SQLI_SKILL_ID,
    ASSESS_WEB_XSS_SKILL_ID,
    COMPOSE_WEB_ATTACK_PATH_SKILL_ID,
    WRITE_WEB_SECURITY_FINDING_SKILL_ID,
)


def _raw_entry(skill_id: str = ASSESS_WEB_SQLI_SKILL_ID) -> dict[str, object]:
    registry = built_in_analysis_skill_registry()
    reference = next(item for item in registry.references() if item.skill_id == skill_id)
    return registry.resolve(reference).model_dump(mode="json", by_alias=True)


def _all_keys(value: object) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            keys.add(str(key))
            keys.update(_all_keys(nested))
    elif isinstance(value, list):
        for nested in value:
            keys.update(_all_keys(nested))
    return keys


def test_built_in_registry_is_deterministic_catalogued_and_metadata_first() -> None:
    first = built_in_analysis_skill_registry()
    second = built_in_analysis_skill_registry()
    reversed_registry = SkillDefinitionRegistry(
        tuple(first.resolve(reference) for reference in reversed(first.references()))
    )

    assert first.reference() == second.reference()
    assert first.reference() == reversed_registry.reference()
    assert first.registry_digest == _EXPECTED_REGISTRY_DIGEST
    assert first.references() == second.references()
    assert tuple(item.skill_id for item in first.references()) == tuple(sorted(_EXPECTED_SKILL_IDS))
    assert tuple(item.skill_id for item in first.definitions()) == tuple(
        sorted(_EXPECTED_SKILL_IDS)
    )
    assert all(
        item.lifecycle_stage is SkillLifecycleStage.CATALOGUED for item in first.definitions()
    )
    assert all(not item.selection_available for item in first.definitions())
    assert all(not item.model_projection_available for item in first.definitions())
    assert all(not item.recipe_binding_available for item in first.definitions())
    assert all(not item.lab_execution_evidence_available for item in first.definitions())
    assert all(not item.independent_validation_evidence_available for item in first.definitions())
    assert not hasattr(first.definitions()[0], "workflow_steps")
    selected = first.resolve(first.references()[0])
    assert selected.instructions.workflow_steps
    assert selected.instructions.instruction_digest == selected.definition.instruction_digest


def test_registry_resolves_only_exact_identity_without_latest_or_substitution() -> None:
    registry = built_in_analysis_skill_registry()
    first, second = registry.references()[:2]

    assert registry.resolve(first).definition.reference() == first
    wrong_digest = first.model_copy(update={"skill_digest": _DIGEST_A})
    with pytest.raises(SkillDefinitionError, match="digest differs"):
        registry.resolve(wrong_digest)
    substituted = first.model_copy(update={"skill_digest": second.skill_digest})
    with pytest.raises(SkillDefinitionError, match="digest differs"):
        registry.resolve(substituted)
    latest = first.model_copy(update={"skill_version": "latest"})
    with pytest.raises(SkillDefinitionError, match="not registered"):
        registry.resolve(latest)
    unknown = first.model_copy(update={"skill_version": "9.9.9"})
    with pytest.raises(SkillDefinitionError, match="not registered"):
        registry.resolve(unknown)


def test_registry_rejects_empty_duplicate_and_noncanonical_entries() -> None:
    registry = built_in_analysis_skill_registry()
    entry = registry.resolve(registry.references()[0])

    with pytest.raises(SkillDefinitionError, match="empty"):
        SkillDefinitionRegistry(())
    with pytest.raises(SkillDefinitionError, match="duplicate"):
        SkillDefinitionRegistry((entry, entry))

    forged_definition = entry.definition.model_copy(update={"instruction_digest": _DIGEST_A})
    forged_entry = entry.model_copy(update={"definition": forged_definition})
    with pytest.raises(SkillDefinitionError, match="not canonical"):
        SkillDefinitionRegistry((forged_entry,))


def test_registry_storage_is_immutable_and_digest_bound() -> None:
    registry = built_in_analysis_skill_registry()
    reference = registry.reference()
    key = next(iter(registry._records))

    with pytest.raises(TypeError):
        delitem(registry._records, key)
    with pytest.raises(AttributeError, match="immutable"):
        registry._records = {}
    with pytest.raises(AttributeError, match="immutable"):
        del registry._registry_digest

    assert registry.reference() == reference
    assert len(registry.references()) == len(_EXPECTED_SKILL_IDS)


def test_instruction_and_definition_digests_reject_content_and_schema_drift() -> None:
    raw_entry = _raw_entry()
    raw_instructions = raw_entry["instructions"]
    assert isinstance(raw_instructions, dict)
    workflow = raw_instructions["workflowSteps"]
    assert isinstance(workflow, list)
    workflow[0] = "Mutated instructions must not retain the old digest."
    with pytest.raises(ValidationError, match="instruction digest differs"):
        RegisteredSkill.model_validate(raw_entry)

    raw_entry = _raw_entry()
    raw_definition = raw_entry["definition"]
    assert isinstance(raw_definition, dict)
    raw_definition["inputSchemaDigest"] = skill_schema_digest(
        {"type": "object", "properties": {"mutated": {"type": "boolean"}}}
    )
    with pytest.raises(ValidationError, match="definition digest differs"):
        RegisteredSkill.model_validate(raw_entry)

    first = skill_schema_digest({"type": "object", "required": ["a"]})
    second = skill_schema_digest({"required": ["a"], "type": "object"})
    changed = skill_schema_digest({"type": "object", "required": ["b"]})
    assert first == second
    assert first != changed


@pytest.mark.parametrize(
    ("location", "field_name", "field_value"),
    (
        ("definition", "tool", {"id": "forbidden"}),
        ("definition", "capability", {"id": "forbidden"}),
        ("definition", "target", "https://forbidden.invalid"),
        ("instructions", "payload", "forbidden"),
        ("instructions", "command", ["forbidden"]),
        ("instructions", "groundTruth", {"expected": True}),
    ),
)
def test_skill_wire_rejects_unknown_executable_and_ground_truth_fields(
    location: str,
    field_name: str,
    field_value: object,
) -> None:
    raw_entry = _raw_entry()
    target = raw_entry[location]
    assert isinstance(target, dict)
    target[field_name] = field_value

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RegisteredSkill.model_validate(raw_entry)


@pytest.mark.parametrize("value", (True, 0, 1, "false", None))
def test_authority_markers_require_literal_false(value: object) -> None:
    raw_entry = _raw_entry()
    raw_definition = raw_entry["definition"]
    assert isinstance(raw_definition, dict)
    raw_definition["executionAuthority"] = value

    with pytest.raises(ValidationError):
        RegisteredSkill.model_validate(raw_entry)


@pytest.mark.parametrize(
    ("stage", "markers"),
    (
        (SkillLifecycleStage.CATALOGUED, (False, False, False, False, False)),
        (SkillLifecycleStage.PROPOSAL_ONLY, (True, True, False, False, False)),
        (SkillLifecycleStage.RECIPE_BACKED, (True, True, True, False, False)),
        (SkillLifecycleStage.LAB_EXECUTABLE, (True, True, True, True, False)),
        (SkillLifecycleStage.INDEPENDENTLY_VERIFIED, (True, True, True, True, True)),
    ),
)
def test_lifecycle_stage_is_evidence_only_and_never_authority(
    stage: SkillLifecycleStage,
    markers: tuple[bool, bool, bool, bool, bool],
) -> None:
    raw_entry = _raw_entry()
    raw_definition = raw_entry["definition"]
    assert isinstance(raw_definition, dict)
    raw_definition["skillDigest"] = ""
    raw_definition["lifecycleStage"] = stage.value
    (
        raw_definition["selectionAvailable"],
        raw_definition["modelProjectionAvailable"],
        raw_definition["recipeBindingAvailable"],
        raw_definition["labExecutionEvidenceAvailable"],
        raw_definition["independentValidationEvidenceAvailable"],
    ) = markers

    definition = SkillDefinition.model_validate(raw_definition)
    assert definition.lifecycle_stage is stage
    assert definition.knowledge_only is True
    assert definition.scope_expansion_authority is False
    assert definition.target_selection_authority is False
    assert definition.tool_request_authority is False
    assert definition.capability_authority is False
    assert definition.permit_authority is False
    assert definition.execution_authority is False
    assert definition.graph_admission_authority is False
    assert definition.finding_authority is False
    assert definition.report_delivery_authority is False


def test_lifecycle_stage_rejects_mismatched_evidence_markers() -> None:
    raw_entry = _raw_entry()
    raw_definition = raw_entry["definition"]
    assert isinstance(raw_definition, dict)
    raw_definition["skillDigest"] = ""
    raw_definition["lifecycleStage"] = SkillLifecycleStage.PROPOSAL_ONLY.value

    with pytest.raises(ValidationError, match="lifecycle markers differ"):
        SkillDefinition.model_validate(raw_definition)


def test_provenance_is_pinned_without_becoming_trust_or_fetch_authority() -> None:
    with pytest.raises(ValidationError, match="cannot declare an upstream URI"):
        SkillProvenance(
            sourceKind=SkillSourceKind.REPOSITORY_OWNED,
            sourceId="pajin.repository.analysis-skills",
            sourceRevision="1.0.0",
            licenseId="Apache-2.0",
            upstreamUri="https://example.invalid/repository",
        )
    with pytest.raises(ValidationError, match="requires an upstream URI"):
        SkillProvenance(
            sourceKind=SkillSourceKind.VENDORED,
            sourceId="example.vendor.skill",
            sourceRevision="a" * 40,
            licenseId="MIT",
        )

    vendored = SkillProvenance(
        sourceKind=SkillSourceKind.VENDORED,
        sourceId="example.vendor.skill",
        sourceRevision="a" * 40,
        licenseId="MIT",
        upstreamUri="https://example.invalid/repository",
    )
    assert vendored.upstream_uri == "https://example.invalid/repository"


@pytest.mark.parametrize(
    "revision",
    (
        "main",
        "master",
        "latest",
        "HEAD",
        "moving-tag",
        "01.0.0",
        "1.0.0-.",
        "1.0.0-alpha..1",
        "1.0.0+.",
        "1.0.0-01",
    ),
)
def test_provenance_rejects_moving_source_revisions(revision: str) -> None:
    with pytest.raises(ValidationError, match="pinned source revision"):
        SkillProvenance(
            sourceKind=SkillSourceKind.VENDORED,
            sourceId="example.vendor.skill",
            sourceRevision=revision,
            licenseId="MIT",
            upstreamUri="https://example.invalid/repository",
        )
    with pytest.raises(ValidationError, match="immutable revision"):
        SkillProvenance(
            sourceKind=SkillSourceKind.REPOSITORY_OWNED,
            sourceId="pajin.repository.analysis-skills",
            sourceRevision=revision,
            licenseId="Apache-2.0",
        )


def test_repository_provenance_accepts_exact_semver_revision() -> None:
    provenance = SkillProvenance(
        sourceKind=SkillSourceKind.REPOSITORY_OWNED,
        sourceId="pajin.repository.analysis-skills",
        sourceRevision="1.2.3-alpha.1+build.05",
        licenseId="Apache-2.0",
    )

    assert provenance.source_revision == "1.2.3-alpha.1+build.05"


def test_registry_has_no_execution_surface_or_forbidden_dependencies() -> None:
    registry = built_in_analysis_skill_registry()
    for name in ("register", "execute", "dispatch", "compile", "issue_permit"):
        assert not hasattr(registry, name)

    forbidden_keys = {
        "callable",
        "capability",
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
    for reference in registry.references():
        raw = registry.resolve(reference).model_dump(mode="json", by_alias=True)
        assert not (_all_keys(raw) & forbidden_keys)

    package_root = Path(__file__).parents[1] / "src" / "pajin" / "skills"
    forbidden_import_roots = {
        "httpx",
        "subprocess",
        "pajin.graph",
        "pajin.runtime.worker",
        "pajin.tools",
    }
    for source_path in sorted(package_root.glob("*.py")):
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        imported.update(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
        assert not {
            module
            for module in imported
            if any(
                module == forbidden or module.startswith(forbidden + ".")
                for forbidden in forbidden_import_roots
            )
        }

    production_root = package_root.parent
    allowed_consumer = production_root / "web_assessment" / "analysis_skill_projection.py"
    observed_consumers: set[Path] = set()
    for source_path in sorted(production_root.rglob("*.py")):
        if package_root in source_path.parents:
            continue
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        imported.update(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
        skill_imports = {
            module
            for module in imported
            if module == "pajin.skills" or module.startswith("pajin.skills.")
        }
        if skill_imports:
            observed_consumers.add(source_path)
            assert source_path == allowed_consumer, (
                f"analysis Skills have an unexpected production consumer in {source_path}"
            )
    assert observed_consumers == {allowed_consumer}


def test_registry_projection_contains_no_private_ground_truth_or_target_material() -> None:
    registry = built_in_analysis_skill_registry()
    metadata = canonical_skill_json(
        [item.model_dump(mode="json", by_alias=True) for item in registry.definitions()],
        label="Skill registry metadata projection",
    )
    selected_content = canonical_skill_json(
        [
            registry.resolve(reference).model_dump(mode="json", by_alias=True)
            for reference in registry.references()
        ],
        label="Skill registry selected content",
    )
    forbidden_markers = (
        b'"challengeAnswer":',
        b'"evaluatorSeed":',
        b'"expectedFinding":',
        b'"groundTruth":',
        b'"matcherDigest":',
        b'"matcherId":',
        b'"targetLocator":',
    )
    for marker in forbidden_markers:
        assert marker not in metadata
        assert marker not in selected_content
    for canary in (
        b"juice shop",
        b"127.0.0.1",
        b"localhost",
        b"/rest/",
        b"admin@",
        b"challenge answer",
        b"evaluator seed",
    ):
        assert canary not in selected_content.lower()


def test_reference_and_instruction_models_reject_extra_fields() -> None:
    registry = built_in_analysis_skill_registry()
    reference = registry.references()[0]
    raw_reference = reference.model_dump(mode="json", by_alias=True)
    raw_reference["latest"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SkillDefinitionRef.model_validate(raw_reference)

    entry = registry.resolve(reference)
    raw_instructions = entry.instructions.model_dump(mode="json", by_alias=True)
    raw_instructions["selector"] = "forbidden"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SkillInstructionBundle.model_validate(raw_instructions)


def test_skill_version_rejects_moving_aliases_and_invalid_semver() -> None:
    entry = built_in_analysis_skill_registry().resolve(
        built_in_analysis_skill_registry().references()[0]
    )
    for version in (
        "latest",
        "main",
        "HEAD",
        "1",
        "01.0.0",
        "1.0.0-.",
        "1.0.0-alpha..1",
        "1.0.0+.",
        "1.0.0-01",
    ):
        raw_instructions = entry.instructions.model_dump(mode="json", by_alias=True)
        raw_instructions["instructionDigest"] = ""
        raw_instructions["skillVersion"] = version
        with pytest.raises(ValidationError):
            SkillInstructionBundle.model_validate(raw_instructions)

        raw_definition = entry.definition.model_dump(mode="json", by_alias=True)
        raw_definition["skillDigest"] = ""
        raw_definition["skillVersion"] = version
        with pytest.raises(ValidationError):
            SkillDefinition.model_validate(raw_definition)

    raw_instructions = entry.instructions.model_dump(mode="json", by_alias=True)
    raw_instructions["instructionDigest"] = ""
    raw_instructions["skillVersion"] = "1.2.3-alpha.1+build.05"
    assert (
        SkillInstructionBundle.model_validate(raw_instructions).skill_version
        == "1.2.3-alpha.1+build.05"
    )
