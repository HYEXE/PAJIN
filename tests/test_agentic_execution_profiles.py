from __future__ import annotations

import socket
from dataclasses import FrozenInstanceError

import pytest
from pydantic import ValidationError

from pajin.agentic.execution_profiles import (
    ResolvedSpecialistExecutionProfile,
    SpecialistExecutionProfileCatalog,
    SpecialistExecutionProfileError,
    SpecialistExecutionProfileRef,
    SpecialistExecutionProfileSnapshot,
)
from pajin.agentic.models import PentestSpecialization
from pajin.skills.catalog import (
    ASSESS_WEB_OBJECT_ACCESS_SKILL_ID,
    ASSESS_WEB_SQLI_SKILL_ID,
    ASSESS_WEB_XSS_SKILL_ID,
)
from pajin.web_assessment import specialist_profiles as specialist_profiles_module
from pajin.web_assessment.adapter_catalog import (
    _LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
    _testing_adapter_implementation_catalog,
    production_adapter_implementation_catalog,
)
from pajin.web_assessment.specialist_profiles import (
    WEB_AUTHORIZATION_SPECIALIST_PROFILE_ID,
    WEB_SPECIALIST_PROFILE_VERSION,
    WEB_SQLI_SPECIALIST_PROFILE_ID,
    WEB_XSS_SPECIALIST_PROFILE_ID,
    WebSpecialistExecutionProfileError,
    production_web_specialist_execution_profile_catalog,
)


def _profiles() -> dict[str, ResolvedSpecialistExecutionProfile]:
    catalog = production_web_specialist_execution_profile_catalog()
    return {reference.profile_id: catalog.resolve(reference) for reference in catalog.references()}


def _forged_snapshot(
    source: SpecialistExecutionProfileSnapshot,
    **changes: object,
) -> SpecialistExecutionProfileSnapshot:
    wire = source.model_dump(mode="json", by_alias=True)
    wire.update(changes)
    wire["profileDigest"] = ""
    return SpecialistExecutionProfileSnapshot.model_validate(wire)


def test_production_catalog_is_deterministic_exact_and_inert() -> None:
    first = production_web_specialist_execution_profile_catalog()
    second = production_web_specialist_execution_profile_catalog()

    assert first.registry_digest == second.registry_digest
    assert first.references() == second.references()
    assert tuple(reference.profile_id for reference in first.references()) == tuple(
        sorted(
            (
                WEB_AUTHORIZATION_SPECIALIST_PROFILE_ID,
                WEB_SQLI_SPECIALIST_PROFILE_ID,
                WEB_XSS_SPECIALIST_PROFILE_ID,
            )
        )
    )
    assert all(
        reference.profile_version == WEB_SPECIALIST_PROFILE_VERSION
        for reference in first.references()
    )

    for reference in first.references():
        resolved = first.resolve(reference)
        snapshot = resolved.snapshot()
        assert first.reload_snapshot(snapshot).reference() == reference
        assert snapshot.state == "registered-inert"
        assert snapshot.execution_binding == "unbound"
        assert snapshot.runtime_support_asserted is False
        assert snapshot.fresh_approval_required is True
        assert snapshot.independent_validation_required is True
        assert snapshot.caller_executable_input is False
        assert snapshot.scope_authority is False
        assert snapshot.capability_authority is False
        assert snapshot.permit_authority is False
        assert snapshot.gateway_authority is False
        assert snapshot.worker_authority is False
        assert snapshot.execution_authority is False
        assert snapshot.evidence_authority is False
        assert snapshot.finding_authority is False
        assert snapshot.graph_admission_authority is False
        assert snapshot.report_authority is False
        assert snapshot.skill_lifecycle_upgrade_authority is False


def test_web_profiles_preserve_three_distinct_least_privilege_closures() -> None:
    profiles = _profiles()
    xss = profiles[WEB_XSS_SPECIALIST_PROFILE_ID].snapshot()
    sqli = profiles[WEB_SQLI_SPECIALIST_PROFILE_ID].snapshot()
    authorization = profiles[WEB_AUTHORIZATION_SPECIALIST_PROFILE_ID].snapshot()

    assert xss.specialization is PentestSpecialization.XSS
    assert xss.threat_class == "xss"
    assert xss.diagnostic_steps == ("dom-xss",)
    assert xss.promotable_steps == ("dom-xss",)
    assert xss.dependency_edges == ()
    assert xss.required_capability_categories == ("CWE-79",)
    assert xss.promotable_finding_categories == ("CWE-79",)
    assert xss.selection_skill_refs[0].skill_id == ASSESS_WEB_XSS_SKILL_ID
    assert xss.supporting_skill_refs == ()

    assert sqli.specialization is PentestSpecialization.SQL_INJECTION
    assert sqli.threat_class == "sql-injection"
    assert sqli.diagnostic_steps == ("sql-login",)
    assert sqli.promotable_steps == ("sql-login",)
    assert sqli.dependency_edges == ()
    assert sqli.required_capability_categories == ("CWE-89",)
    assert sqli.promotable_finding_categories == ("CWE-89",)
    assert sqli.selection_skill_refs[0].skill_id == ASSESS_WEB_SQLI_SKILL_ID
    assert sqli.supporting_skill_refs == ()

    assert authorization.specialization is PentestSpecialization.AUTHORIZATION
    assert authorization.threat_class == "authorization"
    assert authorization.diagnostic_steps == ("sql-login", "object-access")
    assert authorization.promotable_steps == ("object-access",)
    assert authorization.required_capability_categories == ("CWE-639", "CWE-89")
    assert authorization.promotable_finding_categories == ("CWE-639",)
    assert authorization.selection_skill_refs[0].skill_id == (ASSESS_WEB_OBJECT_ACCESS_SKILL_ID)
    assert authorization.supporting_skill_refs[0].skill_id == ASSESS_WEB_SQLI_SKILL_ID
    assert len(authorization.dependency_edges) == 1
    dependency = authorization.dependency_edges[0]
    assert dependency.predecessor_step == "sql-login"
    assert dependency.dependent_step == "object-access"
    assert dependency.purpose == "session-acquisition"
    assert dependency.evidence_type == "web.session-and-object-identity"


def test_profiles_bind_only_the_exact_adapter_and_no_runtime_bundle() -> None:
    expected_catalog_digest = production_adapter_implementation_catalog().catalog_digest
    forbidden_keys = {
        "callable",
        "diagnosticBundleDigest",
        "endpoint",
        "origin",
        "payload",
        "routes",
        "selectors",
        "toolRequest",
        "workerJob",
    }
    for profile in _profiles().values():
        snapshot = profile.snapshot()
        wire = snapshot.model_dump(mode="json", by_alias=True)
        assert snapshot.adapter_implementation_id == JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID
        assert snapshot.adapter_implementation_digest == (JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST)
        assert snapshot.adapter_catalog_digest == expected_catalog_digest
        assert forbidden_keys.isdisjoint(wire)
        assert "diagnosticBundle" not in "".join(wire)


@pytest.mark.parametrize(
    "field",
    (
        "runtimeSupportAsserted",
        "callerExecutableInput",
        "scopeAuthority",
        "capabilityAuthority",
        "permitAuthority",
        "gatewayAuthority",
        "workerAuthority",
        "executionAuthority",
        "evidenceAuthority",
        "findingAuthority",
        "graphAdmissionAuthority",
        "reportAuthority",
        "skillLifecycleUpgradeAuthority",
    ),
)
def test_authority_and_runtime_markers_require_literal_false(field: str) -> None:
    source = _profiles()[WEB_XSS_SPECIALIST_PROFILE_ID].snapshot()
    wire = source.model_dump(mode="json", by_alias=True)
    wire[field] = True
    wire["profileDigest"] = ""

    with pytest.raises(ValidationError, match="literal false"):
        SpecialistExecutionProfileSnapshot.model_validate(wire)


@pytest.mark.parametrize(
    "field",
    ("freshApprovalRequired", "independentValidationRequired"),
)
def test_boundary_markers_require_literal_true(field: str) -> None:
    source = _profiles()[WEB_XSS_SPECIALIST_PROFILE_ID].snapshot()
    wire = source.model_dump(mode="json", by_alias=True)
    wire[field] = 1
    wire["profileDigest"] = ""

    with pytest.raises(ValidationError, match="literal true"):
        SpecialistExecutionProfileSnapshot.model_validate(wire)


def test_catalog_resolves_only_full_exact_references_without_fallback() -> None:
    catalog = production_web_specialist_execution_profile_catalog()
    reference = catalog.references()[0]

    for wrong in (
        reference.model_copy(update={"profile_version": "1.0.1"}),
        reference.model_copy(update={"profile_digest": "0" * 64}),
        reference.model_copy(update={"profile_id": "pajin.web-specialist.latest"}),
    ):
        with pytest.raises(SpecialistExecutionProfileError, match="not installed"):
            catalog.resolve(wrong)

    with pytest.raises(ValidationError):
        SpecialistExecutionProfileRef.model_validate(
            {
                "profileId": reference.profile_id,
                "profileVersion": reference.profile_version,
            }
        )
    assert not hasattr(catalog, "register")
    assert not hasattr(catalog, "resolve_latest")
    assert not hasattr(catalog, "select")
    assert not hasattr(catalog, "select_exact")


@pytest.mark.parametrize(
    "skill_field",
    (
        "skillId",
        "skillVersion",
        "skillDigest",
        "instructionDigest",
        "inputSchemaDigest",
        "outputSchemaDigest",
    ),
)
def test_snapshot_reload_rejects_any_selection_skill_identity_drift(
    skill_field: str,
) -> None:
    catalog = production_web_specialist_execution_profile_catalog()
    source = _profiles()[WEB_XSS_SPECIALIST_PROFILE_ID].snapshot()
    wire = source.model_dump(mode="json", by_alias=True)
    skill = wire["selectionSkillRefs"][0]
    assert isinstance(skill, dict)
    replacements = {
        "skillId": "pajin.skill.web.assess-sqli",
        "skillVersion": "1.0.0",
        "skillDigest": "0" * 64,
        "instructionDigest": "1" * 64,
        "inputSchemaDigest": "2" * 64,
        "outputSchemaDigest": "3" * 64,
    }
    skill[skill_field] = replacements[skill_field]
    wire["profileDigest"] = ""
    forged = SpecialistExecutionProfileSnapshot.model_validate(wire)

    with pytest.raises(SpecialistExecutionProfileError, match="not installed"):
        catalog.reload_snapshot(forged)


def test_snapshot_reload_rejects_self_consistent_closure_substitution() -> None:
    catalog = production_web_specialist_execution_profile_catalog()
    source = _profiles()[WEB_XSS_SPECIALIST_PROFILE_ID].snapshot()
    forged = _forged_snapshot(
        source,
        diagnosticSteps=["sql-login"],
        promotableSteps=["sql-login"],
        requiredCapabilityCategories=["CWE-89"],
        promotableFindingCategories=["CWE-89"],
    )

    assert forged.profile_digest != source.profile_digest
    with pytest.raises(SpecialistExecutionProfileError, match="not installed"):
        catalog.reload_snapshot(forged)


def test_snapshot_and_reference_hidden_state_or_subclass_fail_strict_reload() -> None:
    catalog = production_web_specialist_execution_profile_catalog()
    source = _profiles()[WEB_XSS_SPECIALIST_PROFILE_ID].snapshot()
    hidden_snapshot = source.model_copy(update={"hidden_state": "caller-controlled"})
    hidden_reference = source.reference().model_copy(update={"hidden_state": "caller-controlled"})

    with pytest.raises(SpecialistExecutionProfileError, match="runtime shape"):
        catalog.reload_snapshot(hidden_snapshot)
    with pytest.raises(SpecialistExecutionProfileError, match="runtime shape"):
        catalog.resolve(hidden_reference)

    class SnapshotSubclass(SpecialistExecutionProfileSnapshot):
        pass

    subclass = SnapshotSubclass.model_validate(source.model_dump(mode="json", by_alias=True))
    with pytest.raises(SpecialistExecutionProfileError, match="runtime shape"):
        catalog.reload_snapshot(subclass)


def test_snapshot_and_reference_primitive_subclasses_fail_strict_reload() -> None:
    class EvilStr(str):
        pass

    catalog = production_web_specialist_execution_profile_catalog()
    source = _profiles()[WEB_XSS_SPECIALIST_PROFILE_ID].snapshot()
    forged_id = source.model_copy(update={"profile_id": EvilStr(source.profile_id)})
    forged_step = source.model_copy(update={"diagnostic_steps": (EvilStr("dom-xss"),)})
    source_skill = source.selection_skill_refs[0]
    forged_skill = source_skill.model_copy(update={"skill_id": EvilStr(source_skill.skill_id)})
    forged_nested = source.model_copy(update={"selection_skill_refs": (forged_skill,)})
    forged_reference = source.reference().model_copy(
        update={"profile_id": EvilStr(source.profile_id)}
    )

    for forged in (forged_id, forged_step, forged_nested):
        with pytest.raises(SpecialistExecutionProfileError, match="runtime shape"):
            catalog.reload_snapshot(forged)
    with pytest.raises(SpecialistExecutionProfileError, match="runtime shape"):
        catalog.resolve(forged_reference)


def test_catalog_and_resolved_handles_require_code_owned_construction() -> None:
    catalog = production_web_specialist_execution_profile_catalog()
    profile = catalog.resolve(catalog.references()[0])

    with pytest.raises(TypeError, match="code-owned factory"):
        SpecialistExecutionProfileCatalog(_profiles=())
    with pytest.raises(TypeError, match="catalog resolution"):
        ResolvedSpecialistExecutionProfile(
            registry_digest=catalog.registry_digest,
            _snapshot=profile.snapshot(),
            _descriptor=object(),  # type: ignore[arg-type]
            _catalog=catalog,
            _factory_token=object(),
        )
    with pytest.raises(FrozenInstanceError):
        profile.registry_digest = "0" * 64  # type: ignore[misc]

    object.__setattr__(profile, "registry_digest", "0" * 64)
    with pytest.raises(SpecialistExecutionProfileError, match="registry identity changed"):
        profile.reference()


def test_catalog_mutation_and_model_copy_hidden_state_fail_closed() -> None:
    catalog = production_web_specialist_execution_profile_catalog()
    entries = object.__getattribute__(
        catalog,
        "_SpecialistExecutionProfileCatalog__entries",
    )
    object.__setattr__(
        catalog,
        "_SpecialistExecutionProfileCatalog__entries",
        dict(entries),
    )

    with pytest.raises(SpecialistExecutionProfileError, match="identity changed"):
        catalog.references()


def test_profile_resolution_performs_no_network_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    def deny_connection(*args: object, **kwargs: object) -> object:
        raise AssertionError("profile resolution attempted target I/O")

    monkeypatch.setattr(socket, "create_connection", deny_connection)
    catalog = production_web_specialist_execution_profile_catalog()
    for reference in catalog.references():
        catalog.reload_snapshot(catalog.resolve(reference).snapshot())


def test_web_profile_factory_rejects_removed_production_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_only = _testing_adapter_implementation_catalog(
        implementation_ids=(_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,)
    )
    monkeypatch.setattr(
        specialist_profiles_module,
        "production_adapter_implementation_catalog",
        lambda: fixture_only,
    )

    with pytest.raises(WebSpecialistExecutionProfileError, match="not installed exactly"):
        production_web_specialist_execution_profile_catalog()
