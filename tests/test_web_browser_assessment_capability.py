from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from pajin.capabilities.authorities import (
    CapabilityAuthorityError,
    CapabilityAuthorityRole,
    CapabilityOracleDecision,
)
from pajin.capabilities.models import CapabilitySideEffectClass
from pajin.capabilities.web_browser_assessment import (
    WEB_BROWSER_ASSESSMENT_CAPABILITY_ID,
    WEB_BROWSER_ASSESSMENT_METHODS,
    WEB_BROWSER_ASSESSMENT_ORIGIN,
    WEB_BROWSER_ASSESSMENT_REQUEST_UNITS,
    WEB_BROWSER_ASSESSMENT_SOURCE_PLAN_DIGEST,
    WEB_BROWSER_ASSESSMENT_TOOL_ID,
    WebBrowserAssessmentCapabilityError,
    WebBrowserAssessmentParameters,
    WebBrowserAssessmentPlan,
    WebBrowserAssessmentProfile,
    WebBrowserAssessmentProfileRef,
    WebBrowserAssessmentTool,
    WebBrowserProvisionedAccountReceipt,
    registered_web_browser_assessment_capability_definition,
    registered_web_browser_assessment_plan,
    registered_web_browser_assessment_profile,
    resolve_web_browser_assessment_plan,
    resolve_web_browser_assessment_profile,
    web_browser_assessment_capability_bundle,
)
from pajin.domain.models import ToolRequest, ToolResult, ToolRiskTier
from pajin.tools.base import ToolRegistry
from pajin.web_assessment.recipes import juice_shop_plan

NOW = datetime(2026, 9, 14, 3, 0, tzinfo=UTC)


def _tools(tool: WebBrowserAssessmentTool | None = None) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(tool or WebBrowserAssessmentTool())
    return registry


def _receipt() -> WebBrowserProvisionedAccountReceipt:
    return WebBrowserProvisionedAccountReceipt(
        accountReferenceDigest="a" * 64,
        provisioningEvidenceDigest="b" * 64,
        issuerAuthorityDigest="c" * 64,
        issuedAt=NOW,
        expiresAt=NOW + timedelta(minutes=5),
    )


def _parameters() -> WebBrowserAssessmentParameters:
    return WebBrowserAssessmentParameters(accountReceipt=_receipt())


def _request(arguments: dict[str, object] | None = None) -> ToolRequest:
    return ToolRequest(
        request_id="tool_web_browser_assessment",
        agent_id="agent:web-browser-assessment",
        tool_id=WEB_BROWSER_ASSESSMENT_TOOL_ID,
        target=WEB_BROWSER_ASSESSMENT_ORIGIN,
        method="POST",
        arguments=arguments or _parameters().model_dump(mode="json", by_alias=True),
    )


def test_exact_bundle_registers_all_roles_without_activation_authority() -> None:
    bundle = web_browser_assessment_capability_bundle(_tools())
    definition = bundle.definitions.definitions()[0]
    receipt = _receipt()
    profile = registered_web_browser_assessment_profile(bundle, receipt)
    plan = registered_web_browser_assessment_plan(bundle, receipt)

    assert definition == registered_web_browser_assessment_capability_definition()
    assert definition.capability_id == WEB_BROWSER_ASSESSMENT_CAPABILITY_ID
    assert definition.domain == "bug-bounty"
    assert definition.risk_tier is ToolRiskTier.T2
    assert definition.side_effect_class is CapabilitySideEffectClass.IRREVERSIBLE_WRITE
    assert definition.approval_required is True
    assert definition.cleanup_required is True
    assert definition.network_access is True
    assert definition.request_unit_cost == WEB_BROWSER_ASSESSMENT_REQUEST_UNITS
    assert definition.supported_surface_types == ("web.application",)
    assert [item.role.value for item in bundle.capability.authorities] == sorted(
        role.value for role in CapabilityAuthorityRole
    )
    assert profile.capability == bundle.capability.reference()
    assert profile.action_capability.definition_digest == definition.capability_digest
    assert profile.allowed_methods == WEB_BROWSER_ASSESSMENT_METHODS
    assert plan.profile == profile
    assert plan.parameters.account_receipt == receipt
    for value in (profile, plan):
        assert value.side_effect_class == "irreversible-write"
        assert value.cleanup_required is True
        assert value.lifecycle_activated is False
        assert value.execution_authorized is False
        assert value.action_permit_issued is False
        assert value.gateway_dispatched is False
        assert value.finding_authority is False
        assert value.credential_delivery_authorized is False
        assert value.login_state_mutation_authorized is False
        assert value.cleanup_authority_bound is False
        assert value.cleanup_reservation_held is False
        assert value.cleanup_permit_issued is False
        assert value.account_deletion_authorized is False
    assert profile.account_receipt_authenticated is False
    assert profile.account_creation_allowed is False
    assert profile.caller_authored_routes_allowed is False
    assert "signed-lifecycle-activation-required" in profile.route_limitations
    assert "browser-worker-route-not-configured" in plan.route_limitations
    assert "cleanup-route-not-configured" in plan.route_limitations


def test_source_origin_and_web003_plan_digest_are_literal_authority() -> None:
    assert juice_shop_plan(WEB_BROWSER_ASSESSMENT_ORIGIN).plan_digest == (
        WEB_BROWSER_ASSESSMENT_SOURCE_PLAN_DIGEST
    )
    receipt = _receipt()
    assert receipt.origin == "http://127.0.0.1:3000"
    assert receipt.source_plan_digest == WEB_BROWSER_ASSESSMENT_SOURCE_PLAN_DIGEST

    raw = receipt.model_dump(mode="json", by_alias=True)
    raw.pop("receiptId")
    raw.pop("receiptDigest")
    raw["origin"] = "http://127.0.0.1:3001"
    with pytest.raises(ValidationError):
        WebBrowserProvisionedAccountReceipt.model_validate(raw)

    raw["origin"] = "http://localhost:3000"
    with pytest.raises(ValidationError):
        WebBrowserProvisionedAccountReceipt.model_validate(raw)

    raw["origin"] = WEB_BROWSER_ASSESSMENT_ORIGIN
    raw["sourcePlanDigest"] = "d" * 64
    with pytest.raises(ValidationError):
        WebBrowserProvisionedAccountReceipt.model_validate(raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("accountAlreadyProvisioned", False),
        ("accountAlreadyProvisioned", 1),
        ("accountCreationAuthorized", True),
        ("accountCreationAuthorized", 0),
        ("credentialMaterialIncluded", True),
        ("issuerAuthenticated", True),
    ],
)
def test_account_receipt_rejects_authority_and_credential_coercion(
    field: str,
    value: object,
) -> None:
    raw = _receipt().model_dump(mode="json", by_alias=True)
    raw.pop("receiptId")
    raw.pop("receiptDigest")
    raw[field] = value
    with pytest.raises(ValidationError):
        WebBrowserProvisionedAccountReceipt.model_validate(raw)


def test_materializer_requires_receipt_and_forbids_caller_forms_or_credentials() -> None:
    bundle = web_browser_assessment_capability_bundle(_tools())
    materializer = bundle.authorities.authority(
        bundle.capability.reference(),
        CapabilityAuthorityRole.MATERIALIZER,
    )
    expected = _parameters().model_dump(mode="json", by_alias=True)

    assert materializer.materialize(expected) == expected
    for field in ("password", "credentials", "routes", "forms", "accountCreation"):
        altered = {**expected, field: "caller-controlled"}
        with pytest.raises(CapabilityAuthorityError):
            materializer.materialize(altered)

    without_receipt = dict(expected)
    without_receipt.pop("accountReceipt")
    with pytest.raises(CapabilityAuthorityError):
        materializer.materialize(without_receipt)

    nested_secret = dict(expected)
    nested_secret["accountReceipt"] = {
        **expected["accountReceipt"],
        "password": "must-not-be-accepted",
    }
    with pytest.raises(CapabilityAuthorityError):
        materializer.materialize(nested_secret)


def test_compiler_binds_exact_target_method_and_parameter_identity() -> None:
    bundle = web_browser_assessment_capability_bundle(_tools())
    compiler = bundle.authorities.authority(
        bundle.capability.reference(),
        CapabilityAuthorityRole.ACTION_COMPILER,
    )
    request = _request()
    materialized = _parameters().model_dump(mode="json", by_alias=True)

    assert compiler.compile(request, materialized) == request

    for changes in (
        {"target": "http://127.0.0.1:3001"},
        {"target": "http://localhost:3000"},
        {"method": "GET"},
        {"tool_id": "http.get"},
    ):
        with pytest.raises(CapabilityAuthorityError):
            compiler.compile(request.model_copy(update=changes), materialized)

    changed_arguments = {
        **materialized,
        "sourcePlanDigest": "d" * 64,
    }
    with pytest.raises(CapabilityAuthorityError):
        compiler.compile(
            request.model_copy(update={"arguments": changed_arguments}),
            changed_arguments,
        )


def test_executor_stops_before_worker_gateway_and_oracle_remains_inconclusive() -> None:
    bundle = web_browser_assessment_capability_bundle(_tools())
    reference = bundle.capability.reference()
    request = _request()
    executor = bundle.authorities.authority(
        reference,
        CapabilityAuthorityRole.EXECUTOR_ADAPTER,
    )
    oracle = bundle.authorities.authority(
        reference,
        CapabilityAuthorityRole.SUCCESS_ORACLE,
    )
    replay = bundle.authorities.authority(
        reference,
        CapabilityAuthorityRole.REPLAY_STRATEGY,
    )
    cleanup = bundle.authorities.authority(
        reference,
        CapabilityAuthorityRole.CLEANUP_HANDLER,
    )
    result = ToolResult(
        request_id=request.request_id,
        tool_id=request.tool_id,
        success=True,
        started_at=NOW,
        finished_at=NOW + timedelta(seconds=1),
    )

    with pytest.raises(CapabilityAuthorityError, match="no Worker route"):
        executor.prepare(request)
    with pytest.raises(ValueError, match="no activated Worker route"):
        WebBrowserAssessmentTool().prepare(request)
    assert oracle.evaluate(request, result) is CapabilityOracleDecision.INCONCLUSIVE
    assert replay.plan_replay(request, result) is None
    assert cleanup.plan_cleanup(request, result) is None


@pytest.mark.parametrize(
    "model_type",
    (WebBrowserAssessmentProfile, WebBrowserAssessmentPlan),
)
@pytest.mark.parametrize(
    "field",
    (
        "lifecycleActivated",
        "executionAuthorized",
        "actionPermitIssued",
        "gatewayDispatched",
        "findingAuthority",
        "credentialDeliveryAuthorized",
        "loginStateMutationAuthorized",
        "cleanupAuthorityBound",
        "cleanupReservationHeld",
        "cleanupPermitIssued",
        "accountDeletionAuthorized",
    ),
)
def test_profile_and_plan_reject_forged_authority_markers(
    model_type: type[WebBrowserAssessmentProfile] | type[WebBrowserAssessmentPlan],
    field: str,
) -> None:
    bundle = web_browser_assessment_capability_bundle(_tools())
    value = (
        registered_web_browser_assessment_profile(bundle, _receipt())
        if model_type is WebBrowserAssessmentProfile
        else registered_web_browser_assessment_plan(bundle, _receipt())
    )
    raw = value.model_dump(mode="json", by_alias=True)
    raw.pop("profileDigest" if model_type is WebBrowserAssessmentProfile else "planDigest")
    if model_type is WebBrowserAssessmentPlan:
        raw.pop("planId")
    raw[field] = True
    with pytest.raises(ValidationError, match="authority markers"):
        model_type.model_validate(raw)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("sideEffectClass", "read-only"),
        ("cleanupRequired", False),
    ),
)
@pytest.mark.parametrize(
    "model_type",
    (WebBrowserAssessmentProfile, WebBrowserAssessmentPlan),
)
def test_profile_and_plan_reject_weakened_side_effect_contract(
    model_type: type[WebBrowserAssessmentProfile] | type[WebBrowserAssessmentPlan],
    field: str,
    value: object,
) -> None:
    bundle = web_browser_assessment_capability_bundle(_tools())
    contract = (
        registered_web_browser_assessment_profile(bundle, _receipt())
        if model_type is WebBrowserAssessmentProfile
        else registered_web_browser_assessment_plan(bundle, _receipt())
    )
    raw = contract.model_dump(mode="json", by_alias=True)
    raw.pop("profileDigest" if model_type is WebBrowserAssessmentProfile else "planDigest")
    if model_type is WebBrowserAssessmentPlan:
        raw.pop("planId")
    raw[field] = value

    with pytest.raises(ValidationError):
        model_type.model_validate(raw)


def test_content_addresses_and_exact_resolvers_reject_substitution() -> None:
    bundle = web_browser_assessment_capability_bundle(_tools())
    receipt = _receipt()
    profile = registered_web_browser_assessment_profile(bundle, receipt)
    plan = registered_web_browser_assessment_plan(bundle, receipt)

    assert (
        resolve_web_browser_assessment_profile(
            profile.reference(),
            bundle=bundle,
            receipt=receipt,
        )
        == profile
    )
    assert (
        resolve_web_browser_assessment_plan(
            plan.reference(),
            bundle=bundle,
            receipt=receipt,
        )
        == plan
    )

    forged_profile_ref = WebBrowserAssessmentProfileRef(
        profileId=profile.profile_id,
        profileVersion=profile.profile_version,
        profileDigest="f" * 64,
    )
    with pytest.raises(WebBrowserAssessmentCapabilityError, match="not registered"):
        resolve_web_browser_assessment_profile(
            forged_profile_ref,
            bundle=bundle,
            receipt=receipt,
        )

    raw_receipt = receipt.model_dump(mode="json", by_alias=True)
    raw_receipt["receiptDigest"] = "f" * 64
    with pytest.raises(ValidationError, match="receipt digest"):
        WebBrowserProvisionedAccountReceipt.model_validate(raw_receipt)

    definition = registered_web_browser_assessment_capability_definition()
    raw_definition = definition.model_dump(mode="json", by_alias=True)
    raw_definition["capabilityDigest"] = "f" * 64
    with pytest.raises(ValidationError, match="definition digest"):
        type(definition).model_validate(raw_definition)

    raw_profile = profile.model_dump(mode="json", by_alias=True)
    raw_profile.pop("profileDigest")
    raw_profile["capability"]["authoritySetDigest"] = "f" * 64
    raw_profile["capability"]["authoritySetId"] = "capability-authority-set_" + "f" * 64
    with pytest.raises(ValidationError, match="Profile differs"):
        WebBrowserAssessmentProfile.model_validate(raw_profile)


def test_bundle_rejects_missing_or_alternate_tool_implementation() -> None:
    with pytest.raises(WebBrowserAssessmentCapabilityError, match="unavailable"):
        web_browser_assessment_capability_bundle(ToolRegistry())

    class AlternateBrowserAssessmentTool(WebBrowserAssessmentTool):
        pass

    with pytest.raises(WebBrowserAssessmentCapabilityError, match="implementation"):
        web_browser_assessment_capability_bundle(_tools(AlternateBrowserAssessmentTool()))
