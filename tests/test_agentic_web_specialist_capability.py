from __future__ import annotations

import socket
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from types import MappingProxyType
from typing import Any, cast

import pytest
from pydantic import ValidationError

from pajin.agentic.durable import (
    AgenticCoordinationBinding,
    AgenticCoordinationStore,
    AgenticSpecialistExecutionEntry,
    AgenticSpecialistExecutionState,
    VerifiedSpecialistExecutionReservation,
)
from pajin.agentic.frontier import default_path_scoring_policy
from pajin.agentic.models import PentestSpecialization
from pajin.agentic.specialist_preparation import (
    AgenticSpecialistPreparation,
    prepare_agentic_specialist_action,
)
from pajin.agentic.supervisor import DynamicSupervisorPolicy
from pajin.capabilities.activation import (
    capability_normalized_parameters_digest,
    capability_tool_request_digest,
)
from pajin.capabilities.agentic_web_specialist import (
    WEB_AUTHORIZATION_SPECIALIST_CAPABILITY_ID,
    WEB_AUTHORIZATION_SPECIALIST_TOOL_ID,
    WEB_SPECIALIST_REQUEST_UNITS,
    WEB_SQLI_SPECIALIST_CAPABILITY_ID,
    WEB_SQLI_SPECIALIST_TOOL_ID,
    WEB_XSS_SPECIALIST_CAPABILITY_ID,
    WEB_XSS_SPECIALIST_TOOL_ID,
    AgenticSpecialistPreparationRegistry,
    AgenticWebSpecialistCapabilityError,
    WebSpecialistAssessmentParameters,
    WebSpecialistAssessmentTool,
    activate_web_specialist_capability,
    web_specialist_assessment_tools,
    web_specialist_capability_bundle,
)
from pajin.capabilities.agentic_web_specialist_v2 import (
    AGENTIC_SPECIALIST_CLAIM_VERIFICATION_API_VERSION,
    AGENTIC_SPECIALIST_DISPATCH_VERIFICATION_API_VERSION,
    AGENTIC_SPECIALIST_JOB_ATTEMPT_API_VERSION,
    AGENTIC_SPECIALIST_TERMINAL_RECEIPT_API_VERSION,
    WEB_SQLI_SPECIALIST_V2_CAPABILITY_ID,
    WEB_SQLI_SPECIALIST_V2_CAPABILITY_VERSION,
    WEB_SQLI_SPECIALIST_V2_TOOL_ID,
    WEB_SQLI_SPECIALIST_V2_TOOL_VERSION,
    AgenticWebSpecialistV2CapabilityError,
    WebSQLSpecialistAuthorizationToolV2,
    web_sqli_specialist_planning_contract_v2,
)
from pajin.capabilities.authorities import CapabilityAuthorityError, CapabilityAuthorityRole
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleError,
    CapabilityLifecycleKeyRole,
    CapabilityLifecycleKeyState,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleRegistry,
    CapabilityLifecycleSigner,
    CapabilityLifecycleTrustKey,
    CapabilityReleaseBundle,
    CapabilityReleaseStatement,
    CapabilityReviewDecision,
    CapabilityReviewStatement,
    CapabilityUseProfile,
    capability_lifecycle_public_key,
)
from pajin.capabilities.models import (
    CapabilityMaturity,
    CapabilitySideEffectClass,
    capability_definition_digest,
)
from pajin.discovery.canonicalization import discovery_digest
from pajin.domain.models import (
    CampaignManifest,
    ToolRequest,
    ToolResult,
    ToolRiskTier,
    campaign_manifest_digest,
)
from pajin.policy.capability import CapabilityLedger
from pajin.runtime.worker import SimulatedWorkerBackend, WorkerResult, WorkerStatus
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import ToolGateway
from pajin.web_assessment.analysis_skill_projection import registered_web_pentest_exploit_group
from pajin.web_assessment.governed import _campaign
from pajin.web_assessment.governed_adapter_profile import (
    GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
    GOVERNED_JUICE_SHOP_ORIGIN,
    GOVERNED_WEB_TARGET_ID,
    production_governed_web_adapter_profile_registry,
)
from pajin.web_assessment.governed_models import (
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
    ProvisionedWebAccountReceipt,
    ProvisionedWebAccountReceiptRegistry,
    WebAssessmentAdapterManifest,
    WebAssessmentAdapterRegistry,
    WebAssessmentSigningKeyState,
    WebAssessmentSigningRole,
    WebAssessmentVerificationKey,
    sign_provisioned_web_account_receipt,
    sign_web_assessment_adapter,
    web_assessment_public_key_base64url,
)
from pajin.web_assessment.recipes import juice_shop_plan

NOW = datetime(2026, 9, 18, 3, 0, tzinfo=UTC)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64


@dataclass(frozen=True, slots=True)
class SpecialistCapabilityFixture:
    preparations: tuple[AgenticSpecialistPreparation, ...]
    preparation_registry: AgenticSpecialistPreparationRegistry
    manifest: WebAssessmentAdapterManifest
    receipt: ProvisionedWebAccountReceipt
    tools: tuple[WebSpecialistAssessmentTool, ...]
    registry: ToolRegistry
    bundle: object

    def preparation(self, specialization: PentestSpecialization) -> AgenticSpecialistPreparation:
        return next(item for item in self.preparations if item.specialization is specialization)

    def tool(self, specialization: PentestSpecialization) -> WebSpecialistAssessmentTool:
        return next(item for item in self.tools if item.specialization is specialization)


def _seed(label: str) -> bytes:
    return sha256(f"agentic-c3a:{label}".encode()).digest()


def _digest(label: str) -> str:
    return sha256(f"agentic-c3a-digest:{label}".encode()).hexdigest()


def _campaign_manifest() -> CampaignManifest:
    profile = production_governed_web_adapter_profile_registry().resolve(
        adapter_reference=GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
        origin=GOVERNED_JUICE_SHOP_ORIGIN,
    )
    return _campaign(profile, now=NOW)


def _binding(campaign: CampaignManifest) -> AgenticCoordinationBinding:
    group = registered_web_pentest_exploit_group()
    supervisor_policy = DynamicSupervisorPolicy(beamWidth=1, minScoreBps=0)
    scoring_policy = default_path_scoring_policy()
    return AgenticCoordinationBinding(
        controlPlaneRunId="agentic-control-plane:c3a",
        campaignId=campaign.metadata.name,
        campaignManifestDigest=campaign_manifest_digest(campaign),
        deploymentDigest=SHA_A,
        supervisorAgentId="agent:dynamic-supervisor",
        sourceSnapshotId="graph-snapshot:c3a",
        sourceSnapshotDigest=SHA_B,
        initialCheckpointId="agentic-checkpoint_" + SHA_C,
        initialCheckpointDigest=SHA_C,
        exploitGroupId=group.group_id,
        exploitGroupDigest=group.group_digest,
        exploitGroup=group,
        supervisorPolicyId=supervisor_policy.policy_id,
        supervisorPolicyDigest=supervisor_policy.policy_digest,
        supervisorPolicy=supervisor_policy,
        scoringPolicyId=scoring_policy.policy_id,
        scoringPolicyDigest=scoring_policy.policy_digest,
        scoringPolicy=scoring_policy,
        allowedTargetIds=(GOVERNED_WEB_TARGET_ID,),
    )


def _preparation(
    monkeypatch: pytest.MonkeyPatch,
    *,
    specialization: PentestSpecialization,
    threat_class: str,
    ordinal: int,
) -> AgenticSpecialistPreparation:
    campaign = _campaign_manifest()
    binding = _binding(campaign)
    specialist = binding.exploit_group.specialist_for(specialization, threat_class)
    assert specialist is not None
    specialist_digest = discovery_digest(
        "pajin.agentic.specialist-definition/v1",
        specialist.model_dump(mode="json", by_alias=True),
    )
    store_id = f"agentic-store:{ordinal:032x}"
    entry = AgenticSpecialistExecutionEntry(
        storeId=store_id,
        coordinationBindingDigest=binding.binding_digest,
        sourceHeadCheckpointId="agentic-checkpoint_" + SHA_C,
        sourceHeadCheckpointDigest=SHA_C,
        graphSnapshotId="graph-snapshot:c3a",
        graphSnapshotDigest=SHA_B,
        cycleId="agentic-cycle_" + SHA_D,
        cycleDigest=SHA_D,
        commandId="agent-command_" + f"{ordinal:064x}",
        commandDigest=f"{ordinal:064x}",
        admissionReceiptId="agentic-command-admission_" + f"{ordinal + 10:064x}",
        admissionReceiptDigest=f"{ordinal + 10:064x}",
        targetAgentId=f"agent:specialist-{ordinal}",
        taskId=f"task:specialist-{ordinal}",
        candidateId="frontier-candidate_" + f"{ordinal + 20:064x}",
        candidateDigest=f"{ordinal + 20:064x}",
        proposalDigest=f"{ordinal + 30:064x}",
        targetId=GOVERNED_WEB_TARGET_ID,
        threatClass=threat_class,
        specialization=specialization,
        specialistDefinitionDigest=specialist_digest,
        state=AgenticSpecialistExecutionState.RESERVED,
        reservedAt=cast(Any, NOW.isoformat().replace("+00:00", "Z")),
    )
    store = object.__new__(AgenticCoordinationStore)
    store.binding = binding
    store.store_id = store_id
    reservation = VerifiedSpecialistExecutionReservation(entry, _authority=object())

    def specialist_preparation_entry(
        observed_store: AgenticCoordinationStore,
        observed_reservation: VerifiedSpecialistExecutionReservation,
        *,
        graph_resolver: object,
        graph_head: object,
    ) -> AgenticSpecialistExecutionEntry:
        assert observed_store is store
        assert observed_reservation is reservation
        assert graph_resolver is resolver
        assert graph_head is head
        return entry

    resolver = object()
    head = object()
    monkeypatch.setattr(
        AgenticCoordinationStore,
        "specialist_preparation_entry",
        specialist_preparation_entry,
    )
    return prepare_agentic_specialist_action(
        store=store,
        reservation=reservation,
        graph_resolver=cast(Any, resolver),
        graph_head=cast(Any, head),
        campaign=campaign,
    )


def _verification_key(
    label: str,
    role: WebAssessmentSigningRole,
) -> WebAssessmentVerificationKey:
    return WebAssessmentVerificationKey(
        keyId=f"agentic.{label}",
        principalId=f"principal.{label}",
        role=role,
        publicKeyBase64url=web_assessment_public_key_base64url(_seed(label)),
        state=WebAssessmentSigningKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=1),
        notAfter=NOW + timedelta(days=1),
    )


def _manifest() -> WebAssessmentAdapterManifest:
    return WebAssessmentAdapterManifest(
        adapterId="pajin.adapter.juice-shop.local",
        adapterVersion="1.0.0",
        origin=GOVERNED_JUICE_SHOP_ORIGIN,
        implementationId=JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
        implementationDigest=JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
        recipeDigest=juice_shop_plan(GOVERNED_JUICE_SHOP_ORIGIN).plan_digest,
        issuedAt=NOW - timedelta(minutes=2),
        expiresAt=NOW + timedelta(hours=1),
    )


def _adapter_registry(manifest: WebAssessmentAdapterManifest) -> WebAssessmentAdapterRegistry:
    key = _verification_key("adapter", WebAssessmentSigningRole.ADAPTER_PUBLISHER)
    signed = sign_web_assessment_adapter(
        manifest,
        key_id=key.key_id,
        private_key=_seed("adapter"),
    )
    return WebAssessmentAdapterRegistry(
        keys=(key,),
        adapters=(signed,),
        clock=lambda: NOW,
    )


def _receipt(manifest: WebAssessmentAdapterManifest) -> ProvisionedWebAccountReceipt:
    return ProvisionedWebAccountReceipt(
        adapter=manifest.reference(),
        origin=GOVERNED_JUICE_SHOP_ORIGIN,
        accountReferenceDigest=SHA_A,
        provisioningEvidenceDigest=SHA_B,
        targetFingerprintResponseSha256=_digest("target-fingerprint"),
        targetIdentityDigest=SHA_C,
        authorizationIds=("authorization:source", "authorization:validation"),
        identityMaterialRef="secret:web-account-name",
        proofMaterialRef="secret:web-account-proof",
        issuedAt=NOW - timedelta(minutes=1),
        expiresAt=NOW + timedelta(minutes=10),
    )


def _receipt_registry(
    receipt: ProvisionedWebAccountReceipt,
) -> ProvisionedWebAccountReceiptRegistry:
    key = _verification_key("account", WebAssessmentSigningRole.ACCOUNT_ISSUER)
    signed = sign_provisioned_web_account_receipt(
        receipt,
        key_id=key.key_id,
        private_key=_seed("account"),
    )
    return ProvisionedWebAccountReceiptRegistry(
        keys=(key,),
        receipts=(signed,),
        clock=lambda: NOW,
    )


def _fixture(monkeypatch: pytest.MonkeyPatch) -> SpecialistCapabilityFixture:
    preparations = (
        _preparation(
            monkeypatch,
            specialization=PentestSpecialization.AUTHORIZATION,
            threat_class="authorization",
            ordinal=1,
        ),
        _preparation(
            monkeypatch,
            specialization=PentestSpecialization.SQL_INJECTION,
            threat_class="sql-injection",
            ordinal=2,
        ),
        _preparation(
            monkeypatch,
            specialization=PentestSpecialization.XSS,
            threat_class="xss",
            ordinal=3,
        ),
    )
    preparation_registry = AgenticSpecialistPreparationRegistry(preparations)
    manifest = _manifest()
    receipt = _receipt(manifest)
    tools = web_specialist_assessment_tools(
        preparations=preparation_registry,
        adapters=_adapter_registry(manifest),
        account_receipts=_receipt_registry(receipt),
    )
    registry = ToolRegistry()
    for tool in tools:
        registry.register(tool)
    bundle = web_specialist_capability_bundle(registry)
    return SpecialistCapabilityFixture(
        preparations=preparations,
        preparation_registry=preparation_registry,
        manifest=manifest,
        receipt=receipt,
        tools=tools,
        registry=registry,
        bundle=bundle,
    )


def _request(
    fixture: SpecialistCapabilityFixture,
    specialization: PentestSpecialization,
    **changes: object,
) -> ToolRequest:
    preparation = fixture.preparation(specialization)
    tool = fixture.tool(specialization)
    values: dict[str, object] = {
        "request_id": f"agentic-specialist-{specialization.value}",
        "agent_id": preparation.target_agent_id,
        "tool_id": tool.spec.tool_id,
        "target": preparation.target_endpoint,
        "method": "POST",
        "arguments": WebSpecialistAssessmentParameters(
            preparationId=preparation.preparation_id,
            preparationDigest=preparation.preparation_digest,
            accountReceiptRef=fixture.receipt.reference(),
        ).model_dump(mode="json", by_alias=True),
    }
    values.update(changes)
    return ToolRequest.model_validate(values)


def _lifecycle_key(
    label: str,
    *,
    principal: str,
    role: CapabilityLifecycleKeyRole,
) -> CapabilityLifecycleTrustKey:
    return CapabilityLifecycleTrustKey(
        keyId=f"agentic.lifecycle.{label}",
        principalId=principal,
        role=role,
        publicKeyBase64url=capability_lifecycle_public_key(_seed(label)),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=2),
        notAfter=NOW + timedelta(days=2),
    )


def _activation(
    fixture: SpecialistCapabilityFixture,
    specialization: PentestSpecialization,
) -> object:
    bundle = cast(Any, fixture.bundle)
    policy = CapabilityLifecyclePolicy.reference_policy()
    publisher_key = _lifecycle_key(
        "publisher",
        principal="agentic.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
    )
    reviewer_key = _lifecycle_key(
        "reviewer",
        principal="agentic.reviewer",
        role=CapabilityLifecycleKeyRole.REVIEWER,
    )
    publisher = CapabilityLifecycleSigner.from_private_key_bytes(
        key=publisher_key,
        private_key=_seed("publisher"),
    )
    reviewer = CapabilityLifecycleSigner.from_private_key_bytes(
        key=reviewer_key,
        private_key=_seed("reviewer"),
    )
    capability = bundle.capability(specialization).reference()
    review = CapabilityReviewStatement(
        capability=capability,
        targetMaturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewerPrincipalId=reviewer.key.principal_id,
        checklistDigest=_digest(f"review:{specialization.value}"),
        decision=CapabilityReviewDecision.APPROVED,
        issuedAt=NOW - timedelta(minutes=10),
        expiresAt=NOW + timedelta(hours=1),
    )
    signed_review = reviewer.sign_review(review)
    release = CapabilityReleaseStatement(
        capability=capability,
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewDigests=(signed_review.statement.review_digest,),
        publisherPrincipalId=publisher.key.principal_id,
        issuedAt=NOW - timedelta(minutes=5),
    )
    release_bundle = CapabilityReleaseBundle(
        release=publisher.sign_release(release),
        reviews=(signed_review,),
    )
    lifecycle = CapabilityLifecycleRegistry(
        definitions=bundle.definitions,
        authorities=bundle.authorities,
        policy=policy,
        trust_keys=(publisher_key, reviewer_key),
        releases=(release_bundle,),
        clock=lambda: NOW,
    )
    return activate_web_specialist_capability(
        bundle=bundle,
        lifecycle=lifecycle,
        specialization=specialization,
        release=release_bundle.release.statement.reference(),
    )


def test_three_exact_specialist_capabilities_have_complete_separate_authority_sets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    bundle = cast(Any, fixture.bundle)
    definitions = bundle.definitions.definitions()

    assert {item.capability_id for item in definitions} == {
        WEB_AUTHORIZATION_SPECIALIST_CAPABILITY_ID,
        WEB_SQLI_SPECIALIST_CAPABILITY_ID,
        WEB_XSS_SPECIALIST_CAPABILITY_ID,
    }
    assert {item.tool.tool_id for item in definitions} == {
        WEB_AUTHORIZATION_SPECIALIST_TOOL_ID,
        WEB_SQLI_SPECIALIST_TOOL_ID,
        WEB_XSS_SPECIALIST_TOOL_ID,
    }
    assert len({item.capability_digest for item in definitions}) == 3
    for specialization in PentestSpecialization:
        if specialization not in {
            PentestSpecialization.AUTHORIZATION,
            PentestSpecialization.SQL_INJECTION,
            PentestSpecialization.XSS,
        }:
            continue
        definition = bundle.entry(specialization).definition
        capability = bundle.capability(specialization)
        assert definition.risk_tier is ToolRiskTier.T2
        assert definition.side_effect_class is CapabilitySideEffectClass.READ_ONLY
        assert definition.approval_required is True
        assert definition.cleanup_required is False
        assert definition.request_unit_cost == WEB_SPECIALIST_REQUEST_UNITS
        assert [item.role.value for item in capability.authorities] == sorted(
            role.value for role in CapabilityAuthorityRole
        )
    assert set(fixture.registry.tool_ids()) == {
        WEB_AUTHORIZATION_SPECIALIST_TOOL_ID,
        WEB_SQLI_SPECIALIST_TOOL_ID,
        WEB_XSS_SPECIALIST_TOOL_ID,
    }


@pytest.mark.parametrize(
    "field",
    (
        "adapter",
        "credential",
        "observation",
        "origin",
        "payload",
        "policy",
        "profile",
        "route",
        "selector",
        "transport",
    ),
)
def test_parameters_reject_every_caller_execution_surface(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    fixture = _fixture(monkeypatch)
    preparation = fixture.preparation(PentestSpecialization.XSS)
    parameters = WebSpecialistAssessmentParameters(
        preparationId=preparation.preparation_id,
        preparationDigest=preparation.preparation_digest,
        accountReceiptRef=fixture.receipt.reference(),
    ).model_dump(mode="json", by_alias=True)

    with pytest.raises(ValidationError):
        WebSpecialistAssessmentParameters.model_validate({**parameters, field: "caller-controlled"})


def test_request_parameters_reject_python_aliases_and_nested_receipt_aliases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    preparation = fixture.preparation(PentestSpecialization.XSS)
    tool = fixture.tool(PentestSpecialization.XSS)

    with pytest.raises(ValidationError):
        WebSpecialistAssessmentParameters.model_validate(
            {
                "preparation_id": preparation.preparation_id,
                "preparation_digest": preparation.preparation_digest,
                "account_receipt_ref": fixture.receipt.reference(),
            }
        )

    nested_aliases = {
        "preparationId": preparation.preparation_id,
        "preparationDigest": preparation.preparation_digest,
        "accountReceiptRef": {
            "receipt_id": fixture.receipt.receipt_id,
            "receipt_digest": fixture.receipt.receipt_digest,
        },
    }
    with pytest.raises(AgenticWebSpecialistCapabilityError, match="exact JSON"):
        tool.validate_request(
            _request(fixture, PentestSpecialization.XSS, arguments=nested_aliases)
        )


def test_wrong_specialist_aggregate_tool_and_unknown_receipt_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    xss = fixture.tool(PentestSpecialization.XSS)
    sqli_preparation = fixture.preparation(PentestSpecialization.SQL_INJECTION)
    arguments = WebSpecialistAssessmentParameters(
        preparationId=sqli_preparation.preparation_id,
        preparationDigest=sqli_preparation.preparation_digest,
        accountReceiptRef=fixture.receipt.reference(),
    ).model_dump(mode="json", by_alias=True)

    with pytest.raises(AgenticWebSpecialistCapabilityError, match=r"current.*code"):
        xss.validate_request(_request(fixture, PentestSpecialization.XSS, arguments=arguments))

    with pytest.raises(AgenticWebSpecialistCapabilityError, match="identity"):
        xss.validate_request(
            _request(
                fixture,
                PentestSpecialization.XSS,
                tool_id="web.authenticated-read-only-assessment",
            )
        )

    unknown = fixture.receipt.reference().model_copy(update={"receipt_digest": "9" * 64})
    unknown_arguments = WebSpecialistAssessmentParameters(
        preparationId=fixture.preparation(PentestSpecialization.XSS).preparation_id,
        preparationDigest=fixture.preparation(PentestSpecialization.XSS).preparation_digest,
        accountReceiptRef=unknown,
    ).model_dump(mode="json", by_alias=True)
    with pytest.raises(AgenticWebSpecialistCapabilityError, match="untrusted"):
        xss.validate_request(
            _request(fixture, PentestSpecialization.XSS, arguments=unknown_arguments)
        )


def test_resolvable_signed_account_receipt_for_another_origin_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    foreign_receipt = ProvisionedWebAccountReceipt(
        adapter=fixture.manifest.reference(),
        origin="http://127.0.0.1:3999",
        accountReferenceDigest=SHA_A,
        provisioningEvidenceDigest=SHA_B,
        targetFingerprintResponseSha256=_digest("foreign-target-fingerprint"),
        targetIdentityDigest=SHA_C,
        authorizationIds=("authorization:source", "authorization:validation"),
        identityMaterialRef="secret:web-account-name",
        proofMaterialRef="secret:web-account-proof",
        issuedAt=NOW - timedelta(minutes=1),
        expiresAt=NOW + timedelta(minutes=10),
    )
    tools = web_specialist_assessment_tools(
        preparations=fixture.preparation_registry,
        adapters=_adapter_registry(fixture.manifest),
        account_receipts=_receipt_registry(foreign_receipt),
    )
    registry = ToolRegistry()
    for tool in tools:
        registry.register(tool)
    foreign_fixture = SpecialistCapabilityFixture(
        preparations=fixture.preparations,
        preparation_registry=fixture.preparation_registry,
        manifest=fixture.manifest,
        receipt=foreign_receipt,
        tools=tools,
        registry=registry,
        bundle=web_specialist_capability_bundle(registry),
    )
    preparation = foreign_fixture.preparation(PentestSpecialization.XSS)
    request = _request(foreign_fixture, PentestSpecialization.XSS)
    with pytest.raises(AgenticWebSpecialistCapabilityError, match="differ"):
        foreign_fixture.tool(PentestSpecialization.XSS).validate_request(request)

    activation = cast(Any, _activation(foreign_fixture, PentestSpecialization.XSS))
    with pytest.raises(AgenticWebSpecialistCapabilityError):
        activation.prepare_action(
            release=activation.activation_set.binding.release,
            preparation_id=preparation.preparation_id,
            preparation_digest=preparation.preparation_digest,
            account_receipt_ref=foreign_receipt.reference(),
        )


def test_preparation_registry_rejects_tamper_duplicates_and_fuzzy_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    preparation = fixture.preparation(PentestSpecialization.XSS)
    with pytest.raises(AgenticWebSpecialistCapabilityError, match="more than once"):
        AgenticSpecialistPreparationRegistry((preparation, preparation))

    tampered = preparation.model_copy(update={"executor_digest": "9" * 64})
    with pytest.raises(AgenticWebSpecialistCapabilityError, match="non-canonical"):
        AgenticSpecialistPreparationRegistry((tampered,))

    with pytest.raises(AgenticWebSpecialistCapabilityError, match="not registered"):
        fixture.preparation_registry.resolve(
            preparation.preparation_id,
            "9" * 64,
        )
    with pytest.raises(AgenticWebSpecialistCapabilityError, match="not registered"):
        fixture.preparation_registry.resolve("latest", preparation.preparation_digest)


def test_preparation_registry_is_immutable_and_detects_replaced_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    activation = cast(Any, _activation(fixture, PentestSpecialization.XSS))
    preparation = fixture.preparation(PentestSpecialization.XSS)
    original_digest = fixture.preparation_registry.registry_digest

    with pytest.raises(AttributeError, match="immutable"):
        fixture.preparation_registry.registry_digest = "9" * 64  # type: ignore[misc]
    with pytest.raises(AttributeError, match="immutable"):
        fixture.preparation_registry._AgenticSpecialistPreparationRegistry__installed = (
            MappingProxyType({})
        )

    forged_wire = preparation.model_dump(mode="json", by_alias=True)
    forged_wire["preparationId"] = ""
    forged_wire["preparationDigest"] = ""
    forged_wire["targetAgentId"] = "agent:forged-specialist"
    forged_wire["taskId"] = "task:forged-specialist"
    requirement = cast(dict[str, Any], forged_wire["capabilityRequirement"])
    requirement["requirementId"] = ""
    requirement["requirementDigest"] = ""
    requirement["subjectAgentId"] = "agent:forged-specialist"
    requirement["taskId"] = "task:forged-specialist"
    forged = AgenticSpecialistPreparation.model_validate(forged_wire)
    object.__setattr__(
        fixture.preparation_registry,
        "_AgenticSpecialistPreparationRegistry__installed",
        MappingProxyType(
            {(preparation.preparation_id, preparation.preparation_digest): forged}
        ),
    )

    assert fixture.preparation_registry.registry_digest == original_digest
    with pytest.raises(
        AgenticWebSpecialistCapabilityError,
        match="registered specialist preparation drifted",
    ):
        activation.prepare_action(
            release=activation.activation_set.binding.release,
            preparation_id=preparation.preparation_id,
            preparation_digest=preparation.preparation_digest,
            account_receipt_ref=fixture.receipt.reference(),
        )


def test_signed_range_activation_prepares_one_deterministic_non_executable_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    activation = cast(Any, _activation(fixture, PentestSpecialization.XSS))
    preparation = fixture.preparation(PentestSpecialization.XSS)
    release = activation.activation_set.binding.release

    first = activation.prepare_action(
        release=release,
        preparation_id=preparation.preparation_id,
        preparation_digest=preparation.preparation_digest,
        account_receipt_ref=fixture.receipt.reference(),
    )
    second = activation.prepare_action(
        release=release,
        preparation_id=preparation.preparation_id,
        preparation_digest=preparation.preparation_digest,
        account_receipt_ref=fixture.receipt.reference(),
    )

    assert first == second
    assert first.request.tool_id == WEB_XSS_SPECIALIST_TOOL_ID
    assert first.request.agent_id == preparation.target_agent_id
    assert first.request.target == preparation.target_endpoint
    assert first.request.method == "POST"
    assert set(first.request.arguments) == {
        "preparationId",
        "preparationDigest",
        "accountReceiptRef",
    }
    assert first.request_digest == capability_tool_request_digest(first.request)
    assert first.normalized_parameters_digest == capability_normalized_parameters_digest(
        cast(dict[str, Any], first.request.arguments)
    )
    assert activation.action_registry().resolve(first.capability) == (
        activation.activation_set.binding.action_capability
    )

    tool = fixture.tool(PentestSpecialization.XSS)
    with pytest.raises(AgenticWebSpecialistCapabilityError, match="C3B"):
        tool.prepare(first.request)
    executor = activation.authority(CapabilityAuthorityRole.EXECUTOR_ADAPTER)
    with pytest.raises(CapabilityAuthorityError, match="C3B"):
        executor.prepare(first.request)


def test_every_authority_and_tool_execution_surface_remains_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    activation = cast(Any, _activation(fixture, PentestSpecialization.XSS))
    preparation = fixture.preparation(PentestSpecialization.XSS)
    prepared = activation.prepare_action(
        release=activation.activation_set.binding.release,
        preparation_id=preparation.preparation_id,
        preparation_digest=preparation.preparation_digest,
        account_receipt_ref=fixture.receipt.reference(),
    )
    materializer = activation.authority(CapabilityAuthorityRole.MATERIALIZER)
    compiler = activation.authority(CapabilityAuthorityRole.ACTION_COMPILER)
    materialized = materializer.materialize(cast(dict[str, Any], prepared.request.arguments))
    assert compiler.compile(prepared.request, materialized) == prepared.request

    worker_result = WorkerResult(
        execution_id="execution-specialist",
        backend="specialist-test",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        started_at=NOW,
        finished_at=NOW,
    )
    tool_result = ToolResult(
        request_id=prepared.request.request_id,
        tool_id=prepared.request.tool_id,
        success=True,
        started_at=NOW,
        finished_at=NOW,
    )
    fail_closed = (
        lambda: activation.authority(CapabilityAuthorityRole.EXECUTOR_ADAPTER).prepare(
            prepared.request
        ),
        lambda: activation.authority(CapabilityAuthorityRole.RESULT_NORMALIZER).normalize(
            prepared.request, worker_result
        ),
        lambda: activation.authority(CapabilityAuthorityRole.SUCCESS_ORACLE).evaluate(
            prepared.request, tool_result
        ),
        lambda: activation.authority(CapabilityAuthorityRole.REPLAY_STRATEGY).plan_replay(
            prepared.request, tool_result
        ),
        lambda: activation.authority(CapabilityAuthorityRole.CLEANUP_HANDLER).plan_cleanup(
            prepared.request, tool_result
        ),
        lambda: fixture.tool(PentestSpecialization.XSS).prepare(prepared.request),
        lambda: fixture.tool(PentestSpecialization.XSS).interpret(
            prepared.request, worker_result
        ),
    )
    for invoke in fail_closed:
        with pytest.raises(
            (AgenticWebSpecialistCapabilityError, CapabilityAuthorityError),
            match="C3B",
        ):
            invoke()


def test_all_specialists_have_exact_deterministic_distinct_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    prepared_actions = []
    selected = (
        PentestSpecialization.AUTHORIZATION,
        PentestSpecialization.SQL_INJECTION,
        PentestSpecialization.XSS,
    )
    for specialization in selected:
        activation = cast(Any, _activation(fixture, specialization))
        preparation = fixture.preparation(specialization)
        parameters = WebSpecialistAssessmentParameters(
            preparationId=preparation.preparation_id,
            preparationDigest=preparation.preparation_digest,
            accountReceiptRef=fixture.receipt.reference(),
        )
        prepared = activation.prepare_action(
            release=activation.activation_set.binding.release,
            preparation_id=preparation.preparation_id,
            preparation_digest=preparation.preparation_digest,
            account_receipt_ref=fixture.receipt.reference(),
        )
        request_identity = capability_definition_digest(
            "pajin.agentic.web-specialist-tool-request/v1",
            {
                "toolId": fixture.tool(specialization).spec.tool_id,
                "toolVersion": fixture.tool(specialization).spec.version,
                "specialization": specialization.value,
                "agentId": preparation.target_agent_id,
                "target": preparation.target_endpoint,
                "parameters": parameters.model_dump(mode="json", by_alias=True),
            },
        )
        assert prepared.request.request_id == f"agentic-specialist-request_{request_identity}"
        assert prepared.request.tool_id == fixture.tool(specialization).spec.tool_id
        prepared_actions.append(prepared)

        foreign = fixture.preparation(
            next(item for item in selected if item is not specialization)
        )
        with pytest.raises(AgenticWebSpecialistCapabilityError):
            activation.prepare_action(
                release=activation.activation_set.binding.release,
                preparation_id=foreign.preparation_id,
                preparation_digest=foreign.preparation_digest,
                account_receipt_ref=fixture.receipt.reference(),
            )

    assert len({item.request.request_id for item in prepared_actions}) == len(selected)
    assert len({item.request_digest for item in prepared_actions}) == len(selected)


def test_tool_rejects_self_consistent_request_id_substitution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    request = _request(fixture, PentestSpecialization.XSS)
    substituted = request.model_copy(update={"request_id": "agentic-specialist-forged"})

    with pytest.raises(AgenticWebSpecialistCapabilityError, match="differ"):
        fixture.tool(PentestSpecialization.XSS).validate_request(substituted)


def test_activation_rechecks_current_range_lifecycle_head_on_each_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    activation = cast(Any, _activation(fixture, PentestSpecialization.XSS))
    preparation = fixture.preparation(PentestSpecialization.XSS)
    profiles: list[CapabilityUseProfile] = []

    def reject_historical_release(
        _release: object,
        profile: CapabilityUseProfile,
    ) -> object:
        profiles.append(profile)
        raise CapabilityLifecycleError("Capability release is historical")

    monkeypatch.setattr(
        activation.lifecycle,
        "resolve_for_use",
        reject_historical_release,
    )
    with pytest.raises(AgenticWebSpecialistCapabilityError, match="current signed release"):
        activation.prepare_action(
            release=activation.activation_set.binding.release,
            preparation_id=preparation.preparation_id,
            preparation_digest=preparation.preparation_digest,
            account_receipt_ref=fixture.receipt.reference(),
        )
    assert profiles == [CapabilityUseProfile.RANGE]


def test_specialist_capability_path_performs_no_grant_gateway_worker_or_socket_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def sync_tripwire(*_args: object, **_kwargs: object) -> None:
        calls.append("sync")

    async def async_tripwire(*_args: object, **_kwargs: object) -> None:
        calls.append("async")

    monkeypatch.setattr(CapabilityLedger, "consume", sync_tripwire)
    monkeypatch.setattr(ToolGateway, "execute", async_tripwire)
    monkeypatch.setattr(SimulatedWorkerBackend, "run", async_tripwire)
    monkeypatch.setattr(socket, "create_connection", sync_tripwire)

    fixture = _fixture(monkeypatch)
    activation = cast(Any, _activation(fixture, PentestSpecialization.XSS))
    preparation = fixture.preparation(PentestSpecialization.XSS)
    prepared = activation.prepare_action(
        release=activation.activation_set.binding.release,
        preparation_id=preparation.preparation_id,
        preparation_digest=preparation.preparation_digest,
        account_receipt_ref=fixture.receipt.reference(),
    )
    with pytest.raises(CapabilityAuthorityError, match="C3B"):
        activation.authority(CapabilityAuthorityRole.EXECUTOR_ADAPTER).prepare(
            prepared.request
        )
    assert calls == []


def test_activation_rejects_cross_specialist_release_and_hidden_preparation_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    xss = cast(Any, _activation(fixture, PentestSpecialization.XSS))
    sqli = cast(Any, _activation(fixture, PentestSpecialization.SQL_INJECTION))
    preparation = fixture.preparation(PentestSpecialization.XSS)

    with pytest.raises(AgenticWebSpecialistCapabilityError, match="outside"):
        xss.prepare_action(
            release=sqli.activation_set.binding.release,
            preparation_id=preparation.preparation_id,
            preparation_digest=preparation.preparation_digest,
            account_receipt_ref=fixture.receipt.reference(),
        )

    hidden = preparation.model_copy(update={"executor_id": "pajin.web-specialist.forged"})
    with pytest.raises(AgenticWebSpecialistCapabilityError):
        AgenticSpecialistPreparationRegistry((hidden,))


def test_tool_factory_rejects_unsupported_specialization_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    xss = fixture.tool(PentestSpecialization.XSS)
    with pytest.raises(AgenticWebSpecialistCapabilityError, match="unsupported"):
        WebSpecialistAssessmentTool(
            specialization=cast(PentestSpecialization, "ssrf-specialist"),
            preparations=xss.preparations,
            adapters=xss.adapters,
            account_receipts=xss.account_receipts,
        )


def test_capability_bundle_rejects_incomplete_tool_inventory_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    incomplete = ToolRegistry()
    incomplete.register(fixture.tool(PentestSpecialization.XSS))
    incomplete.register(fixture.tool(PentestSpecialization.SQL_INJECTION))

    with pytest.raises(AgenticWebSpecialistCapabilityError, match="incomplete"):
        web_specialist_capability_bundle(incomplete)


def _v2_tool(fixture: SpecialistCapabilityFixture) -> WebSQLSpecialistAuthorizationToolV2:
    legacy = fixture.tool(PentestSpecialization.SQL_INJECTION)
    return WebSQLSpecialistAuthorizationToolV2(
        preparations=fixture.preparation_registry,
        adapters=legacy.adapters,
        account_receipts=legacy.account_receipts,
    )


def test_v1_identity_snapshot_remains_frozen_when_v2_is_registered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    fixture.registry.register(_v2_tool(fixture))
    v2 = web_sqli_specialist_planning_contract_v2(fixture.registry)
    bundle = cast(Any, fixture.bundle)
    expected = {
        PentestSpecialization.AUTHORIZATION: (
            "9e6080d7985d7ad65dc7180e4e5051d5d3c16077dfa55b2477032c37c0a3fb4f",
            "d231806f2626dccecca8688c3cc8175d24003fab816c291932c7295680c62078",
            "35757c71722f41c4e1a6d1d50c6aa30676ca7c3cb0da2dfb9e3b8e296af4415b",
            "ef63743bc3d92a19beab272979adb904ef61f5ee614d479e678c8062cf34c812",
            "a3fb9fece3e0f25f729d0017a9d3a3fceab7b7e83b1b5664d12ebb2971969eb1",
        ),
        PentestSpecialization.SQL_INJECTION: (
            "c602e69641f7b0ff8146006401d61dd16c9720fe411bb0ca21f571f4fcc7967e",
            "89291c4ae15e73bf5b3de146f7945c2379845b236e70073364bcd9ee0c2c398e",
            "00a568215c84e27f1715e46e4cd3fac69bc425b2fb061f7a808c20c41c7d7aad",
            "5a0c309e006b73902e960115d45d8edeee474608b95619e7529b3c6cbb10b3c9",
            "084f8eb07d3084434282ff61883feb76ac40bc530cd76a9265ebd7e0616d7040",
        ),
        PentestSpecialization.XSS: (
            "fc91c5685eb19b854b6babd706dd652e0c184ec8b070e40565d4f06156259504",
            "6b7f803a8ef0ca9ccebc9762f5385de381b59415e845f18c36c413c3015e165b",
            "3707cb2eb3bac77d5b5a1f2de0115f5b75c06ca4c4cfb9c52464a6106ab5ebdf",
            "bfcfc111df7db18f67fbef3240da729f1f1598ecc6578bea258a7e9c37f3d7c4",
            "2136f0dcdd49074e8045fe16cf0e4677ffa903960bd306a978a41fdb27f4f44e",
        ),
    }
    for specialization, frozen in expected.items():
        entry = bundle.entry(specialization)
        code_capability = bundle.capability(specialization)
        activation = cast(Any, _activation(fixture, specialization))
        observed = (
            entry.definition.capability_digest,
            entry.definition.parameter_schema_digest,
            code_capability.authority_set_digest,
            activation.activation_set.activation_set_digest,
            sha256(
                activation.activation_set.model_dump_json(by_alias=True).encode("utf-8")
            ).hexdigest(),
        )
        assert observed == frozen

    assert v2.definition.capability_id == WEB_SQLI_SPECIALIST_V2_CAPABILITY_ID
    assert WEB_SQLI_SPECIALIST_V2_CAPABILITY_ID == WEB_SQLI_SPECIALIST_CAPABILITY_ID
    assert v2.definition.capability_version == WEB_SQLI_SPECIALIST_V2_CAPABILITY_VERSION
    assert v2.definition.tool.tool_id == WEB_SQLI_SPECIALIST_V2_TOOL_ID
    assert v2.definition.tool.tool_version == WEB_SQLI_SPECIALIST_V2_TOOL_VERSION
    assert v2.definition.reference() != bundle.entry(
        PentestSpecialization.SQL_INJECTION
    ).definition.reference()


def test_v2_planning_contract_compiles_exact_sqli_request_without_release_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    tool = _v2_tool(fixture)
    fixture.registry.register(tool)
    contract = web_sqli_specialist_planning_contract_v2(fixture.registry)
    preparation = fixture.preparation(PentestSpecialization.SQL_INJECTION)

    first = contract.tool.compile_request(
        preparation_id=preparation.preparation_id,
        preparation_digest=preparation.preparation_digest,
        account_receipt_ref=fixture.receipt.reference(),
    )
    second = contract.tool.compile_request(
        preparation_id=preparation.preparation_id,
        preparation_digest=preparation.preparation_digest,
        account_receipt_ref=fixture.receipt.reference(),
    )

    assert first == second
    assert first.request_id.startswith("agentic-specialist-v2-request_")
    assert first.tool_id == WEB_SQLI_SPECIALIST_V2_TOOL_ID
    assert first.tool_id != WEB_SQLI_SPECIALIST_TOOL_ID
    assert first.agent_id == preparation.target_agent_id
    assert first.target == preparation.target_endpoint
    assert contract.action_capability.capability_version == "2.0.0"
    assert contract.action_capability.tool_id == WEB_SQLI_SPECIALIST_V2_TOOL_ID
    assert contract.definition.preconditions == tuple(sorted(contract.definition.preconditions))
    context = tool.stable_execution_context()
    assert context["minimumCoordinationSchemaVersion"] == 6
    assert context["jobAttemptContract"] == AGENTIC_SPECIALIST_JOB_ATTEMPT_API_VERSION
    assert context["terminalReceiptContract"] == (
        AGENTIC_SPECIALIST_TERMINAL_RECEIPT_API_VERSION
    )
    assert context["claimVerificationContract"] == (
        AGENTIC_SPECIALIST_CLAIM_VERIFICATION_API_VERSION
    )
    assert context["dispatchVerificationContract"] == (
        AGENTIC_SPECIALIST_DISPATCH_VERIFICATION_API_VERSION
    )
    assert context["directToolDispatchAllowed"] is False
    assert context["v1PlanOrPermitUpgradeAllowed"] is False
    assert not hasattr(contract, "activation_set")

    with pytest.raises(
        AgenticWebSpecialistV2CapabilityError,
        match="schema-v6 specialist Gateway",
    ):
        contract.tool.prepare(first)


def test_v1_and_v2_requests_cannot_substitute_for_each_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    legacy = fixture.tool(PentestSpecialization.SQL_INJECTION)
    v2 = _v2_tool(fixture)
    preparation = fixture.preparation(PentestSpecialization.SQL_INJECTION)
    v2_request = v2.compile_request(
        preparation_id=preparation.preparation_id,
        preparation_digest=preparation.preparation_digest,
        account_receipt_ref=fixture.receipt.reference(),
    )
    v1_request = _request(fixture, PentestSpecialization.SQL_INJECTION)
    v1_parameters = WebSpecialistAssessmentParameters.model_validate(v1_request.arguments)
    v1_request = v1_request.model_copy(
        update={
            "request_id": "agentic-specialist-request_"
            + capability_definition_digest(
                "pajin.agentic.web-specialist-tool-request/v1",
                {
                    "toolId": legacy.spec.tool_id,
                    "toolVersion": legacy.spec.version,
                    "specialization": PentestSpecialization.SQL_INJECTION.value,
                    "agentId": preparation.target_agent_id,
                    "target": preparation.target_endpoint,
                    "parameters": v1_parameters.model_dump(mode="json", by_alias=True),
                },
            )
        }
    )
    legacy.validate_request(v1_request)

    with pytest.raises(AgenticWebSpecialistV2CapabilityError, match="identity"):
        v2.validate_request(v1_request)
    with pytest.raises(AgenticWebSpecialistCapabilityError, match="identity"):
        legacy.validate_request(v2_request)


def test_v2_planning_path_performs_no_grant_gateway_worker_or_socket_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def sync_tripwire(*_args: object, **_kwargs: object) -> None:
        calls.append("sync")

    async def async_tripwire(*_args: object, **_kwargs: object) -> None:
        calls.append("async")

    monkeypatch.setattr(CapabilityLedger, "consume", sync_tripwire)
    monkeypatch.setattr(ToolGateway, "execute", async_tripwire)
    monkeypatch.setattr(SimulatedWorkerBackend, "run", async_tripwire)
    monkeypatch.setattr(socket, "create_connection", sync_tripwire)

    fixture = _fixture(monkeypatch)
    tool = _v2_tool(fixture)
    fixture.registry.register(tool)
    contract = web_sqli_specialist_planning_contract_v2(fixture.registry)
    preparation = fixture.preparation(PentestSpecialization.SQL_INJECTION)
    request = contract.tool.compile_request(
        preparation_id=preparation.preparation_id,
        preparation_digest=preparation.preparation_digest,
        account_receipt_ref=fixture.receipt.reference(),
    )
    with pytest.raises(AgenticWebSpecialistV2CapabilityError):
        contract.tool.prepare(request)
    assert calls == []
