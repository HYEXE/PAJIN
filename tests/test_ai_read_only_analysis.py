from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from hashlib import sha256

import pytest
from pydantic import ValidationError

from pajin.capabilities import (
    CapabilityLifecycleKeyRole,
    CapabilityLifecycleKeyState,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleSigner,
    CapabilityLifecycleTrustKey,
    CapabilityMaturity,
    CapabilityReleaseBundle,
    CapabilityReleaseRef,
    CapabilityReleaseStatement,
    CapabilityReviewDecision,
    CapabilityReviewStatement,
    CapabilityUseProfile,
    ExistingModeCapabilityActivation,
    activate_existing_mode_capabilities,
    admit_existing_mode_capability_releases,
    capability_lifecycle_public_key,
    existing_mode_capability_bundle,
)
from pajin.capabilities.ai_analysis import (
    AIAnalysisBudgetCeiling,
    AIProviderModelBinding,
    AIReadOnlyAnalysisBinding,
    AIReadOnlyAnalysisCapabilityBinding,
    AIReadOnlyAnalysisError,
    AIReadOnlyAnalysisPreparation,
    ai_provider_registration_digest,
    bind_ai_provider_model,
    bind_ai_read_only_analysis,
    prepare_ai_read_only_analysis,
    registered_ai_read_only_analysis_capability_bindings,
    resolve_ai_read_only_analysis_capability_binding,
)
from pajin.capabilities.existing import (
    REGISTERED_MCP_CAPABILITY_ID,
    REGISTERED_MCP_TARGET,
)
from pajin.control_plane.domain_worker_boundaries import (
    WorkerCredentialBoundary,
    WorkerFilesystemBoundary,
    WorkerNetworkBoundary,
    WorkerRuntimeBoundary,
    resolve_registered_domain_worker_boundary_profile,
)
from pajin.control_plane.redteam_profiles import (
    REDTEAM_LLM_PROFILE,
    REDTEAM_LLM_PROFILE_DIGEST,
    REDTEAM_LLM_RAG_CAPABILITY_ID,
    REDTEAM_LLM_RAG_PROFILE,
    REDTEAM_LLM_RAG_PROFILE_DIGEST,
    REDTEAM_MCP_PROFILE,
    REDTEAM_MCP_PROFILE_DIGEST,
)
from pajin.discovery import (
    AISurfaceClass,
    MCPServerSurfaceLocator,
    http_rag_surface_locator,
    http_route_surface_locator,
    typed_ai_security_surface,
)
from pajin.domain.models import ToolRequest
from pajin.domain.security_domain import SecurityDomain
from pajin.modes.ai_redteam.catalog import KISA_CATALOG
from pajin.providers.models import ProviderRegistration
from pajin.runtime.worker import NetworkMode
from pajin.tools.ai import AIChatProbeInput, AIChatProbeTool
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool
from pajin.tools.mcp import MCP_INSTRUCTION_HIJACKING_PROBE_TEXT, demo_mcp_tool
from pajin.tools.mock import MockAgentProbe

NOW = datetime(2026, 8, 24, 10, tzinfo=UTC)
_M03_CAPABILITY_ID = "pajin.ai.kisa.system-prompt-disclosure"
_M06_CAPABILITY_ID = "pajin.ai.kisa.jailbreak-policy-bypass"
_MODEL_REVISION = "2026-08-24-model-sha256"

_CAPABILITY_FALSE_ALIASES = (
    "profileMetadataAuthority",
    "domainMetadataAuthority",
    "surfaceMetadataAuthority",
    "toolMetadataAuthority",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "credentialAccessAuthorized",
    "graphAdmissionAuthorized",
    "findingConfirmationAuthorized",
    "runtimeSupportAssertedByBinding",
    "executionAuthorized",
)
_BINDING_FALSE_ALIASES = (
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "budgetReserved",
    "credentialLeaseMaterialized",
    "workerJobMaterialized",
    "gatewayDispatchAuthorized",
    "graphAdmissionAuthorized",
    "findingConfirmationAuthorized",
    "executionAuthorized",
)
_PREPARATION_FALSE_ALIASES = (
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "budgetReserved",
    "credentialLeaseMaterialized",
    "workerJobMaterialized",
    "observationProduced",
    "evidenceSealed",
    "graphAdmitted",
    "gatewayDispatchAuthorized",
    "executionAuthorized",
)


def _provider() -> ProviderRegistration:
    return ProviderRegistration(
        provider_id="analysis-provider",
        endpoint="https://ai.example.test/v1/chat",
        model="analysis-model-2026-08",
        secret_ref="provider/analysis/api-key",
        allow_streaming=False,
        allowed_function_tools=set(),
        lease_ttl_seconds=30,
        input_cost_per_million_usd=2.5,
        output_cost_per_million_usd=7.5,
    )


def _provider_budget(*, request_units: int = 1) -> AIAnalysisBudgetCeiling:
    return AIAnalysisBudgetCeiling(
        requestUnits=request_units,
        maxInputTokens=4096,
        maxOutputTokens=1024,
        maxTotalTokens=5120,
        maxCostMicroUsd=250_000,
        providerUsageApplicable=True,
    )


def _mcp_budget() -> AIAnalysisBudgetCeiling:
    return AIAnalysisBudgetCeiling(
        requestUnits=1,
        maxInputTokens=0,
        maxOutputTokens=0,
        maxTotalTokens=0,
        maxCostMicroUsd=0,
        providerUsageApplicable=False,
    )


def _rag_surface(*, endpoint: str = "https://ai.example.test/v1/chat"):
    scheme, rest = endpoint.split("://", maxsplit=1)
    host, path = rest.split("/", maxsplit=1)
    return typed_ai_security_surface(
        locator=http_rag_surface_locator(
            route=http_route_surface_locator(
                base_url=f"{scheme}://{host}",
                path_template=f"/{path}",
                method="POST",
                request_content_types=("application/json",),
                response_content_types=("application/json",),
            ),
            boundary="retrieval",
            index_ids=("assessment-memory",),
        )
    )


def _mcp_surface():
    return typed_ai_security_surface(
        locator=MCPServerSurfaceLocator(
            server_id="demo-security",
            protocol_version="2025-06-18",
            capabilities=("tools",),
        )
    )


def _capability_binding(capability_id: str):
    return next(
        item
        for item in registered_ai_read_only_analysis_capability_bindings()
        if item.capability.capability.capability_id == capability_id
    )


def _provider_binding(capability_id: str, *, request_units: int = 1):
    rag_surface = _rag_surface() if capability_id == REDTEAM_LLM_RAG_CAPABILITY_ID else None
    return bind_ai_read_only_analysis(
        capability=_capability_binding(capability_id).reference(),
        budget=_provider_budget(request_units=request_units),
        provider_registration=_provider(),
        model_revision=_MODEL_REVISION,
        rag_surface=rag_surface,
    )


def _mcp_binding():
    return bind_ai_read_only_analysis(
        capability=_capability_binding(REGISTERED_MCP_CAPABILITY_ID).reference(),
        budget=_mcp_budget(),
        mcp_surface=_mcp_surface(),
    )


def _bundle():
    tools = ToolRegistry()
    for tool in (
        MockAgentProbe(),
        AIChatProbeTool(),
        BooleanSQLiProbeTool(),
        CTFWebBackupProbeTool(),
        CTFCryptoXORTool(),
        demo_mcp_tool(),
    ):
        tools.register(tool)
    return existing_mode_capability_bundle(tools, include_registered_mcp=True)


def _seed(label: str) -> bytes:
    return sha256(f"ai-read-only-analysis:{label}".encode()).digest()


def _signer(
    label: str,
    *,
    principal: str,
    role: CapabilityLifecycleKeyRole,
):
    key = CapabilityLifecycleTrustKey(
        keyId=f"ai-analysis.{label}",
        principalId=principal,
        role=role,
        publicKeyBase64url=capability_lifecycle_public_key(_seed(label)),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=30),
        notAfter=NOW + timedelta(days=30),
    )
    signer = CapabilityLifecycleSigner.from_private_key_bytes(
        key=key,
        private_key=_seed(label),
    )
    return key, signer


@lru_cache(maxsize=1)
def _signed_activation() -> tuple[
    ExistingModeCapabilityActivation,
    dict[str, CapabilityReleaseRef],
]:
    bundle = _bundle()
    policy = CapabilityLifecyclePolicy.reference_policy()
    publisher_key, publisher = _signer(
        "publisher",
        principal="ai-analysis.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
    )
    reviewer_key, reviewer = _signer(
        "reviewer",
        principal="ai-analysis.reviewer",
        role=CapabilityLifecycleKeyRole.REVIEWER,
    )
    release_bundles: list[CapabilityReleaseBundle] = []
    for capability in bundle.capabilities():
        reference = capability.reference()
        review = CapabilityReviewStatement(
            capability=reference,
            targetMaturity=CapabilityMaturity.EXPERIMENTAL,
            sequence=1,
            previousReleaseDigest=None,
            policyDigest=policy.digest,
            reviewerPrincipalId=reviewer.key.principal_id,
            checklistDigest=sha256(
                f"AI-001B:{reference.capability.capability_id}".encode()
            ).hexdigest(),
            decision=CapabilityReviewDecision.APPROVED,
            issuedAt=NOW - timedelta(days=2),
            expiresAt=NOW + timedelta(days=5),
        )
        signed_review = reviewer.sign_review(review)
        release = CapabilityReleaseStatement(
            capability=reference,
            maturity=CapabilityMaturity.EXPERIMENTAL,
            sequence=1,
            previousReleaseDigest=None,
            policyDigest=policy.digest,
            reviewDigests=(review.review_digest,),
            publisherPrincipalId=publisher.key.principal_id,
            issuedAt=NOW - timedelta(days=1),
        )
        release_bundles.append(
            CapabilityReleaseBundle(
                release=publisher.sign_release(release),
                reviews=(signed_review,),
            )
        )
    rollout = admit_existing_mode_capability_releases(
        bundle=bundle,
        policy=policy,
        trust_keys=(publisher_key, reviewer_key),
        releases=tuple(release_bundles),
        clock=lambda: NOW,
    )
    selected_ids = {
        _M03_CAPABILITY_ID,
        _M06_CAPABILITY_ID,
        REDTEAM_LLM_RAG_CAPABILITY_ID,
        REGISTERED_MCP_CAPABILITY_ID,
    }
    release_by_id = {
        item.capability.capability.capability_id: item.release
        for item in rollout.release_set.bindings
        if item.capability.capability.capability_id in selected_ids
    }
    activation = activate_existing_mode_capabilities(
        rollout=rollout,
        releases=tuple(release_by_id[key] for key in sorted(release_by_id)),
        profile=CapabilityUseProfile.RANGE,
    )
    return activation, release_by_id


def _kisa_request(capability_id: str) -> ToolRequest:
    binding = _capability_binding(capability_id)
    scenario = next(
        item for item in KISA_CATALOG.scenarios if item.scenario_id == binding.scenario_id
    )
    assert scenario.probe is not None
    probe = AIChatProbeInput(
        scenario_id=scenario.scenario_id,
        threat_class=binding.threat_class,
        session_id=f"ai-analysis:{binding.threat_class.lower()}",
        turns=scenario.probe.turns,
        checks=scenario.probe.checks,
    )
    return ToolRequest(
        request_id=f"ai-analysis-request-{binding.threat_class.lower()}",
        agent_id="agent:ai-analysis",
        tool_id="ai.chat-probe",
        target=str(_provider().endpoint),
        method="POST",
        arguments=probe.model_dump(mode="json", by_alias=True),
    )


def _mcp_request() -> ToolRequest:
    return ToolRequest(
        request_id="ai-analysis-request-mcp",
        agent_id="agent:ai-analysis",
        tool_id="mcp.demo-security.inspect-text",
        target=REGISTERED_MCP_TARGET,
        method="POST",
        arguments={"text": MCP_INSTRUCTION_HIJACKING_PROBE_TEXT},
    )


def test_capability_inventory_binds_redteam_cap_002_tool_and_ai_worker() -> None:
    bindings = registered_ai_read_only_analysis_capability_bindings()

    assert tuple(item.capability.capability.capability_id for item in bindings) == (
        _M03_CAPABILITY_ID,
        _M06_CAPABILITY_ID,
        REDTEAM_LLM_RAG_CAPABILITY_ID,
        REGISTERED_MCP_CAPABILITY_ID,
    )
    assert tuple(item.profile.profile_id for item in bindings) == (
        REDTEAM_LLM_PROFILE,
        REDTEAM_LLM_PROFILE,
        REDTEAM_LLM_RAG_PROFILE,
        REDTEAM_MCP_PROFILE,
    )
    assert tuple(item.profile.profile_digest for item in bindings) == (
        REDTEAM_LLM_PROFILE_DIGEST,
        REDTEAM_LLM_PROFILE_DIGEST,
        REDTEAM_LLM_RAG_PROFILE_DIGEST,
        REDTEAM_MCP_PROFILE_DIGEST,
    )
    assert tuple(item.request_units for item in bindings) == (1, 1, 2, 1)
    assert tuple(item.required_surface_classes for item in bindings) == (
        (AISurfaceClass.MODEL, AISurfaceClass.TOOL),
        (AISurfaceClass.MODEL, AISurfaceClass.TOOL),
        (AISurfaceClass.MODEL, AISurfaceClass.RAG, AISurfaceClass.TOOL),
        (AISurfaceClass.MCP, AISurfaceClass.TOOL),
    )
    for binding in bindings:
        worker = resolve_registered_domain_worker_boundary_profile(binding.worker_profile)
        assert binding.capability_domain_classification.domain_classification.domain is (
            SecurityDomain.AI
        )
        assert binding.tool_surface.surface_class is AISurfaceClass.TOOL
        assert binding.tool_surface.initial_state == "registered-not-authorized"
        assert worker.network_boundary is WorkerNetworkBoundary.BOUNDED_EGRESS
        assert worker.filesystem_boundary is WorkerFilesystemBoundary.NO_HOST_ACCESS
        assert worker.credential_boundary is WorkerCredentialBoundary.EPHEMERAL_LEASE
        assert worker.runtime_boundary is WorkerRuntimeBoundary.ISOLATED_NON_ROOT
        assert AIReadOnlyAnalysisCapabilityBinding.model_validate(
            binding.model_dump(mode="json", by_alias=True)
        ) == binding


def test_exact_capability_binding_resolution_rejects_digest_substitution() -> None:
    binding = _capability_binding(_M03_CAPABILITY_ID)

    resolved = resolve_ai_read_only_analysis_capability_binding(binding.reference())
    assert resolved == binding
    assert resolved is not binding

    with pytest.raises(AIReadOnlyAnalysisError, match="not registered exactly"):
        resolve_ai_read_only_analysis_capability_binding(
            binding.reference().model_copy(update={"binding_digest": "0" * 64})
        )


def test_provider_model_binding_is_exact_secret_free_and_non_invocable() -> None:
    registration = _provider()
    binding = bind_ai_provider_model(registration, model_revision=_MODEL_REVISION)
    payload = binding.model_dump(mode="json", by_alias=True)

    assert binding.provider_registration_digest == ai_provider_registration_digest(registration)
    assert binding.model_surface.surface_class is AISurfaceClass.MODEL
    assert binding.model_surface.locator.provider_id == registration.provider_id
    assert binding.model_surface.locator.model_id == registration.model
    assert binding.model_surface.locator.model_revision == _MODEL_REVISION
    assert registration.secret_ref not in str(payload)
    assert "secretRef" not in payload
    assert binding.secret_reference_embedded is False
    assert binding.credential_material_embedded is False
    assert binding.credential_access_authorized is False
    assert binding.provider_invocation_authorized is False
    assert AIProviderModelBinding.model_validate(payload) == binding


def test_model_rag_and_mcp_bindings_require_exact_surface_sets_and_budget_semantics() -> None:
    model = _provider_binding(_M03_CAPABILITY_ID)
    rag = _provider_binding(REDTEAM_LLM_RAG_CAPABILITY_ID, request_units=2)
    mcp = _mcp_binding()

    assert tuple(item.surface_class for item in model.surfaces) == (
        AISurfaceClass.MODEL,
        AISurfaceClass.TOOL,
    )
    assert tuple(item.surface_class for item in rag.surfaces) == (
        AISurfaceClass.MODEL,
        AISurfaceClass.RAG,
        AISurfaceClass.TOOL,
    )
    assert tuple(item.surface_class for item in mcp.surfaces) == (
        AISurfaceClass.MCP,
        AISurfaceClass.TOOL,
    )
    assert model.provider_model is not None
    assert rag.provider_model is not None
    assert mcp.provider_model is None
    assert model.budget.provider_usage_applicable is True
    assert rag.budget.request_units == 2
    assert mcp.budget.provider_usage_applicable is False
    assert mcp.budget.max_total_tokens == 0
    for binding in (model, rag, mcp):
        assert binding.state == "bound-not-authorized"
        assert binding.binding_id == f"ai-read-only-analysis-binding_{binding.binding_digest}"
        assert AIReadOnlyAnalysisBinding.model_validate(
            binding.model_dump(mode="json", by_alias=True)
        ) == binding


@pytest.mark.parametrize(
    ("capability_id", "request_units"),
    (
        (_M03_CAPABILITY_ID, 1),
        (_M06_CAPABILITY_ID, 1),
        (REDTEAM_LLM_RAG_CAPABILITY_ID, 2),
    ),
)
def test_signed_activation_prepares_exact_provider_analysis_without_dispatch_authority(
    capability_id: str,
    request_units: int,
) -> None:
    activation, releases = _signed_activation()
    binding = _provider_binding(capability_id, request_units=request_units)
    preparation = prepare_ai_read_only_analysis(
        activation=activation,
        release=releases[capability_id],
        binding=binding,
        request=_kisa_request(capability_id),
        provider_registration=_provider(),
    )
    definition = activation.rollout.bundle.definitions.resolve(
        binding.capability_binding.capability.capability
    )
    executor = activation.rollout.bundle.authorities.authority(
        binding.capability_binding.capability,
        role="executor-adapter",
    )
    pre_gateway_job = executor.prepare(preparation.prepared_action.request)

    assert definition.request_unit_cost == request_units
    assert preparation.state == "prepared-not-authorized"
    assert preparation.provider_registration_reverified is True
    assert preparation.prepared_action.release == releases[capability_id]
    assert preparation.prepared_action.request.target == str(_provider().endpoint)
    assert pre_gateway_job.network is NetworkMode.NONE
    assert pre_gateway_job.egress_policy is None
    assert pre_gateway_job.secret_requests == []
    assert preparation.credential_lease_materialized is False
    assert preparation.preparation_id == (
        f"ai-analysis-preparation_{preparation.preparation_digest}"
    )
    assert AIReadOnlyAnalysisPreparation.model_validate(
        preparation.model_dump(mode="json", by_alias=True)
    ) == preparation


def test_signed_activation_prepares_exact_registered_mcp_without_provider_authority() -> None:
    activation, releases = _signed_activation()
    binding = _mcp_binding()
    preparation = prepare_ai_read_only_analysis(
        activation=activation,
        release=releases[REGISTERED_MCP_CAPABILITY_ID],
        binding=binding,
        request=_mcp_request(),
    )

    assert preparation.provider_registration_reverified is False
    assert preparation.prepared_action.request.target == REGISTERED_MCP_TARGET
    assert preparation.prepared_action.request.arguments == {
        "text": MCP_INSTRUCTION_HIJACKING_PROBE_TEXT
    }
    assert preparation.gateway_dispatch_authorized is False
    assert preparation.execution_authorized is False


def test_provider_rag_mcp_and_budget_substitution_fail_closed() -> None:
    with pytest.raises(AIReadOnlyAnalysisError, match="RAG analysis requires"):
        bind_ai_read_only_analysis(
            capability=_capability_binding(REDTEAM_LLM_RAG_CAPABILITY_ID).reference(),
            budget=_provider_budget(request_units=2),
            provider_registration=_provider(),
            model_revision=_MODEL_REVISION,
        )

    with pytest.raises(AIReadOnlyAnalysisError, match="binding failed closed"):
        bind_ai_read_only_analysis(
            capability=_capability_binding(REDTEAM_LLM_RAG_CAPABILITY_ID).reference(),
            budget=_provider_budget(request_units=2),
            provider_registration=_provider(),
            model_revision=_MODEL_REVISION,
            rag_surface=_rag_surface(endpoint="https://other.example.test/v1/chat"),
        )

    with pytest.raises(AIReadOnlyAnalysisError, match="model-only"):
        bind_ai_read_only_analysis(
            capability=_capability_binding(_M03_CAPABILITY_ID).reference(),
            budget=_provider_budget(),
            provider_registration=_provider(),
            model_revision=_MODEL_REVISION,
            rag_surface=_rag_surface(),
        )

    with pytest.raises(AIReadOnlyAnalysisError, match="MCP-only"):
        bind_ai_read_only_analysis(
            capability=_capability_binding(REGISTERED_MCP_CAPABILITY_ID).reference(),
            budget=_mcp_budget(),
            provider_registration=_provider(),
            model_revision=_MODEL_REVISION,
            mcp_surface=_mcp_surface(),
        )

    with pytest.raises(AIReadOnlyAnalysisError, match="binding failed closed"):
        bind_ai_read_only_analysis(
            capability=_capability_binding(_M03_CAPABILITY_ID).reference(),
            budget=_provider_budget(request_units=2),
            provider_registration=_provider(),
            model_revision=_MODEL_REVISION,
        )


def test_provider_and_release_drift_fail_before_cap_002_preparation() -> None:
    activation, releases = _signed_activation()
    binding = _provider_binding(_M03_CAPABILITY_ID)
    changed_provider = _provider().model_copy(update={"model": "changed-model"})

    with pytest.raises(AIReadOnlyAnalysisError, match="differs from its binding"):
        prepare_ai_read_only_analysis(
            activation=activation,
            release=releases[_M03_CAPABILITY_ID],
            binding=binding,
            request=_kisa_request(_M03_CAPABILITY_ID),
            provider_registration=changed_provider,
        )

    with pytest.raises(AIReadOnlyAnalysisError, match="preparation failed closed"):
        prepare_ai_read_only_analysis(
            activation=activation,
            release=releases[_M03_CAPABILITY_ID].model_copy(
                update={"release_digest": "0" * 64}
            ),
            binding=binding,
            request=_kisa_request(_M03_CAPABILITY_ID),
            provider_registration=_provider(),
        )


def test_binding_and_preparation_explicitly_carry_no_derived_authority() -> None:
    activation, releases = _signed_activation()
    capability = _capability_binding(_M03_CAPABILITY_ID)
    binding = _provider_binding(_M03_CAPABILITY_ID)
    preparation = prepare_ai_read_only_analysis(
        activation=activation,
        release=releases[_M03_CAPABILITY_ID],
        binding=binding,
        request=_kisa_request(_M03_CAPABILITY_ID),
        provider_registration=_provider(),
    )
    capability_payload = capability.model_dump(mode="json", by_alias=True)
    binding_payload = binding.model_dump(mode="json", by_alias=True)
    preparation_payload = preparation.model_dump(mode="json", by_alias=True)

    assert all(capability_payload[alias] is False for alias in _CAPABILITY_FALSE_ALIASES)
    assert all(binding_payload[alias] is False for alias in _BINDING_FALSE_ALIASES)
    assert all(preparation_payload[alias] is False for alias in _PREPARATION_FALSE_ALIASES)
    assert {
        "campaign",
        "scope",
        "approval",
        "permit",
        "worker",
        "observation",
        "evidence",
        "finding",
    }.isdisjoint(AIReadOnlyAnalysisPreparation.model_fields)


@pytest.mark.parametrize("alias", _CAPABILITY_FALSE_ALIASES)
def test_capability_binding_rejects_authority_escalation_and_coercion(alias: str) -> None:
    payload = _capability_binding(_M03_CAPABILITY_ID).model_dump(
        mode="json", by_alias=True
    )
    payload[alias] = True
    with pytest.raises(ValidationError):
        AIReadOnlyAnalysisCapabilityBinding.model_validate(payload)

    payload[alias] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        AIReadOnlyAnalysisCapabilityBinding.model_validate(payload)


@pytest.mark.parametrize("alias", _BINDING_FALSE_ALIASES)
def test_analysis_binding_rejects_authority_escalation_and_coercion(alias: str) -> None:
    payload = _provider_binding(_M03_CAPABILITY_ID).model_dump(
        mode="json", by_alias=True
    )
    payload[alias] = True
    with pytest.raises(ValidationError):
        AIReadOnlyAnalysisBinding.model_validate(payload)

    payload[alias] = "false"
    with pytest.raises(ValidationError, match="must be booleans"):
        AIReadOnlyAnalysisBinding.model_validate(payload)


def test_bindings_reject_capability_surface_budget_digest_and_metadata_injection() -> None:
    capability_payload = deepcopy(
        _capability_binding(_M03_CAPABILITY_ID).model_dump(
            mode="json", by_alias=True
        )
    )
    capability_payload["capability"]["authoritySetDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="code authority"):
        AIReadOnlyAnalysisCapabilityBinding.model_validate(capability_payload)

    binding_payload = deepcopy(
        _provider_binding(_M03_CAPABILITY_ID).model_dump(mode="json", by_alias=True)
    )
    binding_payload["surfaces"][0]["surfaceDigest"] = "0" * 64
    with pytest.raises(ValidationError):
        AIReadOnlyAnalysisBinding.model_validate(binding_payload)

    binding_payload = _provider_binding(_M03_CAPABILITY_ID).model_dump(
        mode="json", by_alias=True
    )
    binding_payload["budget"]["requestUnits"] = 2
    with pytest.raises(ValidationError, match="budget differs"):
        AIReadOnlyAnalysisBinding.model_validate(binding_payload)

    for field, value in (
        ("scope", {"allow": ["https://example.test/**"]}),
        ("workerId", "worker.ai"),
        ("permit", {"authorized": True}),
    ):
        payload = _provider_binding(_M03_CAPABILITY_ID).model_dump(
            mode="json", by_alias=True
        )
        payload[field] = value
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            AIReadOnlyAnalysisBinding.model_validate(payload)
