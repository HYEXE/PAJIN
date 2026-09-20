"""Production-inert preparation for one governed specialist assignment.

This module deliberately stops before Capability construction.  It binds a
live durable reservation to code-owned target, profile, executor, Campaign,
Scope, and budget identities while granting no approval, Permit, Gateway,
Worker, execution, Evidence, Finding, or Graph authority.
"""

from __future__ import annotations

from typing import Literal, Self, cast

from pydantic import ConfigDict, Field, ValidationInfo, field_validator, model_validator

from pajin.agentic.durable import (
    AgenticCoordinationBinding,
    AgenticCoordinationError,
    AgenticCoordinationStore,
    AgenticSpecialistExecutionEntry,
    AgenticSpecialistExecutionState,
    VerifiedSpecialistExecutionReservation,
)
from pajin.agentic.durable_graph import CurrentGraphHeadResolver, VerifiedCurrentGraphHead
from pajin.agentic.execution_profiles import (
    ResolvedSpecialistExecutionProfile,
    SpecialistExecutionProfileCatalog,
    SpecialistExecutionProfileError,
    SpecialistExecutionProfileRef,
)
from pajin.agentic.models import (
    AgenticStrictModel,
    Identifier,
    PentestSpecialization,
    Sha256,
    _literal_false,
    _literal_true,
)
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.domain.models import CampaignManifest, ToolRiskTier, campaign_manifest_digest
from pajin.web_assessment.governed_adapter_profile import (
    GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
    GOVERNED_JUICE_SHOP_ORIGIN,
    GovernedWebAdapterProfileError,
    production_governed_web_adapter_profile_registry,
)
from pajin.web_assessment.specialist_executors import (
    SpecialistExecutorDescriptor,
    WebSpecialistExecutorError,
    production_web_specialist_executor_catalog,
)
from pajin.web_assessment.specialist_profiles import (
    WebSpecialistExecutionProfileError,
    production_web_specialist_execution_profile_catalog,
)

AGENTIC_SPECIALIST_PREPARATION_API_VERSION: Literal[
    "pajin.dev/agentic-specialist-preparation/v1alpha1"
] = "pajin.dev/agentic-specialist-preparation/v1alpha1"
_STORE_ID_PATTERN = r"^agentic-store:[a-f0-9]{32}$"
_MAX_PREPARATION_BYTES = 128 * 1024


class AgenticSpecialistPreparationError(ValueError):
    """Raised when an inert specialist preparation cannot be bound exactly."""


class AgenticSpecialistCapabilityRequirement(AgenticStrictModel):
    """Non-authoritative requirements for a future task-scoped Capability."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    requirement_id: str = Field(default="", alias="requirementId", max_length=110)
    requirement_digest: str = Field(
        default="",
        alias="requirementDigest",
        max_length=64,
    )
    campaign_id: str = Field(alias="campaignId", min_length=3, max_length=80)
    campaign_manifest_digest: Sha256 = Field(alias="campaignManifestDigest")
    subject_agent_id: Identifier = Field(alias="subjectAgentId")
    task_id: Identifier = Field(alias="taskId")
    target_id: Identifier = Field(alias="targetId")
    target_digest: Sha256 = Field(alias="targetDigest")
    scope_digest: Sha256 = Field(alias="scopeDigest")
    budget_digest: Sha256 = Field(alias="budgetDigest")
    specialization: PentestSpecialization
    threat_class: str = Field(
        alias="threatClass",
        min_length=2,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9.-]{1,79}$",
    )
    profile: SpecialistExecutionProfileRef
    executor_id: Identifier = Field(alias="executorId")
    executor_digest: Sha256 = Field(alias="executorDigest")
    required_capability_categories: tuple[Identifier, ...] = Field(
        alias="requiredCapabilityCategories",
        min_length=1,
        max_length=16,
    )
    requirement: Literal["future-one-call-non-delegable"] = "future-one-call-non-delegable"
    max_calls: Literal[1] = Field(default=1, alias="maxCalls")
    max_risk_tier: Literal[ToolRiskTier.T2] = Field(
        default=ToolRiskTier.T2,
        alias="maxRiskTier",
    )
    delegable: Literal[False] = False
    fresh_approval_required: Literal[True] = Field(
        default=True,
        alias="freshApprovalRequired",
    )
    capability_registered: Literal[False] = Field(
        default=False,
        alias="capabilityRegistered",
    )
    capability_granted: Literal[False] = Field(
        default=False,
        alias="capabilityGranted",
    )
    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    permit_authority: Literal[False] = Field(default=False, alias="permitAuthority")
    gateway_authority: Literal[False] = Field(default=False, alias="gatewayAuthority")
    worker_authority: Literal[False] = Field(default=False, alias="workerAuthority")
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")
    evidence_authority: Literal[False] = Field(default=False, alias="evidenceAuthority")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    graph_authority: Literal[False] = Field(default=False, alias="graphAuthority")

    @field_validator("max_calls", mode="before")
    @classmethod
    def require_one_call(cls, value: object) -> object:
        if type(value) is not int or value != 1:
            raise ValueError("specialist Capability requirement must be exactly one call")
        return value

    @field_validator("fresh_approval_required", mode="before")
    @classmethod
    def require_fresh_approval(cls, value: object) -> object:
        return _literal_true(value, label="fresh approval requirement")

    @field_validator(
        "delegable",
        "capability_registered",
        "capability_granted",
        "approval_authority",
        "permit_authority",
        "gateway_authority",
        "worker_authority",
        "execution_authority",
        "evidence_authority",
        "finding_authority",
        "graph_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @model_validator(mode="after")
    def bind_requirement(self) -> Self:
        if self.required_capability_categories != tuple(
            sorted(set(self.required_capability_categories))
        ):
            raise ValueError("specialist Capability categories must be unique and sorted")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"requirement_id", "requirement_digest"},
        )
        digest = discovery_digest(
            "pajin.agentic.specialist-capability-requirement/v1",
            material,
        )
        expected_id = f"agentic-specialist-capability-requirement_{digest}"
        if self.requirement_digest and self.requirement_digest != digest:
            raise ValueError("specialist Capability requirement Digest differs")
        if self.requirement_id and self.requirement_id != expected_id:
            raise ValueError("specialist Capability requirement ID differs")
        object.__setattr__(self, "requirement_digest", digest)
        object.__setattr__(self, "requirement_id", expected_id)
        return self


class AgenticSpecialistPreparation(AgenticStrictModel):
    """Content-addressed, inert bridge from assignment to future authority work."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    api_version: Literal["pajin.dev/agentic-specialist-preparation/v1alpha1"] = Field(
        default=AGENTIC_SPECIALIST_PREPARATION_API_VERSION, alias="apiVersion"
    )
    kind: Literal["AgenticSpecialistPreparation"] = "AgenticSpecialistPreparation"
    preparation_id: str = Field(default="", alias="preparationId", max_length=110)
    preparation_digest: str = Field(
        default="",
        alias="preparationDigest",
        max_length=64,
    )
    state: Literal["prepared-inert"] = "prepared-inert"

    store_id: str = Field(alias="storeId", pattern=_STORE_ID_PATTERN)
    coordination_binding_id: str = Field(alias="coordinationBindingId", max_length=96)
    coordination_binding_digest: Sha256 = Field(alias="coordinationBindingDigest")
    control_plane_run_id: Identifier = Field(alias="controlPlaneRunId")
    deployment_digest: Sha256 = Field(alias="deploymentDigest")

    reservation_id: str = Field(alias="reservationId", max_length=110)
    reservation_digest: Sha256 = Field(alias="reservationDigest")
    reservation_state_digest: Sha256 = Field(alias="reservationStateDigest")
    source_head_checkpoint_id: str = Field(
        alias="sourceHeadCheckpointId",
        pattern=r"^agentic-checkpoint_[a-f0-9]{64}$",
    )
    source_head_checkpoint_digest: Sha256 = Field(alias="sourceHeadCheckpointDigest")
    graph_snapshot_id: Identifier = Field(alias="graphSnapshotId")
    graph_snapshot_digest: Sha256 = Field(alias="graphSnapshotDigest")

    cycle_id: str = Field(alias="cycleId", pattern=r"^agentic-cycle_[a-f0-9]{64}$")
    cycle_digest: Sha256 = Field(alias="cycleDigest")
    command_id: str = Field(alias="commandId", pattern=r"^agent-command_[a-f0-9]{64}$")
    command_digest: Sha256 = Field(alias="commandDigest")
    admission_receipt_id: str = Field(
        alias="admissionReceiptId",
        pattern=r"^agentic-command-admission_[a-f0-9]{64}$",
    )
    admission_receipt_digest: Sha256 = Field(alias="admissionReceiptDigest")
    target_agent_id: Identifier = Field(alias="targetAgentId")
    task_id: Identifier = Field(alias="taskId")
    candidate_id: str = Field(
        alias="candidateId",
        pattern=r"^frontier-candidate_[a-f0-9]{64}$",
    )
    candidate_digest: Sha256 = Field(alias="candidateDigest")
    proposal_digest: Sha256 = Field(alias="proposalDigest")
    specialist_definition_digest: Sha256 = Field(alias="specialistDefinitionDigest")
    specialization: PentestSpecialization
    threat_class: str = Field(
        alias="threatClass",
        min_length=2,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9.-]{1,79}$",
    )

    target_registry_digest: Sha256 = Field(alias="targetRegistryDigest")
    target_profile_digest: Sha256 = Field(alias="targetProfileDigest")
    adapter_catalog_digest: Sha256 = Field(alias="adapterCatalogDigest")
    adapter_reference: str = Field(alias="adapterReference", max_length=80)
    adapter_implementation_id: Identifier = Field(alias="adapterImplementationId")
    adapter_implementation_digest: Sha256 = Field(alias="adapterImplementationDigest")
    adapter_plan_digest: Sha256 = Field(alias="adapterPlanDigest")
    target_id: Identifier = Field(alias="targetId")
    target_type: str = Field(alias="targetType", min_length=1, max_length=50)
    target_endpoint: str = Field(alias="targetEndpoint", min_length=1, max_length=2_000)
    target_digest: Sha256 = Field(alias="targetDigest")

    profile_registry_digest: Sha256 = Field(alias="profileRegistryDigest")
    profile: SpecialistExecutionProfileRef
    executor_catalog_digest: Sha256 = Field(alias="executorCatalogDigest")
    executor_id: Identifier = Field(alias="executorId")
    executor_version: str = Field(alias="executorVersion", min_length=1, max_length=40)
    executor_digest: Sha256 = Field(alias="executorDigest")
    browser_implementation_id: Identifier | None = Field(alias="browserImplementationId")
    browser_implementation_version: str | None = Field(
        alias="browserImplementationVersion",
        max_length=40,
    )
    browser_implementation_digest: Sha256 | None = Field(alias="browserImplementationDigest")
    diagnostic_steps: tuple[Identifier, ...] = Field(
        alias="diagnosticSteps",
        min_length=1,
        max_length=16,
    )
    promotable_steps: tuple[Identifier, ...] = Field(
        alias="promotableSteps",
        min_length=1,
        max_length=16,
    )

    campaign_id: str = Field(alias="campaignId", min_length=3, max_length=80)
    campaign_manifest_digest: Sha256 = Field(alias="campaignManifestDigest")
    scope_digest: Sha256 = Field(alias="scopeDigest")
    budget_digest: Sha256 = Field(alias="budgetDigest")
    capability_requirement: AgenticSpecialistCapabilityRequirement = Field(
        alias="capabilityRequirement"
    )

    scope_authority: Literal[False] = Field(default=False, alias="scopeAuthority")
    capability_authority: Literal[False] = Field(default=False, alias="capabilityAuthority")
    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    permit_authority: Literal[False] = Field(default=False, alias="permitAuthority")
    permit_issued: Literal[False] = Field(default=False, alias="permitIssued")
    gateway_authority: Literal[False] = Field(default=False, alias="gatewayAuthority")
    gateway_dispatched: Literal[False] = Field(default=False, alias="gatewayDispatched")
    worker_authority: Literal[False] = Field(default=False, alias="workerAuthority")
    worker_dispatched: Literal[False] = Field(default=False, alias="workerDispatched")
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")
    execution_started: Literal[False] = Field(default=False, alias="executionStarted")
    evidence_authority: Literal[False] = Field(default=False, alias="evidenceAuthority")
    evidence_produced: Literal[False] = Field(default=False, alias="evidenceProduced")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    finding_produced: Literal[False] = Field(default=False, alias="findingProduced")
    graph_authority: Literal[False] = Field(default=False, alias="graphAuthority")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")

    @field_validator(
        "scope_authority",
        "capability_authority",
        "approval_authority",
        "approval_satisfied",
        "permit_authority",
        "permit_issued",
        "gateway_authority",
        "gateway_dispatched",
        "worker_authority",
        "worker_dispatched",
        "execution_authority",
        "execution_started",
        "evidence_authority",
        "evidence_produced",
        "finding_authority",
        "finding_produced",
        "graph_authority",
        "graph_admitted",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @model_validator(mode="after")
    def bind_preparation(self) -> Self:
        requirement = self.capability_requirement
        if (
            requirement.campaign_id != self.campaign_id
            or requirement.campaign_manifest_digest != self.campaign_manifest_digest
            or requirement.subject_agent_id != self.target_agent_id
            or requirement.task_id != self.task_id
            or requirement.target_id != self.target_id
            or requirement.target_digest != self.target_digest
            or requirement.scope_digest != self.scope_digest
            or requirement.budget_digest != self.budget_digest
            or requirement.specialization is not self.specialization
            or requirement.threat_class != self.threat_class
            or requirement.profile != self.profile
            or requirement.executor_id != self.executor_id
            or requirement.executor_digest != self.executor_digest
        ):
            raise ValueError("specialist Capability requirement differs from preparation")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"preparation_id", "preparation_digest"},
        )
        digest = discovery_digest("pajin.agentic.specialist-preparation/v1", material)
        expected_id = f"agentic-specialist-preparation_{digest}"
        if self.preparation_digest and self.preparation_digest != digest:
            raise ValueError("Agentic Specialist Preparation Digest differs")
        if self.preparation_id and self.preparation_id != expected_id:
            raise ValueError("Agentic Specialist Preparation ID differs")
        object.__setattr__(self, "preparation_digest", digest)
        object.__setattr__(self, "preparation_id", expected_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Agentic Specialist Preparation",
            max_bytes=_MAX_PREPARATION_BYTES,
        )
        return self


def _strict_campaign(campaign: CampaignManifest) -> CampaignManifest:
    if type(campaign) is not CampaignManifest:
        raise AgenticSpecialistPreparationError(
            "specialist preparation requires an exact Campaign Manifest"
        )
    try:
        canonical = CampaignManifest.model_validate_json(campaign.model_dump_json(by_alias=True))
    except (AttributeError, TypeError, ValueError) as exc:
        raise AgenticSpecialistPreparationError(
            "specialist preparation Campaign failed strict reload"
        ) from exc
    if canonical != campaign:
        raise AgenticSpecialistPreparationError(
            "specialist preparation Campaign differs after strict reload"
        )
    return canonical


def _strict_binding(store: AgenticCoordinationStore) -> AgenticCoordinationBinding:
    try:
        binding = AgenticCoordinationBinding.model_validate(
            store.binding.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise AgenticSpecialistPreparationError(
            "specialist preparation coordination binding failed strict reload"
        ) from exc
    if binding != store.binding:
        raise AgenticSpecialistPreparationError(
            "specialist preparation coordination binding differs after strict reload"
        )
    return binding


def _resolve_profile_and_executor(
    entry: AgenticSpecialistExecutionEntry,
) -> tuple[
    SpecialistExecutionProfileCatalog,
    ResolvedSpecialistExecutionProfile,
    SpecialistExecutorDescriptor,
]:
    profile_catalog = production_web_specialist_execution_profile_catalog()
    matches = []
    for reference in profile_catalog.references():
        resolved = profile_catalog.resolve(reference)
        if (
            resolved.specialization is entry.specialization
            and resolved.threat_class == entry.threat_class
        ):
            matches.append(resolved)
    if len(matches) != 1:
        raise AgenticSpecialistPreparationError(
            "specialist assignment has no exact code-owned execution profile"
        )
    profile = matches[0]
    executor_catalog = production_web_specialist_executor_catalog()
    descriptor = executor_catalog.resolve(profile)
    snapshot = profile.snapshot()
    if (
        descriptor.catalog_digest != executor_catalog.catalog_digest
        or descriptor.profile_registry_digest != profile_catalog.registry_digest
        or descriptor.profile_ref != profile.reference()
        or descriptor.diagnostic_steps != snapshot.diagnostic_steps
        or descriptor.promotable_steps != snapshot.promotable_steps
        or any(
            marker is not False
            for marker in (
                descriptor.scope_authority,
                descriptor.capability_authority,
                descriptor.permit_authority,
                descriptor.gateway_authority,
                descriptor.worker_authority,
            )
        )
    ):
        raise AgenticSpecialistPreparationError(
            "specialist executor descriptor differs from its code-owned profile"
        )
    return profile_catalog, profile, descriptor


def prepare_agentic_specialist_action(
    *,
    store: AgenticCoordinationStore,
    reservation: VerifiedSpecialistExecutionReservation,
    graph_resolver: CurrentGraphHeadResolver,
    graph_head: VerifiedCurrentGraphHead,
    campaign: CampaignManifest,
) -> AgenticSpecialistPreparation:
    """Bind a current reservation to inert code-owned execution prerequisites.

    The exact signature intentionally accepts no profile, executor, transport,
    payload, ToolRequest, or prepared Capability action from the caller.
    """

    if type(store) is not AgenticCoordinationStore:
        raise AgenticSpecialistPreparationError(
            "specialist preparation requires the concrete coordination store"
        )
    if type(reservation) is not VerifiedSpecialistExecutionReservation:
        raise AgenticSpecialistPreparationError(
            "specialist preparation requires verified reservation authority"
        )
    canonical_campaign = _strict_campaign(campaign)
    binding = _strict_binding(store)
    try:
        entry = store.specialist_preparation_entry(
            reservation,
            graph_resolver=graph_resolver,
            graph_head=graph_head,
        )
    except AgenticCoordinationError as exc:
        raise AgenticSpecialistPreparationError(
            "specialist preparation requires a live store-local reservation"
        ) from exc
    if type(entry) is not AgenticSpecialistExecutionEntry:
        raise AgenticSpecialistPreparationError(
            "specialist preparation seam returned a non-canonical entry"
        )
    if (
        entry.store_id != store.store_id
        or entry.coordination_binding_digest != binding.binding_digest
        or entry.state is not AgenticSpecialistExecutionState.RESERVED
    ):
        raise AgenticSpecialistPreparationError(
            "specialist reservation differs from its coordination store or is not reserved"
        )

    try:
        target_registry = production_governed_web_adapter_profile_registry()
        target_profile = target_registry.resolve(
            adapter_reference=GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
            origin=GOVERNED_JUICE_SHOP_ORIGIN,
        )
        profile_catalog, profile, descriptor = _resolve_profile_and_executor(entry)
        profile_snapshot = profile.snapshot()
    except (
        GovernedWebAdapterProfileError,
        SpecialistExecutionProfileError,
        WebSpecialistExecutionProfileError,
        WebSpecialistExecutorError,
        TypeError,
        ValueError,
    ) as exc:
        raise AgenticSpecialistPreparationError(
            "specialist preparation code-owned route is unavailable"
        ) from exc

    if (
        binding.campaign_id != target_profile.campaign_id
        or binding.allowed_target_ids != (target_profile.target_id,)
        or entry.target_id != target_profile.target_id
        or profile_snapshot.adapter_implementation_id != target_profile.implementation_id
        or profile_snapshot.adapter_implementation_digest != target_profile.implementation_digest
        or profile_snapshot.adapter_catalog_digest != target_profile.catalog_digest
    ):
        raise AgenticSpecialistPreparationError(
            "specialist assignment is outside the exact governed target route"
        )

    observed_campaign_digest = campaign_manifest_digest(canonical_campaign)
    if (
        canonical_campaign.metadata.name != binding.campaign_id
        or canonical_campaign.metadata.name != target_profile.campaign_id
        or observed_campaign_digest != binding.campaign_manifest_digest
    ):
        raise AgenticSpecialistPreparationError(
            "specialist Campaign identity differs from coordination binding"
        )
    if len(canonical_campaign.spec.targets) != 1:
        raise AgenticSpecialistPreparationError(
            "specialist Campaign must contain exactly one code-owned target"
        )
    target = canonical_campaign.spec.targets[0]
    if (
        target.id != entry.target_id
        or target.id != target_profile.target_id
        or target.type != target_profile.target_type
        or target.endpoint != target_profile.origin
        or target.simulation
    ):
        raise AgenticSpecialistPreparationError(
            "specialist Campaign target differs from code-owned routing"
        )
    expected_allow = [target_profile.origin + "/**"]
    expected_deny = [target_profile.origin + path + "*" for path in target_profile.plan.deny_paths]
    if (
        canonical_campaign.spec.scope.allow != expected_allow
        or canonical_campaign.spec.scope.deny != expected_deny
    ):
        raise AgenticSpecialistPreparationError(
            "specialist Campaign Scope differs from code-owned target routing"
        )
    budgets = canonical_campaign.spec.budgets
    rules = canonical_campaign.spec.rules_of_engagement
    if (
        budgets.max_agents < 1
        or budgets.max_tool_calls < 1
        or rules.max_tool_risk_tier < ToolRiskTier.T2
        or not rules.allow_private_networks
    ):
        raise AgenticSpecialistPreparationError(
            "specialist Campaign budget or risk ceiling cannot support one governed call"
        )

    target_digest = discovery_digest(
        "pajin.agentic.specialist-target/v1",
        target.model_dump(mode="json", by_alias=True),
    )
    scope_digest = discovery_digest(
        "pajin.agentic.specialist-scope/v1",
        canonical_campaign.spec.scope.model_dump(mode="json", by_alias=True),
    )
    budget_digest = discovery_digest(
        "pajin.agentic.specialist-budget/v1",
        budgets.model_dump(mode="json", by_alias=True),
    )
    profile_reference = profile.reference()
    requirement = AgenticSpecialistCapabilityRequirement(
        campaignId=binding.campaign_id,
        campaignManifestDigest=observed_campaign_digest,
        subjectAgentId=entry.target_agent_id,
        taskId=entry.task_id,
        targetId=entry.target_id,
        targetDigest=target_digest,
        scopeDigest=scope_digest,
        budgetDigest=budget_digest,
        specialization=entry.specialization,
        threatClass=entry.threat_class,
        profile=profile_reference,
        executorId=descriptor.executor_id,
        executorDigest=descriptor.executor_digest,
        requiredCapabilityCategories=profile_snapshot.required_capability_categories,
    )
    return AgenticSpecialistPreparation(
        storeId=store.store_id,
        coordinationBindingId=binding.binding_id,
        coordinationBindingDigest=binding.binding_digest,
        controlPlaneRunId=binding.control_plane_run_id,
        deploymentDigest=binding.deployment_digest,
        reservationId=entry.reservation_id,
        reservationDigest=entry.reservation_digest,
        reservationStateDigest=entry.state_digest,
        sourceHeadCheckpointId=entry.source_head_checkpoint_id,
        sourceHeadCheckpointDigest=entry.source_head_checkpoint_digest,
        graphSnapshotId=entry.graph_snapshot_id,
        graphSnapshotDigest=entry.graph_snapshot_digest,
        cycleId=entry.cycle_id,
        cycleDigest=entry.cycle_digest,
        commandId=entry.command_id,
        commandDigest=entry.command_digest,
        admissionReceiptId=entry.admission_receipt_id,
        admissionReceiptDigest=entry.admission_receipt_digest,
        targetAgentId=entry.target_agent_id,
        taskId=entry.task_id,
        candidateId=entry.candidate_id,
        candidateDigest=entry.candidate_digest,
        proposalDigest=entry.proposal_digest,
        specialistDefinitionDigest=entry.specialist_definition_digest,
        specialization=entry.specialization,
        threatClass=entry.threat_class,
        targetRegistryDigest=target_profile.registry_digest,
        targetProfileDigest=target_profile.profile_digest,
        adapterCatalogDigest=target_profile.catalog_digest,
        adapterReference=target_profile.adapter_reference,
        adapterImplementationId=target_profile.implementation_id,
        adapterImplementationDigest=target_profile.implementation_digest,
        adapterPlanDigest=target_profile.plan_digest,
        targetId=target_profile.target_id,
        targetType=target_profile.target_type,
        targetEndpoint=target_profile.origin,
        targetDigest=target_digest,
        profileRegistryDigest=profile_catalog.registry_digest,
        profile=profile_reference,
        executorCatalogDigest=descriptor.catalog_digest,
        executorId=descriptor.executor_id,
        executorVersion=descriptor.executor_version,
        executorDigest=descriptor.executor_digest,
        browserImplementationId=descriptor.browser_implementation_id,
        browserImplementationVersion=descriptor.browser_implementation_version,
        browserImplementationDigest=descriptor.browser_implementation_digest,
        diagnosticSteps=cast(tuple[str, ...], descriptor.diagnostic_steps),
        promotableSteps=cast(tuple[str, ...], descriptor.promotable_steps),
        campaignId=binding.campaign_id,
        campaignManifestDigest=observed_campaign_digest,
        scopeDigest=scope_digest,
        budgetDigest=budget_digest,
        capabilityRequirement=requirement,
    )


__all__ = [
    "AGENTIC_SPECIALIST_PREPARATION_API_VERSION",
    "AgenticSpecialistCapabilityRequirement",
    "AgenticSpecialistPreparation",
    "AgenticSpecialistPreparationError",
    "prepare_agentic_specialist_action",
]
