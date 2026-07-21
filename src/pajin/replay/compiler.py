"""Pure, fail-closed compilation of non-executable replay intent."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Collection, Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from typing import Protocol, cast

from pydantic import JsonValue

from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    ToolRequest,
    ToolRiskTier,
)
from pajin.domain.replay import (
    CompiledReplaySpec,
    ModeReplayContract,
    ReplayBinding,
    ReplayCapabilityGrant,
    ReplayCompilation,
    ReplayIntent,
    ReplayPurpose,
    ReplaySessionPolicy,
    ReplaySourceCapabilityReceipt,
    ValidationPacket,
    replay_argument_digest,
    replay_evidence_digest,
    replay_request_digest,
    replay_retest_context_digest,
    replay_source_capability_digest,
)
from pajin.policy.engine import PolicyEngine
from pajin.replay.tickets import (
    ReplayExecutionTicket,
    ReplayTicketContext,
    ReplayTicketIssuer,
    replay_context_digest,
)
from pajin.tools.base import ToolSpec

REPLAY_GRANT_TTL = timedelta(minutes=5)

_PROHIBITED_TOOL_CATEGORIES = frozenset(
    {
        "ambiguous",
        "credential-theft",
        "data-destruction",
        "denial-of-service",
        "destructive",
        "manual-only",
        "persistence",
    }
)
_SENSITIVE_ARGUMENT_PARTS = frozenset(
    {
        "api-key",
        "apikey",
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "passwd",
        "password",
        "secret",
        "token",
    }
)
_LEASE_ID_PATTERN = re.compile(r"^lease_[A-Za-z0-9][A-Za-z0-9_.:-]{0,193}$")
_MAX_REPLAY_ARGUMENT_DEPTH = 32
_MAX_REPLAY_ARGUMENT_NODES = 10_000
_MAX_REPLAY_ARGUMENT_BYTES = 256 * 1024


class ReplayScenarioDefinition(Protocol):
    """Trusted Mode scenario attributes required by the generic compiler."""

    scenario_id: str
    target_types: set[str]
    threat_classes: set[str]
    tool_id: str
    method: str


class ReplayCompileReason(StrEnum):
    CANCELLED = "cancelled"
    AUTHORIZATION_INACTIVE = "authorization-inactive"
    BUDGET_EXCEEDED = "budget-exceeded"
    IDENTITY_MISMATCH = "identity-mismatch"
    PROVENANCE_MISMATCH = "provenance-mismatch"
    EVIDENCE_MISMATCH = "evidence-mismatch"
    SPECIALIST_GRANT_INVALID = "specialist-grant-invalid"
    TOOL_UNREGISTERED = "tool-unregistered"
    REPLAY_NOT_ELIGIBLE = "replay-not-eligible"
    SCENARIO_TEMPLATE_MISMATCH = "scenario-template-mismatch"
    ARGUMENT_NOT_ALLOWLISTED = "argument-not-allowlisted"
    SECRET_ARGUMENT = "secret-argument"
    POLICY_DENIED = "policy-denied"


class ReplayCompilationError(ValueError):
    """Typed compiler rejection that never includes secret material."""

    def __init__(
        self,
        reason: ReplayCompileReason,
        message: str,
        *,
        policy: str | None = None,
    ) -> None:
        self.reason = reason
        self.policy = policy
        super().__init__(message)


class ReplayCompiler:
    """Compile trusted lineage into one deterministic, least-privilege replay bundle."""

    @staticmethod
    def compile(
        *,
        campaign: CampaignManifest,
        plan: AgentPlan,
        original_request: ToolRequest,
        source_capability: ReplaySourceCapabilityReceipt,
        validation_packet: ValidationPacket,
        intent: ReplayIntent,
        contract: ModeReplayContract,
        scenario: ReplayScenarioDefinition,
        registered_tools: Mapping[str, ToolSpec],
        evidence_by_request: Mapping[str, Collection[str]],
        trusted_original_request_digest: str,
        trusted_original_evidence_digest: str,
        replay_run_id: str,
        used_campaign_calls: int,
        compiled_at: datetime,
        cancellation_active: bool = False,
        secret_lease_ids: Collection[str] = (),
        forbidden_secret_values: Collection[str] = (),
    ) -> ReplayCompilation:
        now = _normalize_utc(compiled_at)
        if cancellation_active:
            raise ReplayCompilationError(
                ReplayCompileReason.CANCELLED,
                "replay compilation is blocked by active cancellation",
            )
        if not campaign.spec.authorization.is_active(now):
            raise ReplayCompilationError(
                ReplayCompileReason.AUTHORIZATION_INACTIVE,
                "campaign authorization is not active at compilation time",
            )
        context = validation_packet.retest_context
        if replay_run_id == validation_packet.candidate_run_id or (
            context is not None and replay_run_id == context.retest_run_id
        ):
            raise ReplayCompilationError(
                ReplayCompileReason.IDENTITY_MISMATCH,
                "replay Run must differ from Candidate and parent Retest Runs",
            )
        if used_campaign_calls < 0 or (
            used_campaign_calls + contract.repetitions > campaign.spec.budgets.max_tool_calls
        ):
            raise ReplayCompilationError(
                ReplayCompileReason.BUDGET_EXCEEDED,
                "campaign has insufficient remaining calls for replay repetitions",
            )
        tool_spec = registered_tools.get(contract.tool_id)
        if tool_spec is None:
            raise ReplayCompilationError(
                ReplayCompileReason.TOOL_UNREGISTERED,
                "Mode replay contract references an unregistered Tool",
            )

        arguments = _validate_arguments(
            original_request.arguments,
            contract,
            forbidden_secret_values,
        )
        canonical_request = original_request.model_copy(update={"arguments": arguments})
        _validate_identity(
            campaign=campaign,
            packet=validation_packet,
            intent=intent,
            contract=contract,
            scenario=scenario,
            tool_spec=tool_spec,
            original_request=canonical_request,
        )
        plan_step_id = _validate_plan(
            plan,
            canonical_request,
            scenario,
            contract=contract,
            forbidden_secret_values=forbidden_secret_values,
        )
        _validate_replay_eligibility(contract, tool_spec)
        trusted_source_capability = _validate_source_capability(
            source_capability,
            campaign,
            canonical_request,
            tool_spec,
            validation_packet,
            intent,
            compiled_at=now,
        )
        specialist_grant = trusted_source_capability.specialist_grant
        original_evidence = _validate_evidence(
            validation_packet,
            canonical_request,
            evidence_by_request,
        )
        _validate_scenario_arguments(scenario, arguments)
        leases = _validate_secret_lease_ids(secret_lease_ids)

        argument_digest = replay_argument_digest(arguments)
        request_digest = replay_request_digest(canonical_request)
        evidence_digest = replay_evidence_digest(original_evidence)
        source_capability_digest = replay_source_capability_digest(trusted_source_capability)
        if request_digest != trusted_original_request_digest:
            raise ReplayCompilationError(
                ReplayCompileReason.PROVENANCE_MISMATCH,
                "original request does not match its trusted integrity digest",
            )
        if evidence_digest != trusted_original_evidence_digest:
            raise ReplayCompilationError(
                ReplayCompileReason.EVIDENCE_MISMATCH,
                "original evidence does not match its trusted integrity digest",
            )
        compilation_digest = _compilation_digest(
            validation_packet=validation_packet,
            intent=intent,
            contract=contract,
            tool_spec=tool_spec,
            original_request_digest=request_digest,
            original_evidence_digest=evidence_digest,
            source_capability_digest=source_capability_digest,
            original_plan_step_id=plan_step_id,
            secret_lease_ids=leases,
            replay_run_id=replay_run_id,
            compiled_at=now,
        )
        grant_id = f"grant_replay_{compilation_digest[:32]}"
        spec_id = f"compiled-replay_{compilation_digest[32:64]}"
        grant_expiry = min(
            now + REPLAY_GRANT_TTL,
            _normalize_utc(campaign.spec.authorization.expires_at),
        )
        target = next(
            item for item in campaign.spec.targets if item.id == validation_packet.target_id
        )
        binding = ReplayBinding(
            candidate_id=validation_packet.candidate.candidate_id,
            campaign=campaign.metadata.name,
            candidate_run_id=validation_packet.candidate_run_id,
            replay_run_id=replay_run_id,
            purpose=validation_packet.purpose,
            context_run_id=context.retest_run_id if context is not None else None,
            original_request_id=original_request.request_id,
            mode=campaign.spec.mode,
            scenario_id=scenario.scenario_id,
            threat_class=validation_packet.threat_class,
            tool_id=tool_spec.tool_id,
            tool_version=tool_spec.version,
            target_id=target.id,
            target=target.endpoint,
        )
        grant = ReplayCapabilityGrant(
            grant_id=grant_id,
            subject=f"reproducer:{grant_id}",
            campaign=campaign.metadata.name,
            tools={tool_spec.tool_id},
            targets={target.endpoint},
            max_risk_tier=tool_spec.risk_tier,
            max_calls=contract.repetitions,
            expires_at=grant_expiry,
            issued_at=now,
            contract_id=contract.contract_id,
            candidate_id=binding.candidate_id,
            candidate_run_id=binding.candidate_run_id,
            replay_run_id=binding.replay_run_id,
            original_request_id=binding.original_request_id,
            original_grant_id=specialist_grant.grant_id,
            source_capability_digest=source_capability_digest,
            original_subject=original_request.agent_id,
            tool_id=binding.tool_id,
            target=binding.target,
            repetitions=contract.repetitions,
        )

        policy_request = canonical_request.model_copy(
            update={
                "request_id": f"compile-{spec_id}",
                "agent_id": grant.subject,
            }
        )
        policy = PolicyEngine().evaluate_tool_request(
            campaign,
            grant,
            policy_request,
            tool_spec,
            used_calls=0,
            now=now,
        )
        if not policy.allowed:
            raise ReplayCompilationError(
                ReplayCompileReason.POLICY_DENIED,
                f"replay compilation denied by policy: {policy.policy}",
                policy=policy.policy,
            )

        try:
            spec = CompiledReplaySpec(
                spec_id=spec_id,
                intent_id=intent.intent_id,
                contract_id=contract.contract_id,
                purpose=validation_packet.purpose,
                retest_context_digest=(
                    replay_retest_context_digest(context) if context is not None else None
                ),
                original_plan_step_id=plan_step_id,
                binding=binding,
                method=canonical_request.method,
                arguments=arguments,
                argument_digest=argument_digest,
                original_request_digest=request_digest,
                original_evidence_digest=evidence_digest,
                source_capability_digest=source_capability_digest,
                secret_lease_ids=leases,
                risk_tier=tool_spec.risk_tier,
                replay_safe=True,
                idempotent=True,
                session_policy=contract.session_policy,
                materializer_id=contract.materializer_id,
                materializer_version=contract.materializer_version,
                ephemeral_argument_fields=contract.ephemeral_argument_fields,
                repetitions=contract.repetitions,
                required_successes=contract.required_successes,
                required_contradictions=contract.required_contradictions,
                oracle_id=contract.oracle_id,
                oracle_version=contract.oracle_version,
                observation_schema=contract.observation_schema,
                semantic_support_required=contract.semantic_support_required,
                grant_id=grant.grant_id,
                max_calls=contract.repetitions,
                compiled_at=now,
                expires_at=grant.expires_at,
            )
            return ReplayCompilation(
                validation_packet=validation_packet,
                contract=contract,
                intent=intent,
                original_request=canonical_request,
                original_evidence=original_evidence,
                source_capability=trusted_source_capability,
                spec=spec,
                grant=grant,
            )
        except (TypeError, ValueError, RecursionError) as exc:
            raise ReplayCompilationError(
                ReplayCompileReason.PROVENANCE_MISMATCH,
                "trusted replay inputs could not be compiled into canonical artifacts",
            ) from exc

    @staticmethod
    def compile_ticket(
        *,
        ticket_issuer: ReplayTicketIssuer,
        candidate_source_root_digest: str,
        campaign: CampaignManifest,
        plan: AgentPlan,
        original_request: ToolRequest,
        source_capability: ReplaySourceCapabilityReceipt,
        validation_packet: ValidationPacket,
        intent: ReplayIntent,
        contract: ModeReplayContract,
        scenario: ReplayScenarioDefinition,
        registered_tools: Mapping[str, ToolSpec],
        evidence_by_request: Mapping[str, Collection[str]],
        trusted_original_request_digest: str,
        trusted_original_evidence_digest: str,
        replay_run_id: str,
        used_campaign_calls: int,
        compiled_at: datetime,
        cancellation_active: bool = False,
        secret_lease_ids: Collection[str] = (),
        forbidden_secret_values: Collection[str] = (),
    ) -> ReplayExecutionTicket:
        """Compile and atomically admit one opaque, single-use runtime ticket."""

        compilation = ReplayCompiler.compile(
            campaign=campaign,
            plan=plan,
            original_request=original_request,
            source_capability=source_capability,
            validation_packet=validation_packet,
            intent=intent,
            contract=contract,
            scenario=scenario,
            registered_tools=registered_tools,
            evidence_by_request=evidence_by_request,
            trusted_original_request_digest=trusted_original_request_digest,
            trusted_original_evidence_digest=trusted_original_evidence_digest,
            replay_run_id=replay_run_id,
            used_campaign_calls=used_campaign_calls,
            compiled_at=compiled_at,
            cancellation_active=cancellation_active,
            secret_lease_ids=secret_lease_ids,
            forbidden_secret_values=forbidden_secret_values,
        )
        tool_spec = registered_tools[contract.tool_id]
        context = ReplayTicketContext(
            candidate_source_root_digest=candidate_source_root_digest,
            campaign_digest=replay_context_digest(campaign),
            tool_spec_digest=replay_context_digest(tool_spec),
            scenario_digest=replay_scenario_digest(scenario),
        )
        return ticket_issuer.issue_from_compiler(compilation, context=context)


def replay_scenario_digest(scenario: ReplayScenarioDefinition) -> str:
    """Fingerprint the trusted scenario attributes consumed by the compiler."""

    model_dump = getattr(scenario, "model_dump", None)
    if callable(model_dump):
        return replay_context_digest(model_dump(mode="python", by_alias=True))
    return replay_context_digest(
        {
            "scenarioId": scenario.scenario_id,
            "targetTypes": sorted(scenario.target_types),
            "threatClasses": sorted(scenario.threat_classes),
            "toolId": scenario.tool_id,
            "method": scenario.method.upper(),
        }
    )


def _validate_identity(
    *,
    campaign: CampaignManifest,
    packet: ValidationPacket,
    intent: ReplayIntent,
    contract: ModeReplayContract,
    scenario: ReplayScenarioDefinition,
    tool_spec: ToolSpec,
    original_request: ToolRequest,
) -> None:
    candidate = packet.candidate
    matching_targets = [item for item in campaign.spec.targets if item.id == packet.target_id]
    if len(matching_targets) != 1:
        _identity_error("validation packet target ID is not unique in the Campaign")
    target = matching_targets[0]
    if (
        packet.mode != campaign.spec.mode
        or packet.target != target.endpoint
        or candidate.claim.target != target.endpoint
        or candidate.claim.threat_class != packet.threat_class
        or packet.threat_class not in campaign.spec.threat_classes
        or packet.replay_contract_id != contract.contract_id
        or packet.purpose != contract.purpose
    ):
        _identity_error("Candidate or validation packet does not match the Campaign")
    if (
        intent.replay_contract_id != contract.contract_id
        or intent.purpose != packet.purpose
        or intent.retest_context != packet.retest_context
        or intent.candidate_id != candidate.candidate_id
        or intent.candidate_run_id != packet.candidate_run_id
        or intent.original_request_id != original_request.request_id
        or intent.mode != packet.mode
        or intent.scenario_id != packet.scenario_id
        or intent.threat_class != packet.threat_class
    ):
        _identity_error("ReplayIntent identity does not match the trusted Candidate lineage")
    context = packet.retest_context
    if packet.purpose is ReplayPurpose.CONFIRMATION:
        if context is not None:
            _identity_error("confirmation replay cannot bind remediation retest context")
    elif (
        context is None
        or context.baseline_finding_id != candidate.claim.finding_id
        or context.retest_run_id == packet.candidate_run_id
    ):
        _identity_error("remediation retest context does not match Candidate lineage")
    if (
        scenario.scenario_id != packet.scenario_id
        or scenario.scenario_id != contract.scenario_id
        or target.type not in scenario.target_types
        or packet.threat_class not in scenario.threat_classes
        or scenario.tool_id != contract.tool_id
        or scenario.method.upper() != contract.method
        or tool_spec.tool_id != contract.tool_id
        or tool_spec.version != contract.tool_version
        or original_request.tool_id != contract.tool_id
        or original_request.target != target.endpoint
        or original_request.method != contract.method
        or original_request.request_id not in candidate.source_request_ids
        or original_request.request_id not in packet.original_request_ids
    ):
        _identity_error("Scenario, Tool, target, or original request identity was substituted")


def _validate_plan(
    plan: AgentPlan,
    original_request: ToolRequest,
    scenario: ReplayScenarioDefinition,
    *,
    contract: ModeReplayContract,
    forbidden_secret_values: Collection[str],
) -> str:
    steps = [step for step in plan.steps if step.request.request_id == original_request.request_id]
    if len(steps) != 1:
        raise ReplayCompilationError(
            ReplayCompileReason.PROVENANCE_MISMATCH,
            "original request must resolve to exactly one trusted Plan step",
        )
    step = steps[0]
    planned_arguments = _validate_arguments(
        step.request.arguments,
        contract,
        forbidden_secret_values,
    )
    if (
        step.request.request_id != original_request.request_id
        or step.request.tool_id != original_request.tool_id
        or step.request.target != original_request.target
        or step.request.method != original_request.method
        or planned_arguments != original_request.arguments
        or step.scenario_id != scenario.scenario_id
        or step.threat_classes != scenario.threat_classes
    ):
        raise ReplayCompilationError(
            ReplayCompileReason.PROVENANCE_MISMATCH,
            "original execution does not match its trusted Plan step and Scenario",
        )
    return step.step_id


def _validate_source_capability(
    source_capability: ReplaySourceCapabilityReceipt,
    campaign: CampaignManifest,
    request: ToolRequest,
    tool_spec: ToolSpec,
    packet: ValidationPacket,
    intent: ReplayIntent,
    *,
    compiled_at: datetime,
) -> ReplaySourceCapabilityReceipt:
    if not isinstance(source_capability, ReplaySourceCapabilityReceipt):
        raise ReplayCompilationError(
            ReplayCompileReason.SPECIALIST_GRANT_INVALID,
            "source execution requires a verified capability lineage receipt",
        )
    try:
        trusted = ReplaySourceCapabilityReceipt.model_validate(
            source_capability.model_dump(mode="python", by_alias=True)
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ReplayCompilationError(
            ReplayCompileReason.SPECIALIST_GRANT_INVALID,
            "source capability lineage receipt is invalid",
        ) from exc

    grant = trusted.specialist_grant
    authorization = campaign.spec.authorization
    authorization_approved_at = _normalize_utc(authorization.approved_at)
    authorization_expires_at = _normalize_utc(authorization.expires_at)
    candidate_created_at = _normalize_utc(packet.candidate.created_at)
    packet_created_at = _normalize_utc(packet.created_at)
    intent_created_at = _normalize_utc(intent.created_at)
    chronology_valid = (
        trusted.execution_finished_at
        <= candidate_created_at
        <= packet_created_at
        <= intent_created_at
        <= compiled_at
    )
    lineage_valid = all(
        item.campaign == campaign.metadata.name
        and _normalize_utc(item.issued_at) >= authorization_approved_at
        and _normalize_utc(item.expires_at) <= authorization_expires_at
        and item.max_risk_tier <= campaign.spec.rules_of_engagement.max_tool_risk_tier
        for item in trusted.lineage
    )
    if (
        isinstance(grant, ReplayCapabilityGrant)
        or not chronology_valid
        or not lineage_valid
        or (
            trusted.request_id != request.request_id
            or grant.subject != request.agent_id
            or request.tool_id not in grant.tools
            or request.target not in grant.targets
            or tool_spec.risk_tier > grant.max_risk_tier
            or grant.max_calls < 1
        )
    ):
        raise ReplayCompilationError(
            ReplayCompileReason.SPECIALIST_GRANT_INVALID,
            "original request is not bound to valid historical Specialist authority",
        )
    return trusted


def _validate_evidence(
    packet: ValidationPacket,
    original_request: ToolRequest,
    evidence_by_request: Mapping[str, Collection[str]],
) -> list[str]:
    if any(request_id not in evidence_by_request for request_id in packet.original_request_ids):
        raise ReplayCompilationError(
            ReplayCompileReason.EVIDENCE_MISMATCH,
            "Candidate source request is missing trusted evidence lineage",
        )
    known_evidence = {
        reference
        for request_id in packet.original_request_ids
        for reference in evidence_by_request[request_id]
    }
    candidate_evidence = packet.candidate.claim.evidence
    if not set(candidate_evidence) <= known_evidence:
        raise ReplayCompilationError(
            ReplayCompileReason.EVIDENCE_MISMATCH,
            "Candidate evidence is not linked to its source requests",
        )
    selected_evidence = set(evidence_by_request[original_request.request_id])
    original_evidence = [
        reference for reference in candidate_evidence if reference in selected_evidence
    ]
    if not original_evidence:
        raise ReplayCompilationError(
            ReplayCompileReason.EVIDENCE_MISMATCH,
            "selected original request has no Candidate-bound evidence",
        )
    return original_evidence


def _validate_replay_eligibility(contract: ModeReplayContract, tool_spec: ToolSpec) -> None:
    if (
        not contract.automatic
        or not contract.replay_safe
        or not contract.idempotent
        or contract.session_policy is ReplaySessionPolicy.PRESERVE_SCENARIO_SESSION
        or contract.risk_tier > ToolRiskTier.T2
        or tool_spec.risk_tier > ToolRiskTier.T2
        or tool_spec.risk_tier != contract.risk_tier
        or bool(tool_spec.categories & _PROHIBITED_TOOL_CATEGORIES)
    ):
        raise ReplayCompilationError(
            ReplayCompileReason.REPLAY_NOT_ELIGIBLE,
            "Tool or Mode contract is not eligible for automatic restricted replay",
        )


def _validate_scenario_arguments(
    scenario: ReplayScenarioDefinition,
    arguments: Mapping[str, object],
) -> None:
    """Apply a Mode-owned exact-template check when the scenario supplies one."""

    matches = getattr(scenario, "matches_replay_arguments", None)
    if callable(matches) and not bool(matches(arguments)):
        raise ReplayCompilationError(
            ReplayCompileReason.SCENARIO_TEMPLATE_MISMATCH,
            "original arguments do not match the trusted Mode scenario template",
        )


def _validate_arguments(
    arguments: Mapping[str, object],
    contract: ModeReplayContract,
    forbidden_secret_values: Collection[str],
) -> dict[str, JsonValue]:
    if not set(arguments) <= contract.allowed_argument_fields:
        raise ReplayCompilationError(
            ReplayCompileReason.ARGUMENT_NOT_ALLOWLISTED,
            "original arguments exceed the trusted Mode allowlist",
        )
    if any(not isinstance(item, str) for item in forbidden_secret_values):
        raise ReplayCompilationError(
            ReplayCompileReason.SECRET_ARGUMENT,
            "forbidden replay secret values must be bounded text",
        )
    secrets = tuple(item for item in forbidden_secret_values if item)
    counter = [0]
    try:
        canonical = _canonicalize_argument_value(
            arguments,
            depth=0,
            active_container_ids=set(),
            counter=counter,
            forbidden_secret_values=secrets,
        )
        if not isinstance(canonical, dict):
            raise TypeError("top-level replay arguments must be an object")
        encoded = json.dumps(
            canonical,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded) > _MAX_REPLAY_ARGUMENT_BYTES:
            raise ValueError("replay argument bytes exceeded")
    except ReplayCompilationError:
        raise
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ReplayCompilationError(
            ReplayCompileReason.ARGUMENT_NOT_ALLOWLISTED,
            "replay arguments must be bounded canonical JSON",
        ) from exc
    return canonical


def _canonicalize_argument_value(
    value: object,
    *,
    depth: int,
    active_container_ids: set[int],
    counter: list[int],
    forbidden_secret_values: tuple[str, ...],
) -> JsonValue:
    counter[0] += 1
    if depth > _MAX_REPLAY_ARGUMENT_DEPTH or counter[0] > _MAX_REPLAY_ARGUMENT_NODES:
        raise ReplayCompilationError(
            ReplayCompileReason.ARGUMENT_NOT_ALLOWLISTED,
            "replay arguments exceed the bounded JSON structure limit",
        )
    if value is None or type(value) in {bool, int}:
        return cast(JsonValue, value)
    if type(value) is float:
        if not math.isfinite(value):
            raise ReplayCompilationError(
                ReplayCompileReason.ARGUMENT_NOT_ALLOWLISTED,
                "replay arguments require finite JSON numbers",
            )
        return cast(JsonValue, value)
    if type(value) is str:
        if any(secret in value for secret in forbidden_secret_values):
            raise ReplayCompilationError(
                ReplayCompileReason.SECRET_ARGUMENT,
                "replay arguments contain secret material; use a Secret Lease reference",
            )
        return value
    if type(value) not in {dict, list}:
        raise ReplayCompilationError(
            ReplayCompileReason.ARGUMENT_NOT_ALLOWLISTED,
            "replay arguments contain a non-JSON value",
        )

    container_id = id(value)
    if container_id in active_container_ids:
        raise ReplayCompilationError(
            ReplayCompileReason.ARGUMENT_NOT_ALLOWLISTED,
            "replay arguments contain a container cycle",
        )
    active_container_ids.add(container_id)
    try:
        if type(value) is list:
            return [
                _canonicalize_argument_value(
                    item,
                    depth=depth + 1,
                    active_container_ids=active_container_ids,
                    counter=counter,
                    forbidden_secret_values=forbidden_secret_values,
                )
                for item in value
            ]

        result: dict[str, JsonValue] = {}
        mapping = cast(dict[object, object], value)
        for key, item in mapping.items():
            if type(key) is not str:
                raise ReplayCompilationError(
                    ReplayCompileReason.ARGUMENT_NOT_ALLOWLISTED,
                    "replay JSON object keys must be strings",
                )
            normalized = re.sub(r"[^a-z0-9]+", "-", key.lower()).strip("-")
            parts = set(normalized.split("-"))
            if normalized in _SENSITIVE_ARGUMENT_PARTS or parts & _SENSITIVE_ARGUMENT_PARTS:
                raise ReplayCompilationError(
                    ReplayCompileReason.SECRET_ARGUMENT,
                    "replay arguments contain secret material; use a Secret Lease reference",
                )
            result[key] = _canonicalize_argument_value(
                item,
                depth=depth + 1,
                active_container_ids=active_container_ids,
                counter=counter,
                forbidden_secret_values=forbidden_secret_values,
            )
        return result
    finally:
        active_container_ids.remove(container_id)


def _validate_secret_lease_ids(secret_lease_ids: Collection[str]) -> list[str]:
    leases = list(secret_lease_ids)
    if len(leases) != len(set(leases)) or any(
        _LEASE_ID_PATTERN.fullmatch(item) is None for item in leases
    ):
        raise ReplayCompilationError(
            ReplayCompileReason.SECRET_ARGUMENT,
            "replay secrets must be unique Secret Lease references",
        )
    return leases


def _compilation_digest(
    *,
    validation_packet: ValidationPacket,
    intent: ReplayIntent,
    contract: ModeReplayContract,
    tool_spec: ToolSpec,
    original_request_digest: str,
    original_evidence_digest: str,
    source_capability_digest: str,
    original_plan_step_id: str,
    secret_lease_ids: list[str],
    replay_run_id: str,
    compiled_at: datetime,
) -> str:
    payload = {
        "candidateId": validation_packet.candidate.candidate_id,
        "candidateRunId": validation_packet.candidate_run_id,
        "compiledAt": compiled_at.isoformat(),
        "contract": _canonical_value(contract.model_dump(mode="python", by_alias=True)),
        "intentId": intent.intent_id,
        "purpose": validation_packet.purpose.value,
        "retestContext": (
            _canonical_value(
                validation_packet.retest_context.model_dump(mode="python", by_alias=True)
            )
            if validation_packet.retest_context is not None
            else None
        ),
        "originalEvidenceDigest": original_evidence_digest,
        "originalPlanStepId": original_plan_step_id,
        "originalRequestDigest": original_request_digest,
        "sourceCapabilityDigest": source_capability_digest,
        "replayRunId": replay_run_id,
        "secretLeaseIds": secret_lease_ids,
        "targetId": validation_packet.target_id,
        "threatClass": validation_packet.threat_class,
        "toolSpec": _canonical_value(tool_spec.model_dump(mode="python")),
    }
    try:
        canonical = json.dumps(
            payload,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ReplayCompilationError(
            ReplayCompileReason.PROVENANCE_MISMATCH,
            "trusted replay metadata is not canonical JSON",
        ) from exc
    return sha256(canonical).hexdigest()


def _identity_error(message: str) -> None:
    raise ReplayCompilationError(ReplayCompileReason.IDENTITY_MISMATCH, message)


def _canonical_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (set, frozenset)):
        return sorted(
            (_canonical_value(item) for item in value),
            key=lambda item: json.dumps(
                item,
                sort_keys=True,
                default=str,
                allow_nan=False,
            ),
        )
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, datetime):
        return _normalize_utc(value).isoformat()
    return value


def _normalize_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ReplayCompilationError(
            ReplayCompileReason.PROVENANCE_MISMATCH,
            "compilation time must include a UTC offset or Z",
        )
    return value.astimezone(UTC)
