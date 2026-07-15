"""Pure, fail-closed compilation of non-executable replay intent."""

from __future__ import annotations

import json
import re
from collections.abc import Collection, Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from typing import Protocol

from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    CapabilityGrant,
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
    ValidationPacket,
    replay_argument_digest,
    replay_evidence_digest,
    replay_request_digest,
)
from pajin.policy.engine import PolicyEngine
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
        specialist_grant: CapabilityGrant,
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
        if replay_run_id == validation_packet.candidate_run_id:
            raise ReplayCompilationError(
                ReplayCompileReason.IDENTITY_MISMATCH,
                "replay Run must differ from the Candidate Run",
            )
        if used_campaign_calls < 0 or (
            used_campaign_calls + contract.repetitions
            > campaign.spec.budgets.max_tool_calls
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

        _validate_identity(
            campaign=campaign,
            packet=validation_packet,
            intent=intent,
            contract=contract,
            scenario=scenario,
            tool_spec=tool_spec,
            original_request=original_request,
        )
        plan_step_id = _validate_plan(plan, original_request, scenario)
        _validate_replay_eligibility(contract, tool_spec)
        _validate_specialist_grant(
            campaign,
            specialist_grant,
            original_request,
            tool_spec,
        )
        original_evidence = _validate_evidence(
            validation_packet,
            original_request,
            evidence_by_request,
        )
        _validate_arguments(
            original_request.arguments,
            contract,
            forbidden_secret_values,
        )
        leases = _validate_secret_lease_ids(secret_lease_ids)

        argument_digest = replay_argument_digest(original_request.arguments)
        request_digest = replay_request_digest(original_request)
        evidence_digest = replay_evidence_digest(original_evidence)
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
            original_grant_id=specialist_grant.grant_id,
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
            original_subject=original_request.agent_id,
            tool_id=binding.tool_id,
            target=binding.target,
            repetitions=contract.repetitions,
        )

        policy_request = original_request.model_copy(
            update={
                "request_id": f"compile:{spec_id}",
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

        arguments = json.loads(
            json.dumps(
                original_request.arguments,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        spec = CompiledReplaySpec(
            spec_id=spec_id,
            intent_id=intent.intent_id,
            contract_id=contract.contract_id,
            original_plan_step_id=plan_step_id,
            binding=binding,
            method=original_request.method,
            arguments=arguments,
            argument_digest=argument_digest,
            original_request_digest=request_digest,
            original_evidence_digest=evidence_digest,
            secret_lease_ids=leases,
            risk_tier=tool_spec.risk_tier,
            replay_safe=True,
            idempotent=True,
            session_policy=contract.session_policy,
            repetitions=contract.repetitions,
            required_successes=contract.required_successes,
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
            original_request=original_request,
            original_evidence=original_evidence,
            spec=spec,
            grant=grant,
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
    ):
        _identity_error("Candidate or validation packet does not match the Campaign")
    if (
        intent.replay_contract_id != contract.contract_id
        or intent.candidate_id != candidate.candidate_id
        or intent.candidate_run_id != packet.candidate_run_id
        or intent.original_request_id != original_request.request_id
        or intent.mode != packet.mode
        or intent.scenario_id != packet.scenario_id
        or intent.threat_class != packet.threat_class
    ):
        _identity_error("ReplayIntent identity does not match the trusted Candidate lineage")
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
) -> str:
    steps = [
        step for step in plan.steps if step.request.request_id == original_request.request_id
    ]
    if len(steps) != 1:
        raise ReplayCompilationError(
            ReplayCompileReason.PROVENANCE_MISMATCH,
            "original request must resolve to exactly one trusted Plan step",
        )
    step = steps[0]
    planned_operation = step.request.model_dump(mode="json", exclude={"agent_id"})
    executed_operation = original_request.model_dump(mode="json", exclude={"agent_id"})
    if (
        planned_operation != executed_operation
        or step.scenario_id != scenario.scenario_id
        or step.threat_classes != scenario.threat_classes
    ):
        raise ReplayCompilationError(
            ReplayCompileReason.PROVENANCE_MISMATCH,
            "original execution does not match its trusted Plan step and Scenario",
        )
    return step.step_id


def _validate_specialist_grant(
    campaign: CampaignManifest,
    grant: CapabilityGrant,
    request: ToolRequest,
    tool_spec: ToolSpec,
) -> None:
    if isinstance(grant, ReplayCapabilityGrant) or (
        grant.campaign != campaign.metadata.name
        or grant.subject != request.agent_id
        or request.tool_id not in grant.tools
        or request.target not in grant.targets
        or tool_spec.risk_tier > grant.max_risk_tier
        or grant.max_risk_tier
        > campaign.spec.rules_of_engagement.max_tool_risk_tier
        or grant.max_calls < 1
        or _normalize_utc(grant.expires_at)
        > _normalize_utc(campaign.spec.authorization.expires_at)
    ):
        raise ReplayCompilationError(
            ReplayCompileReason.SPECIALIST_GRANT_INVALID,
            "original request is not bound to a valid Specialist capability",
        )


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
        or contract.risk_tier > ToolRiskTier.T2
        or tool_spec.risk_tier > ToolRiskTier.T2
        or tool_spec.risk_tier != contract.risk_tier
        or bool(tool_spec.categories & _PROHIBITED_TOOL_CATEGORIES)
    ):
        raise ReplayCompilationError(
            ReplayCompileReason.REPLAY_NOT_ELIGIBLE,
            "Tool or Mode contract is not eligible for automatic restricted replay",
        )


def _validate_arguments(
    arguments: Mapping[str, object],
    contract: ModeReplayContract,
    forbidden_secret_values: Collection[str],
) -> None:
    if not set(arguments) <= contract.allowed_argument_fields:
        raise ReplayCompilationError(
            ReplayCompileReason.ARGUMENT_NOT_ALLOWLISTED,
            "original arguments exceed the trusted Mode allowlist",
        )
    if _contains_sensitive_key(arguments) or _contains_forbidden_secret(
        arguments,
        forbidden_secret_values,
    ):
        raise ReplayCompilationError(
            ReplayCompileReason.SECRET_ARGUMENT,
            "replay arguments contain secret material; use a Secret Lease reference",
        )
    try:
        json.dumps(arguments, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ReplayCompilationError(
            ReplayCompileReason.ARGUMENT_NOT_ALLOWLISTED,
            "replay arguments must contain only finite JSON values",
        ) from exc


def _contains_sensitive_key(value: object) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9]+", "-", str(key).lower()).strip("-")
            parts = set(normalized.split("-"))
            if normalized in _SENSITIVE_ARGUMENT_PARTS or parts & _SENSITIVE_ARGUMENT_PARTS:
                return True
            if _contains_sensitive_key(item):
                return True
    elif isinstance(value, Collection) and not isinstance(value, (str, bytes, bytearray)):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _contains_forbidden_secret(
    value: object,
    forbidden_secret_values: Collection[str],
) -> bool:
    secrets = tuple(item for item in forbidden_secret_values if item)
    if not secrets:
        return False
    if isinstance(value, str):
        return any(secret in value for secret in secrets)
    if isinstance(value, Mapping):
        return any(_contains_forbidden_secret(item, secrets) for item in value.values())
    if isinstance(value, Collection) and not isinstance(value, (str, bytes, bytearray)):
        return any(_contains_forbidden_secret(item, secrets) for item in value)
    return False


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
    original_grant_id: str,
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
        "originalEvidenceDigest": original_evidence_digest,
        "originalGrantId": original_grant_id,
        "originalPlanStepId": original_plan_step_id,
        "originalRequestDigest": original_request_digest,
        "replayRunId": replay_run_id,
        "secretLeaseIds": secret_lease_ids,
        "targetId": validation_packet.target_id,
        "threatClass": validation_packet.threat_class,
        "toolSpec": _canonical_value(tool_spec.model_dump(mode="python")),
    }
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
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
            key=lambda item: json.dumps(item, sort_keys=True, default=str),
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
