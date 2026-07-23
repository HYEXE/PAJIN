"""Evidence-bound hypotheses and one bounded dynamic Specialist wave."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from re import fullmatch
from typing import Literal, cast

from pydantic import Field, JsonValue, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.models import AttackSurfaceSet, ToolInterfaceSurfaceLocator
from pajin.discovery.projection import SurfaceProjectionPublication
from pajin.discovery.recon import ReconWaveOutcome
from pajin.domain.models import (
    CampaignManifest,
    StrictModel,
    ToolRequest,
    ToolResult,
    ToolRiskTier,
)
from pajin.policy.capability import CapabilityError, CapabilityLedger
from pajin.policy.engine import PolicyEngine
from pajin.runtime.control import BudgetController, BudgetExceeded, ExecutionCancellationContext
from pajin.runtime.error_safety import audit_safe_exception_type
from pajin.runtime.store import (
    RunIntegrityError,
    RunStore,
    load_verified_run_artifacts,
    verify_run_integrity,
)
from pajin.runtime.worker import WorkerBackend
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import RequestRateLimitLedger, ToolGateway
from pajin.workflow.cancellation import (
    await_with_campaign_deadline,
    ensure_cancellation_context,
    record_engine_cleanup,
)

HYPOTHESIS_API_VERSION = "pajin.dev/discovery-hypothesis/v1alpha1"
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_PORTABLE_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_HYPOTHESIS_ID_PATTERN = r"^attack-hypothesis_[a-f0-9]{64}$"
_HYPOTHESIS_SET_ID_PATTERN = r"^attack-hypothesis-set_[a-f0-9]{64}$"
_HYPOTHESIS_WAVE_PLAN_ID_PATTERN = r"^hypothesis-wave-plan_[a-f0-9]{64}$"
_MAX_ARGUMENT_BYTES = 1_000_000
_MAX_HYPOTHESES = 100
_MAX_HYPOTHESIS_BYTES = 64 * 1024
_MAX_HYPOTHESIS_SET_BYTES = 4 * 1024 * 1024
_MAX_HYPOTHESIS_WAVE_PLAN_BYTES = 4 * 1024 * 1024
_MAX_SURFACE_SET_BYTES = 4 * 1024 * 1024


class HypothesisWaveError(RuntimeError):
    """Raised when a Hypothesis wave cannot complete its fail-closed contract."""


def _safe_text(value: str, *, label: str) -> str:
    if value != value.strip():
        raise ValueError(f"{label} cannot contain surrounding whitespace")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError(f"{label} cannot contain control characters")
    return value


def _utc_wire(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include an explicit UTC offset or Z")
    return value.astimezone(UTC)


def _bounded_arguments(value: object) -> dict[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise ValueError("Hypothesis rule arguments must be an object")
    try:
        encoded = canonical_json_bytes(
            dict(value),
            label="Hypothesis rule arguments",
            max_bytes=_MAX_ARGUMENT_BYTES,
        )
        decoded = json.loads(encoded)
    except (RecursionError, TypeError, ValueError) as exc:
        raise ValueError("Hypothesis rule arguments must be bounded JSON") from exc
    if not isinstance(decoded, dict):
        raise ValueError("Hypothesis rule arguments must be an object")
    return cast(dict[str, JsonValue], decoded)


class RegisteredHypothesisRule(StrictModel):
    """Code-registered mapping from one exact Surface interface to one Tool action."""

    rule_id: str = Field(
        alias="ruleId",
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    source_registry_id: str = Field(
        alias="sourceRegistryId",
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    source_tool_id: str = Field(
        alias="sourceToolId",
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    source_tool_version: str = Field(
        alias="sourceToolVersion",
        min_length=1,
        max_length=100,
    )
    source_input_schema_digest: str = Field(
        alias="sourceInputSchemaDigest",
        pattern=_SHA256_PATTERN,
    )
    threat_class: str = Field(alias="threatClass", min_length=2, max_length=20)
    statement: str = Field(min_length=1, max_length=2_000)
    expected_observable: str = Field(
        alias="expectedObservable",
        min_length=1,
        max_length=2_000,
    )
    required_tool_id: str = Field(
        alias="requiredToolId",
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    method: str = Field(
        default="POST",
        min_length=1,
        max_length=20,
        pattern=r"^[A-Z0-9!#$%&'*+.^_`|~-]+$",
    )
    arguments: dict[str, JsonValue]
    estimated_cost_usd: float = Field(
        default=0,
        alias="estimatedCostUsd",
        ge=0,
        allow_inf_nan=False,
    )
    success_condition: str = Field(
        alias="successCondition",
        min_length=1,
        max_length=2_000,
    )

    @field_validator("method", mode="before")
    @classmethod
    def normalize_method(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value

    @field_validator(
        "source_tool_version",
        "threat_class",
        "statement",
        "expected_observable",
        "success_condition",
    )
    @classmethod
    def validate_text(cls, value: str) -> str:
        return _safe_text(value, label="Hypothesis rule text")

    @field_validator("arguments", mode="before")
    @classmethod
    def validate_arguments(cls, value: object) -> dict[str, JsonValue]:
        return _bounded_arguments(value)

    def matches(self, locator: ToolInterfaceSurfaceLocator) -> bool:
        """Return whether this rule is registered for the exact Surface interface."""

        return (
            locator.registry_id == self.source_registry_id
            and locator.tool_id == self.source_tool_id
            and locator.tool_version == self.source_tool_version
            and locator.input_schema_digest == self.source_input_schema_digest
        )


class AttackHypothesis(StrictModel):
    """Non-executable, evidence-bound claim compiled from one admitted Surface."""

    api_version: Literal["pajin.dev/discovery-hypothesis/v1alpha1"] = Field(
        default="pajin.dev/discovery-hypothesis/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["AttackHypothesis"] = "AttackHypothesis"
    hypothesis_id: str = ""
    compiler_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    rule_id: str = Field(min_length=1, max_length=200, pattern=_IDENTIFIER_PATTERN)
    campaign: str = Field(
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    surface_set_id: str = Field(pattern=r"^attack-surface-set_[a-f0-9]{64}$")
    surface_id: str = Field(pattern=r"^attack-surface_[a-f0-9]{64}$")
    target_id: str = Field(min_length=1, max_length=200, pattern=_IDENTIFIER_PATTERN)
    threat_class: str = Field(min_length=2, max_length=20)
    statement: str = Field(min_length=1, max_length=2_000)
    expected_observable: str = Field(min_length=1, max_length=2_000)
    required_tool_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    required_tool_version: str = Field(min_length=1, max_length=100)
    risk_tier: ToolRiskTier
    estimated_tool_calls: Literal[1] = 1
    estimated_cost_usd: float = Field(ge=0, allow_inf_nan=False)
    success_condition: str = Field(min_length=1, max_length=2_000)

    @field_validator(
        "threat_class",
        "statement",
        "expected_observable",
        "required_tool_version",
        "success_condition",
    )
    @classmethod
    def validate_text(cls, value: str) -> str:
        return _safe_text(value, label="Attack Hypothesis text")

    @field_validator("risk_tier", mode="before")
    @classmethod
    def parse_risk_tier(cls, value: ToolRiskTier | str | int) -> ToolRiskTier:
        return ToolRiskTier.parse(value)

    @model_validator(mode="after")
    def validate_identity(self) -> AttackHypothesis:
        expected = "attack-hypothesis_" + discovery_digest(
            "pajin.discovery.attack-hypothesis/v1",
            {
                "compilerId": self.compiler_id,
                "ruleId": self.rule_id,
                "campaign": self.campaign,
                "surfaceSetId": self.surface_set_id,
                "surfaceId": self.surface_id,
                "targetId": self.target_id,
                "threatClass": self.threat_class,
                "statement": self.statement,
                "expectedObservable": self.expected_observable,
                "requiredToolId": self.required_tool_id,
                "requiredToolVersion": self.required_tool_version,
                "riskTier": self.risk_tier.value,
                "estimatedToolCalls": self.estimated_tool_calls,
                "estimatedCostUsd": self.estimated_cost_usd,
                "successCondition": self.success_condition,
            },
        )
        if not self.hypothesis_id:
            self.hypothesis_id = expected
        elif self.hypothesis_id != expected:
            raise ValueError("Attack Hypothesis ID differs from canonical authority")
        if fullmatch(_HYPOTHESIS_ID_PATTERN, self.hypothesis_id) is None:
            raise ValueError("Attack Hypothesis ID is malformed")
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Attack Hypothesis",
            max_bytes=_MAX_HYPOTHESIS_BYTES,
        )
        return self


class AttackHypothesisSet(StrictModel):
    """Canonical Hypothesis snapshot bound to one verified Surface projection."""

    api_version: Literal["pajin.dev/discovery-hypothesis/v1alpha1"] = Field(
        default="pajin.dev/discovery-hypothesis/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["AttackHypothesisSet"] = "AttackHypothesisSet"
    hypothesis_set_id: str = ""
    compiler_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    campaign: str = Field(
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    source_projection_run_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    source_projection_root_digest: str = Field(pattern=_SHA256_PATTERN)
    source_surface_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    surface_set_id: str = Field(pattern=r"^attack-surface-set_[a-f0-9]{64}$")
    hypotheses: list[AttackHypothesis] = Field(
        min_length=1,
        max_length=_MAX_HYPOTHESES,
    )
    generated_at: datetime

    @field_validator("generated_at")
    @classmethod
    def normalize_generated_at(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Hypothesis Set generated_at")

    @model_validator(mode="after")
    def validate_authority(self) -> AttackHypothesisSet:
        hypothesis_ids = [item.hypothesis_id for item in self.hypotheses]
        if hypothesis_ids != sorted(hypothesis_ids):
            raise ValueError("Attack Hypotheses must be canonically sorted")
        if len(hypothesis_ids) != len(set(hypothesis_ids)):
            raise ValueError("Attack Hypothesis IDs must be unique")
        if any(
            item.compiler_id != self.compiler_id
            or item.campaign != self.campaign
            or item.surface_set_id != self.surface_set_id
            for item in self.hypotheses
        ):
            raise ValueError("Attack Hypothesis belongs to another compiler authority")
        expected = "attack-hypothesis-set_" + discovery_digest(
            "pajin.discovery.attack-hypothesis-set/v1",
            {
                "compilerId": self.compiler_id,
                "campaign": self.campaign,
                "sourceProjectionRunId": self.source_projection_run_id,
                "sourceProjectionRootDigest": self.source_projection_root_digest,
                "sourceSurfaceArtifactSha256": self.source_surface_artifact_sha256,
                "surfaceSetId": self.surface_set_id,
                "hypotheses": [
                    item.model_dump(mode="json", by_alias=True) for item in self.hypotheses
                ],
                "generatedAt": _utc_wire(self.generated_at),
            },
        )
        if not self.hypothesis_set_id:
            self.hypothesis_set_id = expected
        elif self.hypothesis_set_id != expected:
            raise ValueError("Attack Hypothesis Set ID differs from canonical authority")
        if fullmatch(_HYPOTHESIS_SET_ID_PATTERN, self.hypothesis_set_id) is None:
            raise ValueError("Attack Hypothesis Set ID is malformed")
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Attack Hypothesis Set",
            max_bytes=_MAX_HYPOTHESIS_SET_BYTES,
        )
        return self


class HypothesisSpecialistStep(StrictModel):
    """Executable request compiled for one fresh, single-call Specialist."""

    hypothesis_id: str = Field(pattern=_HYPOTHESIS_ID_PATTERN)
    surface_id: str = Field(pattern=r"^attack-surface_[a-f0-9]{64}$")
    specialist_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    request: ToolRequest
    max_tool_calls: Literal[1] = 1

    @model_validator(mode="after")
    def bind_specialist(self) -> HypothesisSpecialistStep:
        expected = f"hypothesis-specialist:{self.hypothesis_id[-32:]}"
        if self.specialist_id != expected or self.request.agent_id != expected:
            raise ValueError("Hypothesis request is not bound to its compiled Specialist")
        return self


class HypothesisWavePlan(StrictModel):
    """Canonical plan for one non-recursive dynamic Specialist wave."""

    api_version: Literal["pajin.dev/discovery-hypothesis/v1alpha1"] = Field(
        default="pajin.dev/discovery-hypothesis/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["HypothesisWavePlan"] = "HypothesisWavePlan"
    wave_plan_id: str = ""
    compiler_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    hypothesis_set_id: str = Field(pattern=_HYPOTHESIS_SET_ID_PATTERN)
    steps: list[HypothesisSpecialistStep] = Field(
        min_length=1,
        max_length=_MAX_HYPOTHESES,
    )
    max_waves: Literal[1] = 1
    stop_condition: Literal["hypothesis-wave-complete"] = "hypothesis-wave-complete"

    @model_validator(mode="after")
    def validate_plan(self) -> HypothesisWavePlan:
        hypothesis_ids = [step.hypothesis_id for step in self.steps]
        request_ids = [step.request.request_id for step in self.steps]
        if hypothesis_ids != sorted(hypothesis_ids):
            raise ValueError("Hypothesis Specialist steps must be canonically sorted")
        if len(hypothesis_ids) != len(set(hypothesis_ids)):
            raise ValueError("Hypothesis Specialist steps must be unique")
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("Hypothesis Specialist request IDs must be unique")
        expected = "hypothesis-wave-plan_" + discovery_digest(
            "pajin.discovery.hypothesis-wave-plan/v1",
            {
                "compilerId": self.compiler_id,
                "hypothesisSetId": self.hypothesis_set_id,
                "steps": [step.model_dump(mode="json") for step in self.steps],
                "maxWaves": self.max_waves,
                "stopCondition": self.stop_condition,
            },
        )
        if not self.wave_plan_id:
            self.wave_plan_id = expected
        elif self.wave_plan_id != expected:
            raise ValueError("Hypothesis Wave Plan ID differs from canonical authority")
        if fullmatch(_HYPOTHESIS_WAVE_PLAN_ID_PATTERN, self.wave_plan_id) is None:
            raise ValueError("Hypothesis Wave Plan ID is malformed")
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Hypothesis Wave Plan",
            max_bytes=_MAX_HYPOTHESIS_WAVE_PLAN_BYTES,
        )
        return self


@dataclass(frozen=True, slots=True)
class CompiledHypothesisWave:
    """Detached deterministic Compiler output."""

    hypothesis_set: AttackHypothesisSet
    plan: HypothesisWavePlan


class DeterministicHypothesisCompiler:
    """Compile only verified Surface projections through code-registered rules."""

    compiler_id = "pajin.discovery.registered-hypothesis-compiler.v1"

    def __init__(
        self,
        *,
        tools: ToolRegistry,
        rules: Sequence[RegisteredHypothesisRule],
    ) -> None:
        if not isinstance(tools, ToolRegistry):
            raise TypeError("Hypothesis Compiler requires a ToolRegistry")
        registered = [
            RegisteredHypothesisRule.model_validate(rule.model_dump(mode="python"))
            for rule in rules
        ]
        if not registered:
            raise ValueError("Hypothesis Compiler requires at least one registered rule")
        rule_ids = [rule.rule_id for rule in registered]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("Hypothesis Compiler rule IDs must be unique")
        self._tools = tools
        self._rules = tuple(sorted(registered, key=lambda item: item.rule_id))

    def compile(
        self,
        campaign: CampaignManifest,
        recon: ReconWaveOutcome,
    ) -> CompiledHypothesisWave:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="python", by_alias=True)
        )
        surface_set = _load_recon_surface_authority(recon)
        if surface_set.campaign != authoritative_campaign.metadata.name:
            raise HypothesisWaveError("Surface projection belongs to another Campaign")

        hypotheses: list[AttackHypothesis] = []
        requests_by_hypothesis: dict[str, ToolRequest] = {}
        for surface in surface_set.surfaces:
            if not isinstance(surface.locator, ToolInterfaceSurfaceLocator):
                raise HypothesisWaveError("no registered Hypothesis rule for Surface kind")
            matching = [rule for rule in self._rules if rule.matches(surface.locator)]
            if not matching:
                raise HypothesisWaveError("no registered Hypothesis rule for Surface interface")
            targets = [
                target
                for target in authoritative_campaign.spec.targets
                if target.id == surface.target_id
            ]
            if len(targets) != 1:
                raise HypothesisWaveError("Hypothesis Surface target is not declared exactly once")
            for rule in matching:
                try:
                    spec = self._tools.spec(rule.required_tool_id)
                except (KeyError, ValueError) as exc:
                    raise HypothesisWaveError(
                        "Hypothesis rule requires an unregistered Tool"
                    ) from exc
                hypothesis = AttackHypothesis(
                    compiler_id=self.compiler_id,
                    rule_id=rule.rule_id,
                    campaign=authoritative_campaign.metadata.name,
                    surface_set_id=surface_set.surface_set_id,
                    surface_id=surface.surface_id,
                    target_id=surface.target_id,
                    threat_class=rule.threat_class,
                    statement=rule.statement,
                    expected_observable=rule.expected_observable,
                    required_tool_id=spec.tool_id,
                    required_tool_version=spec.version,
                    risk_tier=spec.risk_tier,
                    estimated_cost_usd=rule.estimated_cost_usd,
                    success_condition=rule.success_condition,
                )
                specialist_id = f"hypothesis-specialist:{hypothesis.hypothesis_id[-32:]}"
                request_digest = discovery_digest(
                    "pajin.discovery.hypothesis-request/v1",
                    {
                        "campaign": authoritative_campaign.metadata.name,
                        "hypothesisId": hypothesis.hypothesis_id,
                        "surfaceId": surface.surface_id,
                        "targetId": surface.target_id,
                        "target": targets[0].endpoint,
                        "toolId": spec.tool_id,
                        "toolVersion": spec.version,
                        "method": rule.method,
                        "arguments": rule.arguments,
                    },
                )
                hypotheses.append(hypothesis)
                requests_by_hypothesis[hypothesis.hypothesis_id] = ToolRequest(
                    request_id=f"hypothesis_{request_digest[:32]}",
                    agent_id=specialist_id,
                    tool_id=spec.tool_id,
                    target=targets[0].endpoint,
                    method=rule.method,
                    arguments=json.loads(json.dumps(rule.arguments)),
                )
        hypotheses.sort(key=lambda item: item.hypothesis_id)
        if not hypotheses:
            raise HypothesisWaveError("verified Surface projection produced no Hypotheses")
        if len(hypotheses) > _MAX_HYPOTHESES:
            raise HypothesisWaveError("Hypothesis Compiler exceeded the wave size limit")

        publication = recon.publication
        hypothesis_set = AttackHypothesisSet(
            compiler_id=self.compiler_id,
            campaign=authoritative_campaign.metadata.name,
            source_projection_run_id=publication.projection_run_id,
            source_projection_root_digest=publication.projection_root_digest,
            source_surface_artifact_sha256=publication.artifact_sha256,
            surface_set_id=surface_set.surface_set_id,
            hypotheses=hypotheses,
            generated_at=surface_set.generated_at,
        )
        steps = [
            HypothesisSpecialistStep(
                hypothesis_id=hypothesis.hypothesis_id,
                surface_id=hypothesis.surface_id,
                specialist_id=f"hypothesis-specialist:{hypothesis.hypothesis_id[-32:]}",
                request=requests_by_hypothesis[hypothesis.hypothesis_id],
            )
            for hypothesis in hypotheses
        ]
        plan = HypothesisWavePlan(
            compiler_id=self.compiler_id,
            hypothesis_set_id=hypothesis_set.hypothesis_set_id,
            steps=steps,
        )
        return CompiledHypothesisWave(
            hypothesis_set=hypothesis_set.model_copy(deep=True),
            plan=plan.model_copy(deep=True),
        )


def _load_recon_surface_authority(recon: ReconWaveOutcome) -> AttackSurfaceSet:
    if not isinstance(recon, ReconWaveOutcome):
        raise HypothesisWaveError("Hypothesis Compiler requires a Recon Wave outcome")
    publication = recon.publication
    if not isinstance(publication, SurfaceProjectionPublication):
        raise HypothesisWaveError("Recon outcome has no Surface projection authority")
    try:
        source = verify_run_integrity(recon.source_run_path)
    except Exception as exc:
        raise HypothesisWaveError("Recon source Run is not integrity-valid") from exc
    if (
        source.run_id != publication.source_run_id
        or source.root_digest != publication.source_root_digest
        or source.run_id != recon.source_run_id
    ):
        raise HypothesisWaveError("Recon source Run differs from projection authority")
    try:
        snapshot = load_verified_run_artifacts(
            recon.projection_run_path,
            requests={publication.artifact_path: _MAX_SURFACE_SET_BYTES},
            expected_run_id=publication.projection_run_id,
        )
    except (OSError, RunIntegrityError, ValueError) as exc:
        raise HypothesisWaveError("Surface projection Run is not integrity-valid") from exc
    verification = snapshot.verification
    if verification.root_digest != publication.projection_root_digest:
        raise HypothesisWaveError("Surface projection root differs from publication authority")
    content = snapshot.artifact_bytes(publication.artifact_path)
    if sha256(content).hexdigest() != publication.artifact_sha256:
        raise HypothesisWaveError("Surface projection artifact differs from publication authority")
    try:
        surface_set = AttackSurfaceSet.model_validate_json(content)
    except ValueError as exc:
        raise HypothesisWaveError("Surface projection artifact is not a valid Surface Set") from exc
    if (
        surface_set.surface_set_id != publication.surface_set_id
        or surface_set.run_id != publication.source_run_id
        or surface_set.source_root_digest != publication.source_root_digest
    ):
        raise HypothesisWaveError("Surface Set lineage differs from publication authority")
    published_events = [
        event
        for event in snapshot.events
        if event.event_type == "discovery.attack-surface-set.published"
        and event.payload.get("sourceRunId") == publication.source_run_id
        and event.payload.get("sourceRootDigest") == publication.source_root_digest
        and event.payload.get("surfaceSetId") == publication.surface_set_id
        and event.payload.get("artifact") == publication.artifact_path
    ]
    if len(published_events) != 1:
        raise HypothesisWaveError("Surface projection publication event is missing or ambiguous")
    if surface_set != recon.surface_set:
        raise HypothesisWaveError("Recon outcome Surface Set differs from its sealed projection")
    return surface_set.model_copy(deep=True)


@dataclass(frozen=True, slots=True)
class HypothesisWaveOutcome:
    """Sealed result of one compiled Dynamic Specialist Wave."""

    run_id: str
    run_path: Path
    hypothesis_set: AttackHypothesisSet
    plan: HypothesisWavePlan
    tool_results: tuple[ToolResult, ...]


@dataclass(slots=True)
class _HypothesisWaveState:
    budget: BudgetController
    rate_limits: RequestRateLimitLedger
    ledger: CapabilityLedger | None = None
    stage: str = "initialization"
    terminalized: bool = False


class DynamicHypothesisWaveRunner:
    """Compile and execute exactly one opt-in Hypothesis Specialist wave."""

    def __init__(
        self,
        *,
        compiler: DeterministicHypothesisCompiler,
        tools: ToolRegistry,
        policy: PolicyEngine,
        worker: WorkerBackend,
        output_root: Path,
    ) -> None:
        if not isinstance(compiler, DeterministicHypothesisCompiler):
            raise TypeError("Hypothesis Wave runner requires the deterministic Compiler")
        if compiler._tools is not tools:
            raise ValueError("Hypothesis Wave runner and Compiler must share one Tool registry")
        self._compiler = compiler
        self._tools = tools
        self._policy = policy
        self._worker = worker
        self._output_root = output_root

    async def run(
        self,
        campaign: CampaignManifest,
        recon: ReconWaveOutcome,
        *,
        cancellation: ExecutionCancellationContext | None = None,
        budget: BudgetController | None = None,
        rate_limits: RequestRateLimitLedger | None = None,
    ) -> HypothesisWaveOutcome:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="python", by_alias=True)
        )
        if budget is not None and budget.budgets != authoritative_campaign.spec.budgets:
            raise ValueError("shared budget does not match the Campaign budget contract")
        if cancellation is not None and cancellation.binding is not None:
            raise ValueError("execution cancellation context is already bound to another Run")
        budget = budget or BudgetController(authoritative_campaign.spec.budgets)
        rate_limits = rate_limits or RequestRateLimitLedger()
        store = RunStore.create(self._output_root, authoritative_campaign.metadata.name)
        run_cancellation = (
            cancellation.fork_for_run(
                engine="dynamic-hypothesis-wave",
                run_id=store.run_id,
                path=store.path,
            )
            if cancellation is not None
            else None
        )
        state = _HypothesisWaveState(budget=budget, rate_limits=rate_limits)
        try:
            compiled, results = await await_with_campaign_deadline(
                self._execute(authoritative_campaign, recon, store, state),
                budget,
                run_cancellation,
            )
        except asyncio.CancelledError as exc:
            context = ensure_cancellation_context(
                run_cancellation,
                engine="dynamic-hypothesis-wave",
                store=store,
            )
            receipt = record_engine_cleanup(store, context)
            self._terminalize(
                store,
                state,
                status="cancelled",
                error_type=audit_safe_exception_type(exc),
                cancellation_receipt=receipt,
            )
            raise
        except BudgetExceeded as exc:
            self._terminalize(
                store,
                state,
                status="budget-exhausted",
                error_type=audit_safe_exception_type(exc),
            )
            raise
        except Exception as exc:
            self._terminalize(
                store,
                state,
                status="failed",
                error_type=audit_safe_exception_type(exc),
            )
            raise
        return HypothesisWaveOutcome(
            run_id=store.run_id,
            run_path=store.path,
            hypothesis_set=compiled.hypothesis_set.model_copy(deep=True),
            plan=compiled.plan.model_copy(deep=True),
            tool_results=tuple(result.model_copy(deep=True) for result in results),
        )

    async def _execute(
        self,
        campaign: CampaignManifest,
        recon: ReconWaveOutcome,
        store: RunStore,
        state: _HypothesisWaveState,
    ) -> tuple[CompiledHypothesisWave, list[ToolResult]]:
        store.append_event(
            "campaign.started",
            {
                "campaign": campaign.metadata.name,
                "mode": campaign.spec.mode.value,
                "purpose": "dynamic-hypothesis-wave",
            },
        )
        store.write_json("campaign.json", campaign.model_dump(mode="json", by_alias=True))

        state.stage = "hypothesis-compilation"
        compiled = self._compiler.compile(campaign.model_copy(deep=True), recon)
        hypothesis_set = AttackHypothesisSet.model_validate(
            compiled.hypothesis_set.model_dump(mode="python", by_alias=True)
        )
        plan = HypothesisWavePlan.model_validate(
            compiled.plan.model_dump(mode="python", by_alias=True)
        )
        store.write_json(
            "hypothesis-set.json",
            hypothesis_set.model_dump(mode="json", by_alias=True),
        )
        store.write_json(
            "hypothesis-wave-plan.json",
            plan.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "discovery.hypothesis-set.compiled",
            {
                "compilerId": hypothesis_set.compiler_id,
                "hypothesisSetId": hypothesis_set.hypothesis_set_id,
                "surfaceSetId": hypothesis_set.surface_set_id,
                "sourceProjectionRunId": hypothesis_set.source_projection_run_id,
                "sourceProjectionRootDigest": hypothesis_set.source_projection_root_digest,
                "hypothesisIds": [
                    hypothesis.hypothesis_id for hypothesis in hypothesis_set.hypotheses
                ],
                "hypothesisCount": len(hypothesis_set.hypotheses),
            },
        )

        state.stage = "hypothesis-capability-issuance"
        if campaign.spec.budgets.max_spawn_depth < 1:
            raise CapabilityError(
                "Hypothesis Wave requires depth for attenuated Specialist capabilities"
            )
        step_count = len(plan.steps)
        if state.budget.agent_count + step_count > campaign.spec.budgets.max_agents:
            raise BudgetExceeded("Hypothesis Wave requires more agents than the Campaign budget")
        if state.budget.tool_calls + step_count > campaign.spec.budgets.max_tool_calls:
            raise BudgetExceeded("Hypothesis Wave requires more Tool calls than remain")
        estimated_cost = sum(
            hypothesis.estimated_cost_usd for hypothesis in hypothesis_set.hypotheses
        )
        if state.budget.cost_usd + estimated_cost > campaign.spec.budgets.max_cost_usd:
            raise BudgetExceeded("Hypothesis Wave estimated cost exceeds the Campaign budget")
        for _ in plan.steps:
            state.budget.reserve_agent(depth=1)

        ledger = CapabilityLedger(max_depth=campaign.spec.budgets.max_spawn_depth)
        state.ledger = ledger
        root = ledger.issue_root(
            campaign,
            subject=f"hypothesis-supervisor:{self._compiler.compiler_id}",
            tools={step.request.tool_id for step in plan.steps},
            targets={step.request.target for step in plan.steps},
        )
        store.append_event("capability.issued", root.model_dump(mode="json"))
        grants = {}
        hypothesis_by_id = {
            hypothesis.hypothesis_id: hypothesis
            for hypothesis in hypothesis_set.hypotheses
        }
        for step in plan.steps:
            hypothesis = hypothesis_by_id[step.hypothesis_id]
            grant = ledger.delegate(
                root.grant_id,
                subject=step.specialist_id,
                tools={step.request.tool_id},
                targets={step.request.target},
                max_risk_tier=hypothesis.risk_tier,
                max_calls=1,
            )
            grants[step.hypothesis_id] = grant
            store.append_event("capability.issued", grant.model_dump(mode="json"))
            store.append_event(
                "discovery.hypothesis-specialist.created",
                {
                    "hypothesisId": step.hypothesis_id,
                    "surfaceId": step.surface_id,
                    "specialistId": step.specialist_id,
                    "grantId": grant.grant_id,
                    "toolId": step.request.tool_id,
                    "target": step.request.target,
                    "maxToolCalls": step.max_tool_calls,
                },
            )

        state.stage = "hypothesis-tool-execution"
        gateway = ToolGateway(
            policy=self._policy,
            tools=self._tools,
            worker=self._worker,
            store=store,
            rate_limits=state.rate_limits,
        )
        results: list[ToolResult] = []
        for step in plan.steps:
            grant = grants[step.hypothesis_id]
            state.budget.check_tool_call()
            if not ledger.can_consume(grant.grant_id):
                raise CapabilityError("Hypothesis Specialist has no remaining authorized call")
            outcome = await gateway.execute(
                campaign,
                grant,
                step.request,
                used_calls=0,
            )
            if outcome.executed:
                ledger.consume(grant.grant_id)
                state.budget.record_tool_call()
            results.append(outcome.result.model_copy(deep=True))
        failed = [
            result
            for result in results
            if not result.success or result.error is not None
        ]
        if failed:
            raise HypothesisWaveError(
                f"Hypothesis Wave failed {len(failed)} of {len(results)} Tool calls"
            )

        state.stage = "hypothesis-wave-finalization"
        store.write_json(
            "hypothesis-results.json",
            [result.model_dump(mode="json") for result in results],
        )
        store.append_event(
            "discovery.hypothesis-wave.completed",
            {
                "wavePlanId": plan.wave_plan_id,
                "hypothesisSetId": hypothesis_set.hypothesis_set_id,
                "hypothesisIds": [step.hypothesis_id for step in plan.steps],
                "requestIds": [result.request_id for result in results],
                "toolCalls": len(results),
                "maxWaves": plan.max_waves,
                "stopCondition": plan.stop_condition,
            },
        )
        self._write_state(
            store,
            state,
            status="completed",
            extra={
                "hypothesisSetId": hypothesis_set.hypothesis_set_id,
                "wavePlanId": plan.wave_plan_id,
                "stopCondition": plan.stop_condition,
            },
        )
        store.append_event(
            "campaign.completed",
            {
                "purpose": "dynamic-hypothesis-wave",
                "hypothesisSetId": hypothesis_set.hypothesis_set_id,
            },
        )
        state.terminalized = True
        store.seal()
        return (
            CompiledHypothesisWave(
                hypothesis_set=hypothesis_set.model_copy(deep=True),
                plan=plan.model_copy(deep=True),
            ),
            results,
        )

    @staticmethod
    def _write_state(
        store: RunStore,
        state: _HypothesisWaveState,
        *,
        status: str,
        extra: dict[str, object] | None = None,
    ) -> None:
        if state.ledger is not None:
            store.write_json("capabilities.json", state.ledger.snapshot())
        store.write_json("budget.json", state.budget.snapshot())
        store.write_json("rate-limits.json", state.rate_limits.snapshot())
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": status,
                "stage": state.stage,
                "purpose": "dynamic-hypothesis-wave",
                **(extra or {}),
            },
        )

    def _terminalize(
        self,
        store: RunStore,
        state: _HypothesisWaveState,
        *,
        status: str,
        error_type: str,
        cancellation_receipt: str | None = None,
    ) -> None:
        if state.terminalized:
            return
        payload: dict[str, object] = {
            "stage": state.stage,
            "errorType": error_type,
            "purpose": "dynamic-hypothesis-wave",
        }
        extra: dict[str, object] = {"errorType": error_type}
        if cancellation_receipt is not None:
            payload["cancellationReceipt"] = cancellation_receipt
            extra["cancellationReceipt"] = cancellation_receipt
        self._write_state(store, state, status=status, extra=extra)
        store.append_event(f"campaign.{status}", payload)
        store.seal()
        state.terminalized = True
