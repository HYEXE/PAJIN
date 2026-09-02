"""AI-002D sealed read-only product over one exact AI-002C evaluation."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from pajin.benchmark.domain_metrics import DomainBenchmarkMetricApplicability
from pajin.benchmark.models import benchmark_digest
from pajin.domain.models import StrictModel
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts
from pajin.workflow.ai_fixture_runtime import AIFixtureDockerProvider
from pajin.workflow.ai_measured_case_authority import (
    AIMeasuredCaseAuthorityError,
    AIMeasuredCaseMapping,
    AIMeasuredCaseRef,
    AIValidationFloorPolicyRef,
    registered_ai_measured_case_mapping,
    registered_ai_validation_floor_policy,
)
from pajin.workflow.ai_replay_evaluation import (
    AIReplayEvaluationError,
    AIReplayEvaluationOutcome,
    AIReplayFloorEvaluation,
    AIReplayFloorEvaluationRef,
    AIReplayMetricObservation,
    load_ai_replay_floor_evaluation,
)

AI_MEASURED_PRODUCT_API_VERSION: Literal["pajin.dev/ai-measured-product/v1alpha1"] = (
    "pajin.dev/ai-measured-product/v1alpha1"
)
AI_MEASURED_PRODUCT_PATH = "ai-measured-product.json"

_MAX_PRODUCT_BYTES = 4 * 1024 * 1024
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]

_EXPECTED_CASE_STATES = ("synthetic-known-positive-observed",)
_FIXED_RATIONALS = {
    "common.ground-truth-coverage": (1, 1),
    "common.detection-recall": (1, 1),
    "common.false-positive-rate": (0, 2),
    "common.detection-precision": (4, 4),
    "common.replay-or-reanalysis-success-rate": (2, 2),
    "common.total-request-units": (6, 1),
    "common.total-tool-calls": (6, 1),
    "common.total-cost-usd": (0, 1_000_000),
    "common.evidence-completeness": (84, 84),
    "common.policy-denial-correctness": (8, 8),
    "ai.threat-class-coverage": (1, 1),
}
_SOURCE_TRUE_FIELDS = (
    "source_measurement_reopened",
    "replay_measurements_reopened",
    "controls_reopened",
    "source_replay_control_identity_disjoint",
    "private_ground_truth_evaluated",
    "exact_metric_set_evaluated",
    "accounting_observed",
    "cleanup_admission_verified",
    "synthetic_benchmark_only",
    "validation_floor_satisfied",
)
_SOURCE_FALSE_FIELDS = (
    "image_build_authorized",
    "target_creation_authorized",
    "network_creation_authorized",
    "provider_selection_authorized",
    "caller_configuration_authorized",
    "approval_issuance_authorized",
    "replay_execution_authorized",
    "control_execution_authorized",
    "gateway_execution_authorized",
    "worker_execution_authorized",
    "ai_observation_confirmed",
    "graph_admission_authorized",
    "graph_mutation_authorized",
    "finding_authority",
    "product_projection_authorized",
    "reporting_authorized",
    "external_delivery_authorized",
    "credential_access_authorized",
    "external_provider_authorized",
    "external_target_authorized",
    "production_target_authorized",
    "arbitrary_prompt_authorized",
    "arbitrary_tool_authorized",
    "plugin_authorized",
    "rag_authorized",
    "mcp_authorized",
    "memory_mutation_authorized",
    "m06_authorized",
    "a04_authorized",
    "general_ai_scanner_authorized",
    "permit_issuance_authorized",
    "grant_issuance_authorized",
    "application_protocol_write_authorized",
    "model_call_authorized",
    "additional_execution_authorized",
)
_PRODUCT_FALSE_FIELDS = (
    "raw_prompt_included",
    "private_check_included",
    "private_ground_truth_binding_included",
    "private_evaluation_binding_included",
    "source_replay_control_lineage_included",
    "image_identity_included",
    "runtime_coordinate_included",
    "request_session_included",
    "approval_permit_grant_included",
    "worker_tool_result_included",
    "target_receipt_included",
    "transcript_response_included",
    "graph_included",
    "observation_confirmation_included",
    "finding_included",
    "report_included",
    "image_build_authorized",
    "target_creation_authorized",
    "network_creation_authorized",
    "provider_selection_authorized",
    "caller_configuration_authorized",
    "approval_issuance_authorized",
    "action_permit_issuance_authorized",
    "grant_issuance_authorized",
    "replay_execution_authorized",
    "control_execution_authorized",
    "gateway_execution_authorized",
    "worker_execution_authorized",
    "live_measurement_authorized",
    "further_product_projection_authorized",
    "ai_observation_confirmation_authorized",
    "graph_admission_authorized",
    "graph_mutation_authorized",
    "finding_authority",
    "reporting_authorized",
    "external_delivery_authorized",
    "credential_access_authorized",
    "external_provider_authorized",
    "external_target_authorized",
    "production_target_authorized",
    "arbitrary_prompt_authorized",
    "arbitrary_tool_authorized",
    "plugin_authorized",
    "rag_authorized",
    "mcp_authorized",
    "memory_mutation_authorized",
    "m06_authorized",
    "a04_authorized",
    "general_ai_scanner_authorized",
    "application_protocol_write_authorized",
    "model_call_authorized",
    "additional_execution_authorized",
    "http_entrypoint_authorized",
)


class AIMeasuredProductError(RuntimeError):
    """Raised when an AI-002D product cannot be reproduced exactly."""


def _require_known_instance_fields(
    value: object,
    *,
    label: str,
    _seen: set[int] | None = None,
) -> None:
    seen = _seen if _seen is not None else set()
    if isinstance(value, BaseModel):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        if set(value.__dict__) - set(type(value).model_fields):
            raise AIMeasuredProductError(f"{label} contains unmodeled instance state")
        for field_name in type(value).model_fields:
            _require_known_instance_fields(getattr(value, field_name), label=label, _seen=seen)
        return
    if isinstance(value, Mapping):
        for item in value.values():
            _require_known_instance_fields(item, label=label, _seen=seen)
        return
    if isinstance(value, (tuple, list, set, frozenset)):
        for item in value:
            _require_known_instance_fields(item, label=label, _seen=seen)
        return
    if not isinstance(value, type) and is_dataclass(value):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        for item in fields(value):
            _require_known_instance_fields(getattr(value, item.name), label=label, _seen=seen)


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    @model_validator(mode="before")
    @classmethod
    def reject_unmodeled_nested_instance_state(cls, value: object) -> object:
        _require_known_instance_fields(value, label=cls.__name__)
        return value


class AIMeasuredProductCase(_FrozenStrictModel):
    """One public case identity and its bounded synthetic comparison state."""

    case: AIMeasuredCaseRef
    comparison_state: Literal["synthetic-known-positive-observed",] = Field(alias="comparisonState")


class AIMeasuredProductFloor(_FrozenStrictModel):
    """Exact public DOMAIN-006 aggregate values and applicability."""

    evaluation: AIReplayFloorEvaluationRef
    policy: AIValidationFloorPolicyRef
    observations: tuple[AIReplayMetricObservation, ...] = Field(
        min_length=14,
        max_length=14,
    )
    state: Literal["independent-fresh-session-replay-controls-ai-floor-satisfied"] = (
        "independent-fresh-session-replay-controls-ai-floor-satisfied"
    )
    required_metric_count: Literal[12] = Field(default=12, alias="requiredMetricCount")
    not_applicable_metric_count: Literal[2] = Field(
        default=2,
        alias="notApplicableMetricCount",
    )
    validation_floor_satisfied: Literal[True] = Field(
        default=True,
        alias="validationFloorSatisfied",
    )
    synthetic_benchmark_only: Literal[True] = Field(
        default=True,
        alias="syntheticBenchmarkOnly",
    )

    @field_validator("observations", mode="before")
    @classmethod
    def canonicalize_json_tuple(cls, value: object, info: ValidationInfo) -> object:
        if info.mode == "json" and type(value) is list:
            return tuple(value)
        return value

    @field_validator("validation_floor_satisfied", "synthetic_benchmark_only", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("AI-002D product floor markers must be boolean true")
        return value

    @model_validator(mode="after")
    def bind_observations(self) -> Self:
        requirements = registered_ai_validation_floor_policy().requirements
        if tuple(item.metric for item in self.observations) != tuple(
            item.metric for item in requirements
        ):
            raise ValueError("AI-002D product metric membership or order differs")
        for observation, requirement in zip(self.observations, requirements, strict=True):
            if (
                observation.unit is not requirement.unit
                or observation.applicability is not requirement.applicability
                or observation.comparison is not requirement.comparison
                or observation.not_applicable_reason is not requirement.not_applicable_reason
                or observation.floor_satisfied is not True
            ):
                raise ValueError("AI-002D product metric policy binding differs")
            metric_id = observation.metric.metric_id
            if (
                metric_id in _FIXED_RATIONALS
                and (
                    observation.numerator,
                    observation.denominator,
                )
                != _FIXED_RATIONALS[metric_id]
            ):
                raise ValueError("AI-002D product fixed metric rational differs")
            if metric_id == "common.time-to-first-valid-result" and (
                observation.numerator is None or observation.denominator != 1_000_000
            ):
                raise ValueError("AI-002D product elapsed metric rational differs")
        required = sum(
            item.applicability is DomainBenchmarkMetricApplicability.REQUIRED
            for item in self.observations
        )
        if required != self.required_metric_count or len(self.observations) - required != (
            self.not_applicable_metric_count
        ):
            raise ValueError("AI-002D product metric applicability counts differ")
        return self


class AIMeasuredProductAuthorityBoundary(_FrozenStrictModel):
    """Literal disclosure and non-authority ceiling for every AI-002D product."""

    raw_prompt_included: Literal[False] = Field(default=False, alias="rawPromptIncluded")
    private_check_included: Literal[False] = Field(default=False, alias="privateCheckIncluded")
    private_ground_truth_binding_included: Literal[False] = Field(
        default=False,
        alias="privateGroundTruthBindingIncluded",
    )
    private_evaluation_binding_included: Literal[False] = Field(
        default=False,
        alias="privateEvaluationBindingIncluded",
    )
    source_replay_control_lineage_included: Literal[False] = Field(
        default=False,
        alias="sourceReplayControlLineageIncluded",
    )
    image_identity_included: Literal[False] = Field(default=False, alias="imageIdentityIncluded")
    runtime_coordinate_included: Literal[False] = Field(
        default=False, alias="runtimeCoordinateIncluded"
    )
    request_session_included: Literal[False] = Field(
        default=False,
        alias="requestSessionIncluded",
    )
    approval_permit_grant_included: Literal[False] = Field(
        default=False,
        alias="approvalPermitGrantIncluded",
    )
    worker_tool_result_included: Literal[False] = Field(
        default=False, alias="workerToolResultIncluded"
    )
    target_receipt_included: Literal[False] = Field(
        default=False,
        alias="targetReceiptIncluded",
    )
    transcript_response_included: Literal[False] = Field(
        default=False,
        alias="transcriptResponseIncluded",
    )
    graph_included: Literal[False] = Field(default=False, alias="graphIncluded")
    observation_confirmation_included: Literal[False] = Field(
        default=False,
        alias="observationConfirmationIncluded",
    )
    finding_included: Literal[False] = Field(default=False, alias="findingIncluded")
    report_included: Literal[False] = Field(default=False, alias="reportIncluded")
    image_build_authorized: Literal[False] = Field(default=False, alias="imageBuildAuthorized")
    target_creation_authorized: Literal[False] = Field(
        default=False, alias="targetCreationAuthorized"
    )
    network_creation_authorized: Literal[False] = Field(
        default=False, alias="networkCreationAuthorized"
    )
    provider_selection_authorized: Literal[False] = Field(
        default=False, alias="providerSelectionAuthorized"
    )
    caller_configuration_authorized: Literal[False] = Field(
        default=False, alias="callerConfigurationAuthorized"
    )
    approval_issuance_authorized: Literal[False] = Field(
        default=False, alias="approvalIssuanceAuthorized"
    )
    action_permit_issuance_authorized: Literal[False] = Field(
        default=False, alias="actionPermitIssuanceAuthorized"
    )
    grant_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="grantIssuanceAuthorized",
    )
    replay_execution_authorized: Literal[False] = Field(
        default=False,
        alias="replayExecutionAuthorized",
    )
    control_execution_authorized: Literal[False] = Field(
        default=False,
        alias="controlExecutionAuthorized",
    )
    gateway_execution_authorized: Literal[False] = Field(
        default=False, alias="gatewayExecutionAuthorized"
    )
    worker_execution_authorized: Literal[False] = Field(
        default=False, alias="workerExecutionAuthorized"
    )
    live_measurement_authorized: Literal[False] = Field(
        default=False, alias="liveMeasurementAuthorized"
    )
    further_product_projection_authorized: Literal[False] = Field(
        default=False, alias="furtherProductProjectionAuthorized"
    )
    ai_observation_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="aiObservationConfirmationAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False, alias="graphAdmissionAuthorized"
    )
    graph_mutation_authorized: Literal[False] = Field(
        default=False, alias="graphMutationAuthorized"
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    reporting_authorized: Literal[False] = Field(default=False, alias="reportingAuthorized")
    external_delivery_authorized: Literal[False] = Field(
        default=False, alias="externalDeliveryAuthorized"
    )
    credential_access_authorized: Literal[False] = Field(
        default=False, alias="credentialAccessAuthorized"
    )
    external_provider_authorized: Literal[False] = Field(
        default=False,
        alias="externalProviderAuthorized",
    )
    external_target_authorized: Literal[False] = Field(
        default=False, alias="externalTargetAuthorized"
    )
    production_target_authorized: Literal[False] = Field(
        default=False, alias="productionTargetAuthorized"
    )
    arbitrary_prompt_authorized: Literal[False] = Field(
        default=False,
        alias="arbitraryPromptAuthorized",
    )
    arbitrary_tool_authorized: Literal[False] = Field(
        default=False,
        alias="arbitraryToolAuthorized",
    )
    plugin_authorized: Literal[False] = Field(default=False, alias="pluginAuthorized")
    rag_authorized: Literal[False] = Field(default=False, alias="ragAuthorized")
    mcp_authorized: Literal[False] = Field(default=False, alias="mcpAuthorized")
    memory_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="memoryMutationAuthorized",
    )
    m06_authorized: Literal[False] = Field(default=False, alias="m06Authorized")
    a04_authorized: Literal[False] = Field(default=False, alias="a04Authorized")
    general_ai_scanner_authorized: Literal[False] = Field(
        default=False,
        alias="generalAIScannerAuthorized",
    )
    application_protocol_write_authorized: Literal[False] = Field(
        default=False,
        alias="applicationProtocolWriteAuthorized",
    )
    model_call_authorized: Literal[False] = Field(
        default=False,
        alias="modelCallAuthorized",
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False, alias="additionalExecutionAuthorized"
    )
    http_entrypoint_authorized: Literal[False] = Field(
        default=False, alias="httpEntrypointAuthorized"
    )

    @field_validator(*_PRODUCT_FALSE_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("AI-002D product authority markers must be boolean false")
        return value


class AIMeasuredProduct(_FrozenStrictModel):
    """Content-addressed public-safe AI measurement product."""

    api_version: Literal["pajin.dev/ai-measured-product/v1alpha1"] = Field(
        default=AI_MEASURED_PRODUCT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AIMeasuredProduct"] = "AIMeasuredProduct"
    product_id: str = Field(default="", alias="productId", max_length=110)
    product_digest: str = Field(default="", alias="productDigest", max_length=64)
    source_evaluation: AIReplayFloorEvaluationRef = Field(alias="sourceEvaluation")
    cases: tuple[AIMeasuredProductCase, ...] = Field(min_length=1, max_length=1)
    floor: AIMeasuredProductFloor
    authority_boundary: AIMeasuredProductAuthorityBoundary = Field(alias="authorityBoundary")

    @field_validator("cases", mode="before")
    @classmethod
    def canonicalize_json_cases(cls, value: object, info: ValidationInfo) -> object:
        if info.mode == "json" and type(value) is list:
            return tuple(value)
        return value

    @model_validator(mode="after")
    def bind_product(self) -> Self:
        registered = registered_ai_measured_case_mapping().public_authority
        expected_cases = tuple(item.reference() for item in registered.public_registry.cases)
        if (
            self.source_evaluation != self.floor.evaluation
            or self.floor.policy != registered.validation_floor_policy.reference()
            or tuple(item.case for item in self.cases) != expected_cases
            or tuple(item.comparison_state for item in self.cases) != _EXPECTED_CASE_STATES
        ):
            raise ValueError("AI-002D product case, floor, or source binding differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"product_id", "product_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-measured-product/v1",
            material,
            max_bytes=_MAX_PRODUCT_BYTES,
        )
        product_id = f"ai-measured-product_{digest}"
        if self.product_digest and self.product_digest != digest:
            raise ValueError("AI-002D product Digest differs")
        if self.product_id and self.product_id != product_id:
            raise ValueError("AI-002D product ID differs")
        object.__setattr__(self, "product_digest", digest)
        object.__setattr__(self, "product_id", product_id)
        return self


@dataclass(frozen=True, slots=True)
class AIMeasuredProductSourceReopenContext:
    """Deployment-owned verifier context for one exact AI-002C result."""

    measured_cases: AIMeasuredCaseMapping
    provider: AIFixtureDockerProvider


@dataclass(frozen=True, slots=True)
class AIMeasuredProductOutcome:
    run_id: str
    run_path: Path
    artifact_path: str
    product: AIMeasuredProduct
    source: AIReplayEvaluationOutcome


class AIMeasuredProductProjector:
    """Reopen AI-002C and seal only its bounded public product projection."""

    def __init__(self, *, output_root: Path) -> None:
        if not isinstance(output_root, Path):
            raise TypeError("AI-002D product projection requires a Path output root")
        self._output_root = output_root

    def project(
        self,
        source: AIReplayEvaluationOutcome,
        *,
        reopen_context: AIMeasuredProductSourceReopenContext,
    ) -> AIMeasuredProductOutcome:
        try:
            evaluation = _load_source_evaluation(source, reopen_context)
            product = _build_product(evaluation)
            source_run_ids = _source_run_ids(source)
            if len(source_run_ids) != 8:
                raise ValueError("AI-002D requires eight distinct source Runs")
            store = RunStore.create(self._output_root, "ai-measured-product")
            if store.run_id in source_run_ids:
                raise ValueError("AI-002D product Run reuses a source Run")
            store.append_event(
                "campaign.started",
                {
                    "purpose": "ai-measured-product",
                    "sourceEvaluationId": evaluation.evaluation_id,
                },
            )
            artifact_path = store.write_json_create_only(
                AI_MEASURED_PRODUCT_PATH,
                product.model_dump(mode="json", by_alias=True),
            )
            store.append_event(
                "product.ai-measured-system-prompt-disclosure.projected",
                _event_payload(artifact_path, product),
            )
            store.append_event("campaign.completed", {"status": "completed"})
            store.seal()
            outcome = AIMeasuredProductOutcome(
                run_id=store.run_id,
                run_path=store.path,
                artifact_path=artifact_path,
                product=product.model_copy(deep=True),
                source=source,
            )
            load_ai_measured_product(outcome, reopen_context=reopen_context)
            return outcome
        except AIMeasuredProductError:
            raise
        except Exception as exc:
            raise AIMeasuredProductError("AI-002D product projection failed closed") from exc


def load_ai_measured_product(
    outcome: AIMeasuredProductOutcome,
    *,
    reopen_context: AIMeasuredProductSourceReopenContext,
) -> AIMeasuredProduct:
    """Reopen AI-002C first, then rebuild one sealed AI-002D product."""

    if type(outcome) is not AIMeasuredProductOutcome:
        raise TypeError("AI-002D reload requires its exact outcome")
    if type(reopen_context) is not AIMeasuredProductSourceReopenContext:
        raise TypeError("AI-002D reload requires its exact reopen context")
    try:
        evaluation = _load_source_evaluation(outcome.source, reopen_context)
        if outcome.artifact_path != AI_MEASURED_PRODUCT_PATH:
            raise ValueError("AI-002D product artifact path differs")
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={outcome.artifact_path: _MAX_PRODUCT_BYTES},
            expected_run_id=outcome.run_id,
        )
        sealed_bytes = snapshot.artifact_bytes(outcome.artifact_path)
        sealed = AIMeasuredProduct.model_validate_json(sealed_bytes)
        rebuilt = _build_product(evaluation)
        source_run_ids = _source_run_ids(outcome.source)
        if (
            len(source_run_ids) != 8
            or outcome.run_id in source_run_ids
            or tuple(item.event_type for item in snapshot.events)
            != (
                "campaign.started",
                "product.ai-measured-system-prompt-disclosure.projected",
                "campaign.completed",
            )
            or sealed != outcome.product
            or sealed != rebuilt
            or sealed_bytes != _strict_json_bytes(sealed.model_dump(mode="json", by_alias=True))
            or snapshot.events[0].payload
            != {
                "purpose": "ai-measured-product",
                "sourceEvaluationId": evaluation.evaluation_id,
            }
            or snapshot.events[1].payload != _event_payload(outcome.artifact_path, sealed)
            or snapshot.events[2].payload != {"status": "completed"}
        ):
            raise ValueError("AI-002D product publication differs")
        return sealed.model_copy(deep=True)
    except AIMeasuredProductError:
        raise
    except (
        AttributeError,
        AIMeasuredCaseAuthorityError,
        AIReplayEvaluationError,
        OSError,
        RunIntegrityError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise AIMeasuredProductError("AI-002D product is not sealed and reproducible") from exc


def _load_source_evaluation(
    source: AIReplayEvaluationOutcome,
    context: AIMeasuredProductSourceReopenContext,
) -> AIReplayFloorEvaluation:
    if type(source) is not AIReplayEvaluationOutcome:
        raise TypeError("AI-002D product requires one exact AI-002C outcome")
    if type(context) is not AIMeasuredProductSourceReopenContext:
        raise TypeError("AI-002D product requires one exact reopen context")
    return load_ai_replay_floor_evaluation(
        source,
        measured_cases=context.measured_cases,
        provider=context.provider,
    )


def _build_product(evaluation: AIReplayFloorEvaluation) -> AIMeasuredProduct:
    if (
        any(getattr(evaluation, field) is not True for field in _SOURCE_TRUE_FIELDS)
        or any(getattr(evaluation, field) is not False for field in _SOURCE_FALSE_FIELDS)
        or evaluation.state != "independent-fresh-session-replay-controls-ai-floor-satisfied"
        or len(evaluation.operations) != 6
        or len(evaluation.observations) != 14
    ):
        raise ValueError("AI-002D source evaluation authority ceiling differs")
    registered_case = (
        registered_ai_measured_case_mapping().public_authority.public_registry.cases[0].reference()
    )
    if tuple(item.operation.case for item in evaluation.operations) != (registered_case,) * 6:
        raise ValueError("AI-002D source evaluation case membership differs")
    observations = tuple(
        AIReplayMetricObservation.model_validate_json(item.model_dump_json(by_alias=True))
        for item in evaluation.observations
    )
    return AIMeasuredProduct(
        sourceEvaluation=evaluation.reference(),
        cases=(
            AIMeasuredProductCase(
                case=registered_case,
                comparisonState="synthetic-known-positive-observed",
            ),
        ),
        floor=AIMeasuredProductFloor(
            evaluation=evaluation.reference(),
            policy=evaluation.floor_policy,
            observations=observations,
        ),
        authorityBoundary=AIMeasuredProductAuthorityBoundary(),
    )


def _source_run_ids(source: AIReplayEvaluationOutcome) -> frozenset[str]:
    return frozenset(
        (
            source.run_id,
            source.source.run_id,
            source.source.execution.source_inputs.expected_run_id,
            *(item.source_inputs.expected_run_id for item in source.executions),
        )
    )


def _event_payload(artifact_path: str, product: AIMeasuredProduct) -> dict[str, object]:
    return {
        "artifact": artifact_path,
        "productId": product.product_id,
        "productDigest": product.product_digest,
        "sourceEvaluationId": product.source_evaluation.evaluation_id,
        "sourceEvaluationDigest": product.source_evaluation.evaluation_digest,
        "caseCount": len(product.cases),
        "metricCount": len(product.floor.observations),
        "floorSatisfied": product.floor.validation_floor_satisfied,
        "aiObservationConfirmationAuthorized": (
            product.authority_boundary.ai_observation_confirmation_authorized
        ),
        "additionalExecutionAuthorized": (
            product.authority_boundary.additional_execution_authorized
        ),
    }


def _strict_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


__all__ = [
    "AI_MEASURED_PRODUCT_API_VERSION",
    "AI_MEASURED_PRODUCT_PATH",
    "AIMeasuredProduct",
    "AIMeasuredProductAuthorityBoundary",
    "AIMeasuredProductCase",
    "AIMeasuredProductError",
    "AIMeasuredProductFloor",
    "AIMeasuredProductOutcome",
    "AIMeasuredProductProjector",
    "AIMeasuredProductSourceReopenContext",
    "load_ai_measured_product",
]
