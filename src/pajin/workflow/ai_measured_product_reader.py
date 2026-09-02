"""AI-002D deployment-pinned zero-argument product reader."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType
from typing import Protocol

from pajin.workflow.ai_analysis_admission import AIAnalysisObservationSourceInputs
from pajin.workflow.ai_measured_product_flow import (
    AI_MEASURED_PRODUCT_PATH,
    AIMeasuredProduct,
    AIMeasuredProductOutcome,
    AIMeasuredProductSourceReopenContext,
    load_ai_measured_product,
)
from pajin.workflow.ai_replay_evaluation import (
    AIMeasurementExecutionContext,
    AIReplayEvaluationOutcome,
)
from pajin.workflow.ai_source_measurement import (
    AISourceExecutionContext,
    AISourceMeasurementOutcome,
)

_DEPLOYMENT_ID_PATTERN = re.compile(r"^[a-z][a-z0-9.-]{0,127}$")


class AIMeasuredProductReaderError(RuntimeError):
    """Raised when a deployment-pinned AI-002D read cannot be reproduced."""


@dataclass(frozen=True, slots=True)
class AIMeasuredProductReadRegistration:
    """Deployment-owned selection of one product and its complete verifier context."""

    deployment_id: str
    product_run_id: str
    product_id: str
    product_digest: str
    source_evaluation_id: str
    source_evaluation_digest: str
    outcome: AIMeasuredProductOutcome
    reopen_context: AIMeasuredProductSourceReopenContext

    @classmethod
    def from_outcome(
        cls,
        *,
        deployment_id: str,
        outcome: AIMeasuredProductOutcome,
        reopen_context: AIMeasuredProductSourceReopenContext,
    ) -> AIMeasuredProductReadRegistration:
        return cls(
            deployment_id=deployment_id,
            product_run_id=outcome.run_id,
            product_id=outcome.product.product_id,
            product_digest=outcome.product.product_digest,
            source_evaluation_id=outcome.product.source_evaluation.evaluation_id,
            source_evaluation_digest=outcome.product.source_evaluation.evaluation_digest,
            outcome=outcome,
            reopen_context=reopen_context,
        )


class AIMeasuredProductReadResolver(Protocol):
    """Deployment TCB that resolves one exact registered AI product read."""

    def resolve_for_product_read(
        self,
        *,
        deployment_id: str,
    ) -> AIMeasuredProductReadRegistration: ...


@dataclass(frozen=True, slots=True, init=False)
class AIMeasuredProductReadRegistry:
    """Immutable process-local registry of deployment-selected AI-002D reads."""

    _registrations: Mapping[str, AIMeasuredProductReadRegistration]

    def __init__(
        self,
        registrations: tuple[AIMeasuredProductReadRegistration, ...],
    ) -> None:
        if type(registrations) is not tuple or not registrations:
            raise TypeError("AI-002D reader registrations must be a non-empty tuple")
        canonical = tuple(_canonical_registration(item) for item in registrations)
        if len({item.deployment_id for item in canonical}) != len(canonical):
            raise ValueError("AI-002D reader deployment IDs must be unique")
        if len({item.product_run_id for item in canonical}) != len(canonical):
            raise ValueError("AI-002D reader product Run IDs must be unique")
        if len({item.product_id for item in canonical}) != len(canonical):
            raise ValueError("AI-002D reader product IDs must be unique")
        object.__setattr__(
            self,
            "_registrations",
            MappingProxyType({item.deployment_id: item for item in canonical}),
        )

    def resolve_for_product_read(
        self,
        *,
        deployment_id: str,
    ) -> AIMeasuredProductReadRegistration:
        registration = self._registrations.get(deployment_id)
        if registration is None:
            raise KeyError("AI-002D product read is not registered for this deployment")
        return _canonical_registration(registration)


@dataclass(frozen=True, slots=True, init=False)
class AIMeasuredProductReader:
    """Read one deployment-pinned product without caller-selected inputs."""

    _deployment_id: str
    _resolver: AIMeasuredProductReadResolver

    def __init__(
        self,
        *,
        deployment_id: str,
        resolver: AIMeasuredProductReadResolver,
    ) -> None:
        _require_deployment_id(deployment_id)
        if not callable(getattr(resolver, "resolve_for_product_read", None)):
            raise TypeError("AI-002D product reader requires a deployment resolver")
        object.__setattr__(self, "_deployment_id", deployment_id)
        object.__setattr__(self, "_resolver", resolver)

    def read(self) -> AIMeasuredProduct:
        """Reopen the exact AI-002C source and AI-002D product selected by deployment."""

        try:
            registration = self._resolver.resolve_for_product_read(
                deployment_id=self._deployment_id,
            )
            canonical = _canonical_registration(registration)
            if canonical.deployment_id != self._deployment_id:
                raise ValueError("AI-002D reader deployment selection differs")
            return load_ai_measured_product(
                canonical.outcome,
                reopen_context=canonical.reopen_context,
            )
        except AIMeasuredProductReaderError:
            raise
        except Exception as exc:
            raise AIMeasuredProductReaderError(
                "AI-002D deployment product read failed closed"
            ) from exc


def _canonical_registration(
    registration: AIMeasuredProductReadRegistration,
) -> AIMeasuredProductReadRegistration:
    if type(registration) is not AIMeasuredProductReadRegistration:
        raise TypeError("AI-002D resolver returned another registration type")
    _require_deployment_id(registration.deployment_id)
    if type(registration.outcome) is not AIMeasuredProductOutcome:
        raise TypeError("AI-002D registration requires the exact product outcome")
    if type(registration.outcome.source) is not AIReplayEvaluationOutcome:
        raise TypeError("AI-002D registration requires the exact AI-002C outcome")
    if type(registration.reopen_context) is not AIMeasuredProductSourceReopenContext:
        raise TypeError("AI-002D registration requires the complete reopen context")

    outcome = registration.outcome
    source = _canonical_source_outcome(outcome.source)
    product = AIMeasuredProduct.model_validate_json(outcome.product.model_dump_json(by_alias=True))
    product_run_path = _require_directory(outcome.run_path, label="product")
    source_paths = {
        _require_directory(source.run_path, label="evaluation"),
        _require_directory(source.source.run_path, label="source measurement"),
        _require_directory(
            source.source.execution.source_inputs.run_path,
            label="source execution",
        ),
        *(
            _require_directory(item.source_inputs.run_path, label="follow-up execution")
            for item in source.executions
        ),
    }
    if product_run_path in source_paths or len(source_paths) != 8:
        raise ValueError("AI-002D product and AI-002C Runs must be distinct")
    evaluation = source.mapping.public_evaluation
    if (
        outcome.artifact_path != AI_MEASURED_PRODUCT_PATH
        or registration.product_run_id != outcome.run_id
        or registration.product_id != product.product_id
        or registration.product_digest != product.product_digest
        or registration.source_evaluation_id != evaluation.evaluation_id
        or registration.source_evaluation_digest != evaluation.evaluation_digest
        or product.source_evaluation != evaluation.reference()
    ):
        raise ValueError("AI-002D deployment registration identities differ")

    canonical_outcome = AIMeasuredProductOutcome(
        run_id=outcome.run_id,
        run_path=product_run_path,
        artifact_path=outcome.artifact_path,
        product=product.model_copy(deep=True),
        source=source,
    )
    return AIMeasuredProductReadRegistration(
        deployment_id=registration.deployment_id,
        product_run_id=registration.product_run_id,
        product_id=registration.product_id,
        product_digest=registration.product_digest,
        source_evaluation_id=registration.source_evaluation_id,
        source_evaluation_digest=registration.source_evaluation_digest,
        outcome=canonical_outcome,
        reopen_context=registration.reopen_context,
    )


def _canonical_source_outcome(
    outcome: AIReplayEvaluationOutcome,
) -> AIReplayEvaluationOutcome:
    source = _canonical_measurement_outcome(outcome.source)
    if type(outcome.executions) is not tuple or len(outcome.executions) != 5:
        raise TypeError("AI-002D registration requires five exact follow-up executions")
    executions = tuple(_canonical_execution(item) for item in outcome.executions)
    return replace(
        outcome,
        run_path=_require_directory(outcome.run_path, label="evaluation"),
        source=source,
        executions=executions,
    )


def _canonical_measurement_outcome(
    outcome: AISourceMeasurementOutcome,
) -> AISourceMeasurementOutcome:
    if type(outcome) is not AISourceMeasurementOutcome:
        raise TypeError("AI-002D registration contains another measurement outcome type")
    execution = outcome.execution
    if type(execution) is not AISourceExecutionContext:
        raise TypeError("AI-002D registration contains another source execution type")
    return replace(
        outcome,
        run_path=_require_directory(outcome.run_path, label="measurement"),
        execution=replace(
            execution,
            source_inputs=_canonical_source_inputs(
                execution.source_inputs,
                label="source execution",
            ),
        ),
    )


def _canonical_execution(
    execution: AIMeasurementExecutionContext,
) -> AIMeasurementExecutionContext:
    if type(execution) is not AIMeasurementExecutionContext:
        raise TypeError("AI-002D registration contains another follow-up execution type")
    return replace(
        execution,
        source_inputs=_canonical_source_inputs(
            execution.source_inputs,
            label="follow-up execution",
        ),
    )


def _canonical_source_inputs(
    source_inputs: AIAnalysisObservationSourceInputs,
    *,
    label: str,
) -> AIAnalysisObservationSourceInputs:
    if type(source_inputs) is not AIAnalysisObservationSourceInputs:
        raise TypeError(f"AI-002D {label} contains another source input type")
    return replace(
        source_inputs,
        run_path=_require_directory(source_inputs.run_path, label=label),
    )


def _require_directory(value: object, *, label: str) -> Path:
    if not isinstance(value, Path):
        raise TypeError(f"AI-002D {label} Run path must be deployment-owned")
    path = value.resolve(strict=True)
    if not path.is_dir():
        raise ValueError(f"AI-002D {label} Run path must be a directory")
    return path


def _require_deployment_id(value: object) -> str:
    if type(value) is not str or _DEPLOYMENT_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("AI-002D deployment ID is invalid")
    return value


__all__ = [
    "AIMeasuredProductReadRegistration",
    "AIMeasuredProductReadRegistry",
    "AIMeasuredProductReadResolver",
    "AIMeasuredProductReader",
    "AIMeasuredProductReaderError",
]
