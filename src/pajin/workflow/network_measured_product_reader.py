"""NET-002D deployment-pinned zero-argument product reader."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType
from typing import Protocol

from pajin.workflow.network_measured_product_flow import (
    NETWORK_MEASURED_PRODUCT_PATH,
    NetworkMeasuredProduct,
    NetworkMeasuredProductOutcome,
    NetworkMeasuredProductSourceReopenContext,
    load_network_measured_product,
)
from pajin.workflow.network_replay_evaluation import NetworkReplayEvaluationOutcome
from pajin.workflow.network_source_measurement import NetworkSourceMeasurementOutcome

_DEPLOYMENT_ID_PATTERN = re.compile(r"^[a-z][a-z0-9.-]{0,127}$")


class NetworkMeasuredProductReaderError(RuntimeError):
    """Raised when a deployment-pinned NET-002D read cannot be reproduced."""


@dataclass(frozen=True, slots=True)
class NetworkMeasuredProductReadRegistration:
    """Deployment-owned selection of one product and its complete verifier context."""

    deployment_id: str
    product_run_id: str
    product_id: str
    product_digest: str
    source_evaluation_id: str
    source_evaluation_digest: str
    outcome: NetworkMeasuredProductOutcome
    reopen_context: NetworkMeasuredProductSourceReopenContext

    @classmethod
    def from_outcome(
        cls,
        *,
        deployment_id: str,
        outcome: NetworkMeasuredProductOutcome,
        reopen_context: NetworkMeasuredProductSourceReopenContext,
    ) -> NetworkMeasuredProductReadRegistration:
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


class NetworkMeasuredProductReadResolver(Protocol):
    """Deployment TCB that resolves one exact registered Network product read."""

    def resolve_for_product_read(
        self,
        *,
        deployment_id: str,
    ) -> NetworkMeasuredProductReadRegistration: ...


@dataclass(frozen=True, slots=True, init=False)
class NetworkMeasuredProductReadRegistry:
    """Immutable process-local registry of deployment-selected NET-002D reads."""

    _registrations: Mapping[str, NetworkMeasuredProductReadRegistration]

    def __init__(
        self,
        registrations: tuple[NetworkMeasuredProductReadRegistration, ...],
    ) -> None:
        if type(registrations) is not tuple or not registrations:
            raise TypeError("NET-002D reader registrations must be a non-empty tuple")
        canonical = tuple(_canonical_registration(item) for item in registrations)
        if len({item.deployment_id for item in canonical}) != len(canonical):
            raise ValueError("NET-002D reader deployment IDs must be unique")
        if len({item.product_run_id for item in canonical}) != len(canonical):
            raise ValueError("NET-002D reader product Run IDs must be unique")
        if len({item.product_id for item in canonical}) != len(canonical):
            raise ValueError("NET-002D reader product IDs must be unique")
        object.__setattr__(
            self,
            "_registrations",
            MappingProxyType({item.deployment_id: item for item in canonical}),
        )

    def resolve_for_product_read(
        self,
        *,
        deployment_id: str,
    ) -> NetworkMeasuredProductReadRegistration:
        registration = self._registrations.get(deployment_id)
        if registration is None:
            raise KeyError("NET-002D product read is not registered for this deployment")
        return _canonical_registration(registration)


@dataclass(frozen=True, slots=True, init=False)
class NetworkMeasuredProductReader:
    """Read one deployment-pinned product without caller-selected inputs."""

    _deployment_id: str
    _resolver: NetworkMeasuredProductReadResolver

    def __init__(
        self,
        *,
        deployment_id: str,
        resolver: NetworkMeasuredProductReadResolver,
    ) -> None:
        _require_deployment_id(deployment_id)
        if not callable(getattr(resolver, "resolve_for_product_read", None)):
            raise TypeError("NET-002D product reader requires a deployment resolver")
        object.__setattr__(self, "_deployment_id", deployment_id)
        object.__setattr__(self, "_resolver", resolver)

    def read(self) -> NetworkMeasuredProduct:
        """Reopen the exact NET-002C source and NET-002D product selected by deployment."""

        try:
            registration = self._resolver.resolve_for_product_read(
                deployment_id=self._deployment_id,
            )
            canonical = _canonical_registration(registration)
            if canonical.deployment_id != self._deployment_id:
                raise ValueError("NET-002D reader deployment selection differs")
            return load_network_measured_product(
                canonical.outcome,
                reopen_context=canonical.reopen_context,
            )
        except NetworkMeasuredProductReaderError:
            raise
        except Exception as exc:
            raise NetworkMeasuredProductReaderError(
                "NET-002D deployment product read failed closed"
            ) from exc


def _canonical_registration(
    registration: NetworkMeasuredProductReadRegistration,
) -> NetworkMeasuredProductReadRegistration:
    if type(registration) is not NetworkMeasuredProductReadRegistration:
        raise TypeError("NET-002D resolver returned another registration type")
    _require_deployment_id(registration.deployment_id)
    if type(registration.outcome) is not NetworkMeasuredProductOutcome:
        raise TypeError("NET-002D registration requires the exact product outcome")
    if type(registration.outcome.source) is not NetworkReplayEvaluationOutcome:
        raise TypeError("NET-002D registration requires the exact NET-002C outcome")
    if type(registration.reopen_context) is not NetworkMeasuredProductSourceReopenContext:
        raise TypeError("NET-002D registration requires the complete reopen context")

    outcome = registration.outcome
    source = _canonical_source_outcome(outcome.source)
    product = NetworkMeasuredProduct.model_validate_json(
        outcome.product.model_dump_json(by_alias=True)
    )
    product_run_path = _require_directory(outcome.run_path, label="product")
    source_paths = {
        _require_directory(source.run_path, label="evaluation"),
        _require_directory(source.source.run_path, label="source measurement"),
        _require_directory(source.replay.run_path, label="Replay measurement"),
    }
    if product_run_path in source_paths or len(source_paths) != 3:
        raise ValueError("NET-002D product and NET-002C Runs must be distinct")
    evaluation = source.mapping.public_evaluation
    if (
        outcome.artifact_path != NETWORK_MEASURED_PRODUCT_PATH
        or registration.product_run_id != outcome.run_id
        or registration.product_id != product.product_id
        or registration.product_digest != product.product_digest
        or registration.source_evaluation_id != evaluation.evaluation_id
        or registration.source_evaluation_digest != evaluation.evaluation_digest
        or product.source_evaluation != evaluation.reference()
    ):
        raise ValueError("NET-002D deployment registration identities differ")

    canonical_outcome = NetworkMeasuredProductOutcome(
        run_id=outcome.run_id,
        run_path=product_run_path,
        artifact_path=outcome.artifact_path,
        product=product.model_copy(deep=True),
        source=source,
    )
    return NetworkMeasuredProductReadRegistration(
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
    outcome: NetworkReplayEvaluationOutcome,
) -> NetworkReplayEvaluationOutcome:
    source = _canonical_measurement_outcome(outcome.source)
    replay = _canonical_measurement_outcome(outcome.replay)
    return replace(
        outcome,
        run_path=_require_directory(outcome.run_path, label="evaluation"),
        source=source,
        replay=replay,
    )


def _canonical_measurement_outcome(
    outcome: NetworkSourceMeasurementOutcome,
) -> NetworkSourceMeasurementOutcome:
    if type(outcome) is not NetworkSourceMeasurementOutcome:
        raise TypeError("NET-002D registration contains another measurement outcome type")
    return replace(
        outcome,
        run_path=_require_directory(outcome.run_path, label="measurement"),
    )


def _require_directory(value: object, *, label: str) -> Path:
    if not isinstance(value, Path):
        raise TypeError(f"NET-002D {label} Run path must be deployment-owned")
    path = value.resolve(strict=True)
    if not path.is_dir():
        raise ValueError(f"NET-002D {label} Run path must be a directory")
    return path


def _require_deployment_id(value: object) -> str:
    if type(value) is not str or _DEPLOYMENT_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("NET-002D deployment ID is invalid")
    return value


__all__ = [
    "NetworkMeasuredProductReadRegistration",
    "NetworkMeasuredProductReadRegistry",
    "NetworkMeasuredProductReadResolver",
    "NetworkMeasuredProductReader",
    "NetworkMeasuredProductReaderError",
]
