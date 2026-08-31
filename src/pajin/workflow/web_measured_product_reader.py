"""UX-009B deployment-pinned reader for one exact UX-009A projection."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Protocol

from pajin.workflow.web_controlled_validation_authority import (
    WebControlledValidationAuthorityOutcome,
)
from pajin.workflow.web_measured_product_flow import (
    WEB_MEASURED_PRODUCT_FLOW_PATH,
    WebMeasuredProductFlowOutcome,
    WebMeasuredProductFlowProjection,
    WebMeasuredProductSourceReopenContext,
    load_web_measured_product_flow,
)

_DEPLOYMENT_ID_PATTERN = re.compile(r"^[a-z][a-z0-9.-]{0,127}$")
_WEB_CONTROLLED_VALIDATION_AUTHORITY_PATH = "web-controlled-validation-authority.json"


class WebMeasuredProductReaderError(RuntimeError):
    """Raised when a deployment-pinned UX-009B read cannot be reproduced."""


@dataclass(frozen=True, slots=True)
class WebMeasuredProductReadRegistration:
    """Deployment-owned selection of one product Run and its private verifier context."""

    deployment_id: str
    product_run_id: str
    product_flow_id: str
    product_flow_digest: str
    source_run_id: str
    source_authority_id: str
    source_authority_digest: str
    outcome: WebMeasuredProductFlowOutcome
    reopen_context: WebMeasuredProductSourceReopenContext

    @classmethod
    def from_outcome(
        cls,
        *,
        deployment_id: str,
        outcome: WebMeasuredProductFlowOutcome,
        reopen_context: WebMeasuredProductSourceReopenContext,
    ) -> WebMeasuredProductReadRegistration:
        """Pin the exact content-addressed identities selected by deployment composition."""

        return cls(
            deployment_id=deployment_id,
            product_run_id=outcome.run_id,
            product_flow_id=outcome.projection.flow_id,
            product_flow_digest=outcome.projection.flow_digest,
            source_run_id=outcome.source.run_id,
            source_authority_id=outcome.source.authority.authority_id,
            source_authority_digest=outcome.source.authority.authority_digest,
            outcome=outcome,
            reopen_context=reopen_context,
        )


class WebMeasuredProductReadResolver(Protocol):
    """Deployment TCB that resolves one exact registered product read."""

    def resolve_for_product_read(
        self,
        *,
        deployment_id: str,
    ) -> WebMeasuredProductReadRegistration: ...


@dataclass(frozen=True, slots=True, init=False)
class WebMeasuredProductReadRegistry:
    """Immutable process-local registry of deployment-selected UX-009A reads."""

    _registrations: Mapping[str, WebMeasuredProductReadRegistration]

    def __init__(
        self,
        registrations: tuple[WebMeasuredProductReadRegistration, ...],
    ) -> None:
        if type(registrations) is not tuple or not registrations:
            raise TypeError("WEB measured product reader registrations must be a non-empty tuple")
        canonical = tuple(_canonical_registration(item) for item in registrations)
        if len({item.deployment_id for item in canonical}) != len(canonical):
            raise ValueError("WEB measured product reader deployment IDs must be unique")
        if len({item.product_run_id for item in canonical}) != len(canonical):
            raise ValueError("WEB measured product reader product Run IDs must be unique")
        if len({item.product_flow_id for item in canonical}) != len(canonical):
            raise ValueError("WEB measured product reader Flow IDs must be unique")
        object.__setattr__(
            self,
            "_registrations",
            MappingProxyType({item.deployment_id: item for item in canonical}),
        )

    def resolve_for_product_read(
        self,
        *,
        deployment_id: str,
    ) -> WebMeasuredProductReadRegistration:
        registration = self._registrations.get(deployment_id)
        if registration is None:
            raise KeyError("WEB measured product read is not registered for this deployment")
        return _canonical_registration(registration)


@dataclass(frozen=True, slots=True, init=False)
class WebMeasuredProductReader:
    """Read one deployment-pinned projection without accepting caller-selected inputs."""

    _deployment_id: str
    _resolver: WebMeasuredProductReadResolver

    def __init__(
        self,
        *,
        deployment_id: str,
        resolver: WebMeasuredProductReadResolver,
    ) -> None:
        _require_deployment_id(deployment_id)
        if not callable(getattr(resolver, "resolve_for_product_read", None)):
            raise TypeError("WEB measured product reader requires a deployment resolver")
        object.__setattr__(self, "_deployment_id", deployment_id)
        object.__setattr__(self, "_resolver", resolver)

    def read(self) -> WebMeasuredProductFlowProjection:
        """Reopen the exact source and projection selected by deployment configuration."""

        try:
            registration = self._resolver.resolve_for_product_read(
                deployment_id=self._deployment_id,
            )
            canonical = _canonical_registration(registration)
            if canonical.deployment_id != self._deployment_id:
                raise ValueError("WEB measured product reader deployment selection differs")
            return load_web_measured_product_flow(
                canonical.outcome,
                reopen_context=canonical.reopen_context,
            )
        except WebMeasuredProductReaderError:
            raise
        except Exception as exc:
            raise WebMeasuredProductReaderError(
                "WEB measured product deployment read failed closed"
            ) from exc


def _canonical_registration(
    registration: WebMeasuredProductReadRegistration,
) -> WebMeasuredProductReadRegistration:
    if type(registration) is not WebMeasuredProductReadRegistration:
        raise TypeError("WEB measured product resolver returned another registration type")
    _require_deployment_id(registration.deployment_id)
    if type(registration.outcome) is not WebMeasuredProductFlowOutcome:
        raise TypeError("WEB measured product registration requires the exact product outcome")
    if type(registration.outcome.source) is not WebControlledValidationAuthorityOutcome:
        raise TypeError("WEB measured product registration requires the exact source outcome")
    if type(registration.reopen_context) is not WebMeasuredProductSourceReopenContext:
        raise TypeError("WEB measured product registration requires the complete reopen context")
    if not isinstance(registration.outcome.run_path, Path) or not isinstance(
        registration.outcome.source.run_path,
        Path,
    ):
        raise TypeError("WEB measured product registration requires deployment-owned Run paths")

    outcome = registration.outcome
    source = outcome.source
    projection = WebMeasuredProductFlowProjection.model_validate_json(
        outcome.projection.model_dump_json(by_alias=True)
    )
    product_run_path = outcome.run_path.resolve(strict=True)
    source_run_path = source.run_path.resolve(strict=True)
    if not product_run_path.is_dir() or not source_run_path.is_dir():
        raise ValueError("WEB measured product registered Run paths must be directories")
    if product_run_path == source_run_path or outcome.run_id == source.run_id:
        raise ValueError("WEB measured product and source Runs must be distinct")
    if (
        outcome.artifact_path != WEB_MEASURED_PRODUCT_FLOW_PATH
        or source.authority_path != _WEB_CONTROLLED_VALIDATION_AUTHORITY_PATH
        or registration.product_run_id != outcome.run_id
        or registration.product_flow_id != projection.flow_id
        or registration.product_flow_digest != projection.flow_digest
        or registration.source_run_id != source.run_id
        or registration.source_authority_id != source.authority.authority_id
        or registration.source_authority_digest != source.authority.authority_digest
        or projection.source_run_id != source.run_id
        or projection.source_authority_id != source.authority.authority_id
        or projection.source_authority_digest != source.authority.authority_digest
    ):
        raise ValueError("WEB measured product deployment registration identities differ")

    canonical_source = WebControlledValidationAuthorityOutcome(
        run_id=source.run_id,
        run_path=source_run_path,
        authority_path=source.authority_path,
        authority=source.authority,
    )
    canonical_outcome = WebMeasuredProductFlowOutcome(
        run_id=outcome.run_id,
        run_path=product_run_path,
        artifact_path=outcome.artifact_path,
        projection=projection.model_copy(deep=True),
        source=canonical_source,
    )
    return WebMeasuredProductReadRegistration(
        deployment_id=registration.deployment_id,
        product_run_id=registration.product_run_id,
        product_flow_id=registration.product_flow_id,
        product_flow_digest=registration.product_flow_digest,
        source_run_id=registration.source_run_id,
        source_authority_id=registration.source_authority_id,
        source_authority_digest=registration.source_authority_digest,
        outcome=canonical_outcome,
        reopen_context=registration.reopen_context,
    )


def _require_deployment_id(value: object) -> str:
    if type(value) is not str or _DEPLOYMENT_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("WEB measured product deployment ID is invalid")
    return value


__all__ = [
    "WebMeasuredProductReadRegistration",
    "WebMeasuredProductReadRegistry",
    "WebMeasuredProductReadResolver",
    "WebMeasuredProductReader",
    "WebMeasuredProductReaderError",
]
