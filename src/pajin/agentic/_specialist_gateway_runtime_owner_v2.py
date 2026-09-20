"""Trusted in-process owner vault for the frozen specialist v2 fake backend.

This private module is part of the control-plane interpreter TCB.  It is an
encapsulation and drift-detection boundary, not a sandbox against arbitrary
same-interpreter reflection.  Untrusted model, skill, plugin, and target data
must never execute in this interpreter.
"""

from __future__ import annotations

import threading
import weakref
from _thread import RLock as RLockType
from dataclasses import dataclass
from typing import Final

from pajin.agentic.specialist_backend_v2 import (
    SpecialistBackendJobTemplateV2,
    SpecialistBackendOutputVerifierV2,
    SpecialistBackendVerificationKeyV2,
    SpecialistExecutionInventoryV2,
    StructuredFakeSpecialistBackendV2,
)

_RUNTIME_OWNER_ACCESS_AUTHORITY: Final = object()


class _SpecialistGatewayRuntimeOwnerV2Error(RuntimeError):
    """Raised when the private runtime-owner vault differs from its anchors."""


@dataclass(frozen=True, slots=True)
class _SpecialistGatewayRuntimeOwnerV2:
    """Current exact component view; never returned outside the Gateway TCB."""

    identity_token: object
    verification_key: SpecialistBackendVerificationKeyV2
    job_template: SpecialistBackendJobTemplateV2
    execution_inventory: SpecialistExecutionInventoryV2
    backend: StructuredFakeSpecialistBackendV2
    verifier: SpecialistBackendOutputVerifierV2


@dataclass(frozen=True, slots=True)
class _SpecialistGatewayRuntimeAnchorsV2:
    """Factory-time object anchors kept separate from the current owner view."""

    identity_token: object
    verification_key: SpecialistBackendVerificationKeyV2
    job_template: SpecialistBackendJobTemplateV2
    execution_inventory: SpecialistExecutionInventoryV2
    backend: StructuredFakeSpecialistBackendV2
    verifier: SpecialistBackendOutputVerifierV2


@dataclass(frozen=True, slots=True)
class _SpecialistGatewayRuntimeEntryV2:
    owner: _SpecialistGatewayRuntimeOwnerV2
    anchors: _SpecialistGatewayRuntimeAnchorsV2


_RUNTIME_OWNER_REGISTRY_LOCK: Final = threading.RLock()
_RUNTIME_OWNER_REGISTRY: weakref.WeakKeyDictionary[
    object,
    _SpecialistGatewayRuntimeEntryV2,
] = weakref.WeakKeyDictionary()
_RUNTIME_OWNER_REGISTRY_LOCK_IMPLEMENTATION = _RUNTIME_OWNER_REGISTRY_LOCK
_RUNTIME_OWNER_REGISTRY_IMPLEMENTATION = _RUNTIME_OWNER_REGISTRY


def _require_registry() -> None:
    if (
        _RUNTIME_OWNER_REGISTRY_LOCK is not _RUNTIME_OWNER_REGISTRY_LOCK_IMPLEMENTATION
        or type(_RUNTIME_OWNER_REGISTRY_LOCK_IMPLEMENTATION) is not RLockType
        or _RUNTIME_OWNER_REGISTRY is not _RUNTIME_OWNER_REGISTRY_IMPLEMENTATION
    ):
        raise _SpecialistGatewayRuntimeOwnerV2Error(
            "specialist Gateway runtime-owner registry changed"
        )


_REQUIRE_REGISTRY_IMPLEMENTATION = _require_registry


def _register_specialist_gateway_runtime_owner_v2(
    deployment: object,
    *,
    access_authority: object,
    identity_token: object,
    verification_key: SpecialistBackendVerificationKeyV2,
    job_template: SpecialistBackendJobTemplateV2,
    execution_inventory: SpecialistExecutionInventoryV2,
    backend: StructuredFakeSpecialistBackendV2,
    verifier: SpecialistBackendOutputVerifierV2,
) -> None:
    """Register exact factory-time components without returning a raw handle."""

    if (
        access_authority is not _RUNTIME_OWNER_ACCESS_AUTHORITY
        or type(verification_key) is not SpecialistBackendVerificationKeyV2
        or type(job_template) is not SpecialistBackendJobTemplateV2
        or type(execution_inventory) is not SpecialistExecutionInventoryV2
        or type(backend) is not StructuredFakeSpecialistBackendV2
        or type(verifier) is not SpecialistBackendOutputVerifierV2
        or _require_registry is not _REQUIRE_REGISTRY_IMPLEMENTATION
    ):
        raise _SpecialistGatewayRuntimeOwnerV2Error(
            "specialist Gateway runtime owner requires its exact TCB factory"
        )
    owner = _SpecialistGatewayRuntimeOwnerV2(
        identity_token=identity_token,
        verification_key=verification_key,
        job_template=job_template,
        execution_inventory=execution_inventory,
        backend=backend,
        verifier=verifier,
    )
    anchors = _SpecialistGatewayRuntimeAnchorsV2(
        identity_token=identity_token,
        verification_key=verification_key,
        job_template=job_template,
        execution_inventory=execution_inventory,
        backend=backend,
        verifier=verifier,
    )
    with _RUNTIME_OWNER_REGISTRY_LOCK_IMPLEMENTATION:
        _REQUIRE_REGISTRY_IMPLEMENTATION()
        if deployment in _RUNTIME_OWNER_REGISTRY_IMPLEMENTATION:
            raise _SpecialistGatewayRuntimeOwnerV2Error(
                "specialist Gateway runtime owner was already registered"
            )
        _RUNTIME_OWNER_REGISTRY_IMPLEMENTATION[deployment] = _SpecialistGatewayRuntimeEntryV2(
            owner=owner, anchors=anchors
        )


def _resolve_specialist_gateway_runtime_owner_v2(
    deployment: object,
    *,
    access_authority: object,
    identity_token: object,
) -> _SpecialistGatewayRuntimeOwnerV2:
    """Resolve an exact owner after comparing its current view to sealed anchors."""

    if (
        access_authority is not _RUNTIME_OWNER_ACCESS_AUTHORITY
        or _require_registry is not _REQUIRE_REGISTRY_IMPLEMENTATION
    ):
        raise _SpecialistGatewayRuntimeOwnerV2Error(
            "specialist Gateway runtime-owner access is unauthorized"
        )
    with _RUNTIME_OWNER_REGISTRY_LOCK_IMPLEMENTATION:
        _REQUIRE_REGISTRY_IMPLEMENTATION()
        try:
            entry = _RUNTIME_OWNER_REGISTRY_IMPLEMENTATION[deployment]
        except (KeyError, TypeError) as exc:
            raise _SpecialistGatewayRuntimeOwnerV2Error(
                "specialist Gateway runtime owner is not registered"
            ) from exc
        if (
            type(entry) is not _SpecialistGatewayRuntimeEntryV2
            or type(entry.owner) is not _SpecialistGatewayRuntimeOwnerV2
            or type(entry.anchors) is not _SpecialistGatewayRuntimeAnchorsV2
            or entry.owner.identity_token is not identity_token
            or entry.anchors.identity_token is not identity_token
            or entry.owner.verification_key is not entry.anchors.verification_key
            or entry.owner.job_template is not entry.anchors.job_template
            or entry.owner.execution_inventory is not entry.anchors.execution_inventory
            or entry.owner.backend is not entry.anchors.backend
            or entry.owner.verifier is not entry.anchors.verifier
        ):
            raise _SpecialistGatewayRuntimeOwnerV2Error(
                "specialist Gateway runtime owner differs from its factory anchors"
            )
        return entry.owner


def _retire_specialist_gateway_runtime_owner_v2(
    deployment: object,
    *,
    access_authority: object,
    identity_token: object,
) -> None:
    """Purge one runtime owner even when its current view has drifted."""

    if (
        access_authority is not _RUNTIME_OWNER_ACCESS_AUTHORITY
        or _require_registry is not _REQUIRE_REGISTRY_IMPLEMENTATION
    ):
        raise _SpecialistGatewayRuntimeOwnerV2Error(
            "specialist Gateway runtime-owner retirement is unauthorized"
        )
    with _RUNTIME_OWNER_REGISTRY_LOCK_IMPLEMENTATION:
        _REQUIRE_REGISTRY_IMPLEMENTATION()
        try:
            entry = _RUNTIME_OWNER_REGISTRY_IMPLEMENTATION[deployment]
        except (KeyError, TypeError) as exc:
            raise _SpecialistGatewayRuntimeOwnerV2Error(
                "specialist Gateway runtime owner is not registered"
            ) from exc
        exact = (
            type(entry) is _SpecialistGatewayRuntimeEntryV2
            and type(entry.owner) is _SpecialistGatewayRuntimeOwnerV2
            and type(entry.anchors) is _SpecialistGatewayRuntimeAnchorsV2
            and entry.owner.identity_token is identity_token
            and entry.anchors.identity_token is identity_token
        )
        del _RUNTIME_OWNER_REGISTRY_IMPLEMENTATION[deployment]
        if not exact:
            raise _SpecialistGatewayRuntimeOwnerV2Error(
                "specialist Gateway runtime-owner retirement identity changed"
            )


_REGISTER_RUNTIME_OWNER_IMPLEMENTATION = _register_specialist_gateway_runtime_owner_v2
_RESOLVE_RUNTIME_OWNER_IMPLEMENTATION = _resolve_specialist_gateway_runtime_owner_v2
_RETIRE_RUNTIME_OWNER_IMPLEMENTATION = _retire_specialist_gateway_runtime_owner_v2
