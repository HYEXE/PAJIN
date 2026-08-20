"""Authenticated FastAPI surface for the PAJIN Control Plane."""

import asyncio
import json
import math
import os
import re
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Annotated
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, build_opener
from urllib.request import Request as URLRequest

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from pajin.control_plane.abac import (
    ControlPlaneABACAuthorizer,
    ControlPlaneABACPolicy,
    ControlPlaneCheckpointResumeABACPolicy,
    ControlPlaneCheckpointResumeAuthorizer,
    ControlPlaneMaintenanceABACPolicy,
    ControlPlaneMaintenanceAuthorizer,
    ControlPlaneReplayBatchAdmissionABACPolicy,
    ControlPlaneReplayBatchAdmissionAuthorizer,
    ControlPlaneReplaySourceArtifactABACPolicy,
    ControlPlaneReplaySourceArtifactAuthorizer,
    ControlPlaneRunCancellationABACPolicy,
    ControlPlaneRunCancellationAuthorizer,
    ControlPlaneRunSubmissionABACPolicy,
    ControlPlaneRunSubmissionAuthorizer,
    parse_checkpoint_resume_abac_policy,
    parse_control_plane_abac_policy,
    parse_maintenance_abac_policy,
    parse_replay_batch_admission_abac_policy,
    parse_replay_source_artifact_abac_policy,
    parse_run_cancellation_abac_policy,
    parse_run_submission_abac_policy,
)
from pajin.control_plane.api_routes import (
    ControlPlaneDependencies,
    PrincipalDependency,
    RoleDependencyFactory,
    register_control_plane_routes,
)
from pajin.control_plane.artifacts import ManagedArtifactRepository
from pajin.control_plane.attestation import (
    ReplayAttestationTrustAnchor,
    ReplayAttestor,
    parse_replay_attestation_trust_anchor,
    private_key_bytes_from_base64url,
)
from pajin.control_plane.campaign_drafts import (
    ControlPlaneCampaignDraftCompiler,
    ControlPlaneCampaignDraftReader,
)
from pajin.control_plane.database import ControlPlaneRepository
from pajin.control_plane.decision_views import VerifiedGraphDecisionAuditViewReader
from pajin.control_plane.discovery_views import VerifiedDiscoveryViewReader
from pajin.control_plane.errors import (
    AuthorizationDenied,
    ControlPlaneError,
    LeaseRejected,
    ReplayExecutorRejected,
    ResourceNotFound,
    RunCancelled,
    StateConflict,
)
from pajin.control_plane.execution_attestation import (
    ExecutorAttestationTrustAnchor,
    parse_executor_attestation_trust_anchor,
)
from pajin.control_plane.graph_views import (
    VerifiedCanonicalGraphViewReader,
    VerifiedHypothesisAttentionRankingReader,
)
from pajin.control_plane.identity import (
    OIDCHumanAuthenticator,
    OIDCHumanTrustPolicy,
    parse_oidc_human_trust_policy,
)
from pajin.control_plane.models import (
    ControlPlaneConflictCode,
    ControlPlaneConflictResponse,
    Principal,
    PrincipalRole,
)
from pajin.control_plane.pentest_recon import PentestReconDispatchRuntime
from pajin.control_plane.pentest_recon_deployment import (
    load_pentest_recon_operator_deployment,
)
from pajin.control_plane.pentest_replay import PentestReplayDispatchRuntime
from pajin.control_plane.pentest_replay_deployment import (
    load_pentest_replay_operator_deployment,
)
from pajin.control_plane.pentest_workflow import PentestOperatorWorkflowRuntime
from pajin.control_plane.pentest_workflow_coordination import (
    PentestWorkflowCoordinationDispatchRuntime,
)
from pajin.control_plane.pentest_workflow_coordination_deployment import (
    load_pentest_workflow_coordination_deployment,
)
from pajin.control_plane.pentest_workflow_deployment import (
    load_pentest_operator_workflow_deployment,
)
from pajin.control_plane.replay_comparison import VerifiedReplayEvidenceComparisonReader
from pajin.control_plane.security import (
    AuthenticationError,
    BearerAuthenticator,
    ChainedAuthenticator,
    CheckpointIntegrityError,
    CheckpointSigner,
    TokenAuthenticator,
    validate_bearer_token,
)
from pajin.control_plane.service import ControlPlaneService
from pajin.control_plane.validation_comparison import (
    VerifiedWalkingControlComparisonReader,
)
from pajin.control_plane.worker_identity import (
    WorkerMTLSAuthenticator,
    WorkerMTLSTrustPolicy,
    parse_worker_mtls_trust_policy,
)
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.target_attestation import (
    TargetAttestationRegistryBundle,
    TargetAttestationRegistryTrustAnchor,
    TargetAttestationTrustAnchor,
    TargetAttestationTrustRegistry,
    parse_target_attestation_registry_bundle,
    parse_target_attestation_registry_trust_anchor,
    parse_target_attestation_trust_anchor,
    parse_target_attestation_trust_registry,
    verify_target_attestation_registry_bundle,
)

_ABAC_POLICY_ENV = "PAJIN_CP_ABAC_POLICY"
_RUN_SUBMISSION_ABAC_POLICY_ENV = "PAJIN_CP_RUN_SUBMISSION_ABAC_POLICY"
_RUN_CANCELLATION_ABAC_POLICY_ENV = "PAJIN_CP_RUN_CANCELLATION_ABAC_POLICY"
_CHECKPOINT_RESUME_ABAC_POLICY_ENV = "PAJIN_CP_CHECKPOINT_RESUME_ABAC_POLICY"
_REPLAY_SOURCE_ARTIFACT_ABAC_POLICY_ENV = "PAJIN_CP_REPLAY_SOURCE_ARTIFACT_ABAC_POLICY"
_REPLAY_BATCH_ADMISSION_ABAC_POLICY_ENV = "PAJIN_CP_REPLAY_BATCH_ADMISSION_ABAC_POLICY"
_MAINTENANCE_ABAC_POLICY_ENV = "PAJIN_CP_MAINTENANCE_ABAC_POLICY"

_OIDC_HUMAN_TRUST_POLICY_ENV = "PAJIN_CP_OIDC_HUMAN_TRUST_POLICY"
_WORKER_MTLS_TRUST_POLICY_ENV = "PAJIN_CP_WORKER_MTLS_TRUST_POLICY"
_ADDITIONAL_WORKER_CREDENTIALS_ENV = "PAJIN_CP_ADDITIONAL_WORKER_CREDENTIALS"
_PENTEST_RECON_DEPLOYMENT_PATH_ENV = "PAJIN_CP_PENTEST_RECON_DEPLOYMENT_PATH"
_PENTEST_RECON_DEPLOYMENT_SHA256_ENV = "PAJIN_CP_PENTEST_RECON_DEPLOYMENT_SHA256"
_PENTEST_REPLAY_DEPLOYMENT_PATH_ENV = "PAJIN_CP_PENTEST_REPLAY_DEPLOYMENT_PATH"
_PENTEST_REPLAY_DEPLOYMENT_SHA256_ENV = "PAJIN_CP_PENTEST_REPLAY_DEPLOYMENT_SHA256"
_PENTEST_WORKFLOW_DEPLOYMENT_PATH_ENV = "PAJIN_CP_PENTEST_WORKFLOW_DEPLOYMENT_PATH"
_PENTEST_WORKFLOW_DEPLOYMENT_SHA256_ENV = "PAJIN_CP_PENTEST_WORKFLOW_DEPLOYMENT_SHA256"
_PENTEST_WORKFLOW_COORDINATION_DEPLOYMENT_PATH_ENV = (
    "PAJIN_CP_PENTEST_WORKFLOW_COORDINATION_DEPLOYMENT_PATH"
)
_PENTEST_WORKFLOW_COORDINATION_DEPLOYMENT_SHA256_ENV = (
    "PAJIN_CP_PENTEST_WORKFLOW_COORDINATION_DEPLOYMENT_SHA256"
)
_REPLAY_EXECUTOR_PROFILES_ENV = "PAJIN_CP_REPLAY_EXECUTOR_PROFILES"
_REPLAY_ATTESTATION_KEY_ID_ENV = "PAJIN_CP_REPLAY_ATTESTATION_KEY_ID"
_REPLAY_ATTESTATION_PRIVATE_KEY_ENV = "PAJIN_CP_REPLAY_ATTESTATION_PRIVATE_KEY"
_REPLAY_ATTESTATION_TRUST_ANCHOR_ENV = "PAJIN_CP_REPLAY_ATTESTATION_TRUST_ANCHOR"
_EXECUTOR_ATTESTATION_TRUST_ANCHOR_ENV = "PAJIN_CP_EXECUTOR_ATTESTATION_TRUST_ANCHOR"
_TARGET_ATTESTATION_TRUST_ANCHOR_ENV = "PAJIN_CP_TARGET_ATTESTATION_TRUST_ANCHOR"
_TARGET_ATTESTATION_TRUST_REGISTRY_ENV = "PAJIN_CP_TARGET_ATTESTATION_TRUST_REGISTRY"
_TARGET_ATTESTATION_REGISTRY_TRUST_ANCHOR_ENV = "PAJIN_CP_TARGET_ATTESTATION_REGISTRY_TRUST_ANCHOR"
_TARGET_ATTESTATION_TRUST_REGISTRY_BUNDLE_ENV = "PAJIN_CP_TARGET_ATTESTATION_TRUST_REGISTRY_BUNDLE"
_TARGET_ATTESTATION_TRUST_REGISTRY_BUNDLE_URL_ENV = (
    "PAJIN_CP_TARGET_ATTESTATION_TRUST_REGISTRY_BUNDLE_URL"
)
_MAX_TARGET_ATTESTATION_REGISTRY_BUNDLE_BYTES = 512 * 1024
_REPLAY_EXECUTOR_PROFILE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_MAX_REPLAY_EXECUTOR_PROFILES_PER_SUBJECT = 20
_MAX_REPLAY_EXECUTOR_PROFILES_JSON_BYTES = 64 * 1024
_MAX_REPLAY_EXECUTOR_PROFILES_JSON_DEPTH = 4
_MAX_REPLAY_EXECUTOR_PROFILES_JSON_NODES = 4_096
_WORKER_TOKEN_ENV_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_TRUE_ENV_VALUES = frozenset({"1", "true", "yes"})
_FALSE_ENV_VALUES = frozenset({"0", "false", "no"})
# A bounded Control Plane JSON object is at most 1,000,000 canonical UTF-8
# bytes. A standards-compliant client may encode one four-byte Unicode scalar
# as a twelve-byte surrogate pair, so reserve three times that semantic bound
# plus one MiB for the typed endpoint envelope and framing fields.
_MAX_CONTROL_PLANE_REQUEST_BODY_BYTES = 4 * 1024 * 1024
_MAX_CONTROL_PLANE_REQUEST_BODY_CHUNKS = 1024
_DEFAULT_CONTROL_PLANE_REQUEST_BODY_TIMEOUT_SECONDS = 30.0
_JSON_MUTATION_METHODS = frozenset({"PATCH", "POST", "PUT"})


class _DuplicateJSONObjectKey(ValueError):
    """A decoded JSON object used one member name more than once."""


def _reject_duplicate_json_object_keys(body: bytes) -> None:
    """Inspect one bounded JSON document without replacing FastAPI's syntax handling."""

    def reject_duplicates(pairs: list[tuple[str, object]]) -> None:
        names: set[str] = set()
        for name, _value in pairs:
            if name in names:
                raise _DuplicateJSONObjectKey
            names.add(name)
        # The parsed value is deliberately discarded. FastAPI still owns the
        # actual decode and typed validation after this ambiguity-only pass.
        return None

    try:
        json.loads(body, object_pairs_hook=reject_duplicates)
    except _DuplicateJSONObjectKey:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError):
        # Preserve FastAPI/Starlette's existing malformed/empty JSON response
        # contract. This pass owns duplicate names only.
        return


async def _buffer_bounded_http_body(
    receive: Receive,
    *,
    max_body_bytes: int,
    timeout_seconds: float,
) -> deque[Message] | None:
    """Buffer one HTTP body within one absolute elapsed-time deadline."""

    buffered: deque[Message] = deque()
    received_bytes = 0
    received_chunks = 0
    async with asyncio.timeout(timeout_seconds):
        while True:
            message = await receive()
            if message["type"] != "http.request":
                buffered.append(message)
                return buffered

            received_chunks += 1
            if received_chunks > _MAX_CONTROL_PLANE_REQUEST_BODY_CHUNKS:
                return None
            body = message.get("body", b"")
            if not isinstance(body, bytes):  # pragma: no cover - ASGI server contract
                return None
            received_bytes += len(body)
            if received_bytes > max_body_bytes:
                return None

            buffered.append(message)
            if message.get("more_body") is not True:
                return buffered


class _BoundedRequestBodyMiddleware:
    """Reject oversized HTTP bodies before authentication or body parsing."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int = _MAX_CONTROL_PLANE_REQUEST_BODY_BYTES,
        body_timeout_seconds: float = _DEFAULT_CONTROL_PLANE_REQUEST_BODY_TIMEOUT_SECONDS,
    ) -> None:
        self._app = app
        self._max_body_bytes = max_body_bytes
        self._body_timeout_seconds = body_timeout_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        declared_length = self._declared_content_length(scope)
        if declared_length is not None and declared_length > self._max_body_bytes:
            await self._reject(scope, receive, send)
            return

        try:
            buffered = await _buffer_bounded_http_body(
                receive,
                max_body_bytes=self._max_body_bytes,
                timeout_seconds=self._body_timeout_seconds,
            )
        except TimeoutError:
            await self._reject_timeout(scope, receive, send)
            return
        if buffered is None:
            await self._reject(scope, receive, send)
            return

        if self._requires_strict_json_object_keys(scope):
            body = b"".join(
                message.get("body", b"")
                for message in buffered
                if message["type"] == "http.request"
            )
            try:
                _reject_duplicate_json_object_keys(body)
            except _DuplicateJSONObjectKey:
                await self._reject_duplicate_keys(scope, receive, send)
                return

        async def replay_receive() -> Message:
            if buffered:
                return buffered.popleft()
            return await receive()

        await self._app(scope, replay_receive, send)

    @staticmethod
    def _declared_content_length(scope: Scope) -> int | None:
        for raw_name, raw_value in scope.get("headers", ()):  # pragma: no branch
            if raw_name.lower() != b"content-length":
                continue
            try:
                value = raw_value.decode("ascii")
                if not value.isdecimal():
                    return None
                return int(value)
            except (UnicodeDecodeError, ValueError):
                return None
        return None

    @staticmethod
    def _requires_strict_json_object_keys(scope: Scope) -> bool:
        if str(scope.get("method", "")).upper() not in _JSON_MUTATION_METHODS:
            return False
        for raw_name, raw_value in scope.get("headers", ()):
            if not isinstance(raw_name, bytes) or not isinstance(raw_value, bytes):
                return False
            if raw_name.lower() != b"content-type":
                continue
            try:
                media_type = raw_value.decode("ascii").split(";", 1)[0].strip().lower()
            except UnicodeDecodeError:
                return False
            return media_type == "application/json" or (
                media_type.startswith("application/") and media_type.endswith("+json")
            )
        return False

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            content={"detail": "request body exceeds the Control Plane byte limit"},
            headers={
                "Cache-Control": "no-store, max-age=0",
                "Pragma": "no-cache",
                # The middleware deliberately stops reading once the byte/chunk
                # fence is crossed. Prevent an unread remainder from being
                # interpreted as the next request on a persistent connection.
                "Connection": "close",
            },
        )
        await response(scope, receive, send)

    @staticmethod
    async def _reject_timeout(scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse(
            status_code=status.HTTP_408_REQUEST_TIMEOUT,
            content={"detail": "request body was not completed before the deadline"},
            headers={
                "Cache-Control": "no-store, max-age=0",
                "Pragma": "no-cache",
                "Connection": "close",
            },
        )
        await response(scope, receive, send)

    @staticmethod
    async def _reject_duplicate_keys(scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={"detail": "JSON object member names must be unique"},
            headers={
                "Cache-Control": "no-store, max-age=0",
                "Pragma": "no-cache",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            },
        )
        await response(scope, receive, send)


def _parse_strict_environment_boolean(name: str, *, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.lower()
    if normalized in _TRUE_ENV_VALUES:
        return True
    if normalized in _FALSE_ENV_VALUES:
        return False
    raise ValueError(
        f"{name} must be exactly one of 1, true, yes, 0, false, or no "
        "(case-insensitive; surrounding whitespace is not allowed)"
    )


def _validated_replay_executor_profiles(
    value: object,
    *,
    credentials: Mapping[str, Principal],
) -> dict[str, frozenset[str]]:
    if not isinstance(value, dict):
        raise ValueError("Replay executor profiles must be a subject-to-profile mapping")

    worker_subjects = {
        principal.subject
        for principal in credentials.values()
        if PrincipalRole.WORKER in principal.roles
    }
    principals_by_subject: dict[str, list[Principal]] = {}
    for principal in credentials.values():
        principals_by_subject.setdefault(principal.subject, []).append(principal)
    normalized: dict[str, frozenset[str]] = {}
    for subject, raw_profiles in value.items():
        if not isinstance(subject, str) or subject not in worker_subjects:
            raise ValueError(
                "Replay executor profile subjects must name an authenticated Worker principal"
            )
        matching_principals = principals_by_subject[subject]
        if len(matching_principals) != 1 or matching_principals[0].roles != frozenset(
            {PrincipalRole.WORKER}
        ):
            raise ValueError(
                "Replay executor profile subjects require one dedicated Worker-only credential"
            )
        if not isinstance(raw_profiles, (list, tuple, set, frozenset)) or isinstance(
            raw_profiles, (str, bytes)
        ):
            raise ValueError("Replay executor profile entries must be arrays of profile names")
        profiles = list(raw_profiles)
        if not profiles or len(profiles) > _MAX_REPLAY_EXECUTOR_PROFILES_PER_SUBJECT:
            raise ValueError("Replay executor profile arrays must contain between 1 and 20 entries")
        if any(
            not isinstance(profile, str)
            or _REPLAY_EXECUTOR_PROFILE_PATTERN.fullmatch(profile) is None
            for profile in profiles
        ):
            raise ValueError("Replay executor profile names are invalid")
        if len(profiles) != len(set(profiles)):
            raise ValueError("Replay executor profile arrays must not contain duplicates")
        normalized[subject] = frozenset(profiles)
    return normalized


def _require_separated_control_plane_roles(
    roles: frozenset[PrincipalRole],
    *,
    authority: str,
) -> None:
    if {PrincipalRole.OPERATOR, PrincipalRole.APPROVER} <= roles:
        raise ValueError(
            f"{authority} violates Control Plane separation of duties: "
            "operator and approver authority cannot be combined"
        )
    if PrincipalRole.WORKER in roles and roles != frozenset({PrincipalRole.WORKER}):
        raise ValueError(
            f"{authority} violates Control Plane separation of duties: "
            "Worker authority cannot be combined with non-Worker authority"
        )


def _validate_credential_role_separation(
    credentials: Mapping[str, Principal],
) -> None:
    roles_by_subject: dict[str, set[PrincipalRole]] = {}
    for principal in credentials.values():
        _require_separated_control_plane_roles(
            principal.roles,
            authority="a bearer credential",
        )
        roles_by_subject.setdefault(principal.subject, set()).update(principal.roles)

    for roles in roles_by_subject.values():
        _require_separated_control_plane_roles(
            frozenset(roles),
            authority="credentials sharing one subject",
        )


def _validate_oidc_role_separation(
    credentials: Mapping[str, Principal],
    policy: OIDCHumanTrustPolicy | None,
) -> None:
    if policy is None:
        return
    credential_subjects = {principal.subject for principal in credentials.values()}
    oidc_subjects = {identity.principal_subject for identity in policy.identities}
    if credential_subjects & oidc_subjects:
        raise ValueError("OIDC and opaque bearer authorities must not share a principal subject")
    roles_by_subject: dict[str, set[PrincipalRole]] = {}
    for principal in credentials.values():
        roles_by_subject.setdefault(principal.subject, set()).update(principal.roles)
    for identity in policy.identities:
        roles_by_subject.setdefault(identity.principal_subject, set()).update(identity.roles)
    for roles in roles_by_subject.values():
        _require_separated_control_plane_roles(
            frozenset(roles),
            authority="authentication authorities sharing one subject",
        )


def _validate_run_submission_abac_subjects(
    credentials: Mapping[str, Principal],
    oidc_policy: OIDCHumanTrustPolicy | None,
    abac_policy: ControlPlaneRunSubmissionABACPolicy | None,
) -> None:
    if abac_policy is None:
        return
    operator_subjects = {
        principal.subject
        for principal in credentials.values()
        if PrincipalRole.OPERATOR in principal.roles
    }
    if oidc_policy is not None:
        operator_subjects.update(
            identity.principal_subject
            for identity in oidc_policy.identities
            if PrincipalRole.OPERATOR in identity.roles
        )
    if not abac_policy.principal_subjects <= operator_subjects:
        raise ValueError("ABAC Run submission rules must name authenticated Operator subjects")


def _validate_run_cancellation_abac_subjects(
    credentials: Mapping[str, Principal],
    oidc_policy: OIDCHumanTrustPolicy | None,
    abac_policy: ControlPlaneRunCancellationABACPolicy | None,
) -> None:
    if abac_policy is None:
        return
    operator_subjects = {
        principal.subject
        for principal in credentials.values()
        if PrincipalRole.OPERATOR in principal.roles
    }
    if oidc_policy is not None:
        operator_subjects.update(
            identity.principal_subject
            for identity in oidc_policy.identities
            if PrincipalRole.OPERATOR in identity.roles
        )
    if not abac_policy.principal_subjects <= operator_subjects:
        raise ValueError("ABAC Run cancellation rules must name authenticated Operator subjects")


def _validate_checkpoint_resume_abac_subjects(
    credentials: Mapping[str, Principal],
    oidc_policy: OIDCHumanTrustPolicy | None,
    abac_policy: ControlPlaneCheckpointResumeABACPolicy | None,
) -> None:
    if abac_policy is None:
        return
    operator_subjects = {
        principal.subject
        for principal in credentials.values()
        if PrincipalRole.OPERATOR in principal.roles
    }
    if oidc_policy is not None:
        operator_subjects.update(
            identity.principal_subject
            for identity in oidc_policy.identities
            if PrincipalRole.OPERATOR in identity.roles
        )
    if not abac_policy.principal_subjects <= operator_subjects:
        raise ValueError("ABAC checkpoint resume rules must name authenticated Operator subjects")


def _validate_replay_source_artifact_abac_subjects(
    credentials: Mapping[str, Principal],
    oidc_policy: OIDCHumanTrustPolicy | None,
    abac_policy: ControlPlaneReplaySourceArtifactABACPolicy | None,
) -> None:
    if abac_policy is None:
        return
    operator_subjects = {
        principal.subject
        for principal in credentials.values()
        if PrincipalRole.OPERATOR in principal.roles
    }
    if oidc_policy is not None:
        operator_subjects.update(
            identity.principal_subject
            for identity in oidc_policy.identities
            if PrincipalRole.OPERATOR in identity.roles
        )
    if not abac_policy.principal_subjects <= operator_subjects:
        raise ValueError(
            "ABAC Replay source Artifact rules must name authenticated Operator subjects"
        )


def _validate_replay_batch_admission_abac_subjects(
    credentials: Mapping[str, Principal],
    oidc_policy: OIDCHumanTrustPolicy | None,
    abac_policy: ControlPlaneReplayBatchAdmissionABACPolicy | None,
) -> None:
    if abac_policy is None:
        return
    operator_subjects = {
        principal.subject
        for principal in credentials.values()
        if PrincipalRole.OPERATOR in principal.roles
    }
    if oidc_policy is not None:
        operator_subjects.update(
            identity.principal_subject
            for identity in oidc_policy.identities
            if PrincipalRole.OPERATOR in identity.roles
        )
    if not abac_policy.principal_subjects <= operator_subjects:
        raise ValueError(
            "ABAC Replay batch admission rules must name authenticated Operator subjects"
        )


def _validate_maintenance_abac_subjects(
    credentials: Mapping[str, Principal],
    oidc_policy: OIDCHumanTrustPolicy | None,
    abac_policy: ControlPlaneMaintenanceABACPolicy | None,
) -> None:
    if abac_policy is None:
        return
    operator_subjects = {
        principal.subject
        for principal in credentials.values()
        if PrincipalRole.OPERATOR in principal.roles
    }
    if oidc_policy is not None:
        operator_subjects.update(
            identity.principal_subject
            for identity in oidc_policy.identities
            if PrincipalRole.OPERATOR in identity.roles
        )
    if not abac_policy.principal_subjects <= operator_subjects:
        raise ValueError("ABAC maintenance rules must name authenticated Operator subjects")


def _parse_replay_executor_profiles(
    raw: str | None,
    *,
    credentials: Mapping[str, Principal],
) -> dict[str, frozenset[str]]:
    if raw is None:
        return {}
    if not raw.strip():
        raise RuntimeError(f"{_REPLAY_EXECUTOR_PROFILES_ENV} must not be empty")

    try:
        decoded = parse_strict_json_bytes(
            raw.encode("utf-8"),
            label=_REPLAY_EXECUTOR_PROFILES_ENV,
            max_bytes=_MAX_REPLAY_EXECUTOR_PROFILES_JSON_BYTES,
            max_depth=_MAX_REPLAY_EXECUTOR_PROFILES_JSON_DEPTH,
            max_nodes=_MAX_REPLAY_EXECUTOR_PROFILES_JSON_NODES,
        )
        return _validated_replay_executor_profiles(decoded, credentials=credentials)
    except (UnicodeEncodeError, ValueError) as exc:
        raise RuntimeError(
            f"{_REPLAY_EXECUTOR_PROFILES_ENV} must be a strict JSON "
            "subject-to-profile-array allowlist"
        ) from exc


def _parse_additional_worker_credentials(raw: str | None) -> dict[str, str]:
    """Resolve Worker subject-to-token-environment bindings without embedding tokens in JSON."""

    if raw is None:
        return {}
    if not raw.strip():
        raise RuntimeError(f"{_ADDITIONAL_WORKER_CREDENTIALS_ENV} must not be empty")
    try:
        decoded = parse_strict_json_bytes(
            raw.encode("utf-8"),
            label=_ADDITIONAL_WORKER_CREDENTIALS_ENV,
            max_bytes=64 * 1024,
            max_depth=4,
            max_nodes=1_024,
        )
        if not isinstance(decoded, dict) or not 1 <= len(decoded) <= 254:
            raise ValueError("additional Worker credential map must contain 1-254 entries")
        result: dict[str, str] = {}
        for subject, token_environment in decoded.items():
            Principal(subject=subject, roles=frozenset({PrincipalRole.WORKER}))
            if (
                not isinstance(token_environment, str)
                or _WORKER_TOKEN_ENV_PATTERN.fullmatch(token_environment) is None
            ):
                raise ValueError("additional Worker token environment name is invalid")
            token = os.environ.get(token_environment)
            if token is None or not token.strip():
                raise ValueError("additional Worker token environment is unavailable")
            result[subject] = token
        if len(result.values()) != len(set(result.values())):
            raise ValueError("additional Worker bearer credentials must be distinct")
        return result
    except (UnicodeEncodeError, ValueError) as exc:
        raise RuntimeError(
            f"{_ADDITIONAL_WORKER_CREDENTIALS_ENV} must be a strict JSON "
            "Worker-subject-to-token-environment map"
        ) from exc


def _parse_executor_attestation_anchor(
    raw: str | None,
    *,
    replay_worker_token: str | None,
) -> ExecutorAttestationTrustAnchor | None:
    if raw is None:
        return None
    if replay_worker_token is None:
        raise RuntimeError(
            f"{_EXECUTOR_ATTESTATION_TRUST_ANCHOR_ENV} requires PAJIN_CP_REPLAY_WORKER_TOKEN"
        )
    try:
        return parse_executor_attestation_trust_anchor(raw.encode("utf-8"))
    except (UnicodeEncodeError, ValueError) as exc:
        raise RuntimeError("executor attestation trust anchor is invalid") from exc


def _parse_target_attestation_anchor(
    raw: str | None,
) -> TargetAttestationTrustAnchor | None:
    if raw is None:
        return None
    try:
        return parse_target_attestation_trust_anchor(raw.encode("utf-8"))
    except (UnicodeEncodeError, ValueError) as exc:
        raise RuntimeError("target attestation trust anchor is invalid") from exc


def _parse_target_attestation_registry(
    raw: str | None,
) -> TargetAttestationTrustRegistry | None:
    if raw is None:
        return None
    try:
        return parse_target_attestation_trust_registry(raw.encode("utf-8"))
    except (UnicodeEncodeError, ValueError) as exc:
        raise RuntimeError("target attestation trust registry is invalid") from exc


class _RejectRegistryBundleRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: URLRequest,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


def _load_target_attestation_registry_bundle(
    *,
    inline: str | None,
    url: str | None,
) -> TargetAttestationRegistryBundle | None:
    if inline is not None and url is not None:
        raise RuntimeError(
            f"{_TARGET_ATTESTATION_TRUST_REGISTRY_BUNDLE_ENV} and "
            f"{_TARGET_ATTESTATION_TRUST_REGISTRY_BUNDLE_URL_ENV} are mutually exclusive"
        )
    content: bytes
    if inline is not None:
        try:
            content = inline.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise RuntimeError("target attestation registry bundle is invalid") from exc
    elif url is not None:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise RuntimeError(
                f"{_TARGET_ATTESTATION_TRUST_REGISTRY_BUNDLE_URL_ENV} "
                "must be an absolute HTTPS URL without credentials or a fragment"
            )
        request = URLRequest(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "PAJIN-Control-Plane/target-registry-v1",
            },
            method="GET",
        )
        try:
            with build_opener(_RejectRegistryBundleRedirects()).open(
                request,
                timeout=10,
            ) as response:
                if response.geturl() != url or response.getcode() != 200:
                    raise RuntimeError("target attestation registry fetch was redirected or failed")
                content = response.read(_MAX_TARGET_ATTESTATION_REGISTRY_BUNDLE_BYTES + 1)
        except (HTTPError, URLError, OSError) as exc:
            raise RuntimeError("target attestation registry HTTPS fetch failed") from exc
        if len(content) > _MAX_TARGET_ATTESTATION_REGISTRY_BUNDLE_BYTES:
            raise RuntimeError("target attestation registry bundle exceeds 512 KiB")
    else:
        return None
    try:
        return parse_target_attestation_registry_bundle(content)
    except ValueError as exc:
        raise RuntimeError("target attestation registry bundle is invalid") from exc


def _parse_target_attestation_registry_trust_anchor(
    raw: str | None,
) -> TargetAttestationRegistryTrustAnchor | None:
    if raw is None:
        return None
    try:
        return parse_target_attestation_registry_trust_anchor(raw.encode("utf-8"))
    except (UnicodeEncodeError, ValueError) as exc:
        raise RuntimeError("target attestation registry trust anchor is invalid") from exc


def _validate_pentest_recon_deployment_settings(
    path: Path | None,
    digest: str | None,
    worker_policy: WorkerMTLSTrustPolicy | None,
) -> None:
    if (path is None) != (digest is None):
        raise ValueError("Pentest Recon deployment path and SHA-256 must be configured together")
    if path is not None and worker_policy is None:
        raise ValueError("Pentest Recon deployment requires Worker mTLS policy")
    if digest is not None and re.fullmatch(r"^[a-f0-9]{64}$", digest) is None:
        raise ValueError("Pentest Recon deployment SHA-256 is malformed")


def _validate_pentest_workflow_deployment_settings(
    path: Path | None,
    digest: str | None,
) -> None:
    if (path is None) != (digest is None):
        raise ValueError("Pentest workflow deployment path and SHA-256 must be configured together")
    if digest is not None and re.fullmatch(r"^[a-f0-9]{64}$", digest) is None:
        raise ValueError("Pentest workflow deployment SHA-256 is malformed")


def _validate_pentest_replay_deployment_settings(
    path: Path | None,
    digest: str | None,
    worker_policy: WorkerMTLSTrustPolicy | None,
    replay_executor_profiles: Mapping[str, frozenset[str]],
) -> None:
    if (path is None) != (digest is None):
        raise ValueError("Pentest Replay deployment path and SHA-256 must be configured together")
    if path is not None and worker_policy is None:
        raise ValueError("Pentest Replay deployment requires Worker mTLS policy")
    if path is not None and not replay_executor_profiles:
        raise ValueError("Pentest Replay deployment requires a dedicated Replay Worker")
    if digest is not None and re.fullmatch(r"^[a-f0-9]{64}$", digest) is None:
        raise ValueError("Pentest Replay deployment SHA-256 is malformed")


def _validate_pentest_workflow_coordination_deployment_settings(
    path: Path | None,
    digest: str | None,
    worker_policy: WorkerMTLSTrustPolicy | None,
    replay_executor_profiles: Mapping[str, frozenset[str]],
) -> None:
    if (path is None) != (digest is None):
        raise ValueError(
            "Pentest workflow coordination deployment path and SHA-256 "
            "must be configured together"
        )
    if path is not None and worker_policy is None:
        raise ValueError("Pentest workflow coordination deployment requires Worker mTLS policy")
    if path is not None and not replay_executor_profiles:
        raise ValueError(
            "Pentest workflow coordination deployment requires a dedicated Replay Worker"
        )
    if digest is not None and re.fullmatch(r"^[a-f0-9]{64}$", digest) is None:
        raise ValueError("Pentest workflow coordination deployment SHA-256 is malformed")


@dataclass(frozen=True)
class ControlPlaneSettings:
    database_url: str
    credentials: Mapping[str, Principal]
    checkpoint_keys: dict[str, bytes]
    active_checkpoint_key_id: str = "v1"
    oidc_human_trust_policy: OIDCHumanTrustPolicy | None = None
    worker_mtls_trust_policy: WorkerMTLSTrustPolicy | None = None
    pentest_recon_deployment_path: Path | None = None
    pentest_recon_deployment_sha256: str | None = None
    pentest_replay_deployment_path: Path | None = None
    pentest_replay_deployment_sha256: str | None = None
    pentest_workflow_deployment_path: Path | None = None
    pentest_workflow_deployment_sha256: str | None = None
    pentest_workflow_coordination_deployment_path: Path | None = None
    pentest_workflow_coordination_deployment_sha256: str | None = None
    abac_policy: ControlPlaneABACPolicy | None = None
    run_submission_abac_policy: ControlPlaneRunSubmissionABACPolicy | None = None
    run_cancellation_abac_policy: ControlPlaneRunCancellationABACPolicy | None = None
    checkpoint_resume_abac_policy: ControlPlaneCheckpointResumeABACPolicy | None = None
    replay_source_artifact_abac_policy: ControlPlaneReplaySourceArtifactABACPolicy | None = None
    replay_batch_admission_abac_policy: ControlPlaneReplayBatchAdmissionABACPolicy | None = None
    maintenance_abac_policy: ControlPlaneMaintenanceABACPolicy | None = None
    initialize_schema: bool = True
    database_echo: bool = False
    artifact_staging_root: Path | None = None
    artifact_repository_root: Path | None = None
    campaign_draft_root: Path | None = None
    discovery_run_root: Path | None = None
    graph_database: Path | None = None
    graph_decision_audit_database: Path | None = None
    validation_evidence_root: Path | None = None
    replay_executor_profiles: dict[str, frozenset[str]] = field(default_factory=dict)
    replay_attestation_key_id: str | None = None
    replay_attestation_private_key: bytes | None = field(default=None, repr=False)
    replay_attestation_trust_anchor: ReplayAttestationTrustAnchor | None = None
    executor_attestation_trust_anchor: ExecutorAttestationTrustAnchor | None = None
    target_attestation_trust_anchor: TargetAttestationTrustAnchor | None = None
    target_attestation_trust_registry: TargetAttestationTrustRegistry | None = None
    target_attestation_registry_bundle: TargetAttestationRegistryBundle | None = None
    target_attestation_registry_trust_anchor: TargetAttestationRegistryTrustAnchor | None = None
    request_body_timeout_seconds: float = _DEFAULT_CONTROL_PLANE_REQUEST_BODY_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if type(self.initialize_schema) is not bool or type(self.database_echo) is not bool:
            raise ValueError(
                "Control Plane schema initialization and database echo flags must be booleans"
            )
        if (
            type(self.request_body_timeout_seconds) not in {int, float}
            or not math.isfinite(self.request_body_timeout_seconds)
            or not 0.1 <= self.request_body_timeout_seconds <= 300.0
        ):
            raise ValueError(
                "Control Plane request body timeout must be a finite value "
                "between 0.1 and 300 seconds"
            )
        if (self.target_attestation_registry_bundle is None) != (
            self.target_attestation_registry_trust_anchor is None
        ):
            raise ValueError(
                "signed target registry bundle and distribution trust anchor "
                "must be configured together"
            )
        target_authorities = (
            self.target_attestation_trust_anchor,
            self.target_attestation_trust_registry,
            self.target_attestation_registry_bundle,
        )
        if len([value for value in target_authorities if value is not None]) > 1:
            raise ValueError(
                "configure only one target trust anchor, inline registry, or signed registry"
            )
        if (
            self.target_attestation_trust_registry is not None
            and self.target_attestation_trust_registry.api_version
            in {
                "pajin.replay.target-attestation-trust-registry/v3",
                "pajin.replay.target-attestation-trust-registry/v4",
            }
        ):
            raise ValueError("target trust registry v3-v4 requires a signed distribution bundle")
        if self.target_attestation_registry_bundle is not None:
            assert self.target_attestation_registry_trust_anchor is not None
            verify_target_attestation_registry_bundle(
                self.target_attestation_registry_bundle,
                trust_anchor=self.target_attestation_registry_trust_anchor,
                now=datetime.now(UTC),
            )
        credentials = dict(self.credentials)
        for token in credentials:
            validate_bearer_token(
                token,
                label="Control Plane bearer credential",
            )
        _validate_credential_role_separation(credentials)
        _validate_oidc_role_separation(credentials, self.oidc_human_trust_policy)
        if self.abac_policy is not None:
            approver_subjects = {
                principal.subject
                for principal in credentials.values()
                if PrincipalRole.APPROVER in principal.roles
            }
            if self.oidc_human_trust_policy is not None:
                approver_subjects.update(
                    identity.principal_subject
                    for identity in self.oidc_human_trust_policy.identities
                    if PrincipalRole.APPROVER in identity.roles
                )
            if not self.abac_policy.principal_subjects <= approver_subjects:
                raise ValueError("ABAC approval rules must name authenticated Approver subjects")
        _validate_run_submission_abac_subjects(
            credentials,
            self.oidc_human_trust_policy,
            self.run_submission_abac_policy,
        )
        _validate_run_cancellation_abac_subjects(
            credentials,
            self.oidc_human_trust_policy,
            self.run_cancellation_abac_policy,
        )
        _validate_checkpoint_resume_abac_subjects(
            credentials,
            self.oidc_human_trust_policy,
            self.checkpoint_resume_abac_policy,
        )
        _validate_replay_source_artifact_abac_subjects(
            credentials,
            self.oidc_human_trust_policy,
            self.replay_source_artifact_abac_policy,
        )
        _validate_replay_batch_admission_abac_subjects(
            credentials,
            self.oidc_human_trust_policy,
            self.replay_batch_admission_abac_policy,
        )
        _validate_maintenance_abac_subjects(
            credentials,
            self.oidc_human_trust_policy,
            self.maintenance_abac_policy,
        )
        if self.worker_mtls_trust_policy is not None:
            worker_subjects = {
                principal.subject
                for principal in credentials.values()
                if principal.roles == frozenset({PrincipalRole.WORKER})
            }
            bound_subjects = {
                binding.principal_subject for binding in self.worker_mtls_trust_policy.bindings
            }
            if bound_subjects != worker_subjects:
                raise ValueError(
                    "Worker mTLS trust policy must bind every and only configured Worker subject"
                )
        _validate_pentest_recon_deployment_settings(
            self.pentest_recon_deployment_path,
            self.pentest_recon_deployment_sha256,
            self.worker_mtls_trust_policy,
        )
        _validate_pentest_workflow_deployment_settings(
            self.pentest_workflow_deployment_path,
            self.pentest_workflow_deployment_sha256,
        )
        normalized = _validated_replay_executor_profiles(
            self.replay_executor_profiles,
            credentials=credentials,
        )
        _validate_pentest_replay_deployment_settings(
            self.pentest_replay_deployment_path,
            self.pentest_replay_deployment_sha256,
            self.worker_mtls_trust_policy,
            normalized,
        )
        _validate_pentest_workflow_coordination_deployment_settings(
            self.pentest_workflow_coordination_deployment_path,
            self.pentest_workflow_coordination_deployment_sha256,
            self.worker_mtls_trust_policy,
            normalized,
        )
        attestation_values = (
            self.replay_attestation_key_id,
            self.replay_attestation_private_key,
            self.replay_attestation_trust_anchor,
        )
        if any(value is not None for value in attestation_values):
            if not all(value is not None for value in attestation_values):
                raise ValueError(
                    "Replay attestation key ID, private key, and trust anchor "
                    "must be configured together"
                )
            assert self.replay_attestation_key_id is not None
            assert self.replay_attestation_private_key is not None
            assert self.replay_attestation_trust_anchor is not None
            ReplayAttestor.from_private_key_bytes(
                active_key_id=self.replay_attestation_key_id,
                private_key=self.replay_attestation_private_key,
                trust_anchor=self.replay_attestation_trust_anchor,
            )
        object.__setattr__(self, "credentials", MappingProxyType(credentials))
        object.__setattr__(self, "replay_executor_profiles", normalized)

    @classmethod
    def from_env(cls) -> "ControlPlaneSettings":  # noqa: C901
        operator_token = os.environ.get("PAJIN_CP_OPERATOR_TOKEN")
        approver_token = os.environ.get("PAJIN_CP_APPROVER_TOKEN")
        worker_token = os.environ.get("PAJIN_CP_WORKER_TOKEN")
        replay_worker_token = os.environ.get("PAJIN_CP_REPLAY_WORKER_TOKEN")
        replay_worker_subject_setting = os.environ.get("PAJIN_CP_REPLAY_WORKER_SUBJECT")
        raw_oidc_human_trust_policy = os.environ.get(_OIDC_HUMAN_TRUST_POLICY_ENV)
        raw_replay_profiles = os.environ.get(_REPLAY_EXECUTOR_PROFILES_ENV)
        raw_worker_mtls_trust_policy = os.environ.get(_WORKER_MTLS_TRUST_POLICY_ENV)
        raw_additional_worker_credentials = os.environ.get(
            _ADDITIONAL_WORKER_CREDENTIALS_ENV
        )
        pentest_recon_deployment_path = os.environ.get(_PENTEST_RECON_DEPLOYMENT_PATH_ENV)
        pentest_recon_deployment_sha256 = os.environ.get(_PENTEST_RECON_DEPLOYMENT_SHA256_ENV)
        pentest_replay_deployment_path = os.environ.get(_PENTEST_REPLAY_DEPLOYMENT_PATH_ENV)
        pentest_replay_deployment_sha256 = os.environ.get(_PENTEST_REPLAY_DEPLOYMENT_SHA256_ENV)
        pentest_workflow_deployment_path = os.environ.get(_PENTEST_WORKFLOW_DEPLOYMENT_PATH_ENV)
        pentest_workflow_deployment_sha256 = os.environ.get(_PENTEST_WORKFLOW_DEPLOYMENT_SHA256_ENV)
        pentest_workflow_coordination_deployment_path = os.environ.get(
            _PENTEST_WORKFLOW_COORDINATION_DEPLOYMENT_PATH_ENV
        )
        pentest_workflow_coordination_deployment_sha256 = os.environ.get(
            _PENTEST_WORKFLOW_COORDINATION_DEPLOYMENT_SHA256_ENV
        )
        raw_abac_policy = os.environ.get(_ABAC_POLICY_ENV)
        raw_run_submission_abac_policy = os.environ.get(_RUN_SUBMISSION_ABAC_POLICY_ENV)
        raw_run_cancellation_abac_policy = os.environ.get(_RUN_CANCELLATION_ABAC_POLICY_ENV)
        raw_checkpoint_resume_abac_policy = os.environ.get(_CHECKPOINT_RESUME_ABAC_POLICY_ENV)
        raw_replay_source_artifact_abac_policy = os.environ.get(
            _REPLAY_SOURCE_ARTIFACT_ABAC_POLICY_ENV
        )
        raw_replay_batch_admission_abac_policy = os.environ.get(
            _REPLAY_BATCH_ADMISSION_ABAC_POLICY_ENV
        )
        raw_maintenance_abac_policy = os.environ.get(_MAINTENANCE_ABAC_POLICY_ENV)
        replay_attestation_key_id = os.environ.get(_REPLAY_ATTESTATION_KEY_ID_ENV)
        replay_attestation_private_key = os.environ.get(_REPLAY_ATTESTATION_PRIVATE_KEY_ENV)
        replay_attestation_trust_anchor = os.environ.get(_REPLAY_ATTESTATION_TRUST_ANCHOR_ENV)
        executor_attestation_trust_anchor = os.environ.get(_EXECUTOR_ATTESTATION_TRUST_ANCHOR_ENV)
        target_attestation_trust_anchor = os.environ.get(_TARGET_ATTESTATION_TRUST_ANCHOR_ENV)
        target_attestation_trust_registry = os.environ.get(_TARGET_ATTESTATION_TRUST_REGISTRY_ENV)
        target_attestation_registry_trust_anchor = os.environ.get(
            _TARGET_ATTESTATION_REGISTRY_TRUST_ANCHOR_ENV
        )
        target_attestation_trust_registry_bundle = os.environ.get(
            _TARGET_ATTESTATION_TRUST_REGISTRY_BUNDLE_ENV
        )
        target_attestation_trust_registry_bundle_url = os.environ.get(
            _TARGET_ATTESTATION_TRUST_REGISTRY_BUNDLE_URL_ENV
        )
        checkpoint_key = os.environ.get("PAJIN_CP_CHECKPOINT_KEY")
        artifact_staging_root = os.environ.get("PAJIN_CP_ARTIFACT_STAGING_ROOT")
        artifact_repository_root = os.environ.get("PAJIN_CP_ARTIFACT_REPOSITORY_ROOT")
        campaign_draft_root = os.environ.get("PAJIN_CP_CAMPAIGN_DRAFT_ROOT")
        discovery_run_root = os.environ.get("PAJIN_CP_DISCOVERY_RUN_ROOT")
        graph_database = os.environ.get("PAJIN_CP_GRAPH_DATABASE")
        graph_decision_audit_database = os.environ.get("PAJIN_CP_GRAPH_DECISION_AUDIT_DATABASE")
        validation_evidence_root = os.environ.get("PAJIN_CP_VALIDATION_EVIDENCE_ROOT")
        oidc_human_trust_policy: OIDCHumanTrustPolicy | None = None
        if raw_oidc_human_trust_policy is not None:
            if not raw_oidc_human_trust_policy.strip():
                raise RuntimeError(f"{_OIDC_HUMAN_TRUST_POLICY_ENV} must not be blank")
            try:
                oidc_human_trust_policy = parse_oidc_human_trust_policy(
                    raw_oidc_human_trust_policy.encode("utf-8")
                )
            except (UnicodeEncodeError, ValueError) as exc:
                raise RuntimeError(
                    f"{_OIDC_HUMAN_TRUST_POLICY_ENV} is not a valid trust policy"
                ) from exc
        worker_mtls_trust_policy: WorkerMTLSTrustPolicy | None = None
        if raw_worker_mtls_trust_policy is not None:
            if not raw_worker_mtls_trust_policy.strip():
                raise RuntimeError(f"{_WORKER_MTLS_TRUST_POLICY_ENV} must not be blank")
            try:
                worker_mtls_trust_policy = parse_worker_mtls_trust_policy(
                    raw_worker_mtls_trust_policy.encode("utf-8")
                )
            except (UnicodeEncodeError, ValueError) as exc:
                raise RuntimeError(
                    f"{_WORKER_MTLS_TRUST_POLICY_ENV} is not a valid trust policy"
                ) from exc
        abac_policy: ControlPlaneABACPolicy | None = None
        if raw_abac_policy is not None:
            if not raw_abac_policy.strip():
                raise RuntimeError(f"{_ABAC_POLICY_ENV} must not be blank")
            try:
                abac_policy = parse_control_plane_abac_policy(raw_abac_policy.encode("utf-8"))
            except (UnicodeEncodeError, ValueError) as exc:
                raise RuntimeError(
                    f"{_ABAC_POLICY_ENV} is not a valid authorization policy"
                ) from exc
        run_submission_abac_policy: ControlPlaneRunSubmissionABACPolicy | None = None
        if raw_run_submission_abac_policy is not None:
            if not raw_run_submission_abac_policy.strip():
                raise RuntimeError(f"{_RUN_SUBMISSION_ABAC_POLICY_ENV} must not be blank")
            try:
                run_submission_abac_policy = parse_run_submission_abac_policy(
                    raw_run_submission_abac_policy.encode("utf-8")
                )
            except (UnicodeEncodeError, ValueError) as exc:
                raise RuntimeError(
                    f"{_RUN_SUBMISSION_ABAC_POLICY_ENV} is not a valid authorization policy"
                ) from exc
        run_cancellation_abac_policy: ControlPlaneRunCancellationABACPolicy | None = None
        if raw_run_cancellation_abac_policy is not None:
            if not raw_run_cancellation_abac_policy.strip():
                raise RuntimeError(f"{_RUN_CANCELLATION_ABAC_POLICY_ENV} must not be blank")
            try:
                run_cancellation_abac_policy = parse_run_cancellation_abac_policy(
                    raw_run_cancellation_abac_policy.encode("utf-8")
                )
            except (UnicodeEncodeError, ValueError) as exc:
                raise RuntimeError(
                    f"{_RUN_CANCELLATION_ABAC_POLICY_ENV} is not a valid authorization policy"
                ) from exc
        checkpoint_resume_abac_policy: ControlPlaneCheckpointResumeABACPolicy | None = None
        if raw_checkpoint_resume_abac_policy is not None:
            if not raw_checkpoint_resume_abac_policy.strip():
                raise RuntimeError(f"{_CHECKPOINT_RESUME_ABAC_POLICY_ENV} must not be blank")
            try:
                checkpoint_resume_abac_policy = parse_checkpoint_resume_abac_policy(
                    raw_checkpoint_resume_abac_policy.encode("utf-8")
                )
            except (UnicodeEncodeError, ValueError) as exc:
                raise RuntimeError(
                    f"{_CHECKPOINT_RESUME_ABAC_POLICY_ENV} is not a valid authorization policy"
                ) from exc
        replay_source_artifact_abac_policy: ControlPlaneReplaySourceArtifactABACPolicy | None = None
        if raw_replay_source_artifact_abac_policy is not None:
            if not raw_replay_source_artifact_abac_policy.strip():
                raise RuntimeError(f"{_REPLAY_SOURCE_ARTIFACT_ABAC_POLICY_ENV} must not be blank")
            try:
                replay_source_artifact_abac_policy = parse_replay_source_artifact_abac_policy(
                    raw_replay_source_artifact_abac_policy.encode("utf-8")
                )
            except (UnicodeEncodeError, ValueError) as exc:
                raise RuntimeError(
                    f"{_REPLAY_SOURCE_ARTIFACT_ABAC_POLICY_ENV} is not a valid authorization policy"
                ) from exc
        replay_batch_admission_abac_policy: ControlPlaneReplayBatchAdmissionABACPolicy | None = None
        if raw_replay_batch_admission_abac_policy is not None:
            if not raw_replay_batch_admission_abac_policy.strip():
                raise RuntimeError(f"{_REPLAY_BATCH_ADMISSION_ABAC_POLICY_ENV} must not be blank")
            try:
                replay_batch_admission_abac_policy = parse_replay_batch_admission_abac_policy(
                    raw_replay_batch_admission_abac_policy.encode("utf-8")
                )
            except (UnicodeEncodeError, ValueError) as exc:
                raise RuntimeError(
                    f"{_REPLAY_BATCH_ADMISSION_ABAC_POLICY_ENV} is not a valid authorization policy"
                ) from exc
        maintenance_abac_policy: ControlPlaneMaintenanceABACPolicy | None = None
        if raw_maintenance_abac_policy is not None:
            if not raw_maintenance_abac_policy.strip():
                raise RuntimeError(f"{_MAINTENANCE_ABAC_POLICY_ENV} must not be blank")
            try:
                maintenance_abac_policy = parse_maintenance_abac_policy(
                    raw_maintenance_abac_policy.encode("utf-8")
                )
            except (UnicodeEncodeError, ValueError) as exc:
                raise RuntimeError(
                    f"{_MAINTENANCE_ABAC_POLICY_ENV} is not a valid authorization policy"
                ) from exc
        credential_requirements = (
            ("PAJIN_CP_OPERATOR_TOKEN", operator_token, oidc_human_trust_policy is None),
            ("PAJIN_CP_APPROVER_TOKEN", approver_token, oidc_human_trust_policy is None),
            ("PAJIN_CP_WORKER_TOKEN", worker_token, True),
            ("PAJIN_CP_CHECKPOINT_KEY", checkpoint_key, True),
        )
        missing = [
            name for name, value, required in credential_requirements if required and value is None
        ]
        if missing:
            raise RuntimeError(f"missing required Control Plane secrets: {', '.join(missing)}")
        assert worker_token is not None
        assert checkpoint_key is not None
        role_tokens = [
            token for token in (operator_token, approver_token, worker_token) if token is not None
        ]
        if len(role_tokens) != len(set(role_tokens)):
            raise RuntimeError("Control Plane role credentials must be distinct")
        if (replay_worker_token is None) != (raw_replay_profiles is None):
            raise RuntimeError(
                "PAJIN_CP_REPLAY_WORKER_TOKEN and PAJIN_CP_REPLAY_EXECUTOR_PROFILES "
                "must be configured together"
            )
        if replay_worker_subject_setting is not None and replay_worker_token is None:
            raise RuntimeError(
                "PAJIN_CP_REPLAY_WORKER_SUBJECT requires PAJIN_CP_REPLAY_WORKER_TOKEN"
            )
        replay_attestation_values = (
            replay_attestation_key_id,
            replay_attestation_private_key,
            replay_attestation_trust_anchor,
        )
        if any(value is not None for value in replay_attestation_values) and not all(
            value is not None for value in replay_attestation_values
        ):
            raise RuntimeError(
                "PAJIN_CP_REPLAY_ATTESTATION_KEY_ID, "
                "PAJIN_CP_REPLAY_ATTESTATION_PRIVATE_KEY, and "
                "PAJIN_CP_REPLAY_ATTESTATION_TRUST_ANCHOR must be configured together"
            )
        parsed_attestation_private_key: bytes | None = None
        parsed_attestation_trust_anchor: ReplayAttestationTrustAnchor | None = None
        if replay_attestation_private_key is not None:
            assert replay_attestation_trust_anchor is not None
            try:
                parsed_attestation_private_key = private_key_bytes_from_base64url(
                    replay_attestation_private_key
                )
                parsed_attestation_trust_anchor = parse_replay_attestation_trust_anchor(
                    replay_attestation_trust_anchor.encode("utf-8")
                )
            except (UnicodeEncodeError, ValueError) as exc:
                raise RuntimeError(
                    "Replay attestation configuration is not a valid Ed25519 key and trust anchor"
                ) from exc
        parsed_executor_attestation_trust_anchor = _parse_executor_attestation_anchor(
            executor_attestation_trust_anchor,
            replay_worker_token=replay_worker_token,
        )
        parsed_target_attestation_trust_anchor = _parse_target_attestation_anchor(
            target_attestation_trust_anchor
        )
        parsed_target_attestation_trust_registry = _parse_target_attestation_registry(
            target_attestation_trust_registry
        )
        parsed_target_attestation_registry_trust_anchor = (
            _parse_target_attestation_registry_trust_anchor(
                target_attestation_registry_trust_anchor
            )
        )
        parsed_target_attestation_registry_bundle = _load_target_attestation_registry_bundle(
            inline=target_attestation_trust_registry_bundle,
            url=target_attestation_trust_registry_bundle_url,
        )
        configured_target_authorities = (
            parsed_target_attestation_trust_anchor,
            parsed_target_attestation_trust_registry,
            parsed_target_attestation_registry_bundle,
        )
        if len([value for value in configured_target_authorities if value is not None]) > 1:
            raise RuntimeError(
                "PAJIN_CP_TARGET_ATTESTATION_TRUST_ANCHOR and "
                "target registry settings are mutually exclusive"
            )
        if (parsed_target_attestation_registry_bundle is None) != (
            parsed_target_attestation_registry_trust_anchor is None
        ):
            raise RuntimeError(
                "signed target registry bundle requires "
                "PAJIN_CP_TARGET_ATTESTATION_REGISTRY_TRUST_ANCHOR"
            )
        if parsed_target_attestation_trust_registry is not None and (
            parsed_target_attestation_trust_registry.api_version
            in {
                "pajin.replay.target-attestation-trust-registry/v3",
                "pajin.replay.target-attestation-trust-registry/v4",
            }
        ):
            raise RuntimeError("target trust registry v3-v4 requires a signed distribution bundle")
        if parsed_target_attestation_registry_bundle is not None:
            assert parsed_target_attestation_registry_trust_anchor is not None
            try:
                verify_target_attestation_registry_bundle(
                    parsed_target_attestation_registry_bundle,
                    trust_anchor=parsed_target_attestation_registry_trust_anchor,
                    now=datetime.now(UTC),
                )
            except ValueError as exc:
                raise RuntimeError(
                    "target attestation registry bundle is not currently trusted"
                ) from exc
        if replay_worker_token is not None and replay_worker_token in {
            operator_token,
            approver_token,
            worker_token,
        }:
            raise RuntimeError("Replay Worker credential must be distinct from every other role")
        if (artifact_staging_root is None) != (artifact_repository_root is None):
            raise RuntimeError(
                "PAJIN_CP_ARTIFACT_STAGING_ROOT and "
                "PAJIN_CP_ARTIFACT_REPOSITORY_ROOT must be configured together"
            )
        if campaign_draft_root is not None and not campaign_draft_root.strip():
            raise RuntimeError("PAJIN_CP_CAMPAIGN_DRAFT_ROOT must not be blank")
        if discovery_run_root is not None and not discovery_run_root.strip():
            raise RuntimeError("PAJIN_CP_DISCOVERY_RUN_ROOT must not be blank")
        if graph_database is not None and not graph_database.strip():
            raise RuntimeError("PAJIN_CP_GRAPH_DATABASE must not be blank")
        if graph_decision_audit_database is not None and not graph_decision_audit_database.strip():
            raise RuntimeError("PAJIN_CP_GRAPH_DECISION_AUDIT_DATABASE must not be blank")
        if validation_evidence_root is not None and not validation_evidence_root.strip():
            raise RuntimeError("PAJIN_CP_VALIDATION_EVIDENCE_ROOT must not be blank")
        if (pentest_recon_deployment_path in {None, ""}) != (
            pentest_recon_deployment_sha256 in {None, ""}
        ):
            raise RuntimeError(
                "Pentest Recon deployment path and SHA-256 must be configured together"
            )
        if pentest_recon_deployment_path is not None and (
            not pentest_recon_deployment_path
            or pentest_recon_deployment_path != pentest_recon_deployment_path.strip()
            or pentest_recon_deployment_sha256 is None
            or not pentest_recon_deployment_sha256
            or pentest_recon_deployment_sha256 != pentest_recon_deployment_sha256.strip()
        ):
            raise RuntimeError("Pentest Recon deployment settings must not be blank")
        if (pentest_replay_deployment_path in {None, ""}) != (
            pentest_replay_deployment_sha256 in {None, ""}
        ):
            raise RuntimeError(
                "Pentest Replay deployment path and SHA-256 must be configured together"
            )
        if pentest_replay_deployment_path is not None and (
            not pentest_replay_deployment_path
            or pentest_replay_deployment_path != pentest_replay_deployment_path.strip()
            or pentest_replay_deployment_sha256 is None
            or not pentest_replay_deployment_sha256
            or pentest_replay_deployment_sha256 != pentest_replay_deployment_sha256.strip()
        ):
            raise RuntimeError("Pentest Replay deployment settings must not be blank")
        if (pentest_workflow_deployment_path in {None, ""}) != (
            pentest_workflow_deployment_sha256 in {None, ""}
        ):
            raise RuntimeError(
                "Pentest workflow deployment path and SHA-256 must be configured together"
            )
        if pentest_workflow_deployment_path is not None and (
            not pentest_workflow_deployment_path
            or pentest_workflow_deployment_path != pentest_workflow_deployment_path.strip()
            or pentest_workflow_deployment_sha256 is None
            or not pentest_workflow_deployment_sha256
            or pentest_workflow_deployment_sha256 != pentest_workflow_deployment_sha256.strip()
        ):
            raise RuntimeError("Pentest workflow deployment settings must not be blank")
        if (pentest_workflow_coordination_deployment_path in {None, ""}) != (
            pentest_workflow_coordination_deployment_sha256 in {None, ""}
        ):
            raise RuntimeError(
                "Pentest workflow coordination deployment path and SHA-256 "
                "must be configured together"
            )
        if pentest_workflow_coordination_deployment_path is not None and (
            not pentest_workflow_coordination_deployment_path
            or pentest_workflow_coordination_deployment_path
            != pentest_workflow_coordination_deployment_path.strip()
            or pentest_workflow_coordination_deployment_sha256 is None
            or not pentest_workflow_coordination_deployment_sha256
            or pentest_workflow_coordination_deployment_sha256
            != pentest_workflow_coordination_deployment_sha256.strip()
        ):
            raise RuntimeError(
                "Pentest workflow coordination deployment settings must not be blank"
            )
        key_id = os.environ.get("PAJIN_CP_CHECKPOINT_KEY_ID", "v1")
        operator_subject = os.environ.get("PAJIN_CP_OPERATOR_SUBJECT", "operator")
        approver_subject = os.environ.get(
            "PAJIN_CP_APPROVER_SUBJECT",
            "security-approver",
        )
        worker_subject = os.environ.get("PAJIN_CP_WORKER_SUBJECT", "worker-service")
        credentials: dict[str, Principal] = {
            worker_token: Principal(
                subject=worker_subject,
                roles=frozenset({PrincipalRole.WORKER}),
            )
        }
        if operator_token is not None:
            credentials[operator_token] = Principal(
                subject=operator_subject,
                roles=frozenset({PrincipalRole.OPERATOR, PrincipalRole.AUDITOR}),
            )
        if approver_token is not None:
            credentials[approver_token] = Principal(
                subject=approver_subject,
                roles=frozenset({PrincipalRole.APPROVER, PrincipalRole.AUDITOR}),
            )
        additional_worker_credentials = _parse_additional_worker_credentials(
            raw_additional_worker_credentials
        )
        existing_tokens = set(credentials)
        existing_subjects = {principal.subject for principal in credentials.values()}
        for subject, token in additional_worker_credentials.items():
            if token in existing_tokens or subject in existing_subjects:
                raise RuntimeError(
                    "additional Worker credentials must use distinct tokens and subjects"
                )
            credentials[token] = Principal(
                subject=subject,
                roles=frozenset({PrincipalRole.WORKER}),
            )
            existing_tokens.add(token)
            existing_subjects.add(subject)
        authenticated_subjects = {principal.subject for principal in credentials.values()}
        if oidc_human_trust_policy is not None:
            authenticated_subjects.update(
                identity.principal_subject for identity in oidc_human_trust_policy.identities
            )
        replay_worker_subject: str | None = None
        if replay_worker_token is not None:
            replay_worker_subject = replay_worker_subject_setting or "replay-worker-service"
            if replay_worker_token in existing_tokens:
                raise RuntimeError(
                    "Replay Worker credential must be distinct from additional Workers"
                )
            if replay_worker_subject in authenticated_subjects:
                raise RuntimeError(
                    "Replay Worker subject must be distinct from every other role subject"
                )
            credentials[replay_worker_token] = Principal(
                subject=replay_worker_subject,
                roles=frozenset({PrincipalRole.WORKER}),
            )
        effective_human_roles: set[PrincipalRole] = {
            role
            for principal in credentials.values()
            for role in principal.roles
            if role is not PrincipalRole.WORKER
        }
        if oidc_human_trust_policy is not None:
            effective_human_roles.update(
                role for identity in oidc_human_trust_policy.identities for role in identity.roles
            )
        if not {PrincipalRole.OPERATOR, PrincipalRole.APPROVER} <= effective_human_roles:
            raise RuntimeError(
                "Control Plane environment requires separated operator and approver authorities"
            )
        replay_executor_profiles = _parse_replay_executor_profiles(
            raw_replay_profiles,
            credentials=credentials,
        )
        if replay_executor_profiles and set(replay_executor_profiles) != {replay_worker_subject}:
            raise RuntimeError(
                "PAJIN_CP_REPLAY_EXECUTOR_PROFILES may authorize only the dedicated "
                "Replay Worker subject"
            )
        return cls(
            database_url=os.environ.get(
                "PAJIN_CP_DATABASE_URL", "sqlite:///./.pajin/control-plane.db"
            ),
            credentials=credentials,
            checkpoint_keys={key_id: checkpoint_key.encode()},
            active_checkpoint_key_id=key_id,
            oidc_human_trust_policy=oidc_human_trust_policy,
            worker_mtls_trust_policy=worker_mtls_trust_policy,
            pentest_recon_deployment_path=(
                Path(pentest_recon_deployment_path)
                if pentest_recon_deployment_path is not None
                else None
            ),
            pentest_recon_deployment_sha256=pentest_recon_deployment_sha256,
            pentest_replay_deployment_path=(
                Path(pentest_replay_deployment_path)
                if pentest_replay_deployment_path is not None
                else None
            ),
            pentest_replay_deployment_sha256=pentest_replay_deployment_sha256,
            pentest_workflow_deployment_path=(
                Path(pentest_workflow_deployment_path)
                if pentest_workflow_deployment_path is not None
                else None
            ),
            pentest_workflow_deployment_sha256=pentest_workflow_deployment_sha256,
            pentest_workflow_coordination_deployment_path=(
                Path(pentest_workflow_coordination_deployment_path)
                if pentest_workflow_coordination_deployment_path is not None
                else None
            ),
            pentest_workflow_coordination_deployment_sha256=(
                pentest_workflow_coordination_deployment_sha256
            ),
            abac_policy=abac_policy,
            run_submission_abac_policy=run_submission_abac_policy,
            run_cancellation_abac_policy=run_cancellation_abac_policy,
            checkpoint_resume_abac_policy=checkpoint_resume_abac_policy,
            replay_source_artifact_abac_policy=replay_source_artifact_abac_policy,
            replay_batch_admission_abac_policy=replay_batch_admission_abac_policy,
            maintenance_abac_policy=maintenance_abac_policy,
            initialize_schema=_parse_strict_environment_boolean(
                "PAJIN_CP_INITIALIZE_SCHEMA",
                default=True,
            ),
            database_echo=_parse_strict_environment_boolean(
                "PAJIN_CP_DATABASE_ECHO",
                default=False,
            ),
            artifact_staging_root=(
                Path(artifact_staging_root) if artifact_staging_root is not None else None
            ),
            artifact_repository_root=(
                Path(artifact_repository_root) if artifact_repository_root is not None else None
            ),
            campaign_draft_root=(
                Path(campaign_draft_root) if campaign_draft_root is not None else None
            ),
            discovery_run_root=(
                Path(discovery_run_root) if discovery_run_root is not None else None
            ),
            graph_database=(Path(graph_database) if graph_database is not None else None),
            graph_decision_audit_database=(
                Path(graph_decision_audit_database)
                if graph_decision_audit_database is not None
                else None
            ),
            validation_evidence_root=(
                Path(validation_evidence_root) if validation_evidence_root is not None else None
            ),
            replay_executor_profiles=replay_executor_profiles,
            replay_attestation_key_id=replay_attestation_key_id,
            replay_attestation_private_key=parsed_attestation_private_key,
            replay_attestation_trust_anchor=parsed_attestation_trust_anchor,
            executor_attestation_trust_anchor=(parsed_executor_attestation_trust_anchor),
            target_attestation_trust_anchor=parsed_target_attestation_trust_anchor,
            target_attestation_trust_registry=parsed_target_attestation_trust_registry,
            target_attestation_registry_bundle=(parsed_target_attestation_registry_bundle),
            target_attestation_registry_trust_anchor=(
                parsed_target_attestation_registry_trust_anchor
            ),
            request_body_timeout_seconds=float(
                os.environ.get(
                    "PAJIN_CP_REQUEST_BODY_TIMEOUT_SECONDS",
                    str(_DEFAULT_CONTROL_PLANE_REQUEST_BODY_TIMEOUT_SECONDS),
                )
            ),
        )


@dataclass(frozen=True)
class _ControlPlaneApplicationContext:
    settings: ControlPlaneSettings
    repository: ControlPlaneRepository
    artifact_repository: ManagedArtifactRepository | None
    campaign_draft_reader: ControlPlaneCampaignDraftReader
    campaign_draft_compiler: ControlPlaneCampaignDraftCompiler
    discovery_view_reader: VerifiedDiscoveryViewReader
    graph_view_reader: VerifiedCanonicalGraphViewReader
    hypothesis_attention_ranking_reader: VerifiedHypothesisAttentionRankingReader
    decision_audit_reader: VerifiedGraphDecisionAuditViewReader
    replay_comparison_reader: VerifiedReplayEvidenceComparisonReader
    validation_comparison_reader: VerifiedWalkingControlComparisonReader
    pentest_recon_runtime: PentestReconDispatchRuntime | None
    pentest_replay_runtime: PentestReplayDispatchRuntime | None
    pentest_workflow_runtime: PentestOperatorWorkflowRuntime | None
    pentest_workflow_coordination_runtime: PentestWorkflowCoordinationDispatchRuntime | None
    service: ControlPlaneService
    authenticator: BearerAuthenticator


def _build_artifact_repository(
    settings: ControlPlaneSettings,
) -> ManagedArtifactRepository | None:
    staging_root = settings.artifact_staging_root
    repository_root = settings.artifact_repository_root
    if (staging_root is None) != (repository_root is None):
        raise RuntimeError(
            "artifact_staging_root and artifact_repository_root must be configured together"
        )
    if staging_root is None or repository_root is None:
        return None
    return ManagedArtifactRepository(
        staging_root=staging_root,
        repository_root=repository_root,
    )


def _build_bearer_authenticator(settings: ControlPlaneSettings) -> BearerAuthenticator:
    authenticators: list[BearerAuthenticator] = [TokenAuthenticator(dict(settings.credentials))]
    if settings.oidc_human_trust_policy is not None:
        authenticators.append(OIDCHumanAuthenticator(settings.oidc_human_trust_policy))
    return ChainedAuthenticator(tuple(authenticators))


def _build_application_context(
    settings: ControlPlaneSettings,
) -> _ControlPlaneApplicationContext:
    repository = ControlPlaneRepository(
        settings.database_url,
        echo=settings.database_echo,
    )
    signer = CheckpointSigner(
        active_key_id=settings.active_checkpoint_key_id,
        keys=settings.checkpoint_keys,
    )
    artifact_repository = _build_artifact_repository(settings)
    replay_attestor: ReplayAttestor | None = None
    if settings.replay_attestation_key_id is not None:
        assert settings.replay_attestation_private_key is not None
        assert settings.replay_attestation_trust_anchor is not None
        replay_attestor = ReplayAttestor.from_private_key_bytes(
            active_key_id=settings.replay_attestation_key_id,
            private_key=settings.replay_attestation_private_key,
            trust_anchor=settings.replay_attestation_trust_anchor,
        )
    service = ControlPlaneService(
        repository,
        signer,
        replay_executor_profiles=settings.replay_executor_profiles,
        artifact_repository=artifact_repository,
        replay_attestor=replay_attestor,
        executor_attestation_trust_anchor=(settings.executor_attestation_trust_anchor),
        target_attestation_trust_anchor=settings.target_attestation_trust_anchor,
        target_attestation_trust_registry=settings.target_attestation_trust_registry,
        target_attestation_registry_bundle=settings.target_attestation_registry_bundle,
        target_attestation_registry_trust_anchor=(
            settings.target_attestation_registry_trust_anchor
        ),
        abac_authorizer=(
            ControlPlaneABACAuthorizer(settings.abac_policy)
            if settings.abac_policy is not None
            else None
        ),
        run_submission_authorizer=(
            ControlPlaneRunSubmissionAuthorizer(settings.run_submission_abac_policy)
            if settings.run_submission_abac_policy is not None
            else None
        ),
        run_cancellation_authorizer=(
            ControlPlaneRunCancellationAuthorizer(settings.run_cancellation_abac_policy)
            if settings.run_cancellation_abac_policy is not None
            else None
        ),
        checkpoint_resume_authorizer=(
            ControlPlaneCheckpointResumeAuthorizer(settings.checkpoint_resume_abac_policy)
            if settings.checkpoint_resume_abac_policy is not None
            else None
        ),
        replay_source_artifact_authorizer=(
            ControlPlaneReplaySourceArtifactAuthorizer(settings.replay_source_artifact_abac_policy)
            if settings.replay_source_artifact_abac_policy is not None
            else None
        ),
        replay_batch_admission_authorizer=(
            ControlPlaneReplayBatchAdmissionAuthorizer(settings.replay_batch_admission_abac_policy)
            if settings.replay_batch_admission_abac_policy is not None
            else None
        ),
        maintenance_authorizer=(
            ControlPlaneMaintenanceAuthorizer(settings.maintenance_abac_policy)
            if settings.maintenance_abac_policy is not None
            else None
        ),
    )
    campaign_draft_reader = ControlPlaneCampaignDraftReader(root=settings.campaign_draft_root)
    pentest_recon_runtime: PentestReconDispatchRuntime | None = None
    if settings.pentest_recon_deployment_path is not None:
        assert settings.pentest_recon_deployment_sha256 is not None
        assert settings.worker_mtls_trust_policy is not None
        pentest_recon_runtime = load_pentest_recon_operator_deployment(
            settings.pentest_recon_deployment_path,
            expected_sha256=settings.pentest_recon_deployment_sha256,
            current_worker_mtls_policy=settings.worker_mtls_trust_policy,
        )
    pentest_replay_runtime: PentestReplayDispatchRuntime | None = None
    if settings.pentest_replay_deployment_path is not None:
        assert settings.pentest_replay_deployment_sha256 is not None
        assert settings.worker_mtls_trust_policy is not None
        pentest_replay_runtime = load_pentest_replay_operator_deployment(
            settings.pentest_replay_deployment_path,
            expected_sha256=settings.pentest_replay_deployment_sha256,
            current_worker_mtls_policy=settings.worker_mtls_trust_policy,
            allowed_replay_worker_subjects=frozenset(settings.replay_executor_profiles),
        )
    pentest_workflow_runtime: PentestOperatorWorkflowRuntime | None = None
    if settings.pentest_workflow_deployment_path is not None:
        assert settings.pentest_workflow_deployment_sha256 is not None
        pentest_workflow_runtime = load_pentest_operator_workflow_deployment(
            settings.pentest_workflow_deployment_path,
            expected_sha256=settings.pentest_workflow_deployment_sha256,
        )
    pentest_workflow_coordination_runtime: PentestWorkflowCoordinationDispatchRuntime | None = None
    if settings.pentest_workflow_coordination_deployment_path is not None:
        assert settings.pentest_workflow_coordination_deployment_sha256 is not None
        assert settings.worker_mtls_trust_policy is not None
        pentest_workflow_coordination_runtime = load_pentest_workflow_coordination_deployment(
            settings.pentest_workflow_coordination_deployment_path,
            expected_sha256=settings.pentest_workflow_coordination_deployment_sha256,
            current_worker_mtls_policy=settings.worker_mtls_trust_policy,
            allowed_replay_worker_subjects=frozenset(settings.replay_executor_profiles),
        )
    return _ControlPlaneApplicationContext(
        settings=settings,
        repository=repository,
        artifact_repository=artifact_repository,
        campaign_draft_reader=campaign_draft_reader,
        campaign_draft_compiler=ControlPlaneCampaignDraftCompiler(reader=campaign_draft_reader),
        discovery_view_reader=VerifiedDiscoveryViewReader(settings.discovery_run_root),
        graph_view_reader=VerifiedCanonicalGraphViewReader(settings.graph_database),
        hypothesis_attention_ranking_reader=VerifiedHypothesisAttentionRankingReader(
            settings.graph_database
        ),
        decision_audit_reader=VerifiedGraphDecisionAuditViewReader(
            graph_database=settings.graph_database,
            audit_database=settings.graph_decision_audit_database,
        ),
        replay_comparison_reader=VerifiedReplayEvidenceComparisonReader(service),
        validation_comparison_reader=VerifiedWalkingControlComparisonReader(
            settings.validation_evidence_root
        ),
        pentest_recon_runtime=pentest_recon_runtime,
        pentest_replay_runtime=pentest_replay_runtime,
        pentest_workflow_runtime=pentest_workflow_runtime,
        pentest_workflow_coordination_runtime=pentest_workflow_coordination_runtime,
        service=service,
        authenticator=_build_bearer_authenticator(settings),
    )


def _create_lifespan(
    context: _ControlPlaneApplicationContext,
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if context.settings.initialize_schema:
            context.repository.initialize()
        else:
            # Deployment-managed migrations may disable DDL at process startup, but
            # they must never disable the Control Plane's schema compatibility fence.
            context.repository.schema_version()
        context.service.activate_target_attestation_registry()
        app.state.repository = context.repository
        app.state.artifact_repository = context.artifact_repository
        app.state.control_plane = context.service
        try:
            yield
        finally:
            context.repository.close()

    return lifespan


def _configure_middleware(app: FastAPI, settings: ControlPlaneSettings) -> None:
    @app.middleware("http")
    async def prevent_sensitive_response_caching(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        if request.url.path.startswith("/v1/"):
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    # Register this after the response-header middleware so Starlette places the
    # byte fence outermost: it runs before authentication, routing, or parsing.
    app.add_middleware(
        _BoundedRequestBodyMiddleware,
        max_body_bytes=_MAX_CONTROL_PLANE_REQUEST_BODY_BYTES,
        body_timeout_seconds=settings.request_body_timeout_seconds,
    )


def _build_authentication_dependency(
    authenticator: BearerAuthenticator,
    worker_mtls_authenticator: WorkerMTLSAuthenticator | None,
) -> Callable[..., Principal]:
    bearer = HTTPBearer(auto_error=False)

    def authenticate(
        request: Request,
        credential: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ) -> Principal:
        if credential is None or credential.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="bearer credential required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            principal = authenticator.authenticate(credential.credentials)
            if worker_mtls_authenticator is not None and PrincipalRole.WORKER in principal.roles:
                return worker_mtls_authenticator.authenticate(request.scope, principal)
            return principal
        except AuthenticationError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid bearer credential",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

    return authenticate


def _build_role_dependency_factory(
    authenticate: Callable[..., Principal],
) -> RoleDependencyFactory:
    def require_roles(
        *required: PrincipalRole,
    ) -> PrincipalDependency:
        def dependency(
            principal: Annotated[Principal, Depends(authenticate)],
        ) -> Principal:
            if principal.roles.isdisjoint(required):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="credential lacks the required Control Plane role",
                )
            return principal

        return dependency

    return require_roles


def _build_generic_worker_dependency(
    require_roles: RoleDependencyFactory,
    *,
    replay_worker_subjects: frozenset[str],
) -> PrincipalDependency:
    def require_generic_worker(
        principal: Annotated[
            Principal,
            Depends(require_roles(PrincipalRole.WORKER)),
        ],
    ) -> Principal:
        if principal.subject in replay_worker_subjects:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=("dedicated Replay Worker credential cannot access generic Worker routes"),
            )
        return principal

    return require_generic_worker


def _build_replay_worker_dependency(
    require_roles: RoleDependencyFactory,
    *,
    replay_worker_subjects: frozenset[str],
) -> PrincipalDependency:
    def require_replay_worker(
        principal: Annotated[
            Principal,
            Depends(require_roles(PrincipalRole.WORKER)),
        ],
    ) -> Principal:
        if principal.subject not in replay_worker_subjects:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "authenticated Worker principal is not registered for this Replay executor"
                ),
            )
        return principal

    return require_replay_worker


def _build_dependencies(
    context: _ControlPlaneApplicationContext,
) -> ControlPlaneDependencies:
    worker_mtls_authenticator = (
        WorkerMTLSAuthenticator(context.settings.worker_mtls_trust_policy)
        if context.settings.worker_mtls_trust_policy is not None
        else None
    )
    authenticate = _build_authentication_dependency(
        context.authenticator,
        worker_mtls_authenticator,
    )
    require_roles = _build_role_dependency_factory(authenticate)
    replay_worker_subjects = frozenset(context.settings.replay_executor_profiles)
    return ControlPlaneDependencies(
        require_roles=require_roles,
        require_generic_worker=_build_generic_worker_dependency(
            require_roles,
            replay_worker_subjects=replay_worker_subjects,
        ),
        require_replay_worker=_build_replay_worker_dependency(
            require_roles,
            replay_worker_subjects=replay_worker_subjects,
        ),
    )


def _register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ResourceNotFound)
    async def not_found_handler(_request: object, exc: ResourceNotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(RequestValidationError)
    async def request_validation_handler(
        _request: object,
        exc: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={"detail": _safe_request_validation_detail(exc)},
        )

    @app.exception_handler(ReplayExecutorRejected)
    async def replay_executor_rejected_handler(
        _request: object,
        exc: ReplayExecutorRejected,
    ) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(AuthorizationDenied)
    async def authorization_denied_handler(
        _request: object, exc: AuthorizationDenied
    ) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(StateConflict)
    @app.exception_handler(LeaseRejected)
    @app.exception_handler(CheckpointIntegrityError)
    async def conflict_handler(_request: object, exc: Exception) -> JSONResponse:
        code: ControlPlaneConflictCode | None = None
        if isinstance(exc, RunCancelled):
            code = ControlPlaneConflictCode.RUN_CANCELLED
        elif isinstance(exc, LeaseRejected):
            code = ControlPlaneConflictCode.LEASE_LOST
        content = ControlPlaneConflictResponse(detail=str(exc), code=code)
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content=content.model_dump(mode="json", exclude_none=True),
        )

    @app.exception_handler(ControlPlaneError)
    async def control_error_handler(
        _request: object,
        exc: ControlPlaneError,
    ) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})


def _safe_request_validation_detail(
    error: RequestValidationError,
) -> list[dict[str, object]]:
    """Describe malformed requests without reflecting values or validator messages."""

    try:
        candidate_errors = error.errors()
    except BaseException:
        candidate_errors = []
    raw_errors = candidate_errors if isinstance(candidate_errors, list | tuple) else []
    detail: list[dict[str, object]] = []
    for raw_error in raw_errors[:100]:
        location = raw_error.get("loc", ()) if isinstance(raw_error, dict) else ()
        detail.append(
            {
                "type": "request_validation",
                "loc": _safe_request_validation_location(location),
                "msg": _safe_request_validation_message(raw_error),
            }
        )
    if len(raw_errors) > 100:
        detail.append(
            {
                "type": "request_validation",
                "loc": ["request"],
                "msg": "additional request validation errors omitted",
            }
        )
    return detail or [
        {
            "type": "request_validation",
            "loc": ["request"],
            "msg": "request validation failed",
        }
    ]


def _safe_request_validation_location(value: object) -> list[str | int]:
    """Keep only structural request locations, never attacker-controlled field names."""

    if not isinstance(value, tuple | list):
        return ["request"]
    safe: list[str | int] = []
    for item in value[:32]:
        if isinstance(item, str):
            safe.append(
                item if item in {"body", "query", "path", "header", "cookie"} else "<field>"
            )
        elif type(item) is int and 0 <= item <= 1_000_000:
            safe.append(item)
        else:
            safe.append("<field>")
    return safe or ["request"]


def _safe_request_validation_message(error: object) -> str:
    """Map useful validation classes to constants without copying their messages."""

    if not isinstance(error, dict):
        return "request validation failed"
    error_type = error.get("type")
    if error_type == "missing":
        return "required field is missing"
    if error_type == "extra_forbidden":
        return "unexpected field is not permitted"
    if error_type == "json_invalid":
        return "request body is not valid JSON"
    try:
        message = str(error.get("msg", ""))
    except BaseException:
        return "request validation failed"
    if "must be finite" in message:
        return "value must be finite"
    return "request validation failed"


def create_app(
    settings: ControlPlaneSettings | None = None,
    *,
    pentest_recon_runtime: PentestReconDispatchRuntime | None = None,
    pentest_replay_runtime: PentestReplayDispatchRuntime | None = None,
    pentest_workflow_runtime: PentestOperatorWorkflowRuntime | None = None,
    pentest_workflow_coordination_runtime: (
        PentestWorkflowCoordinationDispatchRuntime | None
    ) = None,
) -> FastAPI:
    resolved = settings or ControlPlaneSettings.from_env()
    context = _build_application_context(resolved)
    if pentest_recon_runtime is not None and context.pentest_recon_runtime is not None:
        raise ValueError("Pentest Recon runtime cannot be both injected and deployment-configured")
    selected_pentest_recon_runtime = pentest_recon_runtime or context.pentest_recon_runtime
    if pentest_replay_runtime is not None and context.pentest_replay_runtime is not None:
        raise ValueError("Pentest Replay runtime cannot be both injected and configured")
    selected_pentest_replay_runtime = pentest_replay_runtime or context.pentest_replay_runtime
    if pentest_workflow_runtime is not None and context.pentest_workflow_runtime is not None:
        raise ValueError("Pentest workflow runtime cannot be both injected and configured")
    selected_pentest_workflow_runtime = pentest_workflow_runtime or context.pentest_workflow_runtime
    if (
        pentest_workflow_coordination_runtime is not None
        and context.pentest_workflow_coordination_runtime is not None
    ):
        raise ValueError(
            "Pentest workflow coordination runtime cannot be both injected and configured"
        )
    selected_pentest_workflow_coordination_runtime = (
        pentest_workflow_coordination_runtime or context.pentest_workflow_coordination_runtime
    )
    app = FastAPI(
        title="PAJIN Control Plane",
        version="0.1.0",
        lifespan=_create_lifespan(context),
    )
    _configure_middleware(app, resolved)
    _register_exception_handlers(app)
    dependencies = _build_dependencies(context)

    register_control_plane_routes(
        app,
        repository=context.repository,
        service=context.service,
        campaign_draft_reader=context.campaign_draft_reader,
        campaign_draft_compiler=context.campaign_draft_compiler,
        discovery_view_reader=context.discovery_view_reader,
        graph_view_reader=context.graph_view_reader,
        hypothesis_attention_ranking_reader=(context.hypothesis_attention_ranking_reader),
        decision_audit_reader=context.decision_audit_reader,
        replay_comparison_reader=context.replay_comparison_reader,
        validation_comparison_reader=context.validation_comparison_reader,
        pentest_recon_runtime=selected_pentest_recon_runtime,
        pentest_replay_runtime=selected_pentest_replay_runtime,
        pentest_workflow_runtime=selected_pentest_workflow_runtime,
        pentest_workflow_coordination_runtime=(selected_pentest_workflow_coordination_runtime),
        dependencies=dependencies,
    )
    return app
