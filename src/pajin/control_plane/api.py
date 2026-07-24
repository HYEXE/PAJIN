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
from pathlib import Path
from types import MappingProxyType
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.types import ASGIApp, Message, Receive, Scope, Send

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
from pajin.control_plane.database import ControlPlaneRepository
from pajin.control_plane.errors import (
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
from pajin.control_plane.models import (
    ControlPlaneConflictCode,
    ControlPlaneConflictResponse,
    Principal,
    PrincipalRole,
)
from pajin.control_plane.security import (
    AuthenticationError,
    CheckpointIntegrityError,
    CheckpointSigner,
    TokenAuthenticator,
    validate_bearer_token,
)
from pajin.control_plane.service import ControlPlaneService
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.target_attestation import (
    TargetAttestationTrustAnchor,
    parse_target_attestation_trust_anchor,
)

_REPLAY_EXECUTOR_PROFILES_ENV = "PAJIN_CP_REPLAY_EXECUTOR_PROFILES"
_REPLAY_ATTESTATION_KEY_ID_ENV = "PAJIN_CP_REPLAY_ATTESTATION_KEY_ID"
_REPLAY_ATTESTATION_PRIVATE_KEY_ENV = "PAJIN_CP_REPLAY_ATTESTATION_PRIVATE_KEY"
_REPLAY_ATTESTATION_TRUST_ANCHOR_ENV = "PAJIN_CP_REPLAY_ATTESTATION_TRUST_ANCHOR"
_EXECUTOR_ATTESTATION_TRUST_ANCHOR_ENV = "PAJIN_CP_EXECUTOR_ATTESTATION_TRUST_ANCHOR"
_TARGET_ATTESTATION_TRUST_ANCHOR_ENV = "PAJIN_CP_TARGET_ATTESTATION_TRUST_ANCHOR"
_REPLAY_EXECUTOR_PROFILE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_MAX_REPLAY_EXECUTOR_PROFILES_PER_SUBJECT = 20
_MAX_REPLAY_EXECUTOR_PROFILES_JSON_BYTES = 64 * 1024
_MAX_REPLAY_EXECUTOR_PROFILES_JSON_DEPTH = 4
_MAX_REPLAY_EXECUTOR_PROFILES_JSON_NODES = 4_096
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


@dataclass(frozen=True)
class ControlPlaneSettings:
    database_url: str
    credentials: Mapping[str, Principal]
    checkpoint_keys: dict[str, bytes]
    active_checkpoint_key_id: str = "v1"
    initialize_schema: bool = True
    database_echo: bool = False
    artifact_staging_root: Path | None = None
    artifact_repository_root: Path | None = None
    replay_executor_profiles: dict[str, frozenset[str]] = field(default_factory=dict)
    replay_attestation_key_id: str | None = None
    replay_attestation_private_key: bytes | None = field(default=None, repr=False)
    replay_attestation_trust_anchor: ReplayAttestationTrustAnchor | None = None
    executor_attestation_trust_anchor: ExecutorAttestationTrustAnchor | None = None
    target_attestation_trust_anchor: TargetAttestationTrustAnchor | None = None
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
        credentials = dict(self.credentials)
        for token in credentials:
            validate_bearer_token(
                token,
                label="Control Plane bearer credential",
            )
        _validate_credential_role_separation(credentials)
        normalized = _validated_replay_executor_profiles(
            self.replay_executor_profiles,
            credentials=credentials,
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
    def from_env(cls) -> "ControlPlaneSettings":
        operator_token = os.environ.get("PAJIN_CP_OPERATOR_TOKEN")
        approver_token = os.environ.get("PAJIN_CP_APPROVER_TOKEN")
        worker_token = os.environ.get("PAJIN_CP_WORKER_TOKEN")
        replay_worker_token = os.environ.get("PAJIN_CP_REPLAY_WORKER_TOKEN")
        replay_worker_subject_setting = os.environ.get("PAJIN_CP_REPLAY_WORKER_SUBJECT")
        raw_replay_profiles = os.environ.get(_REPLAY_EXECUTOR_PROFILES_ENV)
        replay_attestation_key_id = os.environ.get(_REPLAY_ATTESTATION_KEY_ID_ENV)
        replay_attestation_private_key = os.environ.get(_REPLAY_ATTESTATION_PRIVATE_KEY_ENV)
        replay_attestation_trust_anchor = os.environ.get(_REPLAY_ATTESTATION_TRUST_ANCHOR_ENV)
        executor_attestation_trust_anchor = os.environ.get(_EXECUTOR_ATTESTATION_TRUST_ANCHOR_ENV)
        target_attestation_trust_anchor = os.environ.get(_TARGET_ATTESTATION_TRUST_ANCHOR_ENV)
        checkpoint_key = os.environ.get("PAJIN_CP_CHECKPOINT_KEY")
        artifact_staging_root = os.environ.get("PAJIN_CP_ARTIFACT_STAGING_ROOT")
        artifact_repository_root = os.environ.get("PAJIN_CP_ARTIFACT_REPOSITORY_ROOT")
        missing = [
            name
            for name, value in (
                ("PAJIN_CP_OPERATOR_TOKEN", operator_token),
                ("PAJIN_CP_APPROVER_TOKEN", approver_token),
                ("PAJIN_CP_WORKER_TOKEN", worker_token),
                ("PAJIN_CP_CHECKPOINT_KEY", checkpoint_key),
            )
            if value is None
        ]
        if missing:
            raise RuntimeError(f"missing required Control Plane secrets: {', '.join(missing)}")
        assert operator_token is not None
        assert approver_token is not None
        assert worker_token is not None
        assert checkpoint_key is not None
        if len({operator_token, approver_token, worker_token}) != 3:
            raise RuntimeError("Control Plane role credentials must be distinct")
        if replay_worker_subject_setting is not None and replay_worker_token is None:
            raise RuntimeError(
                "PAJIN_CP_REPLAY_WORKER_SUBJECT requires PAJIN_CP_REPLAY_WORKER_TOKEN"
            )
        if raw_replay_profiles is not None and replay_worker_token is None:
            raise RuntimeError(
                "PAJIN_CP_REPLAY_EXECUTOR_PROFILES requires a distinct PAJIN_CP_REPLAY_WORKER_TOKEN"
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
        key_id = os.environ.get("PAJIN_CP_CHECKPOINT_KEY_ID", "v1")
        operator_subject = os.environ.get("PAJIN_CP_OPERATOR_SUBJECT", "operator")
        approver_subject = os.environ.get(
            "PAJIN_CP_APPROVER_SUBJECT",
            "security-approver",
        )
        worker_subject = os.environ.get("PAJIN_CP_WORKER_SUBJECT", "worker-service")
        credentials = {
            operator_token: Principal(
                subject=operator_subject,
                roles=frozenset({PrincipalRole.OPERATOR, PrincipalRole.AUDITOR}),
            ),
            approver_token: Principal(
                subject=approver_subject,
                roles=frozenset({PrincipalRole.APPROVER, PrincipalRole.AUDITOR}),
            ),
            worker_token: Principal(
                subject=worker_subject,
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        }
        replay_worker_subject: str | None = None
        if replay_worker_token is not None:
            replay_worker_subject = replay_worker_subject_setting or "replay-worker-service"
            if replay_worker_subject in {
                operator_subject,
                approver_subject,
                worker_subject,
            }:
                raise RuntimeError(
                    "Replay Worker subject must be distinct from every other role subject"
                )
            credentials[replay_worker_token] = Principal(
                subject=replay_worker_subject,
                roles=frozenset({PrincipalRole.WORKER}),
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
            replay_executor_profiles=replay_executor_profiles,
            replay_attestation_key_id=replay_attestation_key_id,
            replay_attestation_private_key=parsed_attestation_private_key,
            replay_attestation_trust_anchor=parsed_attestation_trust_anchor,
            executor_attestation_trust_anchor=(parsed_executor_attestation_trust_anchor),
            target_attestation_trust_anchor=parsed_target_attestation_trust_anchor,
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
    service: ControlPlaneService
    authenticator: TokenAuthenticator


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
    )
    return _ControlPlaneApplicationContext(
        settings=settings,
        repository=repository,
        artifact_repository=artifact_repository,
        service=service,
        authenticator=TokenAuthenticator(dict(settings.credentials)),
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
    authenticator: TokenAuthenticator,
) -> Callable[..., Principal]:
    bearer = HTTPBearer(auto_error=False)

    def authenticate(
        credential: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ) -> Principal:
        if credential is None or credential.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="bearer credential required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            return authenticator.authenticate(credential.credentials)
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
    authenticate = _build_authentication_dependency(context.authenticator)
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


def create_app(settings: ControlPlaneSettings | None = None) -> FastAPI:
    resolved = settings or ControlPlaneSettings.from_env()
    context = _build_application_context(resolved)
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
        dependencies=dependencies,
    )
    return app
