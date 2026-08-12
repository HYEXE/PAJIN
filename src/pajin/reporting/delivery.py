"""Crash-safe external delivery of one exact verified SARIF projection."""

from __future__ import annotations

import hmac
import os
import sqlite3
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Protocol, Self, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from pydantic import (
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import StrictModel
from pajin.reporting.sarif import (
    VerifiedSarifExport,
    load_verified_sarif_export,
)
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.secrets import SecretBroker, SecretLease, SecretLeaseStatus, SecretMaterial

EXTERNAL_DELIVERY_SINK_API_VERSION: Literal["pajin.dev/external-delivery-sink/v1alpha1"] = (
    "pajin.dev/external-delivery-sink/v1alpha1"
)
EXTERNAL_DELIVERY_INTENT_API_VERSION: Literal["pajin.dev/external-delivery-intent/v1alpha1"] = (
    "pajin.dev/external-delivery-intent/v1alpha1"
)
EXTERNAL_DELIVERY_AUTHORIZATION_API_VERSION: Literal[
    "pajin.dev/external-delivery-authorization/v1alpha1"
] = "pajin.dev/external-delivery-authorization/v1alpha1"
EXTERNAL_DELIVERY_SINK_RESPONSE_API_VERSION: Literal[
    "pajin.dev/external-delivery-sink-response/v1alpha1"
] = "pajin.dev/external-delivery-sink-response/v1alpha1"
EXTERNAL_DELIVERY_RECEIPT_API_VERSION: Literal["pajin.dev/external-delivery-receipt/v1alpha1"] = (
    "pajin.dev/external-delivery-receipt/v1alpha1"
)
EXTERNAL_DELIVERY_RECORD_API_VERSION: Literal["pajin.dev/external-delivery-record/v1alpha1"] = (
    "pajin.dev/external-delivery-record/v1alpha1"
)

_SCHEMA_VERSION = 1
_APPLICATION_ID = 0x50414A44  # ASCII "PAJD"
_BUSY_TIMEOUT_MS = 30_000
_MAX_MODEL_BYTES = 512 * 1024
_MAX_RESPONSE_BYTES = 64 * 1024
_MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_PortableId = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")]


class ExternalDeliveryError(RuntimeError):
    """Raised when external delivery cannot safely advance."""


class ExternalDeliveryOutcomeUnknownError(ExternalDeliveryError):
    """Raised after dispatch was durably claimed but no trusted outcome was recorded."""


class ExternalDeliveryState(StrEnum):
    READY_INITIAL = "ready-initial"
    DISPATCH_STARTED_OUTCOME_UNKNOWN = "dispatch-started-outcome-unknown"
    READY_RETRY = "ready-retry"
    DELIVERED = "delivered"
    TERMINAL_NOT_DELIVERED = "terminal-not-delivered"


class ExternalDeliverySink(StrictModel):
    """Content-addressed deployment entry for one exact HTTPS SARIF sink."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/external-delivery-sink/v1alpha1"] = Field(
        default=EXTERNAL_DELIVERY_SINK_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ExternalDeliverySink"] = "ExternalDeliverySink"
    sink_id: str = Field(
        default="",
        alias="sinkId",
        pattern=r"^$|^external-delivery-sink_[a-f0-9]{64}$",
    )
    sink_digest: str = Field(
        default="",
        alias="sinkDigest",
        pattern=r"^$|^[a-f0-9]{64}$",
    )
    sink_type: Literal["issue-tracker", "siem", "soar"] = Field(alias="sinkType")
    delivery_endpoint: str = Field(alias="deliveryEndpoint", min_length=1, max_length=2_048)
    reconciliation_endpoint: str = Field(
        alias="reconciliationEndpoint",
        min_length=1,
        max_length=2_048,
    )
    secret_ref_fingerprint: str = Field(
        alias="secretRefFingerprint",
        pattern=r"^[a-f0-9]{16}$",
    )
    request_authentication: Literal["bearer"] = Field(
        default="bearer",
        alias="requestAuthentication",
    )
    response_authentication: Literal["hmac-sha256"] = Field(
        default="hmac-sha256",
        alias="responseAuthentication",
    )
    network_policy: Literal["https-direct-no-redirects"] = Field(
        default="https-direct-no-redirects",
        alias="networkPolicy",
    )
    retry_policy: Literal["one-retry-after-authenticated-not-received"] = Field(
        default="one-retry-after-authenticated-not-received",
        alias="retryPolicy",
    )
    max_attempts: Literal[2] = Field(default=2, alias="maxAttempts")
    timeout_seconds: int = Field(default=15, alias="timeoutSeconds", ge=1, le=60)

    @field_validator("max_attempts", "timeout_seconds", mode="before")
    @classmethod
    def require_literal_integers(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("External delivery numeric policy fields must be JSON integers")
        return value

    @model_validator(mode="after")
    def bind_sink(self) -> Self:
        delivery_origin = _validated_https_endpoint(
            self.delivery_endpoint,
            label="external delivery endpoint",
        )
        reconciliation_origin = _validated_https_endpoint(
            self.reconciliation_endpoint,
            label="external delivery reconciliation endpoint",
        )
        if delivery_origin != reconciliation_origin:
            raise ValueError("External delivery endpoints must share one exact HTTPS origin")
        digest = _digest(
            "pajin.reporting.external-delivery-sink/v1",
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"sink_id", "sink_digest"},
            ),
        )
        sink_id = f"external-delivery-sink_{digest}"
        if self.sink_digest and self.sink_digest != digest:
            raise ValueError("External delivery Sink Digest differs")
        if self.sink_id and self.sink_id != sink_id:
            raise ValueError("External delivery Sink ID differs")
        object.__setattr__(self, "sink_digest", digest)
        object.__setattr__(self, "sink_id", sink_id)
        _model_bytes(self, label="External delivery sink")
        return self


class ExternalDeliveryIntent(StrictModel):
    """Deterministic binding of one verified SARIF payload to one registered sink."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/external-delivery-intent/v1alpha1"] = Field(
        default=EXTERNAL_DELIVERY_INTENT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ExternalDeliveryIntent"] = "ExternalDeliveryIntent"
    intent_id: str = Field(
        default="",
        alias="intentId",
        pattern=r"^$|^external-delivery-intent_[a-f0-9]{64}$",
    )
    intent_digest: str = Field(
        default="",
        alias="intentDigest",
        pattern=r"^$|^[a-f0-9]{64}$",
    )
    sink_id: str = Field(alias="sinkId", pattern=r"^external-delivery-sink_[a-f0-9]{64}$")
    sink_digest: _Sha256 = Field(alias="sinkDigest")
    source_run_id: _PortableId = Field(alias="sourceRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_finding_set_digest: _Sha256 = Field(alias="sourceFindingSetDigest")
    payload_media_type: Literal["application/sarif+json"] = Field(
        default="application/sarif+json",
        alias="payloadMediaType",
    )
    payload_digest: _Sha256 = Field(alias="payloadDigest")
    payload_bytes: int = Field(alias="payloadBytes", ge=1, le=_MAX_PAYLOAD_BYTES)
    idempotency_key: str = Field(
        default="",
        alias="idempotencyKey",
        pattern=r"^$|^pajin-delivery-[a-f0-9]{64}$",
    )
    external_delivery_requested: Literal[True] = Field(
        default=True,
        alias="externalDeliveryRequested",
    )
    downstream_action_authority: Literal[False] = Field(
        default=False,
        alias="downstreamActionAuthority",
    )

    @field_validator("payload_bytes", mode="before")
    @classmethod
    def require_literal_payload_bytes(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("External delivery payloadBytes must be a JSON integer")
        return value

    @field_validator(
        "external_delivery_requested",
        "downstream_action_authority",
        mode="before",
    )
    @classmethod
    def require_literal_authority_flags(cls, value: object, info: ValidationInfo) -> object:
        field_name = info.field_name
        expected = field_name == "external_delivery_requested"
        if type(value) is not bool or value is not expected:
            raise ValueError("External delivery intent authority markers differ")
        return value

    @model_validator(mode="after")
    def bind_intent(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"intent_id", "intent_digest", "idempotency_key"},
        )
        digest = _digest("pajin.reporting.external-delivery-intent/v1", material)
        intent_id = f"external-delivery-intent_{digest}"
        idempotency_key = f"pajin-delivery-{digest}"
        if self.intent_digest and self.intent_digest != digest:
            raise ValueError("External delivery Intent Digest differs")
        if self.intent_id and self.intent_id != intent_id:
            raise ValueError("External delivery Intent ID differs")
        if self.idempotency_key and self.idempotency_key != idempotency_key:
            raise ValueError("External delivery idempotency key differs")
        object.__setattr__(self, "intent_digest", digest)
        object.__setattr__(self, "intent_id", intent_id)
        object.__setattr__(self, "idempotency_key", idempotency_key)
        _model_bytes(self, label="External delivery intent")
        return self


class ExternalDeliveryAuthorization(StrictModel):
    """Externally verified authority for one exact delivery intent and bounded retry."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/external-delivery-authorization/v1alpha1"] = Field(
        default=EXTERNAL_DELIVERY_AUTHORIZATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ExternalDeliveryAuthorization"] = "ExternalDeliveryAuthorization"
    authorization_id: str = Field(
        default="",
        alias="authorizationId",
        pattern=r"^$|^external-delivery-authorization_[a-f0-9]{64}$",
    )
    authorization_digest: str = Field(
        default="",
        alias="authorizationDigest",
        pattern=r"^$|^[a-f0-9]{64}$",
    )
    intent_id: str = Field(
        alias="intentId",
        pattern=r"^external-delivery-intent_[a-f0-9]{64}$",
    )
    intent_digest: _Sha256 = Field(alias="intentDigest")
    sink_id: str = Field(alias="sinkId", pattern=r"^external-delivery-sink_[a-f0-9]{64}$")
    sink_digest: _Sha256 = Field(alias="sinkDigest")
    payload_digest: _Sha256 = Field(alias="payloadDigest")
    idempotency_key: str = Field(alias="idempotencyKey", pattern=r"^pajin-delivery-[a-f0-9]{64}$")
    authorized_at: datetime = Field(alias="authorizedAt")
    expires_at: datetime = Field(alias="expiresAt")
    max_attempts: Literal[2] = Field(default=2, alias="maxAttempts")
    reconciliation_authorized: Literal[True] = Field(
        default=True,
        alias="reconciliationAuthorized",
    )
    external_delivery_authorized: Literal[True] = Field(
        default=True,
        alias="externalDeliveryAuthorized",
    )
    automatic_retry_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRetryAuthorized",
    )

    @field_validator("authorized_at", "expires_at")
    @classmethod
    def normalize_timestamps(cls, value: datetime) -> datetime:
        return _aware_utc(value, "External delivery authorization time")

    @field_validator("max_attempts", mode="before")
    @classmethod
    def require_literal_attempt_count(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("External delivery maxAttempts must be a JSON integer")
        return value

    @field_validator(
        "reconciliation_authorized",
        "external_delivery_authorized",
        "automatic_retry_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_authorization_flags(
        cls,
        value: object,
        info: ValidationInfo,
    ) -> object:
        field_name = info.field_name
        expected = field_name != "automatic_retry_authorized"
        if type(value) is not bool or value is not expected:
            raise ValueError("External delivery authorization markers differ")
        return value

    @model_validator(mode="after")
    def bind_authorization(self) -> Self:
        if self.expires_at <= self.authorized_at:
            raise ValueError("External delivery authorization must expire after issuance")
        digest = _digest(
            "pajin.reporting.external-delivery-authorization/v1",
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"authorization_id", "authorization_digest"},
            ),
        )
        authorization_id = f"external-delivery-authorization_{digest}"
        if self.authorization_digest and self.authorization_digest != digest:
            raise ValueError("External delivery Authorization Digest differs")
        if self.authorization_id and self.authorization_id != authorization_id:
            raise ValueError("External delivery Authorization ID differs")
        object.__setattr__(self, "authorization_digest", digest)
        object.__setattr__(self, "authorization_id", authorization_id)
        _model_bytes(self, label="External delivery authorization")
        return self


class ExternalDeliverySinkResponse(StrictModel):
    """Application-authenticated response for dispatch or reconciliation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/external-delivery-sink-response/v1alpha1"] = Field(
        default=EXTERNAL_DELIVERY_SINK_RESPONSE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ExternalDeliverySinkResponse"] = "ExternalDeliverySinkResponse"
    response_digest: str = Field(
        default="",
        alias="responseDigest",
        pattern=r"^$|^[a-f0-9]{64}$",
    )
    response_signature: str = Field(
        default="",
        alias="responseSignature",
        pattern=r"^$|^[a-f0-9]{64}$",
    )
    intent_id: str = Field(
        alias="intentId",
        pattern=r"^external-delivery-intent_[a-f0-9]{64}$",
    )
    sink_id: str = Field(alias="sinkId", pattern=r"^external-delivery-sink_[a-f0-9]{64}$")
    idempotency_key: str = Field(alias="idempotencyKey", pattern=r"^pajin-delivery-[a-f0-9]{64}$")
    payload_digest: _Sha256 = Field(alias="payloadDigest")
    attempt_ordinal: int = Field(alias="attemptOrdinal", ge=1, le=2)
    outcome: Literal["accepted", "not-received"]
    external_receipt_id: _PortableId | None = Field(default=None, alias="externalReceiptId")
    accepted_at: datetime | None = Field(default=None, alias="acceptedAt")

    @field_validator("attempt_ordinal", mode="before")
    @classmethod
    def require_literal_ordinal(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("External delivery response ordinal must be a JSON integer")
        return value

    @field_validator("accepted_at")
    @classmethod
    def normalize_accepted_at(cls, value: datetime | None) -> datetime | None:
        return _aware_utc(value, "External delivery acceptance time") if value else None

    @model_validator(mode="after")
    def bind_response(self) -> Self:
        if self.outcome == "accepted":
            if self.external_receipt_id is None or self.accepted_at is None:
                raise ValueError("Accepted delivery response requires receipt identity and time")
        elif self.external_receipt_id is not None or self.accepted_at is not None:
            raise ValueError("Not-received delivery response cannot contain acceptance evidence")
        digest = _digest(
            "pajin.reporting.external-delivery-sink-response/v1",
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"response_digest", "response_signature"},
            ),
        )
        if self.response_digest and self.response_digest != digest:
            raise ValueError("External delivery response digest differs")
        object.__setattr__(self, "response_digest", digest)
        _model_bytes(self, label="External delivery sink response")
        return self


class ExternalDeliveryReceipt(StrictModel):
    """Durable local receipt for one authenticated external acceptance."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/external-delivery-receipt/v1alpha1"] = Field(
        default=EXTERNAL_DELIVERY_RECEIPT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ExternalDeliveryReceipt"] = "ExternalDeliveryReceipt"
    receipt_id: str = Field(
        default="",
        alias="receiptId",
        pattern=r"^$|^external-delivery-receipt_[a-f0-9]{64}$",
    )
    receipt_digest: str = Field(
        default="",
        alias="receiptDigest",
        pattern=r"^$|^[a-f0-9]{64}$",
    )
    intent_id: str = Field(
        alias="intentId",
        pattern=r"^external-delivery-intent_[a-f0-9]{64}$",
    )
    intent_digest: _Sha256 = Field(alias="intentDigest")
    authorization_id: str = Field(
        alias="authorizationId",
        pattern=r"^external-delivery-authorization_[a-f0-9]{64}$",
    )
    authorization_digest: _Sha256 = Field(alias="authorizationDigest")
    sink_id: str = Field(alias="sinkId", pattern=r"^external-delivery-sink_[a-f0-9]{64}$")
    sink_digest: _Sha256 = Field(alias="sinkDigest")
    source_run_id: _PortableId = Field(alias="sourceRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_finding_set_digest: _Sha256 = Field(alias="sourceFindingSetDigest")
    payload_digest: _Sha256 = Field(alias="payloadDigest")
    idempotency_key: str = Field(alias="idempotencyKey", pattern=r"^pajin-delivery-[a-f0-9]{64}$")
    attempt_ordinal: int = Field(alias="attemptOrdinal", ge=1, le=2)
    external_receipt_id: _PortableId = Field(alias="externalReceiptId")
    accepted_at: datetime = Field(alias="acceptedAt")
    authenticated_response_digest: _Sha256 = Field(alias="authenticatedResponseDigest")
    external_delivery_performed: Literal[True] = Field(
        default=True,
        alias="externalDeliveryPerformed",
    )
    delivery_receipt_authority: Literal[True] = Field(
        default=True,
        alias="deliveryReceiptAuthority",
    )
    downstream_action_attested: Literal[False] = Field(
        default=False,
        alias="downstreamActionAttested",
    )

    @field_validator("attempt_ordinal", mode="before")
    @classmethod
    def require_literal_receipt_ordinal(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("External delivery receipt ordinal must be a JSON integer")
        return value

    @field_validator("accepted_at")
    @classmethod
    def normalize_receipt_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, "External delivery receipt time")

    @field_validator(
        "external_delivery_performed",
        "delivery_receipt_authority",
        "downstream_action_attested",
        mode="before",
    )
    @classmethod
    def require_literal_receipt_flags(cls, value: object, info: ValidationInfo) -> object:
        field_name = info.field_name
        expected = field_name != "downstream_action_attested"
        if type(value) is not bool or value is not expected:
            raise ValueError("External delivery receipt authority markers differ")
        return value

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        digest = _digest(
            "pajin.reporting.external-delivery-receipt/v1",
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"receipt_id", "receipt_digest"},
            ),
        )
        receipt_id = f"external-delivery-receipt_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("External delivery Receipt Digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("External delivery Receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        _model_bytes(self, label="External delivery receipt")
        return self


class ExternalDeliveryRecord(StrictModel):
    """Verified current head derived from the append-only delivery journal."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/external-delivery-record/v1alpha1"] = Field(
        default=EXTERNAL_DELIVERY_RECORD_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ExternalDeliveryRecord"] = "ExternalDeliveryRecord"
    intent: ExternalDeliveryIntent
    authorization: ExternalDeliveryAuthorization
    state: ExternalDeliveryState
    attempt_count: int = Field(alias="attemptCount", ge=0, le=2)
    retry_authorized: bool = Field(alias="retryAuthorized")
    automatic_retry_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRetryAuthorized",
    )
    manual_review_required: bool = Field(alias="manualReviewRequired")
    receipt: ExternalDeliveryReceipt | None = None
    last_response: ExternalDeliverySinkResponse | None = Field(
        default=None,
        alias="lastResponse",
    )
    event_digests: tuple[_Sha256, ...] = Field(alias="eventDigests", min_length=1, max_length=5)
    state_digest: str = Field(
        default="",
        alias="stateDigest",
        pattern=r"^$|^[a-f0-9]{64}$",
    )

    @field_validator("attempt_count", mode="before")
    @classmethod
    def require_literal_record_count(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("External delivery attempt count must be a JSON integer")
        return value

    @field_validator(
        "retry_authorized",
        "automatic_retry_authorized",
        "manual_review_required",
        mode="before",
    )
    @classmethod
    def require_literal_record_flags(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("External delivery record flags must be JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_record(self) -> Self:
        expected = {
            ExternalDeliveryState.READY_INITIAL: (0, False, False, False),
            ExternalDeliveryState.DISPATCH_STARTED_OUTCOME_UNKNOWN: (
                self.attempt_count,
                False,
                True,
                False,
            ),
            ExternalDeliveryState.READY_RETRY: (1, True, False, False),
            ExternalDeliveryState.DELIVERED: (
                self.attempt_count,
                False,
                False,
                True,
            ),
            ExternalDeliveryState.TERMINAL_NOT_DELIVERED: (2, False, False, False),
        }[self.state]
        observed = (
            self.attempt_count,
            self.retry_authorized,
            self.manual_review_required,
            self.receipt is not None,
        )
        if observed != expected or self.automatic_retry_authorized is not False:
            raise ValueError("External delivery record state differs")
        if self.state is ExternalDeliveryState.READY_INITIAL and self.last_response is not None:
            raise ValueError("Initial delivery record cannot contain a sink response")
        if self.state in {
            ExternalDeliveryState.READY_RETRY,
            ExternalDeliveryState.TERMINAL_NOT_DELIVERED,
        } and (self.last_response is None or self.last_response.outcome != "not-received"):
            raise ValueError("External delivery retry state lacks not-received evidence")
        if self.state is ExternalDeliveryState.DELIVERED and (
            self.last_response is None or self.last_response.outcome != "accepted"
        ):
            raise ValueError("Delivered record lacks accepted response evidence")
        if len(set(self.event_digests)) != len(self.event_digests):
            raise ValueError("External delivery journal event digests must be unique")
        digest = _digest(
            "pajin.reporting.external-delivery-record/v1",
            {
                "intentDigest": self.intent.intent_digest,
                "authorizationDigest": self.authorization.authorization_digest,
                "state": self.state.value,
                "attemptCount": self.attempt_count,
                "retryAuthorized": self.retry_authorized,
                "manualReviewRequired": self.manual_review_required,
                "receiptDigest": self.receipt.receipt_digest if self.receipt else None,
                "lastResponseDigest": (
                    self.last_response.response_digest if self.last_response else None
                ),
                "eventDigests": list(self.event_digests),
            },
        )
        if self.state_digest and self.state_digest != digest:
            raise ValueError("External delivery Record State Digest differs")
        object.__setattr__(self, "state_digest", digest)
        return self


class ExternalDeliveryAuthorizationAuthority(Protocol):
    """Deployment-pinned verifier for one exact external delivery authorization."""

    def verify_external_delivery_authorization(
        self,
        intent: ExternalDeliveryIntent,
        authorization: ExternalDeliveryAuthorization,
        *,
        evaluated_at: datetime,
    ) -> None:
        """Authenticate and authorize the exact intent or raise."""


class ExternalDeliveryAuthorizationRegistry:
    """Process-local allowlist of externally admitted delivery authorizations."""

    def __init__(self, authorizations: tuple[ExternalDeliveryAuthorization, ...]) -> None:
        canonical = tuple(
            _canonical_model(item, ExternalDeliveryAuthorization) for item in authorizations
        )
        if len({item.authorization_id for item in canonical}) != len(canonical):
            raise ValueError("External delivery authorization IDs must be unique")
        self._authorizations = {item.authorization_id: item for item in canonical}

    def verify_external_delivery_authorization(
        self,
        intent: ExternalDeliveryIntent,
        authorization: ExternalDeliveryAuthorization,
        *,
        evaluated_at: datetime,
    ) -> None:
        expected = self._authorizations.get(authorization.authorization_id)
        if expected is None or expected != authorization:
            raise PermissionError("External delivery authorization is not registered")
        _require_authorization_binding(intent, authorization)
        now = _aware_utc(evaluated_at, "External delivery authorization evaluation time")
        if now < authorization.authorized_at or now >= authorization.expires_at:
            raise PermissionError("External delivery authorization is not active")


class ExternalDeliverySinkRegistry:
    """Deployment-owned exact sink registry; request data cannot add or replace a sink."""

    def __init__(self, sinks: tuple[ExternalDeliverySink, ...]) -> None:
        canonical = tuple(_canonical_model(item, ExternalDeliverySink) for item in sinks)
        if len({item.sink_id for item in canonical}) != len(canonical):
            raise ValueError("External delivery Sink IDs must be unique")
        self._sinks = {item.sink_id: item for item in canonical}

    def resolve(self, sink_id: str) -> ExternalDeliverySink:
        sink = self._sinks.get(sink_id)
        if sink is None:
            raise KeyError("External delivery Sink is not registered")
        return sink.model_copy(deep=True)


@dataclass(frozen=True, slots=True)
class ExternalDeliveryHTTPResponse:
    status_code: int
    content_type: str
    body: bytes


class ExternalDeliveryTransport(Protocol):
    """Transport for the exact mutating dispatch and read-only reconciliation calls."""

    def dispatch(
        self,
        sink: ExternalDeliverySink,
        intent: ExternalDeliveryIntent,
        payload: bytes,
        secret: SecretMaterial,
        *,
        attempt_ordinal: int,
    ) -> ExternalDeliveryHTTPResponse:
        """Perform one exact outbound delivery attempt."""

    def reconcile(
        self,
        sink: ExternalDeliverySink,
        intent: ExternalDeliveryIntent,
        secret: SecretMaterial,
        *,
        attempt_ordinal: int,
    ) -> ExternalDeliveryHTTPResponse:
        """Query whether the exact idempotency key was accepted without mutating the sink."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


class HTTPSExternalDeliveryTransport:
    """Direct HTTPS transport with redirects and ambient proxies disabled."""

    def dispatch(
        self,
        sink: ExternalDeliverySink,
        intent: ExternalDeliveryIntent,
        payload: bytes,
        secret: SecretMaterial,
        *,
        attempt_ordinal: int,
    ) -> ExternalDeliveryHTTPResponse:
        if (
            len(payload) != intent.payload_bytes
            or sha256(payload).hexdigest() != intent.payload_digest
        ):
            raise ExternalDeliveryError("External delivery payload differs from the exact intent")
        request = Request(
            sink.delivery_endpoint,
            data=payload,
            headers=_request_headers(intent, secret, attempt_ordinal=attempt_ordinal),
            method="POST",
        )
        return self._send(request, timeout_seconds=sink.timeout_seconds)

    def reconcile(
        self,
        sink: ExternalDeliverySink,
        intent: ExternalDeliveryIntent,
        secret: SecretMaterial,
        *,
        attempt_ordinal: int,
    ) -> ExternalDeliveryHTTPResponse:
        request = Request(
            sink.reconciliation_endpoint,
            headers=_request_headers(intent, secret, attempt_ordinal=attempt_ordinal),
            method="GET",
        )
        return self._send(request, timeout_seconds=sink.timeout_seconds)

    @staticmethod
    def _send(request: Request, *, timeout_seconds: int) -> ExternalDeliveryHTTPResponse:
        opener = build_opener(ProxyHandler({}), _NoRedirectHandler())
        try:
            with opener.open(request, timeout=timeout_seconds) as response:
                raw_length = response.headers.get("Content-Length")
                if raw_length is not None:
                    try:
                        declared = int(raw_length)
                    except ValueError as exc:
                        raise ExternalDeliveryError(
                            "External delivery response Content-Length is invalid"
                        ) from exc
                    if declared < 0 or declared > _MAX_RESPONSE_BYTES:
                        raise ExternalDeliveryError(
                            "External delivery response exceeds the byte limit"
                        )
                body = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(body) > _MAX_RESPONSE_BYTES:
                    raise ExternalDeliveryError("External delivery response exceeds the byte limit")
                return ExternalDeliveryHTTPResponse(
                    status_code=int(response.status),
                    content_type=response.headers.get("Content-Type", ""),
                    body=body,
                )
        except ExternalDeliveryError:
            raise
        except (HTTPError, TimeoutError, URLError, OSError, ValueError) as exc:
            raise ExternalDeliveryError("External delivery HTTPS request failed closed") from exc


_METADATA_TABLE_SQL = """
    CREATE TABLE external_delivery_metadata (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL
    ) STRICT
    """
_INTENTS_TABLE_SQL = """
    CREATE TABLE external_delivery_intents (
        intent_id TEXT PRIMARY KEY NOT NULL,
        intent_digest TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        sink_digest TEXT NOT NULL,
        payload_digest TEXT NOT NULL,
        authorization_id TEXT NOT NULL UNIQUE,
        authorization_digest TEXT NOT NULL,
        canonical_intent BLOB NOT NULL,
        canonical_authorization BLOB NOT NULL
    ) STRICT
    """
_EVENTS_TABLE_SQL = """
    CREATE TABLE external_delivery_events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        intent_id TEXT NOT NULL REFERENCES external_delivery_intents(intent_id),
        ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 5),
        event_kind TEXT NOT NULL CHECK (event_kind IN (
            'intent-recorded',
            'attempt-started',
            'reconciled-not-received',
            'delivery-accepted'
        )),
        attempt_ordinal INTEGER CHECK (attempt_ordinal BETWEEN 1 AND 2),
        occurred_at TEXT NOT NULL,
        canonical_response BLOB,
        canonical_receipt BLOB,
        previous_event_digest TEXT,
        event_digest TEXT NOT NULL,
        UNIQUE(intent_id, ordinal),
        CHECK (
            (event_kind = 'intent-recorded'
             AND attempt_ordinal IS NULL
             AND canonical_response IS NULL
             AND canonical_receipt IS NULL)
            OR
            (event_kind = 'attempt-started'
             AND attempt_ordinal IS NOT NULL
             AND canonical_response IS NULL
             AND canonical_receipt IS NULL)
            OR
            (event_kind = 'reconciled-not-received'
             AND attempt_ordinal IS NOT NULL
             AND canonical_response IS NOT NULL
             AND canonical_receipt IS NULL)
            OR
            (event_kind = 'delivery-accepted'
             AND attempt_ordinal IS NOT NULL
             AND canonical_response IS NOT NULL
             AND canonical_receipt IS NOT NULL)
        )
    ) STRICT
    """
_EVENTS_INDEX_SQL = (
    "CREATE INDEX external_delivery_events_intent_idx "
    "ON external_delivery_events(intent_id, ordinal)"
)
_IMMUTABLE_TRIGGER_SQL = {
    ("trigger", "external_delivery_metadata_no_update"): """
        CREATE TRIGGER external_delivery_metadata_no_update
        BEFORE UPDATE ON external_delivery_metadata
        BEGIN SELECT RAISE(ABORT, 'External delivery metadata is immutable'); END
        """,
    ("trigger", "external_delivery_metadata_no_delete"): """
        CREATE TRIGGER external_delivery_metadata_no_delete
        BEFORE DELETE ON external_delivery_metadata
        BEGIN SELECT RAISE(ABORT, 'External delivery metadata is immutable'); END
        """,
    ("trigger", "external_delivery_intents_no_update"): """
        CREATE TRIGGER external_delivery_intents_no_update
        BEFORE UPDATE ON external_delivery_intents
        BEGIN SELECT RAISE(ABORT, 'External delivery intents are immutable'); END
        """,
    ("trigger", "external_delivery_intents_no_delete"): """
        CREATE TRIGGER external_delivery_intents_no_delete
        BEFORE DELETE ON external_delivery_intents
        BEGIN SELECT RAISE(ABORT, 'External delivery intents are append-only'); END
        """,
    ("trigger", "external_delivery_events_no_update"): """
        CREATE TRIGGER external_delivery_events_no_update
        BEFORE UPDATE ON external_delivery_events
        BEGIN SELECT RAISE(ABORT, 'External delivery events are append-only'); END
        """,
    ("trigger", "external_delivery_events_no_delete"): """
        CREATE TRIGGER external_delivery_events_no_delete
        BEFORE DELETE ON external_delivery_events
        BEGIN SELECT RAISE(ABORT, 'External delivery events are append-only'); END
        """,
}
_SCHEMA_OBJECT_SQL = {
    ("table", "external_delivery_metadata"): _METADATA_TABLE_SQL,
    ("table", "external_delivery_intents"): _INTENTS_TABLE_SQL,
    ("table", "external_delivery_events"): _EVENTS_TABLE_SQL,
    ("index", "external_delivery_events_intent_idx"): _EVENTS_INDEX_SQL,
    **_IMMUTABLE_TRIGGER_SQL,
}
_TABLES = frozenset(
    {
        "external_delivery_metadata",
        "external_delivery_intents",
        "external_delivery_events",
    }
)
_SCHEMA_DIGEST = sha256(
    canonical_json_bytes(
        {
            f"{kind}:{name}": " ".join(statement.split())
            for (kind, name), statement in sorted(_SCHEMA_OBJECT_SQL.items())
        },
        label="External delivery journal schema",
    )
).hexdigest()


class SQLiteExternalDeliveryJournal:
    """Host-local append-only intent and outcome journal with no automatic retry."""

    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = Path(os.path.abspath(path))
        self._clock = clock or (lambda: datetime.now(UTC))
        _initialize_journal(self.path)

    def register(
        self,
        intent: ExternalDeliveryIntent,
        authorization: ExternalDeliveryAuthorization,
    ) -> ExternalDeliveryRecord:
        intent = _canonical_model(intent, ExternalDeliveryIntent)
        authorization = _canonical_model(authorization, ExternalDeliveryAuthorization)
        _require_authorization_binding(intent, authorization)
        try:
            with _write_transaction(self.path) as connection:
                _validate_schema(connection)
                existing = connection.execute(
                    "SELECT * FROM external_delivery_intents WHERE intent_id = ?",
                    (intent.intent_id,),
                ).fetchone()
                if existing is not None:
                    current = _record_from_row(connection, cast(sqlite3.Row, existing))
                    if current.intent != intent or current.authorization != authorization:
                        raise ExternalDeliveryError(
                            "External delivery intent conflicts with durable authority"
                        )
                    return current
                connection.execute(
                    """
                    INSERT INTO external_delivery_intents (
                        intent_id, intent_digest, idempotency_key, sink_digest,
                        payload_digest, authorization_id, authorization_digest,
                        canonical_intent, canonical_authorization
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        intent.intent_id,
                        intent.intent_digest,
                        intent.idempotency_key,
                        intent.sink_digest,
                        intent.payload_digest,
                        authorization.authorization_id,
                        authorization.authorization_digest,
                        sqlite3.Binary(_model_bytes(intent, label="External delivery intent")),
                        sqlite3.Binary(
                            _model_bytes(
                                authorization,
                                label="External delivery authorization",
                            )
                        ),
                    ),
                )
                self._append_event(
                    connection,
                    intent_id=intent.intent_id,
                    event_kind="intent-recorded",
                    attempt_ordinal=None,
                    response=None,
                    receipt=None,
                )
                return _record_from_row(connection, _load_intent(connection, intent.intent_id))
        except ExternalDeliveryError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise ExternalDeliveryError("External delivery registration failed closed") from exc

    def begin_attempt(
        self,
        record: ExternalDeliveryRecord,
        *,
        attempt_ordinal: int,
    ) -> ExternalDeliveryRecord:
        expected = _canonical_model(record, ExternalDeliveryRecord)
        if type(attempt_ordinal) is not int or attempt_ordinal not in {1, 2}:
            raise ExternalDeliveryError("External delivery attempt ordinal is invalid")
        try:
            with _write_transaction(self.path) as connection:
                _validate_schema(connection)
                current = _record_from_row(
                    connection,
                    _load_intent(connection, expected.intent.intent_id),
                )
                if current != expected:
                    raise ExternalDeliveryError("External delivery claim differs from journal head")
                required_state = (
                    ExternalDeliveryState.READY_INITIAL
                    if attempt_ordinal == 1
                    else ExternalDeliveryState.READY_RETRY
                )
                if (
                    current.state is not required_state
                    or attempt_ordinal != current.attempt_count + 1
                ):
                    raise ExternalDeliveryError("External delivery attempt is not authorized")
                self._append_event(
                    connection,
                    intent_id=current.intent.intent_id,
                    event_kind="attempt-started",
                    attempt_ordinal=attempt_ordinal,
                    response=None,
                    receipt=None,
                )
                return _record_from_row(
                    connection,
                    _load_intent(connection, current.intent.intent_id),
                )
        except ExternalDeliveryError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise ExternalDeliveryError("External delivery attempt claim failed closed") from exc

    def record_accepted(
        self,
        record: ExternalDeliveryRecord,
        response: ExternalDeliverySinkResponse,
        receipt: ExternalDeliveryReceipt,
    ) -> ExternalDeliveryRecord:
        return self._record_outcome(record, response=response, receipt=receipt)

    def record_not_received(
        self,
        record: ExternalDeliveryRecord,
        response: ExternalDeliverySinkResponse,
    ) -> ExternalDeliveryRecord:
        return self._record_outcome(record, response=response, receipt=None)

    def inspect(self, intent_id: str) -> ExternalDeliveryRecord:
        if not isinstance(intent_id, str) or not intent_id:
            raise ExternalDeliveryError("External delivery Intent ID is invalid")
        try:
            with _readonly_connection(self.path) as connection:
                _validate_schema(connection)
                return _record_from_row(connection, _load_intent(connection, intent_id))
        except ExternalDeliveryError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise ExternalDeliveryError("External delivery inspection failed closed") from exc

    def _record_outcome(
        self,
        record: ExternalDeliveryRecord,
        *,
        response: ExternalDeliverySinkResponse,
        receipt: ExternalDeliveryReceipt | None,
    ) -> ExternalDeliveryRecord:
        expected = _canonical_model(record, ExternalDeliveryRecord)
        response = _canonical_model(response, ExternalDeliverySinkResponse)
        receipt = (
            _canonical_model(receipt, ExternalDeliveryReceipt) if receipt is not None else None
        )
        try:
            with _write_transaction(self.path) as connection:
                _validate_schema(connection)
                current = _record_from_row(
                    connection,
                    _load_intent(connection, expected.intent.intent_id),
                )
                if (
                    current != expected
                    or current.state is not ExternalDeliveryState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                ):
                    raise ExternalDeliveryError(
                        "External delivery outcome differs from journal head"
                    )
                _require_response_binding(current.intent, response, current.attempt_count)
                if response.outcome == "accepted":
                    if receipt is None:
                        raise ExternalDeliveryError("Accepted delivery outcome requires a receipt")
                    _require_receipt_binding(current, response, receipt)
                    event_kind = "delivery-accepted"
                else:
                    if receipt is not None:
                        raise ExternalDeliveryError(
                            "Not-received delivery cannot contain a receipt"
                        )
                    event_kind = "reconciled-not-received"
                self._append_event(
                    connection,
                    intent_id=current.intent.intent_id,
                    event_kind=event_kind,
                    attempt_ordinal=current.attempt_count,
                    response=response,
                    receipt=receipt,
                )
                return _record_from_row(
                    connection,
                    _load_intent(connection, current.intent.intent_id),
                )
        except ExternalDeliveryError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise ExternalDeliveryError(
                "External delivery outcome recording failed closed"
            ) from exc

    def _append_event(
        self,
        connection: sqlite3.Connection,
        *,
        intent_id: str,
        event_kind: str,
        attempt_ordinal: int | None,
        response: ExternalDeliverySinkResponse | None,
        receipt: ExternalDeliveryReceipt | None,
    ) -> None:
        previous = connection.execute(
            """
            SELECT ordinal, event_digest
            FROM external_delivery_events
            WHERE intent_id = ?
            ORDER BY ordinal DESC
            LIMIT 1
            """,
            (intent_id,),
        ).fetchone()
        ordinal = 1 if previous is None else int(previous["ordinal"]) + 1
        previous_digest = None if previous is None else str(previous["event_digest"])
        occurred_at = _format_timestamp(self._now())
        response_bytes = (
            _model_bytes(response, label="External delivery sink response")
            if response is not None
            else None
        )
        receipt_bytes = (
            _model_bytes(receipt, label="External delivery receipt")
            if receipt is not None
            else None
        )
        event_digest = _event_digest(
            intent_id=intent_id,
            ordinal=ordinal,
            event_kind=event_kind,
            attempt_ordinal=attempt_ordinal,
            occurred_at=occurred_at,
            response_digest=response.response_digest if response else None,
            receipt_digest=receipt.receipt_digest if receipt else None,
            previous_event_digest=previous_digest,
        )
        connection.execute(
            """
            INSERT INTO external_delivery_events (
                intent_id, ordinal, event_kind, attempt_ordinal, occurred_at,
                canonical_response, canonical_receipt, previous_event_digest, event_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                intent_id,
                ordinal,
                event_kind,
                attempt_ordinal,
                occurred_at,
                sqlite3.Binary(response_bytes) if response_bytes is not None else None,
                sqlite3.Binary(receipt_bytes) if receipt_bytes is not None else None,
                previous_digest,
                event_digest,
            ),
        )

    def _now(self) -> datetime:
        return _aware_utc(self._clock(), "External delivery journal clock")


class ExternalDeliveryCoordinator:
    """Compose registered identity, approval, secret lease, journal, and transport."""

    def __init__(
        self,
        *,
        sinks: ExternalDeliverySinkRegistry,
        authorizations: ExternalDeliveryAuthorizationAuthority,
        secrets: SecretBroker,
        journal: SQLiteExternalDeliveryJournal,
        transport: ExternalDeliveryTransport,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not hasattr(authorizations, "verify_external_delivery_authorization"):
            raise TypeError("External delivery authorization authority is invalid")
        self._sinks = sinks
        self._authorizations = authorizations
        self._secrets = secrets
        self._journal = journal
        self._transport = transport
        self._clock = clock or (lambda: datetime.now(UTC))

    def register(
        self,
        export: VerifiedSarifExport,
        intent: ExternalDeliveryIntent,
        authorization: ExternalDeliveryAuthorization,
    ) -> ExternalDeliveryRecord:
        intent = _canonical_model(intent, ExternalDeliveryIntent)
        authorization = _canonical_model(authorization, ExternalDeliveryAuthorization)
        sink = self._sinks.resolve(intent.sink_id)
        _require_exact_delivery_context(export, sink, intent)
        self._verify_authorization(intent, authorization)
        return self._journal.register(intent, authorization)

    def dispatch_once(
        self,
        record: ExternalDeliveryRecord,
        export: VerifiedSarifExport,
        lease: SecretLease,
    ) -> ExternalDeliveryRecord:
        current, sink = self._verified_current_context(record, export)
        attempt = current.attempt_count + 1
        if current.state not in {
            ExternalDeliveryState.READY_INITIAL,
            ExternalDeliveryState.READY_RETRY,
        }:
            raise ExternalDeliveryError("External delivery dispatch is not available")
        _require_lease_metadata(
            lease,
            sink=sink,
            intent=current.intent,
            operation="dispatch",
            attempt_ordinal=attempt,
            evaluated_at=self._now(),
        )
        claimed = self._journal.begin_attempt(current, attempt_ordinal=attempt)
        try:
            material = self._secrets.materialize(
                lease.lease_id,
                audience=sink.sink_id,
                scope=current.intent.source_run_id,
            )
            _require_secret_material_binding(
                material,
                intent=current.intent,
                operation="dispatch",
                attempt_ordinal=attempt,
            )
            payload = export.content.encode("utf-8", errors="strict")
            http_response = self._transport.dispatch(
                sink,
                current.intent,
                payload,
                material,
                attempt_ordinal=attempt,
            )
            response = _verified_sink_response(
                http_response,
                intent=current.intent,
                secret=material,
                attempt_ordinal=attempt,
                allowed_statuses={200, 201, 202},
            )
            if response.outcome != "accepted":
                raise ExternalDeliveryError(
                    "Mutating delivery response did not authenticate acceptance"
                )
            receipt = _build_receipt(claimed, response)
            return self._journal.record_accepted(claimed, response, receipt)
        except ExternalDeliveryError as exc:
            raise ExternalDeliveryOutcomeUnknownError(
                "External delivery outcome is unknown; reconciliation is required"
            ) from exc
        except (OSError, RuntimeError, TypeError, ValidationError, ValueError) as exc:
            raise ExternalDeliveryOutcomeUnknownError(
                "External delivery outcome is unknown; reconciliation is required"
            ) from exc

    def reconcile(
        self,
        record: ExternalDeliveryRecord,
        export: VerifiedSarifExport,
        lease: SecretLease,
    ) -> ExternalDeliveryRecord:
        current, sink = self._verified_current_context(record, export)
        if current.state is not ExternalDeliveryState.DISPATCH_STARTED_OUTCOME_UNKNOWN:
            raise ExternalDeliveryError("External delivery reconciliation is not required")
        attempt = current.attempt_count
        _require_lease_metadata(
            lease,
            sink=sink,
            intent=current.intent,
            operation="reconcile",
            attempt_ordinal=attempt,
            evaluated_at=self._now(),
        )
        try:
            material = self._secrets.materialize(
                lease.lease_id,
                audience=sink.sink_id,
                scope=current.intent.source_run_id,
            )
            _require_secret_material_binding(
                material,
                intent=current.intent,
                operation="reconcile",
                attempt_ordinal=attempt,
            )
            http_response = self._transport.reconcile(
                sink,
                current.intent,
                material,
                attempt_ordinal=attempt,
            )
            response = _verified_sink_response(
                http_response,
                intent=current.intent,
                secret=material,
                attempt_ordinal=attempt,
                allowed_statuses={200},
            )
            if response.outcome == "accepted":
                receipt = _build_receipt(current, response)
                return self._journal.record_accepted(current, response, receipt)
            return self._journal.record_not_received(current, response)
        except ExternalDeliveryError:
            raise
        except (OSError, RuntimeError, TypeError, ValidationError, ValueError) as exc:
            raise ExternalDeliveryError("External delivery reconciliation failed closed") from exc

    def _verified_current_context(
        self,
        record: ExternalDeliveryRecord,
        export: VerifiedSarifExport,
    ) -> tuple[ExternalDeliveryRecord, ExternalDeliverySink]:
        record = _canonical_model(record, ExternalDeliveryRecord)
        current = self._journal.inspect(record.intent.intent_id)
        if current != record:
            raise ExternalDeliveryError("External delivery request differs from journal head")
        sink = self._sinks.resolve(current.intent.sink_id)
        _require_exact_delivery_context(export, sink, current.intent)
        self._verify_authorization(current.intent, current.authorization)
        return current, sink

    def _verify_authorization(
        self,
        intent: ExternalDeliveryIntent,
        authorization: ExternalDeliveryAuthorization,
    ) -> None:
        _require_authorization_binding(intent, authorization)
        try:
            self._authorizations.verify_external_delivery_authorization(
                intent.model_copy(deep=True),
                authorization.model_copy(deep=True),
                evaluated_at=self._now(),
            )
        except (PermissionError, RuntimeError, TypeError, ValidationError, ValueError) as exc:
            raise ExternalDeliveryError("External delivery authorization was rejected") from exc

    def _now(self) -> datetime:
        return _aware_utc(self._clock(), "External delivery coordinator clock")


def build_external_delivery_intent(
    export: VerifiedSarifExport,
    sink: ExternalDeliverySink,
) -> ExternalDeliveryIntent:
    """Build the deterministic idempotency boundary for one exact verified export."""

    sink = _canonical_model(sink, ExternalDeliverySink)
    current = _require_exact_export(export)
    payload = current.content.encode("utf-8", errors="strict")
    if len(payload) > _MAX_PAYLOAD_BYTES:
        raise ExternalDeliveryError("External delivery payload exceeds the byte limit")
    return ExternalDeliveryIntent(
        sinkId=sink.sink_id,
        sinkDigest=sink.sink_digest,
        sourceRunId=current.source_run_id,
        sourceRootDigest=current.source_root_digest,
        sourceFindingSetDigest=current.finding_set_digest,
        payloadDigest=current.sarif_digest,
        payloadBytes=len(payload),
    )


def sign_external_delivery_sink_response(
    response: ExternalDeliverySinkResponse,
    *,
    secret_value: str,
) -> ExternalDeliverySinkResponse:
    """Sign a sink response using the connector's application response key."""

    response = _canonical_model(response, ExternalDeliverySinkResponse)
    signature = hmac.new(
        secret_value.encode("utf-8", errors="strict"),
        response.response_digest.encode("ascii", errors="strict"),
        sha256,
    ).hexdigest()
    return response.model_copy(update={"response_signature": signature})


def external_delivery_secret_binding(
    intent: ExternalDeliveryIntent,
    *,
    operation: Literal["dispatch", "reconcile"],
    attempt_ordinal: int,
) -> str:
    """Return the exact one-use SecretBroker lease binding for an operation."""

    intent = _canonical_model(intent, ExternalDeliveryIntent)
    if type(attempt_ordinal) is not int or attempt_ordinal not in {1, 2}:
        raise ValueError("External delivery secret binding attempt is invalid")
    return f"external-delivery:{intent.intent_digest}:{operation}:{attempt_ordinal}"


def _require_exact_delivery_context(
    export: VerifiedSarifExport,
    sink: ExternalDeliverySink,
    intent: ExternalDeliveryIntent,
) -> None:
    current = _require_exact_export(export)
    expected = build_external_delivery_intent(current, sink)
    if expected != intent:
        raise ExternalDeliveryError("External delivery intent differs from export or Sink")


def _require_exact_export(export: VerifiedSarifExport) -> VerifiedSarifExport:
    if not isinstance(export, VerifiedSarifExport):
        raise TypeError("External delivery requires a verified SARIF export")
    payload = export.content.encode("utf-8", errors="strict")
    if len(payload) > _MAX_PAYLOAD_BYTES:
        raise ExternalDeliveryError("External delivery SARIF payload is invalid")
    if sha256(payload).hexdigest() != export.sarif_digest:
        raise ExternalDeliveryError("External delivery SARIF digest differs")
    current = load_verified_sarif_export(
        export.source_run_path,
        expected_run_id=export.source_run_id,
        expected_root_digest=export.source_root_digest,
    )
    if current != export:
        raise ExternalDeliveryError("External delivery SARIF authority changed")
    return current


def _require_authorization_binding(
    intent: ExternalDeliveryIntent,
    authorization: ExternalDeliveryAuthorization,
) -> None:
    if (
        authorization.intent_id != intent.intent_id
        or authorization.intent_digest != intent.intent_digest
        or authorization.sink_id != intent.sink_id
        or authorization.sink_digest != intent.sink_digest
        or authorization.payload_digest != intent.payload_digest
        or authorization.idempotency_key != intent.idempotency_key
        or authorization.max_attempts != 2
        or not authorization.reconciliation_authorized
        or not authorization.external_delivery_authorized
        or authorization.automatic_retry_authorized
    ):
        raise ExternalDeliveryError("External delivery authorization differs from intent")


def _require_lease_metadata(
    lease: SecretLease,
    *,
    sink: ExternalDeliverySink,
    intent: ExternalDeliveryIntent,
    operation: Literal["dispatch", "reconcile"],
    attempt_ordinal: int,
    evaluated_at: datetime,
) -> None:
    if not isinstance(lease, SecretLease):
        raise ExternalDeliveryError("External delivery requires a SecretBroker lease")
    expected_binding = external_delivery_secret_binding(
        intent,
        operation=operation,
        attempt_ordinal=attempt_ordinal,
    )
    now = _aware_utc(evaluated_at, "External delivery lease evaluation time")
    if (
        lease.secret_ref_fingerprint != sink.secret_ref_fingerprint
        or lease.audience != sink.sink_id
        or lease.binding != expected_binding
        or lease.scope != intent.source_run_id
        or lease.status is not SecretLeaseStatus.ACTIVE
        or lease.max_uses != 1
        or lease.remaining_uses != 1
        or now < lease.issued_at
        or now >= lease.expires_at
    ):
        raise ExternalDeliveryError("External delivery secret lease differs")


def _require_secret_material_binding(
    material: SecretMaterial,
    *,
    intent: ExternalDeliveryIntent,
    operation: Literal["dispatch", "reconcile"],
    attempt_ordinal: int,
) -> None:
    expected = external_delivery_secret_binding(
        intent,
        operation=operation,
        attempt_ordinal=attempt_ordinal,
    )
    if material.binding != expected:
        raise ExternalDeliveryError("External delivery secret material binding differs")


def _request_headers(
    intent: ExternalDeliveryIntent,
    secret: SecretMaterial,
    *,
    attempt_ordinal: int,
) -> dict[str, str]:
    return {
        "Accept": "application/json",
        "Authorization": f"Bearer {secret.value}",
        "Content-Type": intent.payload_media_type,
        "Connection": "close",
        "User-Agent": "PAJIN external-delivery/v1alpha1",
        "X-PAJIN-Delivery-Intent": intent.intent_id,
        "X-PAJIN-Idempotency-Key": intent.idempotency_key,
        "X-PAJIN-Payload-SHA256": intent.payload_digest,
        "X-PAJIN-Attempt": str(attempt_ordinal),
    }


def _verified_sink_response(
    http_response: ExternalDeliveryHTTPResponse,
    *,
    intent: ExternalDeliveryIntent,
    secret: SecretMaterial,
    attempt_ordinal: int,
    allowed_statuses: set[int],
) -> ExternalDeliverySinkResponse:
    if not isinstance(http_response, ExternalDeliveryHTTPResponse):
        raise ExternalDeliveryError("External delivery transport response is invalid")
    if http_response.status_code not in allowed_statuses:
        raise ExternalDeliveryError("External delivery HTTP status is not accepted")
    media_type = http_response.content_type.split(";", maxsplit=1)[0].strip().lower()
    if media_type != "application/json":
        raise ExternalDeliveryError("External delivery response media type differs")
    try:
        parsed = parse_strict_json_bytes(
            http_response.body,
            label="External delivery sink response",
            max_bytes=_MAX_RESPONSE_BYTES,
            max_depth=16,
            max_nodes=256,
        )
        response = ExternalDeliverySinkResponse.model_validate(parsed)
    except (TypeError, UnicodeDecodeError, ValidationError, ValueError) as exc:
        raise ExternalDeliveryError("External delivery sink response is invalid") from exc
    _require_response_binding(intent, response, attempt_ordinal)
    expected_signature = hmac.new(
        secret.value.encode("utf-8", errors="strict"),
        response.response_digest.encode("ascii", errors="strict"),
        sha256,
    ).hexdigest()
    if not response.response_signature or not hmac.compare_digest(
        response.response_signature,
        expected_signature,
    ):
        raise ExternalDeliveryError("External delivery response authentication failed")
    return response


def _require_response_binding(
    intent: ExternalDeliveryIntent,
    response: ExternalDeliverySinkResponse,
    attempt_ordinal: int,
) -> None:
    if (
        response.intent_id != intent.intent_id
        or response.sink_id != intent.sink_id
        or response.idempotency_key != intent.idempotency_key
        or response.payload_digest != intent.payload_digest
        or response.attempt_ordinal != attempt_ordinal
    ):
        raise ExternalDeliveryError("External delivery response differs from exact intent")


def _build_receipt(
    record: ExternalDeliveryRecord,
    response: ExternalDeliverySinkResponse,
) -> ExternalDeliveryReceipt:
    if (
        response.outcome != "accepted"
        or response.external_receipt_id is None
        or response.accepted_at is None
    ):
        raise ExternalDeliveryError("External delivery receipt requires accepted response evidence")
    return ExternalDeliveryReceipt(
        intentId=record.intent.intent_id,
        intentDigest=record.intent.intent_digest,
        authorizationId=record.authorization.authorization_id,
        authorizationDigest=record.authorization.authorization_digest,
        sinkId=record.intent.sink_id,
        sinkDigest=record.intent.sink_digest,
        sourceRunId=record.intent.source_run_id,
        sourceRootDigest=record.intent.source_root_digest,
        sourceFindingSetDigest=record.intent.source_finding_set_digest,
        payloadDigest=record.intent.payload_digest,
        idempotencyKey=record.intent.idempotency_key,
        attemptOrdinal=response.attempt_ordinal,
        externalReceiptId=response.external_receipt_id,
        acceptedAt=response.accepted_at,
        authenticatedResponseDigest=response.response_digest,
    )


def _require_receipt_binding(
    record: ExternalDeliveryRecord,
    response: ExternalDeliverySinkResponse,
    receipt: ExternalDeliveryReceipt,
) -> None:
    if receipt != _build_receipt(record, response):
        raise ExternalDeliveryError("External delivery receipt differs from accepted response")


def _record_from_row(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
) -> ExternalDeliveryRecord:
    intent = _parse_model_bytes(
        _required_bytes(row, "canonical_intent"),
        ExternalDeliveryIntent,
        label="External delivery intent",
    )
    authorization = _parse_model_bytes(
        _required_bytes(row, "canonical_authorization"),
        ExternalDeliveryAuthorization,
        label="External delivery authorization",
    )
    if (
        row["intent_id"] != intent.intent_id
        or row["intent_digest"] != intent.intent_digest
        or row["idempotency_key"] != intent.idempotency_key
        or row["sink_digest"] != intent.sink_digest
        or row["payload_digest"] != intent.payload_digest
        or row["authorization_id"] != authorization.authorization_id
        or row["authorization_digest"] != authorization.authorization_digest
    ):
        raise ExternalDeliveryError("External delivery journal intent index differs")
    _require_authorization_binding(intent, authorization)

    events = connection.execute(
        """
        SELECT * FROM external_delivery_events
        WHERE intent_id = ?
        ORDER BY ordinal ASC
        """,
        (intent.intent_id,),
    ).fetchall()
    if not events:
        raise ExternalDeliveryError("External delivery journal has no intent event")
    state = ExternalDeliveryState.READY_INITIAL
    attempt_count = 0
    receipt: ExternalDeliveryReceipt | None = None
    last_response: ExternalDeliverySinkResponse | None = None
    event_digests: list[str] = []
    previous_digest: str | None = None
    for index, event in enumerate(events, start=1):
        if int(event["ordinal"]) != index or event["previous_event_digest"] != previous_digest:
            raise ExternalDeliveryError("External delivery event chain order differs")
        event_kind = str(event["event_kind"])
        attempt_raw = event["attempt_ordinal"]
        attempt = int(attempt_raw) if attempt_raw is not None else None
        response = _optional_model_bytes(
            event["canonical_response"],
            ExternalDeliverySinkResponse,
            label="External delivery sink response",
        )
        event_receipt = _optional_model_bytes(
            event["canonical_receipt"],
            ExternalDeliveryReceipt,
            label="External delivery receipt",
        )
        observed_digest = _event_digest(
            intent_id=intent.intent_id,
            ordinal=index,
            event_kind=event_kind,
            attempt_ordinal=attempt,
            occurred_at=str(event["occurred_at"]),
            response_digest=response.response_digest if response else None,
            receipt_digest=event_receipt.receipt_digest if event_receipt else None,
            previous_event_digest=previous_digest,
        )
        if event["event_digest"] != observed_digest:
            raise ExternalDeliveryError("External delivery event digest differs")
        state, attempt_count, last_response, receipt = _advance_state(
            state=state,
            attempt_count=attempt_count,
            event_index=index,
            event_kind=event_kind,
            attempt_ordinal=attempt,
            response=response,
            receipt=event_receipt,
            intent=intent,
            authorization=authorization,
        )
        event_digests.append(observed_digest)
        previous_digest = observed_digest
    return ExternalDeliveryRecord(
        intent=intent,
        authorization=authorization,
        state=state,
        attemptCount=attempt_count,
        retryAuthorized=state is ExternalDeliveryState.READY_RETRY,
        manualReviewRequired=(state is ExternalDeliveryState.DISPATCH_STARTED_OUTCOME_UNKNOWN),
        receipt=receipt,
        lastResponse=last_response,
        eventDigests=tuple(event_digests),
    )


def _advance_state(
    *,
    state: ExternalDeliveryState,
    attempt_count: int,
    event_index: int,
    event_kind: str,
    attempt_ordinal: int | None,
    response: ExternalDeliverySinkResponse | None,
    receipt: ExternalDeliveryReceipt | None,
    intent: ExternalDeliveryIntent,
    authorization: ExternalDeliveryAuthorization,
) -> tuple[
    ExternalDeliveryState,
    int,
    ExternalDeliverySinkResponse | None,
    ExternalDeliveryReceipt | None,
]:
    if event_index == 1:
        if (
            event_kind != "intent-recorded"
            or attempt_ordinal is not None
            or response is not None
            or receipt is not None
        ):
            raise ExternalDeliveryError("External delivery initial event differs")
        return ExternalDeliveryState.READY_INITIAL, 0, None, None
    if event_kind == "attempt-started":
        expected_state = (
            ExternalDeliveryState.READY_INITIAL
            if attempt_count == 0
            else ExternalDeliveryState.READY_RETRY
        )
        if (
            state is not expected_state
            or attempt_ordinal != attempt_count + 1
            or response is not None
            or receipt is not None
        ):
            raise ExternalDeliveryError("External delivery attempt event differs")
        return (
            ExternalDeliveryState.DISPATCH_STARTED_OUTCOME_UNKNOWN,
            attempt_count + 1,
            None,
            None,
        )
    if state is not ExternalDeliveryState.DISPATCH_STARTED_OUTCOME_UNKNOWN:
        raise ExternalDeliveryError("External delivery terminal event has no pending attempt")
    if response is None or attempt_ordinal != attempt_count:
        raise ExternalDeliveryError("External delivery response event differs from attempt")
    _require_response_binding(intent, response, attempt_count)
    if event_kind == "reconciled-not-received":
        if response.outcome != "not-received" or receipt is not None:
            raise ExternalDeliveryError("External delivery reconciliation event differs")
        next_state = (
            ExternalDeliveryState.READY_RETRY
            if attempt_count == 1
            else ExternalDeliveryState.TERMINAL_NOT_DELIVERED
        )
        return next_state, attempt_count, response, None
    if event_kind == "delivery-accepted":
        if response.outcome != "accepted" or receipt is None:
            raise ExternalDeliveryError("External delivery acceptance event differs")
        provisional = ExternalDeliveryRecord(
            intent=intent,
            authorization=authorization,
            state=ExternalDeliveryState.DISPATCH_STARTED_OUTCOME_UNKNOWN,
            attemptCount=attempt_count,
            retryAuthorized=False,
            manualReviewRequired=True,
            eventDigests=("0" * 64,),
        )
        _require_receipt_binding(provisional, response, receipt)
        return ExternalDeliveryState.DELIVERED, attempt_count, response, receipt
    raise ExternalDeliveryError("External delivery event kind differs from lifecycle")


def _event_digest(
    *,
    intent_id: str,
    ordinal: int,
    event_kind: str,
    attempt_ordinal: int | None,
    occurred_at: str,
    response_digest: str | None,
    receipt_digest: str | None,
    previous_event_digest: str | None,
) -> str:
    return _digest(
        "pajin.reporting.external-delivery-event/v1",
        {
            "intentId": intent_id,
            "ordinal": ordinal,
            "eventKind": event_kind,
            "attemptOrdinal": attempt_ordinal,
            "occurredAt": occurred_at,
            "responseDigest": response_digest,
            "receiptDigest": receipt_digest,
            "previousEventDigest": previous_event_digest,
        },
    )


def _initialize_journal(path: Path) -> None:
    _require_safe_journal_path(path)
    _require_safe_journal_sidecars(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        path.parent.chmod(0o700)
    _require_safe_journal_path(path)
    existing_size = path.stat().st_size if path.exists() else 0
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            path,
            isolation_level=None,
            timeout=_BUSY_TIMEOUT_MS / 1_000,
        )
        connection.row_factory = sqlite3.Row
        _configure_connection(connection)
        connection.execute("BEGIN IMMEDIATE")
        if not _application_tables(connection):
            if existing_size != 0:
                raise ExternalDeliveryError(
                    "Existing external delivery journal has no trusted schema"
                )
            mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
            if mode is None or str(mode[0]).lower() != "delete":
                raise ExternalDeliveryError(
                    "External delivery journal requires DELETE journal mode"
                )
            for statement in _SCHEMA_OBJECT_SQL.values():
                connection.execute(statement)
            connection.executemany(
                "INSERT INTO external_delivery_metadata(key, value) VALUES (?, ?)",
                (
                    ("schema_version", str(_SCHEMA_VERSION)),
                    ("schema_digest", _SCHEMA_DIGEST),
                ),
            )
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
        _validate_schema(connection)
        connection.execute("COMMIT")
        if os.name == "posix":
            path.chmod(0o600)
    except BaseException:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        if connection is not None:
            connection.close()
    _require_safe_journal_path(path)
    _require_safe_journal_sidecars(path)


@contextmanager
def _write_transaction(path: Path) -> Iterator[sqlite3.Connection]:
    with _journal_connection(path, readonly=False) as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise


@contextmanager
def _readonly_connection(path: Path) -> Iterator[sqlite3.Connection]:
    with _journal_connection(path, readonly=True) as connection:
        connection.execute("BEGIN")
        try:
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise


@contextmanager
def _journal_connection(path: Path, *, readonly: bool) -> Iterator[sqlite3.Connection]:
    _require_safe_journal_path(path)
    _require_safe_journal_sidecars(path)
    identity = _file_identity(path)
    target: str | Path = f"{path.as_uri()}?mode=ro" if readonly else path
    connection = sqlite3.connect(
        target,
        uri=readonly,
        isolation_level=None,
        timeout=_BUSY_TIMEOUT_MS / 1_000,
    )
    connection.row_factory = sqlite3.Row
    _configure_connection(connection)
    if _file_identity(path) != identity:
        connection.close()
        raise ExternalDeliveryError("External delivery journal changed while opening")
    try:
        yield connection
    finally:
        connection.close()
        _require_safe_journal_path(path)
        _require_safe_journal_sidecars(path)


def _configure_connection(connection: sqlite3.Connection) -> None:
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA synchronous = FULL")
    connection.execute("PRAGMA trusted_schema = OFF")


def _validate_schema(connection: sqlite3.Connection) -> None:
    if _application_tables(connection) != _TABLES:
        raise ExternalDeliveryError("External delivery journal table set differs")
    metadata = dict(connection.execute("SELECT key, value FROM external_delivery_metadata"))
    application_id = connection.execute("PRAGMA application_id").fetchone()
    user_version = connection.execute("PRAGMA user_version").fetchone()
    journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
    if (
        metadata != {"schema_version": str(_SCHEMA_VERSION), "schema_digest": _SCHEMA_DIGEST}
        or application_id is None
        or int(application_id[0]) != _APPLICATION_ID
        or user_version is None
        or int(user_version[0]) != _SCHEMA_VERSION
        or journal_mode is None
        or str(journal_mode[0]).lower() != "delete"
    ):
        raise ExternalDeliveryError("External delivery journal metadata differs")
    rows = connection.execute(
        """
        SELECT type, name, sql FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%'
        """
    ).fetchall()
    observed = {
        (str(row["type"]), str(row["name"])): " ".join(str(row["sql"]).split()) for row in rows
    }
    expected = {key: " ".join(statement.split()) for key, statement in _SCHEMA_OBJECT_SQL.items()}
    if observed != expected:
        raise ExternalDeliveryError("External delivery journal schema differs")
    integrity = connection.execute("PRAGMA integrity_check").fetchone()
    if integrity is None or str(integrity[0]).lower() != "ok":
        raise ExternalDeliveryError("External delivery journal integrity check failed")


def _application_tables(connection: sqlite3.Connection) -> frozenset[str]:
    return frozenset(
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
    )


def _require_safe_journal_path(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    for parent in absolute.parents:
        if parent.exists() and _is_link_or_junction(parent):
            raise ExternalDeliveryError("External delivery journal ancestor is unsafe")
    if absolute.parent.exists() and not absolute.parent.is_dir():
        raise ExternalDeliveryError("External delivery journal parent is unsafe")
    if absolute.exists():
        metadata = os.lstat(absolute)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or _is_link_or_junction(absolute)
            or metadata.st_nlink != 1
        ):
            raise ExternalDeliveryError(
                "External delivery journal is not a single-link regular file"
            )


def _require_safe_journal_sidecars(path: Path) -> None:
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if not sidecar.exists():
            continue
        metadata = os.lstat(sidecar)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or _is_link_or_junction(sidecar)
            or metadata.st_nlink != 1
        ):
            raise ExternalDeliveryError(
                "External delivery journal sidecar is not a single-link regular file"
            )


def _is_link_or_junction(path: Path) -> bool:
    metadata = os.lstat(path)
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def _file_identity(path: Path) -> tuple[int, int, int, int]:
    metadata = path.stat()
    return metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns


def _load_intent(connection: sqlite3.Connection, intent_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM external_delivery_intents WHERE intent_id = ?",
        (intent_id,),
    ).fetchone()
    if row is None:
        raise ExternalDeliveryError("External delivery Intent is not recorded")
    return cast(sqlite3.Row, row)


def _required_bytes(row: sqlite3.Row, field: str) -> bytes:
    value = row[field]
    if not isinstance(value, bytes):
        raise ExternalDeliveryError(f"External delivery journal {field} is invalid")
    return value


def _optional_model_bytes[ModelT: StrictModel](
    raw: object,
    model: type[ModelT],
    *,
    label: str,
) -> ModelT | None:
    if raw is None:
        return None
    if not isinstance(raw, bytes):
        raise ExternalDeliveryError(f"{label} journal bytes are invalid")
    return _parse_model_bytes(raw, model, label=label)


def _parse_model_bytes[ModelT: StrictModel](
    raw: bytes,
    model: type[ModelT],
    *,
    label: str,
) -> ModelT:
    parsed = parse_strict_json_bytes(
        raw,
        label=label,
        max_bytes=_MAX_MODEL_BYTES,
        max_depth=32,
        max_nodes=10_000,
    )
    value = model.model_validate(parsed)
    if raw != _model_bytes(value, label=label):
        raise ExternalDeliveryError(f"{label} journal bytes are not canonical")
    return value


def _canonical_model[ModelT: StrictModel](value: ModelT, model: type[ModelT]) -> ModelT:
    if not isinstance(value, model):
        raise TypeError(f"Expected {model.__name__}")
    return model.model_validate(value.model_dump(mode="json", by_alias=True))


def _model_bytes(value: StrictModel, *, label: str) -> bytes:
    return canonical_json_bytes(
        value.model_dump(mode="json", by_alias=True),
        label=label,
        max_bytes=_MAX_MODEL_BYTES,
    )


def _validated_https_endpoint(value: str, *, label: str) -> tuple[str, str, int]:
    try:
        value.encode("ascii", errors="strict")
        parsed = urlsplit(value)
        port = parsed.port or 443
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"{label} is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or not 1 <= port <= 65_535
    ):
        raise ValueError(f"{label} must be an exact credential-free HTTPS URL")
    return parsed.scheme, parsed.hostname.lower(), port


def _digest(domain: str, value: object) -> str:
    return sha256(
        domain.encode("ascii", errors="strict")
        + b"\x00"
        + canonical_json_bytes(
            value,
            label="External delivery identity",
            max_bytes=_MAX_MODEL_BYTES,
        )
    ).hexdigest()


def _aware_utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _format_timestamp(value: datetime) -> str:
    return _aware_utc(value, "External delivery timestamp").isoformat().replace("+00:00", "Z")


__all__ = [
    "EXTERNAL_DELIVERY_AUTHORIZATION_API_VERSION",
    "EXTERNAL_DELIVERY_INTENT_API_VERSION",
    "EXTERNAL_DELIVERY_RECEIPT_API_VERSION",
    "EXTERNAL_DELIVERY_RECORD_API_VERSION",
    "EXTERNAL_DELIVERY_SINK_API_VERSION",
    "EXTERNAL_DELIVERY_SINK_RESPONSE_API_VERSION",
    "ExternalDeliveryAuthorization",
    "ExternalDeliveryAuthorizationAuthority",
    "ExternalDeliveryAuthorizationRegistry",
    "ExternalDeliveryCoordinator",
    "ExternalDeliveryError",
    "ExternalDeliveryHTTPResponse",
    "ExternalDeliveryIntent",
    "ExternalDeliveryOutcomeUnknownError",
    "ExternalDeliveryReceipt",
    "ExternalDeliveryRecord",
    "ExternalDeliverySink",
    "ExternalDeliverySinkRegistry",
    "ExternalDeliverySinkResponse",
    "ExternalDeliveryState",
    "ExternalDeliveryTransport",
    "HTTPSExternalDeliveryTransport",
    "SQLiteExternalDeliveryJournal",
    "build_external_delivery_intent",
    "external_delivery_secret_binding",
    "sign_external_delivery_sink_response",
]
