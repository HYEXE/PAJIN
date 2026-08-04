"""Receiver-bound, capability-scoped reads of existing sealed artifacts."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from re import fullmatch
from threading import RLock
from typing import Literal, Self

from pydantic import (
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from pajin.capabilities import capability_grant_digest
from pajin.collaboration.handoff import HandoffAgentRef
from pajin.collaboration.snapshots import (
    CollaborationSnapshot,
    CollaborationSnapshotError,
    SharedArtifactSource,
    verify_collaboration_snapshot,
)
from pajin.collaboration.terminal_result import (
    TerminalResultHandoff,
    TerminalResultHandoffAuthority,
    TerminalResultHandoffError,
)
from pajin.collaboration.urgent_observation import UrgentObservationFastGateAuthority
from pajin.domain.models import CapabilityGrant, StrictModel
from pajin.graph.models import canonical_graph_json, graph_digest
from pajin.graph.projection import GraphSnapshotStore
from pajin.policy.capability import CapabilityError, CapabilityLedger
from pajin.runtime.store import RunIntegrityError, load_verified_run_artifacts

RECEIVER_BOUND_ARTIFACT_READ_API_VERSION = (
    "pajin.dev/receiver-bound-artifact-read/v1alpha1"
)
COLLABORATION_ARTIFACT_READ_TOOL = "collaboration.artifact.read"
RECEIVER_BOUND_ARTIFACT_READ_TTL_SECONDS = 60
MAX_RECEIVER_BOUND_ARTIFACT_READ_BYTES = 64 * 1024
MAX_RECEIVER_BOUND_ARTIFACT_READS = 1
_MAX_RECEIPT_BYTES = 128 * 1024
_RECEIPT_ID_PATTERN = r"^receiver-artifact-read_[a-f0-9]{64}$"


def _system_utc_now() -> datetime:
    return datetime.now(UTC)


class ReceiverBoundArtifactReadError(ValueError):
    """Raised when an Artifact read is not exactly receiver and Capability bound."""


class CapabilityGrantRef(StrictModel):
    """Safe identity projection of one exact live Capability Grant."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    grant_id: str = Field(
        alias="grantId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    grant_digest: str = Field(alias="grantDigest", pattern=r"^[a-f0-9]{64}$")
    subject: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    campaign_id: str = Field(alias="campaignId", pattern=r"^[a-z0-9][a-z0-9-]*$")
    tool_id: Literal["collaboration.artifact.read"] = Field(
        default="collaboration.artifact.read", alias="toolId"
    )
    target_artifact_id: str = Field(
        alias="targetArtifactId", pattern=r"^shared-artifact_[a-f0-9]{64}$"
    )
    expires_at: datetime = Field(alias="expiresAt")

    @field_validator("expires_at")
    @classmethod
    def normalize_expires_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("receiver read Capability expiry requires an explicit UTC offset")
        return value.astimezone(UTC)


class ReceiverBoundArtifactReadReceipt(StrictModel):
    """Metadata-only receipt for one completed bounded content delivery."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/receiver-bound-artifact-read/v1alpha1"] = Field(
        default="pajin.dev/receiver-bound-artifact-read/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ReceiverBoundArtifactReadReceipt"] = (
        "ReceiverBoundArtifactReadReceipt"
    )
    receipt_id: str = Field(default="", alias="receiptId", max_length=87)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    authority_id: str = Field(
        alias="authorityId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    authority_digest: str = Field(alias="authorityDigest", pattern=r"^[a-f0-9]{64}$")
    terminal_result_handoff_id: str = Field(
        alias="terminalResultHandoffId",
        pattern=r"^terminal-result-handoff_[a-f0-9]{64}$",
    )
    terminal_result_handoff_digest: str = Field(
        alias="terminalResultHandoffDigest", pattern=r"^[a-f0-9]{64}$"
    )
    handoff_id: str = Field(alias="handoffId", pattern=r"^agent-handoff_[a-f0-9]{64}$")
    handoff_digest: str = Field(alias="handoffDigest", pattern=r"^[a-f0-9]{64}$")
    campaign_id: str = Field(alias="campaignId", pattern=r"^[a-z0-9][a-z0-9-]*$")
    collaboration_snapshot_id: str = Field(
        alias="collaborationSnapshotId",
        pattern=r"^collaboration-snapshot_[a-f0-9]{64}$",
    )
    collaboration_snapshot_digest: str = Field(
        alias="collaborationSnapshotDigest", pattern=r"^[a-f0-9]{64}$"
    )
    receiver: HandoffAgentRef
    artifact_id: str = Field(
        alias="artifactId", pattern=r"^shared-artifact_[a-f0-9]{64}$"
    )
    artifact_digest: str = Field(alias="artifactDigest", pattern=r"^[a-f0-9]{64}$")
    source_run_id: str = Field(
        alias="sourceRunId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    source_root_digest: str = Field(
        alias="sourceRootDigest", pattern=r"^[a-f0-9]{64}$"
    )
    capability: CapabilityGrantRef
    authorized_at: datetime = Field(alias="authorizedAt")
    expires_at: datetime = Field(alias="expiresAt")
    read_at: datetime = Field(alias="readAt")
    max_bytes: Literal[65536] = Field(
        default=65536, alias="maxBytes"
    )
    bytes_read: int = Field(alias="bytesRead", strict=True, ge=0)
    read_count: Literal[1] = Field(default=1, alias="readCount")
    cumulative_bytes: int = Field(alias="cumulativeBytes", strict=True, ge=0)
    content_embedded: Literal[False] = Field(default=False, alias="contentEmbedded")
    filesystem_path_exposed: Literal[False] = Field(
        default=False, alias="filesystemPathExposed"
    )
    prompt_interpretation_authorized: Literal[False] = Field(
        default=False, alias="promptInterpretationAuthorized"
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False, alias="scopeExpansionAuthorized"
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("authorized_at", "expires_at", "read_at")
    @classmethod
    def normalize_times(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("receiver read timestamps require an explicit UTC offset")
        return value.astimezone(UTC)

    @field_validator("max_bytes", "read_count", mode="before")
    @classmethod
    def require_fixed_integer_bounds(cls, value: object, info: ValidationInfo) -> object:
        expected = (
            MAX_RECEIVER_BOUND_ARTIFACT_READ_BYTES
            if info.field_name == "max_bytes"
            else 1
        )
        if type(value) is not int or value != expected:
            raise ValueError("receiver read fixed bounds differ")
        return value

    @field_validator(
        "content_embedded",
        "filesystem_path_exposed",
        "prompt_interpretation_authorized",
        "scope_expansion_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("receiver read authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        if (
            self.receiver.agent_id != self.capability.subject
            or self.campaign_id != self.capability.campaign_id
            or self.artifact_id != self.capability.target_artifact_id
            or self.bytes_read != self.cumulative_bytes
            or self.bytes_read > self.max_bytes
            or self.authorized_at > self.read_at
            or self.read_at >= self.expires_at
            or self.expires_at
            > self.authorized_at
            + timedelta(seconds=RECEIVER_BOUND_ARTIFACT_READ_TTL_SECONDS)
        ):
            raise ValueError("receiver read receipt exceeds its identity, byte, or TTL bound")
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"receipt_id", "receipt_digest"}
        )
        digest = graph_digest(
            "pajin.collaboration.receiver-bound-artifact-read/v1",
            material,
            max_bytes=_MAX_RECEIPT_BYTES,
        )
        receipt_id = f"receiver-artifact-read_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("receiver Artifact read receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("receiver Artifact read receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        if fullmatch(_RECEIPT_ID_PATTERN, self.receipt_id) is None:
            raise ValueError("receiver Artifact read receipt ID is malformed")
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="ReceiverBoundArtifactReadReceipt",
            max_bytes=_MAX_RECEIPT_BYTES,
        )
        return self


@dataclass(frozen=True, slots=True)
class ReceiverBoundArtifactReadOutcome:
    """Authorized bytes plus their metadata-only receipt."""

    receipt: ReceiverBoundArtifactReadReceipt
    content: bytes


class ReceiverBoundArtifactReader:
    """Single-use process-local reader over existing Grant and Run authorities."""

    def __init__(
        self,
        *,
        authority_id: str,
        authority_digest: str,
        capability_ledger: CapabilityLedger,
        urgent_observation_authority: UrgentObservationFastGateAuthority,
        clock: Callable[[], datetime] = _system_utc_now,
    ) -> None:
        if (
            fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", authority_id) is None
            or fullmatch(r"^[a-f0-9]{64}$", authority_digest) is None
        ):
            raise ValueError("receiver Artifact reader authority identity is invalid")
        self._authority_id = authority_id
        self._authority_digest = authority_digest
        self._capability_ledger = capability_ledger
        self._urgent_observation_authority = urgent_observation_authority
        self._clock = clock
        self._attempted: set[tuple[str, str, str]] = set()
        self._receipts: dict[tuple[str, str, str], ReceiverBoundArtifactReadReceipt] = {}
        self._lock = RLock()

    def read(
        self,
        *,
        terminal_result_authority: TerminalResultHandoffAuthority,
        terminal_result: TerminalResultHandoff,
        collaboration_snapshot: CollaborationSnapshot,
        graph_snapshot_store: GraphSnapshotStore,
        shared_artifact_source: SharedArtifactSource,
        capability_grant: CapabilityGrant,
    ) -> ReceiverBoundArtifactReadOutcome:
        try:
            result = terminal_result_authority.resolve(terminal_result)
            snapshot = verify_collaboration_snapshot(
                collaboration_snapshot,
                graph_snapshot_store=graph_snapshot_store,
                shared_artifact_sources=(shared_artifact_source,),
            )
            if (
                snapshot.collaboration_snapshot_id != result.collaboration_snapshot_id
                or snapshot.collaboration_snapshot_digest
                != result.collaboration_snapshot_digest
                or shared_artifact_source.reference != result.result_artifact
                or result.result_artifact not in snapshot.shared_artifacts
            ):
                raise ValueError("receiver read differs from terminal result authority")
            grant = CapabilityGrant.model_validate(
                capability_grant.model_dump(mode="python")
            )
            grant_record = self._capability_ledger.record(grant.grant_id)
            if (
                grant_record.grant != grant
                or grant_record.revoked
                or grant_record.remaining_calls != 1
                or grant.max_calls != 1
                or grant.subject != result.receiver.agent_id
                or grant.campaign != result.campaign_id
                or COLLABORATION_ARTIFACT_READ_TOOL not in grant.tools
                or result.result_artifact.shared_artifact_id not in grant.targets
                or result.result_artifact.size_bytes > MAX_RECEIVER_BOUND_ARTIFACT_READ_BYTES
            ):
                raise ValueError("receiver read Capability or Artifact scope differs")
            evaluated_at = _aware_utc(self._clock())
            authorized_at = result.completed_at
            expires_at = min(
                grant.expires_at,
                authorized_at
                + timedelta(seconds=RECEIVER_BOUND_ARTIFACT_READ_TTL_SECONDS),
            )
            if not max(grant.issued_at, authorized_at) <= evaluated_at < expires_at:
                raise ValueError("receiver read Capability or TTL is inactive")
            key = (
                result.handoff_id,
                result.result_artifact.shared_artifact_id,
                result.receiver.agent_id,
            )
            with self._lock:
                if key in self._attempted:
                    raise ValueError("receiver Artifact read is single-use")
                _require_no_urgent_stop(
                    self._urgent_observation_authority,
                    handoff_id=result.handoff_id,
                )
                if graph_snapshot_store.head_digest() != snapshot.graph_snapshot.snapshot_digest:
                    raise ValueError("receiver read Graph authority became stale")
                self._attempted.add(key)
                self._capability_ledger.consume(grant.grant_id)
                loaded = load_verified_run_artifacts(
                    shared_artifact_source.source_run_path,
                    requests={
                        result.result_artifact.relative_path: (
                            MAX_RECEIVER_BOUND_ARTIFACT_READ_BYTES
                        )
                    },
                    expected_run_id=result.result_artifact.source_run_id,
                )
                content = loaded.artifacts[result.result_artifact.relative_path]
                if (
                    len(content) != result.result_artifact.size_bytes
                    or sha256(content).hexdigest() != result.result_artifact.sha256
                ):
                    raise ValueError("receiver Artifact bytes differ from sealed reference")
                if graph_snapshot_store.head_digest() != snapshot.graph_snapshot.snapshot_digest:
                    raise ValueError("receiver read Graph authority changed during delivery")
                _require_no_urgent_stop(
                    self._urgent_observation_authority,
                    handoff_id=result.handoff_id,
                )
                delivered_at = _aware_utc(self._clock())
                if not evaluated_at <= delivered_at < expires_at:
                    raise ValueError("receiver read TTL expired during delivery")
                receipt = ReceiverBoundArtifactReadReceipt(
                    authorityId=self._authority_id,
                    authorityDigest=self._authority_digest,
                    terminalResultHandoffId=result.result_handoff_id,
                    terminalResultHandoffDigest=result.result_handoff_digest,
                    handoffId=result.handoff_id,
                    handoffDigest=result.handoff_digest,
                    campaignId=result.campaign_id,
                    collaborationSnapshotId=snapshot.collaboration_snapshot_id,
                    collaborationSnapshotDigest=snapshot.collaboration_snapshot_digest,
                    receiver=result.receiver,
                    artifactId=result.result_artifact.shared_artifact_id,
                    artifactDigest=result.result_artifact.shared_artifact_digest,
                    sourceRunId=result.result_artifact.source_run_id,
                    sourceRootDigest=result.result_artifact.source_root_digest,
                    capability=CapabilityGrantRef(
                        grantId=grant.grant_id,
                        grantDigest=capability_grant_digest(grant),
                        subject=grant.subject,
                        campaignId=grant.campaign,
                        targetArtifactId=result.result_artifact.shared_artifact_id,
                        expiresAt=grant.expires_at,
                    ),
                    authorizedAt=authorized_at,
                    expiresAt=expires_at,
                    readAt=delivered_at,
                    bytesRead=len(content),
                    cumulativeBytes=len(content),
                )
                self._receipts[key] = receipt
                return ReceiverBoundArtifactReadOutcome(receipt=receipt, content=content)
        except (
            AttributeError,
            CapabilityError,
            CollaborationSnapshotError,
            KeyError,
            RunIntegrityError,
            TerminalResultHandoffError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise ReceiverBoundArtifactReadError(
                "receiver-bound Artifact read failed closed"
            ) from exc

    def receipt_for(
        self, *, handoff_id: str, artifact_id: str, receiver_id: str
    ) -> ReceiverBoundArtifactReadReceipt | None:
        """Return a defensive receipt copy without returning content again."""

        with self._lock:
            receipt = self._receipts.get((handoff_id, artifact_id, receiver_id))
            if receipt is None:
                return None
            return ReceiverBoundArtifactReadReceipt.model_validate(
                receipt.model_dump(mode="json", by_alias=True)
            )

    def resolve(
        self, receipt: ReceiverBoundArtifactReadReceipt
    ) -> ReceiverBoundArtifactReadReceipt:
        """Resolve one exact stored receipt without returning content again."""

        try:
            canonical = ReceiverBoundArtifactReadReceipt.model_validate(
                receipt.model_dump(mode="json", by_alias=True)
            )
            key = (
                canonical.handoff_id,
                canonical.artifact_id,
                canonical.receiver.agent_id,
            )
            with self._lock:
                stored = self._receipts.get(key)
            if (
                canonical.authority_id != self._authority_id
                or canonical.authority_digest != self._authority_digest
                or stored != canonical
            ):
                raise ValueError("receiver Artifact read receipt was not emitted here")
            return canonical
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise ReceiverBoundArtifactReadError(
                "receiver Artifact read receipt could not be resolved"
            ) from exc


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("receiver read time requires an explicit UTC offset")
    return value.astimezone(UTC)


def _require_no_urgent_stop(
    authority: UrgentObservationFastGateAuthority,
    *,
    handoff_id: str,
) -> None:
    if authority.decision_for(handoff_id) is not None:
        raise ValueError("urgent stop decision denies receiver Artifact delivery")
