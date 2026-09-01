"""WEB-002D exact proxy-only controlled-validation Worker runtime."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import subprocess
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from inspect import getattr_static
from itertools import pairwise
from pathlib import Path
from threading import Lock
from typing import Annotated, Literal, Protocol, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.benchmark.docker_provider import docker_benchmark_target_network_name
from pajin.benchmark.models import benchmark_digest
from pajin.benchmark.target_factory import BenchmarkTargetCoordinate
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import StrictModel, ToolRequest, ToolResult
from pajin.runtime.worker import (
    DockerEgressLifecycleObservation,
    DockerEgressLifecycleObserver,
    DockerWorkerBackend,
    EgressPolicy,
    NetworkMode,
    WorkerJob,
    WorkerResult,
)
from pajin.tools.base import host_observed_http_receipts
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.execution_receipts import normalize_host_receipt, project_tool_result
from pajin.tools.gateway import canonical_tool_request_digest
from pajin.workflow.web_controlled_validation_route import (
    WebControlledValidationRouteClaimLedger,
    WebControlledValidationRouteClaimReceipt,
    load_web_controlled_validation_route_claim_receipt,
)
from pajin.workflow.web_proxy_route_authority import (
    WebProxyRouteBundle,
    WebProxyRouteLiveAuthorityContext,
    WebProxyRouteRuntimePolicy,
    WebProxyRouteVerification,
)

WEB_CONTROLLED_VALIDATION_WORKER_EVIDENCE_API_VERSION: Literal[
    "pajin.dev/web-controlled-validation-worker-evidence/v1alpha1"
] = "pajin.dev/web-controlled-validation-worker-evidence/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_ImageId = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]
_MAX_RUNTIME_BYTES = 8 * 1024 * 1024
_WORKER_EVIDENCE_STORE_BUSY_TIMEOUT_MS = 30_000
_WORKER_EVIDENCE_STORE_TRIGGER_NAMES = {
    "web_controlled_worker_evidence_no_delete",
    "web_controlled_worker_evidence_no_replace",
    "web_controlled_worker_evidence_no_update",
}
_WORKER_EVIDENCE_STORE_TABLE_SQL = """
CREATE TABLE web_controlled_worker_evidence (
    evidence_digest TEXT NOT NULL PRIMARY KEY,
    route_digest TEXT NOT NULL UNIQUE,
    route_verification_digest TEXT NOT NULL,
    route_claim_receipt_digest TEXT NOT NULL UNIQUE,
    consumption_slot_digest TEXT NOT NULL UNIQUE,
    worker_execution_id TEXT NOT NULL UNIQUE,
    backend_context_digest TEXT NOT NULL,
    observer_context_digest TEXT NOT NULL,
    topology_observation_digest TEXT NOT NULL,
    target_before_observation_digest TEXT NOT NULL,
    target_after_observation_digest TEXT NOT NULL,
    record_digest TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL
)
"""
_WORKER_EVIDENCE_STORE_TRIGGER_SQL = {
    "web_controlled_worker_evidence_no_update": """
        CREATE TRIGGER web_controlled_worker_evidence_no_update
        BEFORE UPDATE ON web_controlled_worker_evidence
        BEGIN SELECT RAISE(ABORT, 'WEB controlled Worker Evidence is append-only'); END
    """,
    "web_controlled_worker_evidence_no_delete": """
        CREATE TRIGGER web_controlled_worker_evidence_no_delete
        BEFORE DELETE ON web_controlled_worker_evidence
        BEGIN SELECT RAISE(ABORT, 'WEB controlled Worker Evidence is append-only'); END
    """,
    "web_controlled_worker_evidence_no_replace": """
        CREATE TRIGGER web_controlled_worker_evidence_no_replace
        BEFORE INSERT ON web_controlled_worker_evidence
        WHEN EXISTS (
            SELECT 1 FROM web_controlled_worker_evidence
            WHERE evidence_digest = NEW.evidence_digest
               OR route_digest = NEW.route_digest
               OR route_claim_receipt_digest = NEW.route_claim_receipt_digest
               OR consumption_slot_digest = NEW.consumption_slot_digest
               OR worker_execution_id = NEW.worker_execution_id
               OR record_digest = NEW.record_digest
        )
        BEGIN SELECT RAISE(ABORT, 'WEB controlled Worker Evidence is append-only'); END
    """,
}
_BridgeStage = Literal[
    "target-boundary-before",
    "proxy-bridge-attached",
    "proxy-bridge-detached",
    "ephemeral-resources-absent",
]
_BRIDGE_STAGES: tuple[_BridgeStage, ...] = (
    "target-boundary-before",
    "proxy-bridge-attached",
    "proxy-bridge-detached",
    "ephemeral-resources-absent",
)


class WebControlledValidationRuntimeError(RuntimeError):
    """Raised when the exact controlled-validation runtime cannot be proven."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


class WebControlledTargetBoundaryObservation(_FrozenStrictModel):
    """Host observation of the exact internal Target network before or after a run."""

    observation_digest: str = Field(default="", alias="observationDigest", max_length=64)
    target_network_digest: _Sha256 = Field(alias="targetNetworkDigest")
    target_network_id: _Sha256 = Field(alias="targetNetworkId")
    target_container_id: _Sha256 = Field(alias="targetContainerId")
    target_image_id: _ImageId = Field(alias="targetImageId")
    network_internal: Literal[True] = Field(default=True, alias="networkInternal")
    network_container_count: Literal[1] = Field(default=1, alias="networkContainerCount")
    published_port_count: Literal[0] = Field(default=0, alias="publishedPortCount")
    target_healthy: Literal[True] = Field(default=True, alias="targetHealthy")
    observed_at: datetime = Field(alias="observedAt")

    @field_validator("observed_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("WEB controlled Target observation requires UTC offset")
        return value.astimezone(UTC)

    @field_validator(
        "network_internal",
        "target_healthy",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB controlled Target boundary markers must be true")
        return value

    @field_validator("network_container_count", "published_port_count", mode="before")
    @classmethod
    def require_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("WEB controlled Target counts must be integers")
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        digest = benchmark_digest(
            "pajin.workflow.web-controlled-target-boundary-observation/v1",
            self.model_dump(mode="json", by_alias=True, exclude={"observation_digest"}),
            max_bytes=512 * 1024,
        )
        if self.observation_digest and self.observation_digest != digest:
            raise ValueError("WEB controlled Target observation Digest differs")
        object.__setattr__(self, "observation_digest", digest)
        return self


class WebControlledProxyTopologyObservation(_FrozenStrictModel):
    """Host-observed exact Worker, proxy, Target, and two-network topology."""

    observation_digest: str = Field(default="", alias="observationDigest", max_length=64)
    execution_id: str = Field(alias="executionId", min_length=1, max_length=200)
    worker_container_name: str = Field(alias="workerContainerName", min_length=1, max_length=200)
    worker_container_id: _Sha256 = Field(alias="workerContainerId")
    worker_image_id: _ImageId = Field(alias="workerImageId")
    proxy_container_name: str = Field(alias="proxyContainerName", min_length=1, max_length=200)
    proxy_container_id: _Sha256 = Field(alias="proxyContainerId")
    proxy_image_id: _ImageId = Field(alias="proxyImageId")
    internal_network_name: str = Field(alias="internalNetworkName", min_length=1, max_length=200)
    internal_network_id: _Sha256 = Field(alias="internalNetworkId")
    target_network_name: str = Field(alias="targetNetworkName", min_length=1, max_length=200)
    target_network_id: _Sha256 = Field(alias="targetNetworkId")
    target_container_id: _Sha256 = Field(alias="targetContainerId")
    target_image_id: _ImageId = Field(alias="targetImageId")
    worker_network_ids: tuple[_Sha256, ...] = Field(
        alias="workerNetworkIds", min_length=1, max_length=1
    )
    proxy_network_ids: tuple[_Sha256, ...] = Field(
        alias="proxyNetworkIds", min_length=2, max_length=2
    )
    target_network_ids: tuple[_Sha256, ...] = Field(
        alias="targetNetworkIds", min_length=1, max_length=1
    )
    worker_published_port_count: Literal[0] = Field(default=0, alias="workerPublishedPortCount")
    proxy_published_port_count: Literal[0] = Field(default=0, alias="proxyPublishedPortCount")
    target_published_port_count: Literal[0] = Field(default=0, alias="targetPublishedPortCount")
    internal_network_internal: Literal[True] = Field(default=True, alias="internalNetworkInternal")
    target_network_internal: Literal[True] = Field(default=True, alias="targetNetworkInternal")
    attached_at: datetime = Field(alias="attachedAt")
    proxy_detached_at: datetime = Field(alias="proxyDetachedAt")
    resources_absent_at: datetime = Field(alias="resourcesAbsentAt")
    resources_absent: Literal[True] = Field(default=True, alias="resourcesAbsent")

    @field_validator("attached_at", "proxy_detached_at", "resources_absent_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("WEB controlled topology time requires UTC offset")
        return value.astimezone(UTC)

    @field_validator(
        "worker_published_port_count",
        "proxy_published_port_count",
        "target_published_port_count",
        mode="before",
    )
    @classmethod
    def require_zero_integer(cls, value: object) -> object:
        if type(value) is not int or value != 0:
            raise ValueError("WEB controlled topology published ports must be zero")
        return value

    @field_validator(
        "internal_network_internal",
        "target_network_internal",
        "resources_absent",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB controlled topology markers must be true")
        return value

    @model_validator(mode="after")
    def bind_topology(self) -> Self:
        if (
            self.worker_network_ids != (self.internal_network_id,)
            or self.proxy_network_ids
            != tuple(sorted((self.internal_network_id, self.target_network_id)))
            or self.target_network_ids != (self.target_network_id,)
            or len(
                {
                    self.worker_container_id,
                    self.proxy_container_id,
                    self.target_container_id,
                }
            )
            != 3
            or self.internal_network_id == self.target_network_id
            or not self.attached_at <= self.proxy_detached_at <= self.resources_absent_at
        ):
            raise ValueError("WEB controlled topology binding differs")
        digest = benchmark_digest(
            "pajin.workflow.web-controlled-proxy-topology-observation/v1",
            self.model_dump(mode="json", by_alias=True, exclude={"observation_digest"}),
            max_bytes=2 * 1024 * 1024,
        )
        if self.observation_digest and self.observation_digest != digest:
            raise ValueError("WEB controlled topology observation Digest differs")
        object.__setattr__(self, "observation_digest", digest)
        return self


class WebProxyBridgeLifecycleReceipt(_FrozenStrictModel):
    """One content-addressed route lifecycle checkpoint from the deployment adapter."""

    receipt_id: str = Field(default="", alias="receiptId", max_length=110)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    stage: Literal[
        "target-boundary-before",
        "proxy-bridge-attached",
        "proxy-bridge-detached",
        "ephemeral-resources-absent",
    ]
    route_id: str = Field(alias="routeId", min_length=1, max_length=90)
    route_digest: _Sha256 = Field(alias="routeDigest")
    consumption_slot_digest: _Sha256 = Field(alias="consumptionSlotDigest")
    worker_execution_id: str = Field(alias="workerExecutionId", min_length=1, max_length=200)
    target_network_digest: _Sha256 = Field(alias="targetNetworkDigest")
    worker_proxy_network_slot_digest: _Sha256 = Field(alias="workerProxyNetworkSlotDigest")
    occurred_at: datetime = Field(alias="occurredAt")
    succeeded: Literal[True] = True

    @field_validator("occurred_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("WEB proxy bridge receipt requires UTC offset")
        return value.astimezone(UTC)

    @field_validator("succeeded", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB proxy bridge receipt must succeed")
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"receipt_id", "receipt_digest"}
        )
        digest = benchmark_digest(
            "pajin.workflow.web-proxy-bridge-lifecycle-receipt/v1",
            material,
            max_bytes=512 * 1024,
        )
        receipt_id = f"web-proxy-bridge-receipt:{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("WEB proxy bridge receipt Digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("WEB proxy bridge receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


class WebControlledValidationWorkerEvidence(_FrozenStrictModel):
    """Sealed Worker, proxy and Tool evidence for one consumed exact route."""

    api_version: Literal["pajin.dev/web-controlled-validation-worker-evidence/v1alpha1"] = Field(
        default=WEB_CONTROLLED_VALIDATION_WORKER_EVIDENCE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebControlledValidationWorkerEvidence"] = "WebControlledValidationWorkerEvidence"
    evidence_id: str = Field(default="", alias="evidenceId", max_length=110)
    evidence_digest: str = Field(default="", alias="evidenceDigest", max_length=64)
    route_id: str = Field(alias="routeId", min_length=1, max_length=90)
    route_digest: _Sha256 = Field(alias="routeDigest")
    route_verification_id: str = Field(alias="routeVerificationId", min_length=1, max_length=110)
    route_verification_digest: _Sha256 = Field(alias="routeVerificationDigest")
    route_claim_receipt_id: str = Field(alias="routeClaimReceiptId", min_length=1, max_length=110)
    route_claim_receipt_digest: _Sha256 = Field(alias="routeClaimReceiptDigest")
    consumption_slot_digest: _Sha256 = Field(alias="consumptionSlotDigest")
    target_attempt_id: str = Field(alias="targetAttemptId", min_length=1, max_length=110)
    target_attempt_digest: _Sha256 = Field(alias="targetAttemptDigest")
    target_execution_operation_id: str = Field(
        alias="targetExecutionOperationId", min_length=1, max_length=110
    )
    target_execution_operation_digest: _Sha256 = Field(alias="targetExecutionOperationDigest")
    target_fence: int = Field(alias="targetFence", ge=1, le=2**63 - 1)
    backend_context_digest: _Sha256 = Field(alias="backendContextDigest")
    request_digest: _Sha256 = Field(alias="requestDigest")
    target_before: WebControlledTargetBoundaryObservation = Field(alias="targetBefore")
    target_after: WebControlledTargetBoundaryObservation = Field(alias="targetAfter")
    topology_observation: WebControlledProxyTopologyObservation = Field(alias="topologyObservation")
    bridge_receipts: tuple[WebProxyBridgeLifecycleReceipt, ...] = Field(
        alias="bridgeReceipts", min_length=4, max_length=4
    )
    host_http_receipt_digests: tuple[_Sha256, ...] = Field(
        alias="hostHttpReceiptDigests", min_length=3, max_length=3
    )
    request: ToolRequest
    worker_job: WorkerJob = Field(alias="workerJob")
    worker_result: WorkerResult = Field(alias="workerResult")
    tool_result: ToolResult = Field(alias="toolResult")
    route_consumed: Literal[True] = Field(default=True, alias="routeConsumed")
    worker_proxy_only: Literal[True] = Field(default=True, alias="workerProxyOnly")
    proxy_bridge_verified: Literal[True] = Field(default=True, alias="proxyBridgeVerified")
    host_receipts_verified: Literal[True] = Field(default=True, alias="hostReceiptsVerified")
    ephemeral_resources_absent: Literal[True] = Field(
        default=True, alias="ephemeralResourcesAbsent"
    )
    graph_write_authorized: Literal[False] = Field(default=False, alias="graphWriteAuthorized")
    report_delivery_authorized: Literal[False] = Field(
        default=False, alias="reportDeliveryAuthorized"
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False, alias="additionalExecutionAuthorized"
    )

    @field_validator("target_fence", mode="before")
    @classmethod
    def require_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("WEB controlled Target fence must be an integer")
        return value

    @field_validator(
        "route_consumed",
        "worker_proxy_only",
        "proxy_bridge_verified",
        "host_receipts_verified",
        "ephemeral_resources_absent",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB controlled Worker evidence markers must be true")
        return value

    @field_validator(
        "graph_write_authorized",
        "report_delivery_authorized",
        "additional_execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB controlled Worker evidence cannot grant downstream authority")
        return value

    @model_validator(mode="after")
    def bind_evidence(self) -> Self:
        statement = self
        stages = tuple(receipt.stage for receipt in self.bridge_receipts)
        receipt_binding = {
            (
                receipt.route_id,
                receipt.route_digest,
                receipt.consumption_slot_digest,
                receipt.worker_execution_id,
            )
            for receipt in self.bridge_receipts
        }
        expected_binding = {
            (
                self.route_id,
                self.route_digest,
                self.consumption_slot_digest,
                self.worker_job.execution_id,
            )
        }
        receipts = host_observed_http_receipts(
            self.worker_result,
            network_log_trusted=True,
        )
        actual_receipt_digests = (
            tuple(
                sha256(
                    canonical_json_bytes(
                        receipt.model_dump(mode="json", by_alias=True),
                        label="WEB controlled host HTTP receipt",
                        max_bytes=512 * 1024,
                    )
                ).hexdigest()
                for receipt in receipts
            )
            if receipts is not None
            else ()
        )
        topology = self.topology_observation
        receipt_times = tuple(receipt.occurred_at for receipt in self.bridge_receipts)
        expected_receipt_times = (
            self.target_before.observed_at,
            topology.attached_at,
            topology.proxy_detached_at,
            topology.resources_absent_at,
        )
        binding_failures = tuple(
            label
            for label, failed in (
                ("bridge-stages", stages != _BRIDGE_STAGES),
                ("bridge-binding", receipt_binding != expected_binding),
                ("bridge-times", receipt_times != expected_receipt_times),
                (
                    "target-network-digest",
                    self.target_before.target_network_digest
                    != self.target_after.target_network_digest,
                ),
                (
                    "target-network-id",
                    self.target_before.target_network_id != self.target_after.target_network_id,
                ),
                (
                    "target-container-id",
                    self.target_before.target_container_id != self.target_after.target_container_id,
                ),
                (
                    "target-image-id",
                    self.target_before.target_image_id != self.target_after.target_image_id,
                ),
                ("topology-execution", topology.execution_id != self.worker_job.execution_id),
                (
                    "topology-network",
                    topology.target_network_id != self.target_before.target_network_id,
                ),
                (
                    "topology-target",
                    topology.target_container_id != self.target_before.target_container_id,
                ),
                (
                    "topology-image",
                    topology.target_image_id != self.target_before.target_image_id,
                ),
                (
                    "topology-network-name",
                    sha256(topology.target_network_name.encode("utf-8")).hexdigest()
                    != self.target_before.target_network_digest,
                ),
                (
                    "worker-execution",
                    self.worker_job.execution_id != self.worker_result.execution_id,
                ),
                ("worker-network", self.worker_job.network is not NetworkMode.EGRESS_PROXY),
                ("worker-egress-policy", self.worker_job.egress_policy is None),
                ("tool-request", self.request.request_id != self.tool_result.request_id),
                ("tool-identity", self.request.tool_id != self.tool_result.tool_id),
                ("tool-success", not self.tool_result.success),
                ("host-receipt-count", len(actual_receipt_digests) != 3),
                (
                    "host-receipt-digests",
                    actual_receipt_digests != self.host_http_receipt_digests,
                ),
                (
                    "lifecycle-time",
                    not self.target_before.observed_at
                    <= self.worker_result.started_at
                    <= topology.attached_at
                    <= self.worker_result.finished_at
                    <= topology.proxy_detached_at
                    <= topology.resources_absent_at
                    <= self.target_after.observed_at,
                ),
            )
            if failed
        )
        if binding_failures:
            raise ValueError(
                "WEB controlled Worker evidence binding differs: " + ",".join(binding_failures)
            )
        try:
            BooleanSQLiProbeTool().validate_trusted_execution(
                self.request,
                self.tool_result,
                self.worker_result,
                network_log_trusted=True,
            )
        except Exception as exc:
            raise ValueError("WEB controlled Tool result is not host-receipt bound") from exc
        material = statement.model_dump(
            mode="json", by_alias=True, exclude={"evidence_id", "evidence_digest"}
        )
        digest = benchmark_digest(
            "pajin.workflow.web-controlled-validation-worker-evidence/v1",
            material,
            max_bytes=_MAX_RUNTIME_BYTES,
        )
        evidence_id = f"web-controlled-validation-worker:{digest}"
        if self.evidence_digest and self.evidence_digest != digest:
            raise ValueError("WEB controlled Worker Evidence Digest differs")
        if self.evidence_id and self.evidence_id != evidence_id:
            raise ValueError("WEB controlled Worker Evidence ID differs")
        object.__setattr__(self, "evidence_digest", digest)
        object.__setattr__(self, "evidence_id", evidence_id)
        return self


class _WebControlledValidationWorkerEvidenceRecord(_FrozenStrictModel):
    """Host-owned immutable commitment to one produced Worker Evidence value."""

    record_digest: str = Field(default="", alias="recordDigest", max_length=64)
    evidence_digest: _Sha256 = Field(alias="evidenceDigest")
    route_digest: _Sha256 = Field(alias="routeDigest")
    route_verification_digest: _Sha256 = Field(alias="routeVerificationDigest")
    route_claim_receipt_digest: _Sha256 = Field(alias="routeClaimReceiptDigest")
    consumption_slot_digest: _Sha256 = Field(alias="consumptionSlotDigest")
    worker_execution_id: str = Field(alias="workerExecutionId", min_length=1, max_length=200)
    backend_context_digest: _Sha256 = Field(alias="backendContextDigest")
    observer_context_digest: _Sha256 = Field(alias="observerContextDigest")
    topology_observation_digest: _Sha256 = Field(alias="topologyObservationDigest")
    target_before_observation_digest: _Sha256 = Field(alias="targetBeforeObservationDigest")
    target_after_observation_digest: _Sha256 = Field(alias="targetAfterObservationDigest")

    @model_validator(mode="after")
    def bind_record(self) -> Self:
        digest = benchmark_digest(
            "pajin.workflow.web-controlled-validation-worker-evidence-record/v1",
            self.model_dump(mode="json", by_alias=True, exclude={"record_digest"}),
            max_bytes=512 * 1024,
        )
        if self.record_digest and self.record_digest != digest:
            raise ValueError("WEB controlled Worker Evidence record Digest differs")
        object.__setattr__(self, "record_digest", digest)
        return self


_WORKER_EVIDENCE_SELECT = """
SELECT evidence_digest, route_digest, route_verification_digest,
       route_claim_receipt_digest, consumption_slot_digest, worker_execution_id,
       backend_context_digest, observer_context_digest, topology_observation_digest,
       target_before_observation_digest, target_after_observation_digest,
       record_digest, record_json, evidence_json
FROM web_controlled_worker_evidence
"""


class _WebControlledValidationWorkerEvidenceStore:
    """Production host-owned append-only Worker Evidence provenance store."""

    def __init__(self, path: Path) -> None:
        self.path = Path(os.path.abspath(path))
        _initialize_worker_evidence_store(self.path)

    def append(
        self,
        *,
        record: _WebControlledValidationWorkerEvidenceRecord,
        evidence: WebControlledValidationWorkerEvidence,
    ) -> _WebControlledValidationWorkerEvidenceRecord:
        try:
            if (
                type(record) is not _WebControlledValidationWorkerEvidenceRecord
                or type(evidence) is not WebControlledValidationWorkerEvidence
            ):
                raise TypeError("WEB controlled Worker Evidence store requires exact record types")
            canonical_record = _WebControlledValidationWorkerEvidenceRecord.model_validate(
                record.model_dump(mode="python", by_alias=True)
            )
            canonical_evidence = WebControlledValidationWorkerEvidence.model_validate(
                evidence.model_dump(mode="python", by_alias=True)
            )
            if not _worker_evidence_record_matches(
                canonical_record,
                canonical_evidence,
            ):
                raise ValueError("WEB controlled Worker Evidence record differs from its Evidence")
            record_json = _canonical_worker_evidence_store_json(
                canonical_record,
                label="WEB controlled Worker Evidence record",
                max_bytes=512 * 1024,
            )
            evidence_json = _canonical_worker_evidence_store_json(
                canonical_evidence,
                label="WEB controlled Worker Evidence",
                max_bytes=_MAX_RUNTIME_BYTES,
            )
            with _worker_evidence_write_transaction(self.path) as connection:
                existing = connection.execute(
                    f"""{_WORKER_EVIDENCE_SELECT}
                    WHERE evidence_digest = ? OR route_digest = ?
                       OR route_claim_receipt_digest = ? OR consumption_slot_digest = ?
                       OR worker_execution_id = ? OR record_digest = ?""",
                    (
                        canonical_record.evidence_digest,
                        canonical_record.route_digest,
                        canonical_record.route_claim_receipt_digest,
                        canonical_record.consumption_slot_digest,
                        canonical_record.worker_execution_id,
                        canonical_record.record_digest,
                    ),
                ).fetchone()
                if existing is not None:
                    stored_record, stored_evidence = _worker_evidence_from_row(existing)
                    if stored_record == canonical_record and stored_evidence == canonical_evidence:
                        return stored_record.model_copy(deep=True)
                    raise WebControlledValidationRuntimeError(
                        "WEB controlled Worker Evidence durable identity was reused"
                    )
                connection.execute(
                    """
                    INSERT INTO web_controlled_worker_evidence(
                        evidence_digest, route_digest, route_verification_digest,
                        route_claim_receipt_digest, consumption_slot_digest,
                        worker_execution_id, backend_context_digest,
                        observer_context_digest, topology_observation_digest,
                        target_before_observation_digest,
                        target_after_observation_digest, record_digest,
                        record_json, evidence_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        canonical_record.evidence_digest,
                        canonical_record.route_digest,
                        canonical_record.route_verification_digest,
                        canonical_record.route_claim_receipt_digest,
                        canonical_record.consumption_slot_digest,
                        canonical_record.worker_execution_id,
                        canonical_record.backend_context_digest,
                        canonical_record.observer_context_digest,
                        canonical_record.topology_observation_digest,
                        canonical_record.target_before_observation_digest,
                        canonical_record.target_after_observation_digest,
                        canonical_record.record_digest,
                        record_json,
                        evidence_json,
                    ),
                )
                inserted = connection.execute(
                    f"{_WORKER_EVIDENCE_SELECT} WHERE evidence_digest = ?",
                    (canonical_record.evidence_digest,),
                ).fetchone()
                if inserted is None:
                    raise WebControlledValidationRuntimeError(
                        "WEB controlled Worker Evidence durable write disappeared"
                    )
                stored_record, stored_evidence = _worker_evidence_from_row(inserted)
                if stored_record != canonical_record or stored_evidence != canonical_evidence:
                    raise WebControlledValidationRuntimeError(
                        "WEB controlled Worker Evidence durable write differs"
                    )
            return canonical_record.model_copy(deep=True)
        except WebControlledValidationRuntimeError:
            raise
        except (sqlite3.Error, TypeError, ValueError) as exc:
            raise WebControlledValidationRuntimeError(
                "WEB controlled Worker Evidence durable write failed closed"
            ) from exc

    def load(
        self,
        evidence_digest: str,
    ) -> tuple[
        _WebControlledValidationWorkerEvidenceRecord,
        WebControlledValidationWorkerEvidence,
    ]:
        try:
            if (
                not isinstance(evidence_digest, str)
                or len(evidence_digest) != 64
                or any(character not in "0123456789abcdef" for character in evidence_digest)
            ):
                raise ValueError("WEB controlled Worker Evidence Digest is invalid")
            with _worker_evidence_read_transaction(self.path) as connection:
                row = connection.execute(
                    f"{_WORKER_EVIDENCE_SELECT} WHERE evidence_digest = ?",
                    (evidence_digest,),
                ).fetchone()
            if row is None:
                raise WebControlledValidationRuntimeError(
                    "WEB controlled Worker Evidence lacks a durable production record"
                )
            record, evidence = _worker_evidence_from_row(row)
            return record.model_copy(deep=True), evidence.model_copy(deep=True)
        except WebControlledValidationRuntimeError:
            raise
        except (sqlite3.Error, TypeError, ValueError) as exc:
            raise WebControlledValidationRuntimeError(
                "WEB controlled Worker Evidence durable reload failed closed"
            ) from exc


def _worker_evidence_record_matches(
    record: _WebControlledValidationWorkerEvidenceRecord,
    evidence: WebControlledValidationWorkerEvidence,
) -> bool:
    return (
        record.evidence_digest == evidence.evidence_digest
        and record.route_digest == evidence.route_digest
        and record.route_verification_digest == evidence.route_verification_digest
        and record.route_claim_receipt_digest == evidence.route_claim_receipt_digest
        and record.consumption_slot_digest == evidence.consumption_slot_digest
        and record.worker_execution_id == evidence.worker_job.execution_id
        and record.backend_context_digest == evidence.backend_context_digest
        and record.topology_observation_digest == evidence.topology_observation.observation_digest
        and record.target_before_observation_digest == evidence.target_before.observation_digest
        and record.target_after_observation_digest == evidence.target_after.observation_digest
    )


def _canonical_worker_evidence_store_json(
    value: _FrozenStrictModel,
    *,
    label: str,
    max_bytes: int,
) -> str:
    return canonical_json_bytes(
        value.model_dump(mode="json", by_alias=True),
        label=label,
        max_bytes=max_bytes,
    ).decode("utf-8")


def _worker_evidence_from_row(
    row: sqlite3.Row,
) -> tuple[
    _WebControlledValidationWorkerEvidenceRecord,
    WebControlledValidationWorkerEvidence,
]:
    try:
        record_json = str(row["record_json"])
        evidence_json = str(row["evidence_json"])
        record = _WebControlledValidationWorkerEvidenceRecord.model_validate_json(record_json)
        evidence = WebControlledValidationWorkerEvidence.model_validate_json(evidence_json)
    except (KeyError, TypeError, ValueError) as exc:
        raise WebControlledValidationRuntimeError(
            "WEB controlled Worker Evidence durable content is invalid"
        ) from exc
    expected_columns = {
        "evidence_digest": record.evidence_digest,
        "route_digest": record.route_digest,
        "route_verification_digest": record.route_verification_digest,
        "route_claim_receipt_digest": record.route_claim_receipt_digest,
        "consumption_slot_digest": record.consumption_slot_digest,
        "worker_execution_id": record.worker_execution_id,
        "backend_context_digest": record.backend_context_digest,
        "observer_context_digest": record.observer_context_digest,
        "topology_observation_digest": record.topology_observation_digest,
        "target_before_observation_digest": record.target_before_observation_digest,
        "target_after_observation_digest": record.target_after_observation_digest,
        "record_digest": record.record_digest,
    }
    if (
        any(str(row[column]) != expected for column, expected in expected_columns.items())
        or record_json
        != _canonical_worker_evidence_store_json(
            record,
            label="WEB controlled Worker Evidence record",
            max_bytes=512 * 1024,
        )
        or evidence_json
        != _canonical_worker_evidence_store_json(
            evidence,
            label="WEB controlled Worker Evidence",
            max_bytes=_MAX_RUNTIME_BYTES,
        )
        or not _worker_evidence_record_matches(record, evidence)
    ):
        raise WebControlledValidationRuntimeError(
            "WEB controlled Worker Evidence durable row differs from its content"
        )
    return record, evidence


def _initialize_worker_evidence_store(path: Path) -> None:
    _require_safe_worker_evidence_store_path(path)
    _require_safe_worker_evidence_store_sidecars(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    store_created = False
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    except FileExistsError:
        pass
    else:
        os.close(descriptor)
        store_created = True
    _require_safe_worker_evidence_store_path(path)
    connection: sqlite3.Connection | None = None
    try:
        connection = _open_worker_evidence_write_connection(path)
        if store_created:
            mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
            if mode is None or str(mode[0]).lower() != "delete":
                raise WebControlledValidationRuntimeError(
                    "WEB controlled Worker Evidence journal mode differs"
                )
        connection.execute("BEGIN IMMEDIATE")
        if store_created:
            existing_objects = connection.execute(
                """
                SELECT type, name FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%'
                """
            ).fetchall()
            if existing_objects:
                raise WebControlledValidationRuntimeError(
                    "WEB controlled Worker Evidence new store is not empty"
                )
            connection.execute(_WORKER_EVIDENCE_STORE_TABLE_SQL)
            for statement in _WORKER_EVIDENCE_STORE_TRIGGER_SQL.values():
                connection.execute(statement)
        _require_worker_evidence_store_integrity(connection)
        connection.commit()
        path.chmod(0o600)
        _require_safe_worker_evidence_store_path(path)
        _require_safe_worker_evidence_store_sidecars(path)
    except WebControlledValidationRuntimeError:
        if connection is not None:
            connection.rollback()
        raise
    except sqlite3.Error as exc:
        if connection is not None:
            connection.rollback()
        raise WebControlledValidationRuntimeError(
            "WEB controlled Worker Evidence store could not initialize"
        ) from exc
    finally:
        if connection is not None:
            connection.close()


def _require_worker_evidence_store_integrity(connection: sqlite3.Connection) -> None:
    table_row = connection.execute(
        """
        SELECT sql FROM sqlite_master
        WHERE type = 'table' AND name = 'web_controlled_worker_evidence'
        """
    ).fetchone()
    if table_row is None or _normalize_worker_evidence_store_sql(
        str(table_row[0])
    ) != _normalize_worker_evidence_store_sql(_WORKER_EVIDENCE_STORE_TABLE_SQL):
        raise WebControlledValidationRuntimeError(
            "WEB controlled Worker Evidence store table contract differs"
        )
    columns = connection.execute("PRAGMA table_info(web_controlled_worker_evidence)").fetchall()
    expected_columns = (
        "evidence_digest",
        "route_digest",
        "route_verification_digest",
        "route_claim_receipt_digest",
        "consumption_slot_digest",
        "worker_execution_id",
        "backend_context_digest",
        "observer_context_digest",
        "topology_observation_digest",
        "target_before_observation_digest",
        "target_after_observation_digest",
        "record_digest",
        "record_json",
        "evidence_json",
    )
    if (
        tuple(str(row[1]) for row in columns) != expected_columns
        or any(str(row[2]).upper() != "TEXT" or int(row[3]) != 1 for row in columns)
        or tuple(int(row[5]) for row in columns) != (1,) + (0,) * 13
    ):
        raise WebControlledValidationRuntimeError(
            "WEB controlled Worker Evidence store schema differs"
        )
    indexes = connection.execute("PRAGMA index_list(web_controlled_worker_evidence)").fetchall()
    unique_columns = {
        tuple(
            str(item[2]) for item in connection.execute(f"PRAGMA index_info('{row[1]}')").fetchall()
        )
        for row in indexes
        if int(row[2]) == 1
    }
    if unique_columns != {
        ("evidence_digest",),
        ("route_digest",),
        ("route_claim_receipt_digest",),
        ("consumption_slot_digest",),
        ("worker_execution_id",),
        ("record_digest",),
    }:
        raise WebControlledValidationRuntimeError(
            "WEB controlled Worker Evidence store unique identities differ"
        )
    trigger_rows = connection.execute(
        """
        SELECT name, sql FROM sqlite_master
        WHERE type = 'trigger' AND tbl_name = 'web_controlled_worker_evidence'
        """
    ).fetchall()
    triggers = {
        str(row[0]): _normalize_worker_evidence_store_sql(str(row[1])) for row in trigger_rows
    }
    if set(triggers) != _WORKER_EVIDENCE_STORE_TRIGGER_NAMES:
        raise WebControlledValidationRuntimeError(
            "WEB controlled Worker Evidence append-only guards differ"
        )
    expected_triggers = {
        name: _normalize_worker_evidence_store_sql(statement)
        for name, statement in _WORKER_EVIDENCE_STORE_TRIGGER_SQL.items()
    }
    if triggers != expected_triggers:
        raise WebControlledValidationRuntimeError(
            "WEB controlled Worker Evidence append-only guard definitions differ"
        )
    schema_objects = {
        (str(row[0]), str(row[1]))
        for row in connection.execute(
            """
            SELECT type, name FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
    }
    expected_schema_objects = {
        ("table", "web_controlled_worker_evidence"),
        *(("trigger", name) for name in _WORKER_EVIDENCE_STORE_TRIGGER_NAMES),
    }
    if schema_objects != expected_schema_objects:
        raise WebControlledValidationRuntimeError(
            "WEB controlled Worker Evidence store object contract differs"
        )
    mode = connection.execute("PRAGMA journal_mode").fetchone()
    quick_check = connection.execute("PRAGMA quick_check").fetchall()
    if (
        mode is None
        or str(mode[0]).lower() != "delete"
        or len(quick_check) != 1
        or str(quick_check[0][0]) != "ok"
    ):
        raise WebControlledValidationRuntimeError(
            "WEB controlled Worker Evidence store integrity differs"
        )


def _normalize_worker_evidence_store_sql(statement: str) -> str:
    return " ".join(statement.strip().removesuffix(";").split()).casefold()


def _require_safe_worker_evidence_store_path(path: Path) -> None:
    parent = path.parent
    if any(
        ancestor.exists() and (ancestor.is_symlink() or ancestor.is_junction())
        for ancestor in (parent, *parent.parents)
    ):
        raise WebControlledValidationRuntimeError(
            "WEB controlled Worker Evidence store ancestor is unsafe"
        )
    if parent.exists() and not parent.is_dir():
        raise WebControlledValidationRuntimeError(
            "WEB controlled Worker Evidence store parent is unsafe"
        )
    if (path.exists() or path.is_symlink() or path.is_junction()) and (
        not path.is_file() or path.is_symlink() or path.is_junction() or path.stat().st_nlink != 1
    ):
        raise WebControlledValidationRuntimeError(
            "WEB controlled Worker Evidence store is not a single-link regular file"
        )


def _require_safe_worker_evidence_store_sidecars(path: Path) -> None:
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if not (sidecar.exists() or sidecar.is_symlink() or sidecar.is_junction()):
            continue
        if (
            not sidecar.is_file()
            or sidecar.is_symlink()
            or sidecar.is_junction()
            or sidecar.stat().st_nlink != 1
        ):
            raise WebControlledValidationRuntimeError(
                "WEB controlled Worker Evidence store sidecar is unsafe"
            )


@contextmanager
def _worker_evidence_write_transaction(
    path: Path,
) -> Iterator[sqlite3.Connection]:
    _require_safe_worker_evidence_store_path(path)
    _require_safe_worker_evidence_store_sidecars(path)
    connection = _open_worker_evidence_write_connection(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_worker_evidence_store_integrity(connection)
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()
        _require_safe_worker_evidence_store_path(path)
        _require_safe_worker_evidence_store_sidecars(path)


@contextmanager
def _worker_evidence_read_transaction(
    path: Path,
) -> Iterator[sqlite3.Connection]:
    _require_safe_worker_evidence_store_path(path)
    _require_safe_worker_evidence_store_sidecars(path)
    connection = sqlite3.connect(
        f"file:{path.as_posix()}?mode=ro",
        uri=True,
        isolation_level=None,
        timeout=_WORKER_EVIDENCE_STORE_BUSY_TIMEOUT_MS / 1_000,
    )
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {_WORKER_EVIDENCE_STORE_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA query_only = ON")
    try:
        connection.execute("BEGIN")
        _require_worker_evidence_store_integrity(connection)
        yield connection
    finally:
        connection.rollback()
        connection.close()
        _require_safe_worker_evidence_store_path(path)
        _require_safe_worker_evidence_store_sidecars(path)


def _open_worker_evidence_write_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        f"file:{path.as_posix()}?mode=rw",
        uri=True,
        isolation_level=None,
        timeout=_WORKER_EVIDENCE_STORE_BUSY_TIMEOUT_MS / 1_000,
    )
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {_WORKER_EVIDENCE_STORE_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA synchronous = FULL")
    return connection


@dataclass(frozen=True, slots=True)
class WebControlledValidationWorkerOutcome:
    evidence: WebControlledValidationWorkerEvidence
    verification: WebProxyRouteVerification
    route_claim_receipt: WebControlledValidationRouteClaimReceipt
    backend_context: Mapping[str, object]
    production_boundary_verified: bool


@dataclass(frozen=True, slots=True)
class _AttachedProxyTopology:
    observation: DockerEgressLifecycleObservation
    worker_container_id: str
    worker_image_id: str
    proxy_container_id: str
    proxy_image_id: str
    internal_network_id: str
    target_network_id: str
    target_container_id: str
    target_image_id: str
    worker_network_ids: tuple[str, ...]
    proxy_network_ids: tuple[str, ...]
    target_network_ids: tuple[str, ...]
    attached_at: datetime


class WebControlledDockerBoundaryInspector(
    DockerEgressLifecycleObserver,
    Protocol,
):
    """Deployment-owned Docker observations outside the Worker container."""

    def image_id(self, reference: str) -> str: ...

    def observe_target(
        self,
        *,
        network_name: str,
        expected_network_id: str,
        expected_target_container_id: str,
        expected_target_image_id: str,
    ) -> WebControlledTargetBoundaryObservation: ...

    def ephemeral_resources_absent(self, execution_id: str) -> bool: ...

    def topology_observation(
        self,
        execution_id: str,
    ) -> WebControlledProxyTopologyObservation: ...


class SubprocessWebControlledDockerBoundaryInspector:
    """Bounded shell-free Docker inspection for WEB-002D conformance."""

    def __init__(self, *, executable: str = "docker", timeout_seconds: int = 20) -> None:
        if not executable or executable.strip() != executable or "\x00" in executable:
            raise ValueError("WEB controlled Docker executable is unsafe")
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 120:
            raise ValueError("WEB controlled Docker timeout is invalid")
        self._executable = executable
        self._timeout_seconds = timeout_seconds
        self._topology_lock = Lock()
        self._attached_topologies: dict[str, _AttachedProxyTopology] = {}
        self._completed_topologies: dict[
            str,
            WebControlledProxyTopologyObservation,
        ] = {}

    def stable_observer_context(self) -> Mapping[str, object]:
        return {
            "observerId": "pajin.web-controlled-docker-boundary",
            "observerVersion": "1.0.0",
            "dockerExecutable": self._executable,
            "timeoutSeconds": self._timeout_seconds,
        }

    async def attached(self, observation: DockerEgressLifecycleObservation) -> None:
        attached = await asyncio.to_thread(self._observe_attached, observation)
        with self._topology_lock:
            if (
                observation.execution_id in self._attached_topologies
                or observation.execution_id in self._completed_topologies
            ):
                raise WebControlledValidationRuntimeError(
                    "WEB controlled topology execution identity was reused"
                )
            self._attached_topologies[observation.execution_id] = attached

    async def cleaned(self, observation: DockerEgressLifecycleObservation) -> None:
        with self._topology_lock:
            attached = self._attached_topologies.get(observation.execution_id)
        if attached is None or attached.observation != observation:
            raise WebControlledValidationRuntimeError(
                "WEB controlled topology cleanup lacks its attached observation"
            )
        completed = await asyncio.to_thread(self._observe_cleaned, attached)
        with self._topology_lock:
            if self._attached_topologies.pop(observation.execution_id, None) != attached:
                raise WebControlledValidationRuntimeError(
                    "WEB controlled topology observation changed during cleanup"
                )
            self._completed_topologies[observation.execution_id] = completed

    def topology_observation(
        self,
        execution_id: str,
    ) -> WebControlledProxyTopologyObservation:
        with self._topology_lock:
            observed = self._completed_topologies.get(execution_id)
        if observed is None:
            raise WebControlledValidationRuntimeError(
                "WEB controlled topology observation is incomplete"
            )
        return observed.model_copy(deep=True)

    def _observe_attached(
        self,
        observation: DockerEgressLifecycleObservation,
    ) -> _AttachedProxyTopology:
        deadline = time.monotonic() + self._timeout_seconds
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                return self._observe_attached_once(observation)
            except WebControlledValidationRuntimeError as exc:
                last_error = exc
                time.sleep(0.05)
        raise WebControlledValidationRuntimeError(
            "WEB controlled Docker topology did not become observable"
        ) from last_error

    def _observe_attached_once(
        self,
        observation: DockerEgressLifecycleObservation,
    ) -> _AttachedProxyTopology:
        worker = self._single_inspect(("container", "inspect", observation.worker_container_name))
        proxy = self._single_inspect(("container", "inspect", observation.proxy_container_name))
        internal = self._single_inspect(("network", "inspect", observation.internal_network_name))
        target_network = self._single_inspect(
            ("network", "inspect", observation.external_network_name)
        )
        worker_id = self._docker_sha256(worker.get("Id"), label="Worker container")
        proxy_id = self._docker_sha256(proxy.get("Id"), label="proxy container")
        internal_id = self._docker_sha256(
            internal.get("Id"),
            label="internal network",
        )
        target_network_id = self._docker_sha256(
            target_network.get("Id"),
            label="Target network",
        )
        internal_members = self._network_member_ids(internal)
        target_members = self._network_member_ids(target_network)
        if (
            internal.get("Internal") is not True
            or target_network.get("Internal") is not True
            or internal_members != {worker_id, proxy_id}
            or len(target_members) != 2
            or proxy_id not in target_members
        ):
            raise WebControlledValidationRuntimeError(
                "WEB controlled Docker network membership differs"
            )
        target_id = next(iter(target_members - {proxy_id}))
        target = self._single_inspect(("container", "inspect", target_id))
        worker_network_ids = self._container_network_ids(worker)
        proxy_network_ids = self._container_network_ids(proxy)
        target_network_ids = self._container_network_ids(target)
        if (
            worker_network_ids != (internal_id,)
            or proxy_network_ids != tuple(sorted((internal_id, target_network_id)))
            or target_network_ids != (target_network_id,)
            or self._execution_label(worker) != observation.execution_id
            or self._execution_label(proxy) != observation.execution_id
            or self._published_port_count(worker) != 0
            or self._published_port_count(proxy) != 0
            or self._published_port_count(target) != 0
        ):
            raise WebControlledValidationRuntimeError(
                "WEB controlled Docker container topology differs"
            )
        return _AttachedProxyTopology(
            observation=observation,
            worker_container_id=worker_id,
            worker_image_id=self._docker_image_id(
                worker.get("Image"),
                label="Worker image",
            ),
            proxy_container_id=proxy_id,
            proxy_image_id=self._docker_image_id(
                proxy.get("Image"),
                label="proxy image",
            ),
            internal_network_id=internal_id,
            target_network_id=target_network_id,
            target_container_id=self._docker_sha256(
                target.get("Id"),
                label="Target container",
            ),
            target_image_id=self._docker_image_id(
                target.get("Image"),
                label="Target image",
            ),
            worker_network_ids=worker_network_ids,
            proxy_network_ids=proxy_network_ids,
            target_network_ids=target_network_ids,
            attached_at=datetime.now(UTC),
        )

    def _observe_cleaned(
        self,
        attached: _AttachedProxyTopology,
    ) -> WebControlledProxyTopologyObservation:
        observation = attached.observation
        if self._run(
            (
                "container",
                "ls",
                "--all",
                "--quiet",
                "--filter",
                f"name=^/{observation.proxy_container_name}$",
            )
        ):
            raise WebControlledValidationRuntimeError("WEB controlled proxy remains after cleanup")
        proxy_detached_at = datetime.now(UTC)
        if (
            self._run(
                (
                    "container",
                    "ls",
                    "--all",
                    "--quiet",
                    "--filter",
                    f"name=^/{observation.worker_container_name}$",
                )
            )
            or self._run(
                (
                    "network",
                    "ls",
                    "--quiet",
                    "--filter",
                    f"name=^{observation.internal_network_name}$",
                )
            )
            or not self.ephemeral_resources_absent(observation.execution_id)
        ):
            raise WebControlledValidationRuntimeError(
                "WEB controlled ephemeral resources remain after cleanup"
            )
        self.observe_target(
            network_name=observation.external_network_name,
            expected_network_id=attached.target_network_id,
            expected_target_container_id=attached.target_container_id,
            expected_target_image_id=attached.target_image_id,
        )
        resources_absent_at = datetime.now(UTC)
        return WebControlledProxyTopologyObservation(
            executionId=observation.execution_id,
            workerContainerName=observation.worker_container_name,
            workerContainerId=attached.worker_container_id,
            workerImageId=attached.worker_image_id,
            proxyContainerName=observation.proxy_container_name,
            proxyContainerId=attached.proxy_container_id,
            proxyImageId=attached.proxy_image_id,
            internalNetworkName=observation.internal_network_name,
            internalNetworkId=attached.internal_network_id,
            targetNetworkName=observation.external_network_name,
            targetNetworkId=attached.target_network_id,
            targetContainerId=attached.target_container_id,
            targetImageId=attached.target_image_id,
            workerNetworkIds=attached.worker_network_ids,
            proxyNetworkIds=attached.proxy_network_ids,
            targetNetworkIds=attached.target_network_ids,
            attachedAt=attached.attached_at,
            proxyDetachedAt=proxy_detached_at,
            resourcesAbsentAt=resources_absent_at,
        )

    @staticmethod
    def _docker_sha256(value: object, *, label: str) -> str:
        if not isinstance(value, str) or len(value) != 64:
            raise WebControlledValidationRuntimeError(f"WEB controlled {label} identity differs")
        try:
            int(value, 16)
        except ValueError as exc:
            raise WebControlledValidationRuntimeError(
                f"WEB controlled {label} identity differs"
            ) from exc
        return value

    @staticmethod
    def _docker_image_id(value: object, *, label: str) -> str:
        if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
            raise WebControlledValidationRuntimeError(f"WEB controlled {label} identity differs")
        try:
            int(value.removeprefix("sha256:"), 16)
        except ValueError as exc:
            raise WebControlledValidationRuntimeError(
                f"WEB controlled {label} identity differs"
            ) from exc
        return value

    @classmethod
    def _network_member_ids(cls, network: Mapping[str, object]) -> set[str]:
        containers = network.get("Containers")
        if not isinstance(containers, dict):
            raise WebControlledValidationRuntimeError(
                "WEB controlled Docker network members are invalid"
            )
        return {cls._docker_sha256(value, label="network member") for value in containers}

    @classmethod
    def _container_network_ids(
        cls,
        container: Mapping[str, object],
    ) -> tuple[str, ...]:
        settings = container.get("NetworkSettings")
        networks = settings.get("Networks") if isinstance(settings, dict) else None
        if not isinstance(networks, dict):
            raise WebControlledValidationRuntimeError(
                "WEB controlled Docker container networks are invalid"
            )
        ids: list[str] = []
        for value in networks.values():
            if not isinstance(value, dict):
                raise WebControlledValidationRuntimeError(
                    "WEB controlled Docker endpoint is invalid"
                )
            ids.append(
                cls._docker_sha256(
                    value.get("NetworkID"),
                    label="container network",
                )
            )
        return tuple(sorted(ids))

    @staticmethod
    def _execution_label(container: Mapping[str, object]) -> object:
        config = container.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        return labels.get("pajin.execution-id") if isinstance(labels, dict) else None

    @staticmethod
    def _published_port_count(container: Mapping[str, object]) -> int:
        host = container.get("HostConfig")
        settings = container.get("NetworkSettings")
        bindings = host.get("PortBindings") if isinstance(host, dict) else None
        ports = settings.get("Ports") if isinstance(settings, dict) else None
        if bindings not in (None, {}) or not isinstance(ports, dict):
            raise WebControlledValidationRuntimeError(
                "WEB controlled Docker published-port state differs"
            )
        if any(value not in (None, []) for value in ports.values()):
            raise WebControlledValidationRuntimeError(
                "WEB controlled Docker published ports are not zero"
            )
        return 0

    def image_id(self, reference: str) -> str:
        if not reference or reference.strip() != reference or "\x00" in reference:
            raise ValueError("WEB controlled Docker image reference is unsafe")
        return self._run(("image", "inspect", reference, "--format", "{{.Id}}"))

    def observe_target(
        self,
        *,
        network_name: str,
        expected_network_id: str,
        expected_target_container_id: str,
        expected_target_image_id: str,
    ) -> WebControlledTargetBoundaryObservation:
        network = self._single_inspect(("network", "inspect", network_name))
        target = self._single_inspect(("container", "inspect", expected_target_container_id))
        containers = network.get("Containers")
        state = target.get("State")
        health = state.get("Health") if isinstance(state, dict) else None
        host_config = target.get("HostConfig")
        network_settings = target.get("NetworkSettings")
        ports = network_settings.get("Ports") if isinstance(network_settings, dict) else None
        if (
            network.get("Id") != expected_network_id
            or network.get("Internal") is not True
            or not isinstance(containers, dict)
            or len(containers) != 1
            or expected_target_container_id not in containers
            or target.get("Id") != expected_target_container_id
            or target.get("Image") != expected_target_image_id
            or not isinstance(state, dict)
            or state.get("Running") is not True
            or not isinstance(health, dict)
            or health.get("Status") != "healthy"
            or not isinstance(host_config, dict)
            or host_config.get("PortBindings") not in (None, {})
            or not isinstance(ports, dict)
            or any(value not in (None, []) for value in ports.values())
        ):
            raise WebControlledValidationRuntimeError(
                "WEB controlled Docker Target boundary differs"
            )
        return WebControlledTargetBoundaryObservation(
            targetNetworkDigest=sha256(network_name.encode("utf-8")).hexdigest(),
            targetNetworkId=expected_network_id,
            targetContainerId=expected_target_container_id,
            targetImageId=expected_target_image_id,
            observedAt=datetime.now(UTC),
        )

    def ephemeral_resources_absent(self, execution_id: str) -> bool:
        if not execution_id or execution_id.strip() != execution_id or "\x00" in execution_id:
            raise ValueError("WEB controlled Worker execution identity is unsafe")
        label = f"label=pajin.execution-id={execution_id}"
        containers = self._run(("container", "ls", "--all", "--quiet", "--filter", label))
        networks = self._run(("network", "ls", "--quiet", "--filter", label))
        return not containers and not networks

    def _single_inspect(self, arguments: tuple[str, ...]) -> dict[str, object]:
        try:
            value = json.loads(self._run(arguments))
        except json.JSONDecodeError as exc:
            raise WebControlledValidationRuntimeError(
                "WEB controlled Docker inspect output is invalid"
            ) from exc
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise WebControlledValidationRuntimeError(
                "WEB controlled Docker inspect output is ambiguous"
            )
        return value[0]

    def _run(self, arguments: tuple[str, ...]) -> str:
        try:
            result = subprocess.run(
                [self._executable, *arguments],
                capture_output=True,
                check=False,
                timeout=self._timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise WebControlledValidationRuntimeError(
                "WEB controlled Docker inspection failed"
            ) from exc
        if result.returncode != 0 or len(result.stdout) > 1024 * 1024:
            raise WebControlledValidationRuntimeError(
                "WEB controlled Docker inspection was rejected"
            )
        try:
            return result.stdout.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError as exc:
            raise WebControlledValidationRuntimeError(
                "WEB controlled Docker output is not UTF-8"
            ) from exc


def web_controlled_worker_backend_context_digest(backend: DockerWorkerBackend) -> str:
    """Content-address the exact Docker backend configuration used by WEB-002D."""

    if type(backend) is not DockerWorkerBackend:
        raise TypeError("WEB controlled validation requires the exact Docker Worker backend")
    context = backend.stable_execution_context()
    return benchmark_digest(
        "pajin.workflow.web-controlled-docker-worker-context/v1",
        context,
        max_bytes=512 * 1024,
    )


def _web_controlled_observer_context_digest(
    inspector: WebControlledDockerBoundaryInspector,
) -> str:
    context = json.loads(
        canonical_json_bytes(
            inspector.stable_observer_context(),
            label="WEB controlled topology observer context",
            max_bytes=512 * 1024,
        )
    )
    return benchmark_digest(
        "pajin.workflow.web-controlled-docker-observer-context/v1",
        context,
        max_bytes=512 * 1024,
    )


def _build_worker_evidence_record(
    evidence: WebControlledValidationWorkerEvidence,
    *,
    inspector: WebControlledDockerBoundaryInspector,
) -> _WebControlledValidationWorkerEvidenceRecord:
    canonical = WebControlledValidationWorkerEvidence.model_validate(
        evidence.model_dump(mode="python", by_alias=True)
    )
    return _WebControlledValidationWorkerEvidenceRecord(
        evidenceDigest=canonical.evidence_digest,
        routeDigest=canonical.route_digest,
        routeVerificationDigest=canonical.route_verification_digest,
        routeClaimReceiptDigest=canonical.route_claim_receipt_digest,
        consumptionSlotDigest=canonical.consumption_slot_digest,
        workerExecutionId=canonical.worker_job.execution_id,
        backendContextDigest=canonical.backend_context_digest,
        observerContextDigest=_web_controlled_observer_context_digest(inspector),
        topologyObservationDigest=canonical.topology_observation.observation_digest,
        targetBeforeObservationDigest=canonical.target_before.observation_digest,
        targetAfterObservationDigest=canonical.target_after.observation_digest,
    )


def web_controlled_gateway_policy_digest() -> str:
    """Return the code-owned three-GET egress policy identity."""

    return benchmark_digest(
        "pajin.workflow.web-controlled-gateway-policy/v1",
        {
            "target": "http://target:8080/v1/users/lookup",
            "allowedMethods": ["GET"],
            "allowPrivateNetworks": True,
            "maxResponseBytes": 32768,
            "maxRequests": 3,
            "connectAllowed": False,
            "dnsAllowed": False,
            "callerAuthoredPayloadAllowed": False,
        },
        max_bytes=64 * 1024,
    )


def _system_utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class _ProductionAdapterBinding:
    route_authority: WebProxyRouteLiveAuthorityContext
    claim_ledger: WebControlledValidationRouteClaimLedger
    now: Callable[[], datetime]
    deployment_id: str
    gateway_policy_id: str
    gateway_policy_version: str
    worker_backend_id: str
    worker_backend_version: str
    runtime_policy_digest: str
    claim_ledger_identity_digest: str


class DockerWebControlledValidationAdapter:
    """Live-verify, one-shot claim, then materialize one exact Docker route."""

    def __init__(
        self,
        *,
        backend: DockerWorkerBackend,
        inspector: WebControlledDockerBoundaryInspector,
        route_authority: WebProxyRouteLiveAuthorityContext,
        claim_ledger: WebControlledValidationRouteClaimLedger,
        evidence_store_path: Path,
        deployment_id: str,
        gateway_policy_id: str,
        gateway_policy_version: str,
        worker_backend_id: str,
        worker_backend_version: str,
    ) -> None:
        if type(backend) is not DockerWorkerBackend:
            raise TypeError("WEB controlled adapter requires the exact Docker Worker backend")
        if type(inspector) is not SubprocessWebControlledDockerBoundaryInspector:
            raise TypeError(
                "WEB controlled production adapter requires the code-owned Docker inspector"
            )
        self._initialize(
            backend=backend,
            inspector=inspector,
            route_authority=route_authority,
            claim_ledger=claim_ledger,
            evidence_store_path=evidence_store_path,
            deployment_id=deployment_id,
            gateway_policy_id=gateway_policy_id,
            gateway_policy_version=gateway_policy_version,
            worker_backend_id=worker_backend_id,
            worker_backend_version=worker_backend_version,
            now=_system_utc_now,
            production_boundary_verified=True,
        )
        require_production_web_controlled_validation_adapter(self)

    @classmethod
    def _for_test(
        cls,
        *,
        backend: DockerWorkerBackend,
        inspector: WebControlledDockerBoundaryInspector,
        route_authority: WebProxyRouteLiveAuthorityContext,
        claim_ledger: WebControlledValidationRouteClaimLedger,
        deployment_id: str,
        gateway_policy_id: str,
        gateway_policy_version: str,
        worker_backend_id: str,
        worker_backend_version: str,
        evaluated_at: datetime,
    ) -> DockerWebControlledValidationAdapter:
        """Construct an explicitly non-production unit-test boundary."""

        instance = object.__new__(cls)
        instance._initialize(
            backend=backend,
            inspector=inspector,
            route_authority=route_authority,
            claim_ledger=claim_ledger,
            evidence_store_path=None,
            deployment_id=deployment_id,
            gateway_policy_id=gateway_policy_id,
            gateway_policy_version=gateway_policy_version,
            worker_backend_id=worker_backend_id,
            worker_backend_version=worker_backend_version,
            now=lambda: evaluated_at,
            production_boundary_verified=False,
        )
        return instance

    def _initialize(
        self,
        *,
        backend: DockerWorkerBackend,
        inspector: WebControlledDockerBoundaryInspector,
        route_authority: WebProxyRouteLiveAuthorityContext,
        claim_ledger: WebControlledValidationRouteClaimLedger,
        evidence_store_path: Path | None,
        deployment_id: str,
        gateway_policy_id: str,
        gateway_policy_version: str,
        worker_backend_id: str,
        worker_backend_version: str,
        now: Callable[[], datetime],
        production_boundary_verified: bool,
    ) -> None:
        if type(backend) is not DockerWorkerBackend:
            raise TypeError("WEB controlled adapter requires the exact Docker Worker backend")
        if not backend.binds_egress_lifecycle_observer(inspector):
            raise TypeError("WEB controlled adapter requires its exact host topology observer")
        for label, value in (
            ("deployment", deployment_id),
            ("Gateway policy", gateway_policy_id),
            ("Gateway policy version", gateway_policy_version),
            ("Worker backend", worker_backend_id),
            ("Worker backend version", worker_backend_version),
        ):
            if not isinstance(value, str) or not value or value.strip() != value:
                raise ValueError(f"WEB controlled {label} identity is invalid")
        if (
            type(route_authority) is not WebProxyRouteLiveAuthorityContext
            or type(claim_ledger) is not WebControlledValidationRouteClaimLedger
        ):
            raise TypeError("WEB controlled adapter requires exact live route authority state")
        policy = route_authority.runtime_policy
        claim_ledger_identity_digest = claim_ledger.identity_digest(deployment_id=deployment_id)
        if production_boundary_verified and (
            type(policy) is not WebProxyRouteRuntimePolicy
            or policy.deployment_id != deployment_id
            or policy.claim_ledger_identity_digest != claim_ledger_identity_digest
            or policy.gateway_policy_id != gateway_policy_id
            or policy.gateway_policy_version != gateway_policy_version
            or policy.gateway_policy_digest != web_controlled_gateway_policy_digest()
            or policy.worker_backend_id != worker_backend_id
            or policy.worker_backend_version != worker_backend_version
            or policy.worker_backend_digest != web_controlled_worker_backend_context_digest(backend)
        ):
            raise ValueError("WEB controlled production identities differ from signed route policy")

        evidence_store: _WebControlledValidationWorkerEvidenceStore | None
        if production_boundary_verified:
            if evidence_store_path is None:
                raise TypeError(
                    "WEB controlled production adapter requires a durable Evidence store"
                )
            normalized_evidence_store_path = Path(os.path.abspath(evidence_store_path))
            if os.path.normcase(str(normalized_evidence_store_path)) == os.path.normcase(
                str(claim_ledger.path)
            ):
                raise ValueError(
                    "WEB controlled route claims and Worker Evidence require distinct stores"
                )
            evidence_store = _WebControlledValidationWorkerEvidenceStore(
                normalized_evidence_store_path
            )
        else:
            if evidence_store_path is not None:
                raise TypeError(
                    "WEB controlled test adapter cannot own a production Evidence store"
                )
            evidence_store = None
        self._backend = backend
        self._inspector = inspector
        self._route_authority = route_authority
        self._claim_ledger = claim_ledger
        self._evidence_store = evidence_store
        self._deployment_id = deployment_id
        self._gateway_policy_id = gateway_policy_id
        self._gateway_policy_version = gateway_policy_version
        self._worker_backend_id = worker_backend_id
        self._worker_backend_version = worker_backend_version
        self._now = now
        self._production_boundary_verified = production_boundary_verified
        self._production_binding = (
            _ProductionAdapterBinding(
                route_authority=route_authority,
                claim_ledger=claim_ledger,
                now=now,
                deployment_id=deployment_id,
                gateway_policy_id=gateway_policy_id,
                gateway_policy_version=gateway_policy_version,
                worker_backend_id=worker_backend_id,
                worker_backend_version=worker_backend_version,
                runtime_policy_digest=policy.policy_digest,
                claim_ledger_identity_digest=claim_ledger_identity_digest,
            )
            if production_boundary_verified
            else None
        )

    @property
    def production_boundary_verified(self) -> bool:
        return self._production_boundary_verified

    def reopen_worker_evidence(
        self,
        evidence: WebControlledValidationWorkerEvidence,
        *,
        bundle: WebProxyRouteBundle,
        verification: WebProxyRouteVerification,
        route_claim_receipt: WebControlledValidationRouteClaimReceipt,
        coordinate: BenchmarkTargetCoordinate,
    ) -> WebControlledValidationWorkerEvidence:
        """Reopen Evidence only through the exact production-owned backend."""

        require_production_web_controlled_validation_adapter(self)
        try:
            durable_claim = load_web_controlled_validation_route_claim_receipt(
                ledger=self._claim_ledger,
                receipt=route_claim_receipt,
            )
            canonical = _load_web_controlled_validation_worker_evidence(
                evidence,
                bundle=bundle,
                verification=verification,
                route_claim_receipt=durable_claim,
                coordinate=coordinate,
                backend=self._backend,
            )
            evidence_store = self._evidence_store
            if type(evidence_store) is not _WebControlledValidationWorkerEvidenceStore:
                raise WebControlledValidationRuntimeError(
                    "WEB controlled Worker Evidence lacks its production store"
                )
            durable_record, durable_evidence = evidence_store.load(canonical.evidence_digest)
            expected_record = _build_worker_evidence_record(
                canonical,
                inspector=self._inspector,
            )
            policy = bundle.route.statement.runtime_policy
            if (
                durable_record != expected_record
                or durable_evidence != canonical
                or not self._inspector.ephemeral_resources_absent(canonical.worker_job.execution_id)
                or self._inspector.image_id(policy.worker_image) != policy.worker_image_id
                or self._inspector.image_id(policy.proxy_image) != policy.proxy_image_id
            ):
                raise WebControlledValidationRuntimeError(
                    "WEB controlled Worker Evidence production provenance differs"
                )
            return durable_evidence.model_copy(deep=True)
        except WebControlledValidationRuntimeError:
            raise
        except Exception as exc:
            raise WebControlledValidationRuntimeError(
                "WEB controlled Worker Evidence production reload failed closed"
            ) from exc

    async def execute(
        self,
        *,
        bundle: WebProxyRouteBundle,
        coordinate: BenchmarkTargetCoordinate,
        request: ToolRequest,
    ) -> WebControlledValidationWorkerOutcome:
        """Live-verify and claim the exact route before any Docker side effect."""

        try:
            if self._production_boundary_verified:
                require_production_web_controlled_validation_adapter(self)
            elif self._evidence_store is not None:
                raise WebControlledValidationRuntimeError(
                    "WEB controlled test adapter cannot own a production Evidence store"
                )
            evaluated_at = self._now()
            if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
                raise WebControlledValidationRuntimeError(
                    "WEB controlled host clock lacks a UTC offset"
                )
            evaluated_at = evaluated_at.astimezone(UTC)
            verification = self._route_authority.verify(
                bundle,
                evaluated_at=evaluated_at,
            )
            statement = bundle.route.statement
            route_claim_receipt = self._claim_ledger.claim_once(
                slot_digest=statement.consumption_slot_digest,
                route_digest=statement.route_digest,
                verification_digest=verification.verification_digest,
                claimed_at=evaluated_at,
            )
            return await self._execute(
                bundle=bundle,
                verification=verification,
                route_claim_receipt=route_claim_receipt,
                coordinate=coordinate,
                request=request,
            )
        except WebControlledValidationRuntimeError:
            raise
        except Exception as exc:
            raise WebControlledValidationRuntimeError(
                "WEB controlled validation Worker execution failed closed"
            ) from exc

    async def _execute(
        self,
        *,
        bundle: WebProxyRouteBundle,
        verification: WebProxyRouteVerification,
        route_claim_receipt: WebControlledValidationRouteClaimReceipt,
        coordinate: BenchmarkTargetCoordinate,
        request: ToolRequest,
    ) -> WebControlledValidationWorkerOutcome:
        route = WebProxyRouteBundle.model_validate(
            bundle.model_dump(mode="json", by_alias=True)
        ).route.statement
        verified = WebProxyRouteVerification.model_validate(
            verification.model_dump(mode="json", by_alias=True)
        )
        if type(route_claim_receipt) is not WebControlledValidationRouteClaimReceipt:
            raise WebControlledValidationRuntimeError(
                "WEB controlled route claim requires its exact receipt type"
            )
        if set(route_claim_receipt.__dict__) != set(
            WebControlledValidationRouteClaimReceipt.model_fields
        ):
            raise WebControlledValidationRuntimeError(
                "WEB controlled route claim contains hidden or missing state"
            )
        claim = WebControlledValidationRouteClaimReceipt.model_validate(
            route_claim_receipt.model_dump(mode="python", by_alias=True)
        )
        coordinate = BenchmarkTargetCoordinate.model_validate(
            coordinate.model_dump(mode="json", by_alias=True)
        )
        request = ToolRequest.model_validate(request.model_dump(mode="json"))
        policy = route.runtime_policy
        network_name = docker_benchmark_target_network_name(coordinate)
        backend_context = self._backend.stable_execution_context()
        backend_digest = web_controlled_worker_backend_context_digest(self._backend)
        expected_route_map = {policy.worker_action: network_name}
        expected_observer_context = json.loads(
            canonical_json_bytes(
                self._inspector.stable_observer_context(),
                label="WEB controlled topology observer context",
                max_bytes=512 * 1024,
            )
        )
        if (
            route.route_id != verified.route_id
            or route.route_digest != verified.route_digest
            or route.target.coordinate_digest != coordinate.coordinate_digest
            or route.request_id != request.request_id
            or route.request_digest != canonical_tool_request_digest(request)
            or claim.slot_digest != route.consumption_slot_digest
            or claim.route_digest != route.route_digest
            or claim.verification_digest != verified.verification_digest
            or not route.issued_at <= claim.claimed_at < route.expires_at
            or policy.deployment_id != self._deployment_id
            or policy.gateway_policy_id != self._gateway_policy_id
            or policy.gateway_policy_version != self._gateway_policy_version
            or policy.gateway_policy_digest != web_controlled_gateway_policy_digest()
            or policy.worker_backend_id != self._worker_backend_id
            or policy.worker_backend_version != self._worker_backend_version
            or policy.worker_backend_digest != backend_digest
            or backend_context.get("implementationVersion") != "pajin.docker-worker/v3"
            or backend_context.get("allowedImages") != [policy.worker_image]
            or backend_context.get("egressProxyImage") != policy.proxy_image
            or backend_context.get("externalNetworkRoutes") != expected_route_map
            or backend_context.get("egressLifecycleObserver") != expected_observer_context
        ):
            raise WebControlledValidationRuntimeError(
                "WEB controlled route differs from the deployment runtime"
            )
        if (
            self._inspector.image_id(policy.worker_image) != policy.worker_image_id
            or self._inspector.image_id(policy.proxy_image) != policy.proxy_image_id
        ):
            raise WebControlledValidationRuntimeError(
                "WEB controlled Worker or proxy image identity differs"
            )
        target_network_digest = sha256(network_name.encode("utf-8")).hexdigest()
        if target_network_digest == route.worker_proxy_network_slot_digest:
            raise WebControlledValidationRuntimeError(
                "WEB controlled Target and Worker-proxy network identities overlap"
            )
        before = self._inspector.observe_target(
            network_name=network_name,
            expected_network_id=route.target.target_network_id,
            expected_target_container_id=route.target.target_container_id,
            expected_target_image_id=route.target.target_image_id,
        )
        tool = BooleanSQLiProbeTool()
        prepared = tool.prepare(request)
        job = WorkerJob.model_validate(
            prepared.model_copy(
                update={
                    "network": NetworkMode.EGRESS_PROXY,
                    "egress_policy": EgressPolicy(
                        allow=[request.target],
                        deny=[],
                        allowed_methods={"GET"},
                        allow_private_networks=True,
                        max_response_bytes=policy.max_response_bytes_per_request,
                        max_requests=policy.request_budget,
                    ),
                },
                deep=True,
            ).model_dump(mode="python")
        )
        if (
            job.image != policy.worker_image
            or job.command != [policy.worker_action]
            or job.network is not NetworkMode.EGRESS_PROXY
            or job.egress_policy
            != EgressPolicy(
                allow=[request.target],
                deny=[],
                allowed_methods={"GET"},
                allow_private_networks=True,
                max_response_bytes=32768,
                max_requests=3,
            )
            or job.secret_requests
            or not self._inspector.ephemeral_resources_absent(job.execution_id)
        ):
            raise WebControlledValidationRuntimeError(
                "WEB controlled Worker job or preflight resource state differs"
            )
        worker_result: WorkerResult
        try:
            worker_result = await self._backend.run(job, secrets=[])
        finally:
            cleanup_absent = self._inspector.ephemeral_resources_absent(job.execution_id)
        if not cleanup_absent:
            raise WebControlledValidationRuntimeError(
                "WEB controlled Worker ephemeral resources remain"
            )
        topology = self._inspector.topology_observation(job.execution_id)
        if (
            topology.execution_id != job.execution_id
            or topology.worker_image_id != policy.worker_image_id
            or topology.proxy_image_id != policy.proxy_image_id
            or topology.target_network_name != network_name
            or topology.target_network_id != route.target.target_network_id
            or topology.target_container_id != route.target.target_container_id
            or topology.target_image_id != route.target.target_image_id
        ):
            raise WebControlledValidationRuntimeError(
                "WEB controlled host topology differs from the route"
            )
        after = self._inspector.observe_target(
            network_name=network_name,
            expected_network_id=route.target.target_network_id,
            expected_target_container_id=route.target.target_container_id,
            expected_target_image_id=route.target.target_image_id,
        )
        normalized = normalize_host_receipt(
            backend=self._backend,
            job=job,
            result=worker_result,
            materials=[],
        )
        projection = project_tool_result(
            request=request,
            tool=tool,
            receipt=normalized,
            materials=[],
        )
        if (
            not normalized.network_log_trusted
            or not projection.result_identity_valid
            or not projection.result.success
        ):
            raise WebControlledValidationRuntimeError("WEB controlled Worker result is not trusted")
        host_receipts = host_observed_http_receipts(
            normalized.worker_result,
            network_log_trusted=normalized.network_log_trusted,
        )
        if host_receipts is None or len(host_receipts) != 3:
            raise WebControlledValidationRuntimeError(
                "WEB controlled Worker lacks the three host receipts"
            )
        host_receipt_digests = tuple(
            sha256(
                canonical_json_bytes(
                    receipt.model_dump(mode="json", by_alias=True),
                    label="WEB controlled host HTTP receipt",
                    max_bytes=512 * 1024,
                )
            ).hexdigest()
            for receipt in host_receipts
        )
        receipt_times = (
            before.observed_at,
            topology.attached_at,
            topology.proxy_detached_at,
            topology.resources_absent_at,
        )
        if any(previous > current for previous, current in pairwise(receipt_times)):
            raise WebControlledValidationRuntimeError(
                "WEB controlled proxy lifecycle timestamps are nonmonotonic"
            )
        bridge_receipts = tuple(
            WebProxyBridgeLifecycleReceipt(
                stage=stage,
                routeId=route.route_id,
                routeDigest=route.route_digest,
                consumptionSlotDigest=route.consumption_slot_digest,
                workerExecutionId=job.execution_id,
                targetNetworkDigest=target_network_digest,
                workerProxyNetworkSlotDigest=route.worker_proxy_network_slot_digest,
                occurredAt=occurred_at,
            )
            for stage, occurred_at in zip(_BRIDGE_STAGES, receipt_times, strict=True)
        )
        evidence = WebControlledValidationWorkerEvidence(
            routeId=route.route_id,
            routeDigest=route.route_digest,
            routeVerificationId=verified.verification_id,
            routeVerificationDigest=verified.verification_digest,
            routeClaimReceiptId=(f"web-controlled-validation-route-claim:{claim.receipt_digest}"),
            routeClaimReceiptDigest=claim.receipt_digest,
            consumptionSlotDigest=route.consumption_slot_digest,
            targetAttemptId=route.target.attempt_id,
            targetAttemptDigest=route.target.attempt_digest,
            targetExecutionOperationId=route.target.execution_operation_id,
            targetExecutionOperationDigest=route.target.execution_operation_digest,
            targetFence=route.target.active_fence,
            backendContextDigest=backend_digest,
            requestDigest=canonical_tool_request_digest(request),
            targetBefore=before,
            targetAfter=after,
            topologyObservation=topology,
            bridgeReceipts=bridge_receipts,
            hostHttpReceiptDigests=host_receipt_digests,
            request=request,
            workerJob=job,
            workerResult=normalized.worker_result,
            toolResult=projection.result,
        )
        if self._production_boundary_verified:
            require_production_web_controlled_validation_adapter(self)
            evidence_store = self._evidence_store
            if (
                type(evidence_store) is not _WebControlledValidationWorkerEvidenceStore
                or web_controlled_worker_backend_context_digest(self._backend) != backend_digest
            ):
                raise WebControlledValidationRuntimeError(
                    "WEB controlled production boundary changed before Evidence persistence"
                )
            evidence_store.append(
                record=_build_worker_evidence_record(
                    evidence,
                    inspector=self._inspector,
                ),
                evidence=evidence,
            )
        elif self._evidence_store is not None:
            raise WebControlledValidationRuntimeError(
                "WEB controlled test execution cannot persist production Evidence"
            )
        return WebControlledValidationWorkerOutcome(
            evidence=evidence.model_copy(deep=True),
            verification=verified.model_copy(deep=True),
            route_claim_receipt=claim.model_copy(deep=True),
            backend_context=json.loads(
                canonical_json_bytes(
                    backend_context,
                    label="WEB controlled backend context",
                    max_bytes=512 * 1024,
                )
            ),
            production_boundary_verified=self._production_boundary_verified,
        )


_PRODUCTION_INSPECTOR_DESCRIPTORS = {
    name: getattr_static(SubprocessWebControlledDockerBoundaryInspector, name)
    for name in (
        "__init__",
        "stable_observer_context",
        "attached",
        "cleaned",
        "topology_observation",
        "_observe_attached",
        "_observe_attached_once",
        "_observe_cleaned",
        "_docker_sha256",
        "_docker_image_id",
        "_network_member_ids",
        "_container_network_ids",
        "_execution_label",
        "_published_port_count",
        "image_id",
        "observe_target",
        "ephemeral_resources_absent",
        "_single_inspect",
        "_run",
        "__getattribute__",
    )
}
_PRODUCTION_WORKER_BACKEND_DESCRIPTORS = {
    name: getattr_static(DockerWorkerBackend, name)
    for name in (
        "__init__",
        "stable_execution_context",
        "binds_egress_lifecycle_observer",
        "run",
        "_execute_container_process",
        "_write_stdin_and_wait",
        "_result_from_process_capture",
        "_docker_args",
        "_setup_egress",
        "_proxy_policy_json",
        "_wait_proxy_healthy",
        "_read_proxy_logs",
        "_cleanup_egress",
        "_cleanup_execution",
        "_drain_cleanup",
        "_remove_docker_resource",
        "_bounded_cli_diagnostic",
        "_resource_is_absent",
        "_cleanup_failures",
        "_cleanup_failures_from_exception",
        "_run_cli",
        "_stop_cli_process",
        "_force_remove",
        "_read_bounded",
        "_wire_stdin",
        "_container_name",
        "_rejected",
        "__getattribute__",
    )
}
_PRODUCTION_ADAPTER_DESCRIPTORS = {
    name: getattr_static(DockerWebControlledValidationAdapter, name)
    for name in (
        "__init__",
        "_initialize",
        "production_boundary_verified",
        "reopen_worker_evidence",
        "execute",
        "_execute",
        "__getattribute__",
    )
}
_PRODUCTION_ROUTE_AUTHORITY_DESCRIPTORS = {
    name: getattr_static(WebProxyRouteLiveAuthorityContext, name)
    for name in (
        "verify",
        "verify_cleanup_invalidated_history",
        "__getattribute__",
    )
}
_PRODUCTION_CLAIM_LEDGER_DESCRIPTORS = {
    name: getattr_static(WebControlledValidationRouteClaimLedger, name)
    for name in (
        "__init__",
        "identity_digest",
        "claim_once",
        "seal_denial_if_unclaimed",
        "require_unclaimed",
        "_load",
        "_load_denial",
        "_initialize",
        "_write_transaction",
        "_read_transaction",
        "_open_write_connection",
        "_require_safe_path",
        "_require_safe_sidecars",
        "__getattribute__",
    )
}
_PRODUCTION_CLAIM_LEDGER_STATE = frozenset({"path"})


_PRODUCTION_INSPECTOR_STATE = frozenset(
    {
        "_executable",
        "_timeout_seconds",
        "_topology_lock",
        "_attached_topologies",
        "_completed_topologies",
    }
)
_PRODUCTION_WORKER_BACKEND_STATE = frozenset(
    {
        "_allowed_images",
        "_runtime_image_bindings",
        "_docker",
        "_egress_proxy_image",
        "_external_network",
        "_external_network_routes",
        "_egress_lifecycle_observer",
        "_egress_observer_context",
    }
)
_PRODUCTION_ADAPTER_STATE = frozenset(
    {
        "_backend",
        "_inspector",
        "_route_authority",
        "_claim_ledger",
        "_evidence_store",
        "_deployment_id",
        "_gateway_policy_id",
        "_gateway_policy_version",
        "_worker_backend_id",
        "_worker_backend_version",
        "_now",
        "_production_boundary_verified",
        "_production_binding",
    }
)


def require_production_web_controlled_validation_adapter(
    adapter: DockerWebControlledValidationAdapter,
) -> None:
    """Require the exact unshadowed Worker custody boundary used by WEB-002D."""

    if type(adapter) is not DockerWebControlledValidationAdapter:
        raise WebControlledValidationRuntimeError(
            "WEB controlled production Evidence requires the exact Docker adapter"
        )
    adapter_state = object.__getattribute__(adapter, "__dict__")
    backend = object.__getattribute__(adapter, "_backend")
    inspector = object.__getattribute__(adapter, "_inspector")
    evidence_store = object.__getattribute__(adapter, "_evidence_store")
    route_authority = object.__getattribute__(adapter, "_route_authority")
    claim_ledger = object.__getattribute__(adapter, "_claim_ledger")
    now = object.__getattribute__(adapter, "_now")
    binding = object.__getattribute__(adapter, "_production_binding")
    deployment_id = object.__getattribute__(adapter, "_deployment_id")
    gateway_policy_id = object.__getattribute__(adapter, "_gateway_policy_id")
    gateway_policy_version = object.__getattribute__(adapter, "_gateway_policy_version")
    worker_backend_id = object.__getattribute__(adapter, "_worker_backend_id")
    worker_backend_version = object.__getattribute__(adapter, "_worker_backend_version")
    if (
        type(backend) is not DockerWorkerBackend
        or type(inspector) is not SubprocessWebControlledDockerBoundaryInspector
        or type(evidence_store) is not _WebControlledValidationWorkerEvidenceStore
        or type(route_authority) is not WebProxyRouteLiveAuthorityContext
        or type(claim_ledger) is not WebControlledValidationRouteClaimLedger
        or type(binding) is not _ProductionAdapterBinding
        or now is not _system_utc_now
        or object.__getattribute__(adapter, "_production_boundary_verified") is not True
    ):
        raise WebControlledValidationRuntimeError(
            "WEB controlled Worker Evidence requires the production adapter boundary"
        )
    if any(
        getattr_static(WebProxyRouteLiveAuthorityContext, name, None) is not implementation
        for name, implementation in _PRODUCTION_ROUTE_AUTHORITY_DESCRIPTORS.items()
    ):
        raise WebControlledValidationRuntimeError(
            "WEB controlled production route authority boundary is shadowed"
        )
    for instance, expected_descriptors, expected_state in (
        (adapter, _PRODUCTION_ADAPTER_DESCRIPTORS, _PRODUCTION_ADAPTER_STATE),
        (backend, _PRODUCTION_WORKER_BACKEND_DESCRIPTORS, _PRODUCTION_WORKER_BACKEND_STATE),
        (inspector, _PRODUCTION_INSPECTOR_DESCRIPTORS, _PRODUCTION_INSPECTOR_STATE),
        (
            claim_ledger,
            _PRODUCTION_CLAIM_LEDGER_DESCRIPTORS,
            _PRODUCTION_CLAIM_LEDGER_STATE,
        ),
    ):
        instance_state = object.__getattribute__(instance, "__dict__")
        if set(instance_state) != expected_state or any(
            getattr_static(type(instance), name, None) is not implementation
            for name, implementation in expected_descriptors.items()
        ):
            raise WebControlledValidationRuntimeError(
                "WEB controlled production Worker custody boundary is shadowed"
            )
    policy = object.__getattribute__(route_authority, "runtime_policy")
    ledger_identity_digest = WebControlledValidationRouteClaimLedger.identity_digest(
        claim_ledger,
        deployment_id=deployment_id,
    )
    backend_digest = web_controlled_worker_backend_context_digest(backend)
    inspector_context = SubprocessWebControlledDockerBoundaryInspector.stable_observer_context(
        inspector
    )
    inspector_executable = object.__getattribute__(inspector, "_executable")
    inspector_timeout = object.__getattribute__(inspector, "_timeout_seconds")
    attached_topologies = object.__getattribute__(inspector, "_attached_topologies")
    completed_topologies = object.__getattribute__(inspector, "_completed_topologies")
    if (
        route_authority is not binding.route_authority
        or claim_ledger is not binding.claim_ledger
        or now is not binding.now
        or binding.now is not _system_utc_now
        or deployment_id != binding.deployment_id
        or gateway_policy_id != binding.gateway_policy_id
        or gateway_policy_version != binding.gateway_policy_version
        or worker_backend_id != binding.worker_backend_id
        or worker_backend_version != binding.worker_backend_version
        or type(policy) is not WebProxyRouteRuntimePolicy
        or policy.policy_digest != binding.runtime_policy_digest
        or ledger_identity_digest != binding.claim_ledger_identity_digest
        or policy.claim_ledger_identity_digest != ledger_identity_digest
        or policy.deployment_id != deployment_id
        or policy.gateway_policy_id != gateway_policy_id
        or policy.gateway_policy_version != gateway_policy_version
        or policy.gateway_policy_digest != web_controlled_gateway_policy_digest()
        or policy.worker_backend_id != worker_backend_id
        or policy.worker_backend_version != worker_backend_version
        or policy.worker_backend_digest != backend_digest
        or route_authority.trust_anchor.deployment_id != deployment_id
        or inspector_executable != "docker"
        or inspector_timeout != 20
        or type(attached_topologies) is not dict
        or type(completed_topologies) is not dict
        or type(object.__getattribute__(backend, "_allowed_images")) is not set
        or object.__getattribute__(backend, "_allowed_images") != {policy.worker_image}
        or object.__getattribute__(backend, "_runtime_image_bindings") != {}
        or object.__getattribute__(backend, "_docker") != inspector_executable
        or type(object.__getattribute__(backend, "_external_network_routes")) is not dict
        or object.__getattribute__(backend, "_egress_lifecycle_observer") is not inspector
        or object.__getattribute__(backend, "_egress_observer_context") != inspector_context
        or not DockerWorkerBackend.binds_egress_lifecycle_observer(backend, inspector)
        or set(adapter_state) != _PRODUCTION_ADAPTER_STATE
    ):
        raise WebControlledValidationRuntimeError(
            "WEB controlled production Worker custody state differs"
        )


def _load_web_controlled_validation_worker_evidence(
    evidence: WebControlledValidationWorkerEvidence,
    *,
    bundle: WebProxyRouteBundle,
    verification: WebProxyRouteVerification,
    route_claim_receipt: WebControlledValidationRouteClaimReceipt,
    coordinate: BenchmarkTargetCoordinate,
    backend: DockerWorkerBackend,
) -> WebControlledValidationWorkerEvidence:
    """Reopen Worker Evidence only against the exact Docker backend and route context."""

    try:
        if (
            type(evidence) is not WebControlledValidationWorkerEvidence
            or type(bundle) is not WebProxyRouteBundle
            or type(verification) is not WebProxyRouteVerification
            or type(route_claim_receipt) is not WebControlledValidationRouteClaimReceipt
            or type(coordinate) is not BenchmarkTargetCoordinate
            or type(backend) is not DockerWorkerBackend
        ):
            raise TypeError("WEB controlled Worker evidence requires exact context types")
        canonical = WebControlledValidationWorkerEvidence.model_validate(
            evidence.model_dump(mode="python", by_alias=True)
        )
        route = WebProxyRouteBundle.model_validate(
            bundle.model_dump(mode="python", by_alias=True)
        ).route.statement
        verified = WebProxyRouteVerification.model_validate(
            verification.model_dump(mode="python", by_alias=True)
        )
        claim = WebControlledValidationRouteClaimReceipt.model_validate(
            route_claim_receipt.model_dump(mode="python", by_alias=True)
        )
        target_coordinate = BenchmarkTargetCoordinate.model_validate(
            coordinate.model_dump(mode="python", by_alias=True)
        )
        policy = route.runtime_policy
        backend_context = backend.stable_execution_context()
        expected_route_map = {
            policy.worker_action: docker_benchmark_target_network_name(target_coordinate)
        }
        expected_observer_context = backend_context.get("egressLifecycleObserver")
        if (
            canonical.route_id != route.route_id
            or canonical.route_digest != route.route_digest
            or canonical.route_verification_id != verified.verification_id
            or canonical.route_verification_digest != verified.verification_digest
            or canonical.route_claim_receipt_id
            != f"web-controlled-validation-route-claim:{claim.receipt_digest}"
            or canonical.route_claim_receipt_digest != claim.receipt_digest
            or claim.slot_digest != route.consumption_slot_digest
            or claim.route_digest != route.route_digest
            or claim.verification_digest != verified.verification_digest
            or canonical.target_attempt_id != route.target.attempt_id
            or canonical.target_execution_operation_id != route.target.execution_operation_id
            or route.target.coordinate_digest != target_coordinate.coordinate_digest
            or canonical.backend_context_digest
            != web_controlled_worker_backend_context_digest(backend)
            or backend_context.get("implementationVersion") != "pajin.docker-worker/v3"
            or backend_context.get("allowedImages") != [policy.worker_image]
            or backend_context.get("egressProxyImage") != policy.proxy_image
            or backend_context.get("externalNetworkRoutes") != expected_route_map
            or expected_observer_context is None
            or canonical.topology_observation.worker_image_id != policy.worker_image_id
            or canonical.topology_observation.proxy_image_id != policy.proxy_image_id
            or canonical.topology_observation.target_network_name
            != docker_benchmark_target_network_name(target_coordinate)
            or canonical.topology_observation.target_network_id != route.target.target_network_id
            or canonical.topology_observation.target_container_id
            != route.target.target_container_id
            or canonical.topology_observation.target_image_id != route.target.target_image_id
        ):
            raise ValueError("WEB controlled Worker Evidence context differs")
        return canonical.model_copy(deep=True)
    except WebControlledValidationRuntimeError:
        raise
    except Exception as exc:
        raise WebControlledValidationRuntimeError(
            "WEB controlled Worker Evidence reload failed closed"
        ) from exc


__all__ = [
    "WEB_CONTROLLED_VALIDATION_WORKER_EVIDENCE_API_VERSION",
    "DockerWebControlledValidationAdapter",
    "SubprocessWebControlledDockerBoundaryInspector",
    "WebControlledDockerBoundaryInspector",
    "WebControlledProxyTopologyObservation",
    "WebControlledTargetBoundaryObservation",
    "WebControlledValidationRuntimeError",
    "WebControlledValidationWorkerEvidence",
    "WebControlledValidationWorkerOutcome",
    "WebProxyBridgeLifecycleReceipt",
    "require_production_web_controlled_validation_adapter",
    "web_controlled_gateway_policy_digest",
    "web_controlled_worker_backend_context_digest",
]
