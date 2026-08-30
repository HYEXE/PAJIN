"""P0-E2B recoverable Docker provider for the concrete OWASP ZAP baseline."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from inspect import getattr_static
from pathlib import Path
from typing import Annotated, Literal, Self, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.benchmark.docker_provider import (
    DockerBenchmarkProviderError,
    DockerBenchmarkProviderEvidence,
    DockerBugBountyTargetProfile,
    DockerCommandRunner,
    SubprocessDockerCommandRunner,
    _docker_id,
    _DockerTargetFactoryAdapter,
    _has_no_new_privileges,
    _mapping,
    _network_id,
    _resource_names,
)
from pajin.benchmark.measurement import WalkingBenchmarkRunObservation
from pajin.benchmark.models import BenchmarkGroundTruth, benchmark_digest
from pajin.benchmark.scanner_baseline import ScannerBaselineMeasurementPlanAuthority
from pajin.benchmark.scanner_sarif import (
    ZAP_AUTOMATION_PLAN,
    ZAPSarifNormalization,
    ZAPScannerRegistration,
    parse_zap_sarif,
)
from pajin.benchmark.target_catalog import (
    BenchmarkTargetCatalogError,
    BenchmarkTargetProfileCatalog,
    BenchmarkTargetProfileSelectionAuthority,
    select_traditional_web_api_target_profile,
)
from pajin.benchmark.target_factory import (
    BenchmarkMeasurementAttestation,
    BenchmarkMeasurementAttestationStatement,
    BenchmarkMeasurementTrustAnchor,
    BenchmarkTargetCoordinate,
    BenchmarkTargetRunAuthority,
    BenchmarkTargetStageReceipt,
    RegisteredBenchmarkTargetFactoryAdapter,
)
from pajin.benchmark.target_recovery import (
    BenchmarkTargetOperation,
    BenchmarkTargetRecoveryRequest,
)
from pajin.domain.models import StrictModel
from pajin.runtime.safe_files import read_bounded_regular_bytes

_SARIF_NAME = "p0-e2b.sarif.json"
_REQUEST_UNITS_NAME = "p0-e2b.request-units.json"
_REQUEST_UNITS_DELTA_NAME = "p0-e2b.request-units.jsonl"
_REQUEST_UNITS_BEFORE_NAME = "p0-e2b.target-log-before.jsonl"
_REQUEST_UNITS_AFTER_NAME = "p0-e2b.target-log-after.jsonl"
_PLAN_NAME = "zap.yaml"
_MAX_SARIF_BYTES = 16 * 1024 * 1024
_MAX_REQUEST_UNIT_EVIDENCE_BYTES = 256 * 1024
_MAX_TARGET_HTTP_LOG_BYTES = 8 * 1024 * 1024
_MAX_TARGET_HTTP_LOG_LINES = 100_000
_TARGET_HTTP_METHODS = frozenset({"GET", "POST"})
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


def _write_exclusive_regular_bytes(path: Path, content: bytes, *, label: str) -> None:
    """Create one host-owned artifact without following or replacing a leaf entry."""

    if type(content) is not bytes:
        raise TypeError(f"{label} content must be bytes")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOINHERIT", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_size != 0:
            raise ValueError(f"{label} was not created as one empty regular file")
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError(f"{label} write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
        final_descriptor = os.fstat(descriptor)
        final_path = path.lstat()
        expected_identity = (opened.st_dev, opened.st_ino)
        if (
            not stat.S_ISREG(final_descriptor.st_mode)
            or not stat.S_ISREG(final_path.st_mode)
            or final_descriptor.st_nlink != 1
            or final_path.st_nlink != 1
            or (final_descriptor.st_dev, final_descriptor.st_ino) != expected_identity
            or (final_path.st_dev, final_path.st_ino) != expected_identity
            or final_descriptor.st_size != len(content)
            or final_path.st_size != len(content)
        ):
            raise ValueError(f"{label} identity changed while being written")
    except (OSError, ValueError) as exc:
        raise DockerBenchmarkProviderError(f"{label} could not be created safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


class ZAPScannerRequestUnitEvidence(StrictModel):
    """Host-observed Target HTTP exchanges consumed by one exact ZAP execution."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        strict=True,
    )

    api_version: Literal["pajin.dev/zap-scanner-request-unit-evidence/v1alpha1"] = Field(
        default="pajin.dev/zap-scanner-request-unit-evidence/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ZAPScannerRequestUnitEvidence"] = "ZAPScannerRequestUnitEvidence"
    evidence_digest: str = Field(default="", alias="evidenceDigest", max_length=64)
    operation_id: str = Field(alias="operationId", min_length=1, max_length=110)
    operation_digest: _Sha256 = Field(alias="operationDigest")
    target_container_id: _Sha256 = Field(alias="targetContainerId")
    target_log_before_sha256: _Sha256 = Field(alias="targetLogBeforeSha256")
    target_log_after_sha256: _Sha256 = Field(alias="targetLogAfterSha256")
    target_log_delta_sha256: _Sha256 = Field(alias="targetLogDeltaSha256")
    target_log_delta_size_bytes: int = Field(
        alias="targetLogDeltaSizeBytes",
        strict=True,
        ge=1,
        le=_MAX_TARGET_HTTP_LOG_BYTES,
    )
    target_requests_before: int = Field(
        alias="targetRequestsBefore",
        strict=True,
        ge=0,
        le=2**63 - 1,
    )
    target_requests_after: int = Field(
        alias="targetRequestsAfter",
        strict=True,
        ge=1,
        le=2**63 - 1,
    )
    request_units: int = Field(alias="requestUnits", strict=True, ge=1, le=2**63 - 1)
    unit: Literal["target-lookup-http-response"] = "target-lookup-http-response"
    observed_at: datetime = Field(alias="observedAt")

    @field_validator("observed_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("ZAP request-unit Evidence requires a UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_evidence(self) -> Self:
        if self.target_requests_after - self.target_requests_before != self.request_units:
            raise ValueError("ZAP request-unit Evidence count differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evidence_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.zap-scanner-request-unit-evidence/v1",
            material,
            max_bytes=_MAX_REQUEST_UNIT_EVIDENCE_BYTES,
        )
        if self.evidence_digest and self.evidence_digest != digest:
            raise ValueError("ZAP request-unit Evidence Digest differs")
        object.__setattr__(self, "evidence_digest", digest)
        return self


class DockerZAPScannerTargetFactoryAdapter(_DockerTargetFactoryAdapter):
    """Reuse the fenced P0-D1 lifecycle but replace the synthetic probe with ZAP."""

    def __init__(
        self,
        *,
        state_path: Path,
        profile: DockerBugBountyTargetProfile,
        plan: ScannerBaselineMeasurementPlanAuthority,
        registration: ZAPScannerRegistration,
        trust_anchor: BenchmarkMeasurementTrustAnchor,
        measurement_private_key: bytes,
        command_runner: DockerCommandRunner | None = None,
    ) -> None:
        authoritative_plan = ScannerBaselineMeasurementPlanAuthority.model_validate(
            plan.model_dump(mode="json", by_alias=True)
        )
        authoritative_registration = ZAPScannerRegistration.model_validate(
            registration.model_dump(mode="json", by_alias=True)
        )
        if (
            authoritative_registration.parser_contract_digest
            != authoritative_plan.scanner_contract.parser_contract_digest
        ):
            raise DockerBenchmarkProviderError(
                "ZAP registration differs from the Scanner plan parser contract"
            )
        scanner_command_runner = command_runner or SubprocessDockerCommandRunner(
            timeout_seconds=min(300, max(30, authoritative_plan.manifest.protocol.timeout_seconds))
        )
        super().__init__(
            state_path=state_path,
            profile=profile,
            manifest=authoritative_plan.manifest,
            trust_anchor=trust_anchor,
            measurement_private_key=measurement_private_key,
            command_runner=scanner_command_runner,
        )
        self._scanner_plan = authoritative_plan
        self._scanner_registration = authoritative_registration
        state_parent = Path(os.path.abspath(state_path)).parent
        self._scanner_artifact_root = state_parent / f"{Path(state_path).stem}-zap-artifacts"
        self._scanner_artifact_root.mkdir(mode=0o700, parents=True, exist_ok=True)

    @property
    def scanner_plan(self) -> ScannerBaselineMeasurementPlanAuthority:
        return self._scanner_plan.model_copy(deep=True)

    @property
    def profile(self) -> DockerBugBountyTargetProfile:
        return DockerBugBountyTargetProfile.model_validate(
            cast(DockerBugBountyTargetProfile, self._profile).model_dump(mode="json", by_alias=True)
        )

    @property
    def scanner_registration(self) -> ZAPScannerRegistration:
        return self._scanner_registration.model_copy(deep=True)

    def raw_sarif(self, receipt: BenchmarkTargetStageReceipt) -> bytes:
        """Reopen raw SARIF only through its exact execution receipt and hash."""

        evidence = self.evidence(receipt)
        if evidence.stage != "execution" or evidence.raw_sarif_sha256 is None:
            raise DockerBenchmarkProviderError("ZAP SARIF is unavailable for this receipt")
        path = self._artifact_path(evidence.operation_digest)
        try:
            raw = read_bounded_regular_bytes(
                path,
                max_bytes=_MAX_SARIF_BYTES,
                label="ZAP SARIF artifact",
                require_single_link=True,
            )
        except (OSError, ValueError) as exc:
            raise DockerBenchmarkProviderError("ZAP SARIF artifact is unavailable") from exc
        if (
            not 1 <= len(raw) <= _MAX_SARIF_BYTES
            or len(raw) != evidence.raw_sarif_size_bytes
            or sha256(raw).hexdigest() != evidence.raw_sarif_sha256
        ):
            raise DockerBenchmarkProviderError("ZAP SARIF artifact differs from execution evidence")
        normalized = parse_zap_sarif(raw, registration=self._scanner_registration)
        if normalized.normalization_digest != evidence.sarif_normalization_digest:
            raise DockerBenchmarkProviderError("ZAP SARIF normalization differs from evidence")
        return bytes(raw)

    def request_unit_evidence(
        self,
        receipt: BenchmarkTargetStageReceipt,
    ) -> ZAPScannerRequestUnitEvidence:
        """Reopen the exact query-free Target HTTP exchange observation."""

        evidence = self.evidence(receipt)
        if evidence.stage != "execution" or evidence.target_container_id is None:
            raise DockerBenchmarkProviderError(
                "ZAP request-unit Evidence is unavailable for this receipt"
            )
        path = self._request_unit_evidence_path(evidence.operation_digest)
        delta_path = self._request_unit_delta_path(evidence.operation_digest)
        before_path = self._request_unit_before_path(evidence.operation_digest)
        after_path = self._request_unit_after_path(evidence.operation_digest)
        try:
            raw = read_bounded_regular_bytes(
                path,
                max_bytes=_MAX_REQUEST_UNIT_EVIDENCE_BYTES,
                label="ZAP request-unit Evidence",
                require_single_link=True,
            )
            observed = ZAPScannerRequestUnitEvidence.model_validate_json(raw)
            delta = read_bounded_regular_bytes(
                delta_path,
                max_bytes=_MAX_TARGET_HTTP_LOG_BYTES,
                label="ZAP request-unit Target log delta",
                require_single_link=True,
            )
            before = read_bounded_regular_bytes(
                before_path,
                max_bytes=_MAX_TARGET_HTTP_LOG_BYTES,
                label="ZAP request-unit Target log before snapshot",
                require_single_link=True,
            )
            after = read_bounded_regular_bytes(
                after_path,
                max_bytes=_MAX_TARGET_HTTP_LOG_BYTES,
                label="ZAP request-unit Target log after snapshot",
                require_single_link=True,
            )
        except (OSError, TypeError, ValueError) as exc:
            raise DockerBenchmarkProviderError("ZAP request-unit Evidence is unavailable") from exc
        if (
            raw != (observed.model_dump_json(by_alias=True) + "\n").encode("utf-8")
            or observed.operation_id != evidence.operation_id
            or observed.operation_digest != evidence.operation_digest
            or observed.target_container_id != evidence.target_container_id
            or observed.evidence_digest != evidence.scanner_request_unit_evidence_digest
            or observed.target_log_before_sha256 != evidence.scanner_target_log_before_sha256
            or observed.target_log_after_sha256 != evidence.scanner_target_log_after_sha256
            or observed.target_log_delta_sha256 != evidence.scanner_target_log_delta_sha256
            or observed.request_units != evidence.scanner_request_units
            or len(delta) != observed.target_log_delta_size_bytes
            or sha256(delta).hexdigest() != observed.target_log_delta_sha256
            or _target_lookup_request_count(delta) != observed.request_units
            or after != before + delta
            or sha256(before).hexdigest() != observed.target_log_before_sha256
            or sha256(after).hexdigest() != observed.target_log_after_sha256
            or _target_lookup_request_count(before) != observed.target_requests_before
            or _target_lookup_request_count(after) != observed.target_requests_after
        ):
            raise DockerBenchmarkProviderError(
                "ZAP request-unit Evidence differs from execution Evidence"
            )
        return observed.model_copy(deep=True)

    def _require_images(self) -> None:
        super()._require_images()
        result = self._checked(
            (
                "image",
                "inspect",
                self._scanner_registration.scanner_image,
                "--format",
                "{{.Id}}",
            )
        )
        try:
            observed = result.stdout.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError as exc:
            raise DockerBenchmarkProviderError("ZAP image identity is not UTF-8") from exc
        if observed != self._scanner_registration.scanner_image_id:
            raise DockerBenchmarkProviderError("ZAP image identity differs from registration")

    def _execute(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
    ) -> tuple[
        BenchmarkTargetStageReceipt,
        WalkingBenchmarkRunObservation,
        DockerBenchmarkProviderEvidence,
    ]:
        started = datetime.now(UTC)
        server_version = self._server_version()
        self._require_images()
        names = _resource_names(coordinate)
        labels = self._labels(coordinate, operation)
        target = self._container_inspect(names.target)
        network = self._network_inspect(names.network)
        target_container_id = _docker_id(target, label="target container")
        target_network_id = _network_id(network)
        if set(_mapping(network.get("Containers"), label="network containers")) != {
            target_container_id
        }:
            raise DockerBenchmarkProviderError("Target network membership identity differs")
        self._require_isolation_state(
            coordinate,
            operation,
            target,
            network,
            network_name=names.network,
            expected_members=1,
        )
        workspace = self._workspace(operation.operation_digest)
        plan_path = workspace / _PLAN_NAME
        artifact_path = workspace / _SARIF_NAME
        request_units_path = workspace / _REQUEST_UNITS_NAME
        request_units_delta_path = workspace / _REQUEST_UNITS_DELTA_NAME
        request_units_before_path = workspace / _REQUEST_UNITS_BEFORE_NAME
        request_units_after_path = workspace / _REQUEST_UNITS_AFTER_NAME
        plan_path.write_bytes(ZAP_AUTOMATION_PLAN)
        if (
            artifact_path.exists()
            or request_units_path.exists()
            or request_units_delta_path.exists()
            or request_units_before_path.exists()
            or request_units_after_path.exists()
        ):
            raise DockerBenchmarkProviderError("ZAP output paths were not fresh")
        target_log_before = self._target_log(names.target)
        requests_before = _target_lookup_request_count(target_log_before)
        mount = f"type=bind,source={workspace},target=/zap/wrk"
        self._checked(
            (
                "create",
                "--name",
                names.worker,
                "--network",
                names.network,
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "512",
                "--memory",
                "2g",
                "--cpus",
                "2",
                "--user",
                "1000:1000",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=128m,uid=1000,gid=1000",
                "--tmpfs",
                "/home/zap/.ZAP:rw,nosuid,nodev,size=512m,uid=1000,gid=1000",
                "--mount",
                mount,
                *self._label_arguments(labels, role="scanner"),
                self._scanner_registration.scanner_image_id,
                "zap.sh",
                "-cmd",
                "-autorun",
                "/zap/wrk/zap.yaml",
            )
        )
        self._checked(("start", "--attach", names.worker))
        try:
            observed_plan = read_bounded_regular_bytes(
                plan_path,
                max_bytes=len(ZAP_AUTOMATION_PLAN),
                label="ZAP automation plan",
                require_single_link=True,
            )
        except (OSError, ValueError) as exc:
            raise DockerBenchmarkProviderError("ZAP automation plan is unavailable") from exc
        if observed_plan != ZAP_AUTOMATION_PLAN:
            raise DockerBenchmarkProviderError("ZAP changed its registered automation plan")
        raw = self._read_fresh_sarif(artifact_path)
        normalization = parse_zap_sarif(raw, registration=self._scanner_registration)
        worker = self._container_inspect(names.worker)
        target = self._container_inspect(names.target)
        target_log_after = self._target_log(names.target)
        if (
            _docker_id(target, label="target container") != target_container_id
            or _network_id(network) != target_network_id
        ):
            raise DockerBenchmarkProviderError("Target or network identity changed during ZAP")
        if not target_log_after.startswith(target_log_before):
            raise DockerBenchmarkProviderError("Target HTTP log is not append-only")
        target_log_delta = target_log_after[len(target_log_before) :]
        requests_after = _target_lookup_request_count(target_log_after)
        delta_request_units = _target_lookup_request_count(target_log_delta)
        if requests_after - requests_before != delta_request_units:
            raise DockerBenchmarkProviderError("Target HTTP log delta count differs")
        network = self._network_inspect(names.network)
        if _network_id(network) != target_network_id or set(
            _mapping(network.get("Containers"), label="network containers")
        ) != {target_container_id}:
            raise DockerBenchmarkProviderError("Target network identity changed during ZAP")
        self._require_isolation_state(
            coordinate,
            operation,
            target,
            network,
            network_name=names.network,
            expected_members=1,
        )
        self._require_scanner_state(
            coordinate,
            operation,
            worker,
            network_name=names.network,
            workspace=workspace,
        )
        completed = datetime.now(UTC)
        request_unit_evidence = ZAPScannerRequestUnitEvidence(
            operationId=operation.operation_id,
            operationDigest=operation.operation_digest,
            targetContainerId=target_container_id,
            targetLogBeforeSha256=sha256(target_log_before).hexdigest(),
            targetLogAfterSha256=sha256(target_log_after).hexdigest(),
            targetLogDeltaSha256=sha256(target_log_delta).hexdigest(),
            targetLogDeltaSizeBytes=len(target_log_delta),
            targetRequestsBefore=requests_before,
            targetRequestsAfter=requests_after,
            requestUnits=delta_request_units,
            observedAt=completed,
        )
        _write_exclusive_regular_bytes(
            request_units_before_path,
            target_log_before,
            label="ZAP request-unit Target log before snapshot",
        )
        _write_exclusive_regular_bytes(
            request_units_after_path,
            target_log_after,
            label="ZAP request-unit Target log after snapshot",
        )
        _write_exclusive_regular_bytes(
            request_units_delta_path,
            target_log_delta,
            label="ZAP request-unit Target log delta",
        )
        _write_exclusive_regular_bytes(
            request_units_path,
            (request_unit_evidence.model_dump_json(by_alias=True) + "\n").encode("utf-8"),
            label="ZAP request-unit Evidence",
        )
        evidence = self._evidence(
            coordinate,
            operation,
            server_version=server_version,
            target_container_id=target_container_id,
            worker_container_id=_docker_id(worker, label="Scanner container"),
            network_id=_network_id(network),
            network_internal=True,
            published_port_count=0,
            network_container_count=1,
            target_healthy=True,
            worker_exit_code=0,
            scanner_registration_digest=self._scanner_registration.registration_digest,
            scanner_plan_digest=self._scanner_plan.authority_digest,
            scanner_image_id=self._scanner_registration.scanner_image_id,
            scanner_container_id=_docker_id(worker, label="Scanner container"),
            raw_sarif_sha256=normalization.raw_sarif_sha256,
            raw_sarif_size_bytes=normalization.raw_sarif_size_bytes,
            sarif_normalization_digest=normalization.normalization_digest,
            scanner_request_unit_evidence_digest=request_unit_evidence.evidence_digest,
            scanner_target_log_before_sha256=request_unit_evidence.target_log_before_sha256,
            scanner_target_log_after_sha256=request_unit_evidence.target_log_after_sha256,
            scanner_target_log_delta_sha256=request_unit_evidence.target_log_delta_sha256,
            scanner_request_units=request_unit_evidence.request_units,
            observed_at=completed,
        )
        receipt = self._receipt(coordinate, operation, evidence, started, completed)
        return receipt, self._scanner_observation(coordinate, receipt, normalization), evidence

    def _workspace(self, operation_digest: str) -> Path:
        path = self._scanner_artifact_root / operation_digest
        path.mkdir(mode=0o700, parents=False, exist_ok=True)
        if path.resolve() != path or path.parent != self._scanner_artifact_root:
            raise DockerBenchmarkProviderError("ZAP workspace escaped its artifact root")
        return path

    def _artifact_path(self, operation_digest: str) -> Path:
        return self._scanner_artifact_root / operation_digest / _SARIF_NAME

    def _request_unit_evidence_path(self, operation_digest: str) -> Path:
        return self._scanner_artifact_root / operation_digest / _REQUEST_UNITS_NAME

    def _request_unit_delta_path(self, operation_digest: str) -> Path:
        return self._scanner_artifact_root / operation_digest / _REQUEST_UNITS_DELTA_NAME

    def _request_unit_before_path(self, operation_digest: str) -> Path:
        return self._scanner_artifact_root / operation_digest / _REQUEST_UNITS_BEFORE_NAME

    def _request_unit_after_path(self, operation_digest: str) -> Path:
        return self._scanner_artifact_root / operation_digest / _REQUEST_UNITS_AFTER_NAME

    def _target_log(self, target_name: str) -> bytes:
        result = self._checked(("logs", target_name))
        if result.stderr:
            raise DockerBenchmarkProviderError("Target HTTP log emitted unexpected stderr")
        raw = bytes(result.stdout)
        if len(raw) > _MAX_TARGET_HTTP_LOG_BYTES:
            raise DockerBenchmarkProviderError("Target HTTP log exceeded its Evidence bound")
        return raw

    @staticmethod
    def _read_fresh_sarif(path: Path) -> bytes:
        try:
            raw = read_bounded_regular_bytes(
                path,
                max_bytes=_MAX_SARIF_BYTES,
                label="fresh ZAP SARIF",
                require_single_link=True,
            )
        except (OSError, ValueError) as exc:
            raise DockerBenchmarkProviderError("ZAP did not produce SARIF") from exc
        if not 1 <= len(raw) <= _MAX_SARIF_BYTES:
            raise DockerBenchmarkProviderError("ZAP SARIF is missing or too large")
        return raw

    def _require_scanner_state(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
        worker: Mapping[str, object],
        *,
        network_name: str,
        workspace: Path,
    ) -> None:
        self._require_owned_resource(coordinate, operation, worker)
        state = _mapping(worker.get("State"), label="Scanner state")
        host = _mapping(worker.get("HostConfig"), label="Scanner host config")
        config = _mapping(worker.get("Config"), label="Scanner config")
        mounts = worker.get("Mounts")
        tmpfs = _mapping(host.get("Tmpfs"), label="Scanner tmpfs")
        if (
            state.get("Running") is not False
            or state.get("ExitCode") != 0
            or worker.get("Image") != self._scanner_registration.scanner_image_id
            or host.get("NetworkMode") != network_name
            or host.get("ReadonlyRootfs") is not True
            or host.get("PortBindings") not in (None, {})
            or host.get("Memory") != 2 * 1024 * 1024 * 1024
            or host.get("NanoCpus") != 2_000_000_000
            or host.get("PidsLimit") != 512
            or host.get("CapDrop") != ["ALL"]
            or not _has_no_new_privileges(host)
            or config.get("User") != "1000:1000"
            or config.get("Cmd") != ["zap.sh", "-cmd", "-autorun", "/zap/wrk/zap.yaml"]
            or tmpfs
            != {
                "/tmp": "rw,noexec,nosuid,nodev,size=128m,uid=1000,gid=1000",
                "/home/zap/.ZAP": "rw,nosuid,nodev,size=512m,uid=1000,gid=1000",
            }
            or not isinstance(mounts, list)
            or len(mounts) != 1
        ):
            raise DockerBenchmarkProviderError("ZAP container hardening policy differs")
        mount = cast(dict[str, object], mounts[0])
        if (
            mount.get("Type") != "bind"
            or Path(str(mount.get("Source"))) != workspace
            or mount.get("Destination") != "/zap/wrk"
            or mount.get("RW") is not True
        ):
            raise DockerBenchmarkProviderError("ZAP workspace mount differs")

    def _scanner_observation(
        self,
        coordinate: BenchmarkTargetCoordinate,
        receipt: BenchmarkTargetStageReceipt,
        normalization: ZAPSarifNormalization,
    ) -> WalkingBenchmarkRunObservation:
        arm = coordinate.arm
        matched_findings = sum(finding.matches_known_finding for finding in normalization.findings)
        return WalkingBenchmarkRunObservation(
            benchmarkId=coordinate.benchmark_id,
            manifestDigest=coordinate.manifest_digest,
            armId=arm.arm_id,
            armKind=arm.kind,
            configurationDigest=arm.configuration_digest,
            targetFactoryDigest=self._profile.target_factory_digest,
            campaignDigest=self._manifest.campaign_digest,
            groundTruthDigest=self._manifest.ground_truth_digest,
            protocolId=self._manifest.protocol.protocol_id,
            protocolVersion=self._manifest.protocol.protocol_version,
            measurementAuthorityId=self._definition.measurement_authority_id,
            measurementAuthorityVersion=self._definition.measurement_authority_version,
            measurementAuthorityDigest=self._definition.measurement_authority_digest,
            seed=coordinate.seed,
            repetition=coordinate.repetition,
            startedAt=receipt.started_at,
            completedAt=receipt.completed_at,
            cleanupSucceeded=False,
            toolCallCount=1,
            modelCallCount=0,
            costUsd=0.0,
            knownAttackSurfaceCount=1,
            discoveredKnownAttackSurfaceCount=int(normalization.known_surface_detected),
            knownFindingCount=1,
            matchedKnownFindingCount=int(normalization.known_finding_matched),
            candidateFindingCount=len(normalization.findings),
            validCandidateFindingCount=matched_findings,
            unexpectedValidFindingCount=0,
            confirmedFindingCount=0,
            groundTruthChainCount=1,
            completedGroundTruthChainCount=0,
            firstValidOrConfirmedFindingSeconds=(
                (receipt.completed_at - receipt.started_at).total_seconds()
                if matched_findings
                else None
            ),
            replayAttemptCount=0,
            replaySuccessCount=0,
            policyRejectionOrViolationCount=0,
            humanDecisionCount=0,
            humanInterventionOrOverturnCount=0,
        )


class CatalogBoundDockerZAPScannerTargetFactoryAdapter:
    """Bind ZAP execution to the exact P0-E2A plan and P0-D1 catalog selection."""

    def __init__(
        self,
        *,
        provider: DockerZAPScannerTargetFactoryAdapter,
        catalog: BenchmarkTargetProfileCatalog,
        ground_truth: BenchmarkGroundTruth,
    ) -> None:
        self._provider = provider
        self._definition = provider.definition
        self._profile = provider.profile
        self._plan = provider.scanner_plan
        self._registration = provider.scanner_registration
        self._manifest = self._plan.manifest
        self._ground_truth = BenchmarkGroundTruth.model_validate(
            ground_truth.model_dump(mode="json", by_alias=True)
        )
        self._selection = select_traditional_web_api_target_profile(
            self._manifest,
            adapter=self._definition,
            profile=self._profile,
            catalog=catalog,
            ground_truth=self._ground_truth,
        )

    @property
    def definition(self) -> RegisteredBenchmarkTargetFactoryAdapter:
        return self._definition.model_copy(deep=True)

    @property
    def profile(self) -> DockerBugBountyTargetProfile:
        return self._profile.model_copy(deep=True)

    @property
    def selection(self) -> BenchmarkTargetProfileSelectionAuthority:
        return self._selection.model_copy(deep=True)

    @property
    def scanner_registration(self) -> ZAPScannerRegistration:
        return self._registration.model_copy(deep=True)

    def evidence(self, receipt: BenchmarkTargetStageReceipt) -> DockerBenchmarkProviderEvidence:
        return self._provider.evidence(receipt)

    def raw_sarif(self, receipt: BenchmarkTargetStageReceipt) -> bytes:
        return self._provider.raw_sarif(receipt)

    def request_unit_evidence(
        self,
        receipt: BenchmarkTargetStageReceipt,
    ) -> ZAPScannerRequestUnitEvidence:
        return self._provider.request_unit_evidence(receipt)

    async def reset(
        self, coordinate: BenchmarkTargetCoordinate, operation: BenchmarkTargetOperation
    ) -> BenchmarkTargetStageReceipt:
        return await self._provider.reset(self._coordinate(coordinate), operation)

    async def establish_isolation(
        self,
        coordinate: BenchmarkTargetCoordinate,
        reset: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt:
        return await self._provider.establish_isolation(
            self._coordinate(coordinate), reset, operation
        )

    async def execute(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> tuple[BenchmarkTargetStageReceipt, WalkingBenchmarkRunObservation]:
        authoritative = self._coordinate(coordinate)
        receipt, observation = await self._provider.execute(authoritative, isolation, operation)
        self._require_execution(authoritative, receipt, observation)
        return receipt, observation

    async def cleanup(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt:
        return await self._provider.cleanup(self._coordinate(coordinate), isolation, operation)

    async def reconcile_cleanup(
        self,
        coordinate: BenchmarkTargetCoordinate,
        request: BenchmarkTargetRecoveryRequest,
    ) -> BenchmarkTargetStageReceipt:
        return await self._provider.reconcile_cleanup(self._coordinate(coordinate), request)

    async def attest(
        self, statement: BenchmarkMeasurementAttestationStatement
    ) -> BenchmarkMeasurementAttestation:
        if statement.adapter_digest != self._definition.adapter_digest:
            raise BenchmarkTargetCatalogError("ZAP attestation adapter differs")
        return await self._provider.attest(statement)

    def verify_target_run_match(
        self, authority: BenchmarkTargetRunAuthority
    ) -> tuple[DockerBenchmarkProviderEvidence, bytes, ZAPSarifNormalization]:
        authoritative = BenchmarkTargetRunAuthority.model_validate(
            authority.model_dump(mode="json", by_alias=True)
        )
        self._require_execution(
            authoritative.coordinate,
            authoritative.execution_receipt,
            authoritative.observation,
        )
        raw = self.raw_sarif(authoritative.execution_receipt)
        normalization = parse_zap_sarif(raw, registration=self._registration)
        return self.evidence(authoritative.execution_receipt), raw, normalization

    def _coordinate(self, coordinate: BenchmarkTargetCoordinate) -> BenchmarkTargetCoordinate:
        authoritative = BenchmarkTargetCoordinate.model_validate(
            coordinate.model_dump(mode="json", by_alias=True)
        )
        if (
            authoritative.benchmark_id != self._manifest.benchmark_id
            or authoritative.manifest_digest != self._manifest.digest()
        ):
            raise BenchmarkTargetCatalogError("ZAP coordinate differs from Scanner plan")
        return authoritative

    def _require_execution(
        self,
        coordinate: BenchmarkTargetCoordinate,
        receipt: BenchmarkTargetStageReceipt,
        observation: WalkingBenchmarkRunObservation,
    ) -> None:
        evidence = self.evidence(receipt)
        raw = self.raw_sarif(receipt)
        normalization = parse_zap_sarif(raw, registration=self._registration)
        expected = self._provider._scanner_observation(coordinate, receipt, normalization)
        expected_raw = expected.model_dump(mode="json", by_alias=True)
        expected_raw.pop("observationId")
        expected_raw.pop("observationDigest")
        expected_raw["cleanupSucceeded"] = observation.cleanup_succeeded
        expected = WalkingBenchmarkRunObservation.model_validate(expected_raw)
        if (
            evidence.scanner_registration_digest != self._registration.registration_digest
            or evidence.scanner_plan_digest != self._plan.authority_digest
            or evidence.scanner_image_id != self._registration.scanner_image_id
            or evidence.evidence_digest != receipt.provider_evidence_digest
            or observation != expected
        ):
            raise BenchmarkTargetCatalogError("ZAP execution differs from Scanner authority")


_CATALOG_BOUND_PRODUCTION_METHODS = {
    name: getattr_static(CatalogBoundDockerZAPScannerTargetFactoryAdapter, name)
    for name in (
        "definition",
        "profile",
        "selection",
        "scanner_registration",
        "evidence",
        "raw_sarif",
        "request_unit_evidence",
        "reset",
        "establish_isolation",
        "execute",
        "cleanup",
        "reconcile_cleanup",
        "attest",
        "verify_target_run_match",
        "_coordinate",
        "_require_execution",
        "__getattribute__",
    )
}
_DOCKER_ZAP_PRODUCTION_METHODS = {
    name: getattr_static(DockerZAPScannerTargetFactoryAdapter, name)
    for name in (
        "definition",
        "profile",
        "scanner_plan",
        "scanner_registration",
        "evidence",
        "raw_sarif",
        "request_unit_evidence",
        "reset",
        "establish_isolation",
        "execute",
        "cleanup",
        "reconcile_cleanup",
        "attest",
        "_run_stage",
        "_reset",
        "_isolate",
        "_execute",
        "_cleanup",
        "_resources_absent",
        "_container_exists",
        "_network_exists",
        "_checked",
        "__getattribute__",
    )
}
_SUBPROCESS_DOCKER_PRODUCTION_METHODS = {
    name: getattr_static(SubprocessDockerCommandRunner, name)
    for name in ("run", "__getattribute__")
}
_CATALOG_BOUND_PRODUCTION_STATE = frozenset(
    {
        "_provider",
        "_definition",
        "_profile",
        "_plan",
        "_registration",
        "_manifest",
        "_ground_truth",
        "_selection",
    }
)
_DOCKER_ZAP_PRODUCTION_STATE = frozenset(
    {
        "_profile",
        "_manifest",
        "_trust_anchor",
        "_attestor",
        "_definition",
        "_state_path",
        "_docker",
        "_scanner_plan",
        "_scanner_registration",
        "_scanner_artifact_root",
    }
)
_SUBPROCESS_DOCKER_PRODUCTION_STATE = frozenset({"_executable", "_timeout_seconds"})


def require_production_zap_catalog_provider(
    provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter,
) -> None:
    """Require the exact unshadowed Docker custody boundary used by WEB-002D."""

    if type(provider) is not CatalogBoundDockerZAPScannerTargetFactoryAdapter:
        raise DockerBenchmarkProviderError(
            "ZAP production Evidence requires the exact catalog-bound provider"
        )
    concrete = object.__getattribute__(provider, "_provider")
    if type(concrete) is not DockerZAPScannerTargetFactoryAdapter:
        raise DockerBenchmarkProviderError(
            "ZAP production Evidence requires the exact Docker provider"
        )
    runner = object.__getattribute__(concrete, "_docker")
    if type(runner) is not SubprocessDockerCommandRunner:
        raise DockerBenchmarkProviderError(
            "ZAP production Evidence requires the subprocess Docker runner"
        )
    for instance, expected_methods, expected_state in (
        (
            provider,
            _CATALOG_BOUND_PRODUCTION_METHODS,
            _CATALOG_BOUND_PRODUCTION_STATE,
        ),
        (concrete, _DOCKER_ZAP_PRODUCTION_METHODS, _DOCKER_ZAP_PRODUCTION_STATE),
        (
            runner,
            _SUBPROCESS_DOCKER_PRODUCTION_METHODS,
            _SUBPROCESS_DOCKER_PRODUCTION_STATE,
        ),
    ):
        instance_state = object.__getattribute__(instance, "__dict__")
        if set(instance_state) != expected_state or any(
            getattr_static(type(instance), name, None) is not implementation
            for name, implementation in expected_methods.items()
        ):
            raise DockerBenchmarkProviderError(
                "ZAP production Evidence provider boundary is shadowed"
            )

    concrete_plan = object.__getattribute__(concrete, "_scanner_plan")
    concrete_manifest = object.__getattribute__(concrete, "_manifest")
    concrete_state_path = object.__getattribute__(concrete, "_state_path")
    expected_timeout = min(
        300,
        max(30, concrete_plan.manifest.protocol.timeout_seconds),
    )
    expected_artifact_root = (
        concrete_state_path.parent / f"{concrete_state_path.stem}-zap-artifacts"
    )
    if (
        object.__getattribute__(runner, "_executable") != "docker"
        or object.__getattribute__(runner, "_timeout_seconds") != expected_timeout
        or not concrete_state_path.is_absolute()
        or object.__getattribute__(concrete, "_scanner_artifact_root") != expected_artifact_root
        or object.__getattribute__(provider, "_definition")
        != object.__getattribute__(concrete, "_definition")
        or object.__getattribute__(provider, "_profile")
        != object.__getattribute__(concrete, "_profile")
        or object.__getattribute__(provider, "_plan") != concrete_plan
        or object.__getattribute__(provider, "_registration")
        != object.__getattribute__(concrete, "_scanner_registration")
        or object.__getattribute__(provider, "_manifest") != concrete_manifest
        or concrete_manifest != concrete_plan.manifest
    ):
        raise DockerBenchmarkProviderError("ZAP production Evidence provider state differs")


def _target_lookup_request_count(raw: bytes) -> int:
    """Count query-free synthetic lookup responses from the exact Target stdout."""

    if len(raw) > _MAX_TARGET_HTTP_LOG_BYTES:
        raise DockerBenchmarkProviderError("Target HTTP log exceeded its Evidence bound")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DockerBenchmarkProviderError("Target HTTP log is not UTF-8") from exc
    if not raw:
        return 0
    if not raw.endswith(b"\n") or b"\r" in raw:
        raise DockerBenchmarkProviderError("Target HTTP log is not canonical LF JSONL")
    lines = text[:-1].split("\n")
    if len(lines) > _MAX_TARGET_HTTP_LOG_LINES:
        raise DockerBenchmarkProviderError("Target HTTP log exceeded its line bound")
    count = 0
    for line in lines:
        if not line:
            raise DockerBenchmarkProviderError("Target HTTP log contains an empty record")
        try:
            value = json.loads(line)
        except (TypeError, ValueError) as exc:
            raise DockerBenchmarkProviderError("Target HTTP log is not strict JSONL") from exc
        if type(value) is not dict or set(value) != {"event", "method", "path", "status"}:
            raise DockerBenchmarkProviderError("Target HTTP log record shape differs")
        if (
            value["event"] != "pajin.synthetic-http-response"
            or type(value["method"]) is not str
            or value["method"] not in _TARGET_HTTP_METHODS
            or type(value["path"]) is not str
            or not value["path"].startswith("/")
            or "?" in value["path"]
            or len(value["path"]) > 256
            or type(value["status"]) is not int
            or not 100 <= value["status"] <= 599
            or line
            != json.dumps(
                value,
                separators=(",", ":"),
                sort_keys=True,
            )
        ):
            raise DockerBenchmarkProviderError("Target HTTP log record differs")
        count += int(value["path"] == "/v1/users/lookup")
    return count
