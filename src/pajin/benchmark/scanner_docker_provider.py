"""P0-E2B recoverable Docker provider for the concrete OWASP ZAP baseline."""

from __future__ import annotations

import os
from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import cast

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
from pajin.benchmark.models import BenchmarkGroundTruth
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
from pajin.runtime.safe_files import read_bounded_regular_bytes

_SARIF_NAME = "p0-e2b.sarif.json"
_PLAN_NAME = "zap.yaml"
_MAX_SARIF_BYTES = 16 * 1024 * 1024


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
            cast(DockerBugBountyTargetProfile, self._profile).model_dump(
                mode="json", by_alias=True
            )
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
        plan_path.write_bytes(ZAP_AUTOMATION_PLAN)
        if artifact_path.exists():
            raise DockerBenchmarkProviderError("ZAP output path was not fresh")
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
            raise DockerBenchmarkProviderError(
                "ZAP automation plan is unavailable"
            ) from exc
        if observed_plan != ZAP_AUTOMATION_PLAN:
            raise DockerBenchmarkProviderError("ZAP changed its registered automation plan")
        raw = self._read_fresh_sarif(artifact_path)
        normalization = parse_zap_sarif(raw, registration=self._scanner_registration)
        worker = self._container_inspect(names.worker)
        target = self._container_inspect(names.target)
        network = self._network_inspect(names.network)
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
        evidence = self._evidence(
            coordinate,
            operation,
            server_version=server_version,
            target_container_id=_docker_id(target, label="target container"),
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
            or config.get("Cmd")
            != ["zap.sh", "-cmd", "-autorun", "/zap/wrk/zap.yaml"]
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
        matched_findings = sum(
            finding.matches_known_finding for finding in normalization.findings
        )
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
        receipt, observation = await self._provider.execute(
            authoritative, isolation, operation
        )
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
