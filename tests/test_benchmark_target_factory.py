from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pajin.benchmark import (
    BenchmarkArm,
    BenchmarkArmKind,
    BenchmarkManifest,
    BenchmarkMeasurementAttestation,
    BenchmarkMeasurementAttestationStatement,
    BenchmarkMeasurementAttestor,
    BenchmarkMeasurementTrustAnchor,
    BenchmarkRunProtocol,
    BenchmarkTargetCoordinate,
    BenchmarkTargetFactoryError,
    BenchmarkTargetFactoryRunner,
    BenchmarkTargetStageReceipt,
    RegisteredBenchmarkTargetFactoryAdapter,
    WalkingBenchmarkRunObservation,
    benchmark_measurement_public_key_base64url,
    load_benchmark_target_run_authority,
    load_walking_benchmark_run_observation,
    verify_benchmark_measurement_attestation,
)
from pajin.runtime.store import load_verified_run_events, verify_run_integrity

NOW = datetime(2026, 8, 1, 6, 0, tzinfo=UTC)
PRIVATE_KEY = bytes(range(32))


def _manifest() -> BenchmarkManifest:
    return BenchmarkManifest(
        benchmarkId="benchmark:provider-target-v1",
        targetFactoryId="target-factory:provider-neutral",
        targetFactoryVersion="1.0.0",
        targetFactoryDigest="a" * 64,
        targetProfileId="hybrid:file-rag-mcp",
        targetProfileVersion="1.0.0",
        mutationProfileId=None,
        campaignDigest="b" * 64,
        groundTruthDigest="c" * 64,
        protocol=BenchmarkRunProtocol(
            protocolId="pajin:provider-target-protocol",
            protocolVersion="1.0.0",
            seeds=[7],
            repetitionsPerSeed=1,
            timeoutSeconds=600,
            maxCostUsd=25,
            maxToolCalls=500,
            maxModelCalls=100,
        ),
        arms=[
            BenchmarkArm(
                armId="arm:provider-baseline",
                kind=BenchmarkArmKind.DETERMINISTIC_BASELINE,
                implementationId="pajin:provider-baseline",
                implementationVersion="1.0.0",
                configurationDigest="d" * 64,
                adaptiveSupervisor=False,
            )
        ],
    )


def _trust_anchor() -> BenchmarkMeasurementTrustAnchor:
    return BenchmarkMeasurementTrustAnchor(
        authorityId="measurement-authority:provider-neutral",
        authorityVersion="1.0.0",
        keyId="measurement-key:2026-a",
        publicKeyBase64url=benchmark_measurement_public_key_base64url(PRIVATE_KEY),
    )


class _ProviderAdapter:
    def __init__(
        self,
        manifest: BenchmarkManifest,
        anchor: BenchmarkMeasurementTrustAnchor,
        *,
        execute_raises: bool = False,
        forged_isolation: bool = False,
        duplicate_isolation_identity: bool = False,
        forged_signature: bool = False,
        foreign_observation: bool = False,
        cleanup_succeeded: bool = True,
    ) -> None:
        self.definition = RegisteredBenchmarkTargetFactoryAdapter(
            adapterId="target-adapter:provider-neutral",
            adapterVersion="1.0.0",
            targetFactoryId=manifest.target_factory_id,
            targetFactoryVersion=manifest.target_factory_version,
            targetFactoryDigest=manifest.target_factory_digest,
            measurementAuthorityId=anchor.authority_id,
            measurementAuthorityVersion=anchor.authority_version,
            measurementAuthorityDigest=anchor.anchor_digest,
        )
        self._manifest = manifest
        self._attestor = BenchmarkMeasurementAttestor.from_private_key_bytes(
            active_key_id=anchor.key_id,
            private_key=PRIVATE_KEY,
            trust_anchor=anchor,
        )
        self._execute_raises = execute_raises
        self._forged_isolation = forged_isolation
        self._duplicate_isolation_identity = duplicate_isolation_identity
        self._forged_signature = forged_signature
        self._foreign_observation = foreign_observation
        self._cleanup_succeeded = cleanup_succeeded
        self.calls: list[str] = []

    def _receipt(
        self,
        coordinate: BenchmarkTargetCoordinate,
        stage: str,
        offset: int,
        *,
        status: str = "succeeded",
        environment_id: str = "environment:provider-7-1",
    ) -> BenchmarkTargetStageReceipt:
        return BenchmarkTargetStageReceipt(
            adapterDigest=self.definition.adapter_digest,
            coordinateDigest=coordinate.coordinate_digest,
            stage=stage,
            operationId=f"provider-operation:{stage}",
            environmentId=environment_id,
            isolationId=(None if stage == "reset" else "isolation:provider-7-1"),
            status=status,
            startedAt=NOW + timedelta(seconds=offset),
            completedAt=NOW + timedelta(seconds=offset + 1),
            providerEvidenceDigest=f"{offset + 1:064x}",
        )

    async def reset(
        self,
        coordinate: BenchmarkTargetCoordinate,
    ) -> BenchmarkTargetStageReceipt:
        self.calls.append("reset")
        return self._receipt(coordinate, "reset", 0)

    async def establish_isolation(
        self,
        coordinate: BenchmarkTargetCoordinate,
        reset: BenchmarkTargetStageReceipt,
    ) -> BenchmarkTargetStageReceipt:
        self.calls.append("isolation")
        environment_id = "environment:forged" if self._forged_isolation else reset.environment_id
        receipt = self._receipt(
            coordinate,
            "isolation",
            1,
            environment_id=environment_id,
        )
        if not self._duplicate_isolation_identity:
            return receipt
        raw = receipt.model_dump(mode="json", by_alias=True)
        raw["receiptId"] = ""
        raw["receiptDigest"] = ""
        raw["operationId"] = reset.operation_id
        raw["providerEvidenceDigest"] = reset.provider_evidence_digest
        return BenchmarkTargetStageReceipt.model_validate(raw)

    async def execute(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
    ) -> tuple[BenchmarkTargetStageReceipt, WalkingBenchmarkRunObservation]:
        self.calls.append("execution")
        if self._execute_raises:
            raise RuntimeError("provider execution failed")
        receipt = self._receipt(coordinate, "execution", 2)
        arm = coordinate.arm
        observation = WalkingBenchmarkRunObservation(
            benchmarkId=self._manifest.benchmark_id,
            manifestDigest=self._manifest.digest(),
            armId=arm.arm_id,
            armKind=arm.kind,
            configurationDigest=arm.configuration_digest,
            targetFactoryDigest=self._manifest.target_factory_digest,
            campaignDigest=(
                "9" * 64 if self._foreign_observation else self._manifest.campaign_digest
            ),
            groundTruthDigest=self._manifest.ground_truth_digest,
            protocolId=self._manifest.protocol.protocol_id,
            protocolVersion=self._manifest.protocol.protocol_version,
            measurementAuthorityId=self.definition.measurement_authority_id,
            measurementAuthorityVersion=self.definition.measurement_authority_version,
            measurementAuthorityDigest=self.definition.measurement_authority_digest,
            seed=coordinate.seed,
            repetition=coordinate.repetition,
            startedAt=receipt.started_at,
            completedAt=receipt.completed_at,
            cleanupSucceeded=False,
            toolCallCount=12,
            modelCallCount=0,
            costUsd=10.0,
            knownAttackSurfaceCount=10,
            discoveredKnownAttackSurfaceCount=8,
            knownFindingCount=4,
            matchedKnownFindingCount=2,
            candidateFindingCount=4,
            validCandidateFindingCount=2,
            unexpectedValidFindingCount=0,
            confirmedFindingCount=2,
            groundTruthChainCount=2,
            completedGroundTruthChainCount=1,
            firstValidOrConfirmedFindingSeconds=0.5,
            replayAttemptCount=2,
            replaySuccessCount=1,
            policyRejectionOrViolationCount=2,
            humanDecisionCount=2,
            humanInterventionOrOverturnCount=0,
        )
        return receipt, observation

    async def cleanup(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
    ) -> BenchmarkTargetStageReceipt:
        self.calls.append("cleanup")
        return self._receipt(
            coordinate,
            "cleanup",
            3,
            status="succeeded" if self._cleanup_succeeded else "failed",
        )

    async def attest(
        self,
        statement: BenchmarkMeasurementAttestationStatement,
    ) -> BenchmarkMeasurementAttestation:
        self.calls.append("attestation")
        attestation = self._attestor.attest(statement)
        if not self._forged_signature:
            return attestation
        replacement = "A" if attestation.signature_base64url[0] != "A" else "B"
        return attestation.model_copy(
            update={
                "signature_base64url": replacement
                + attestation.signature_base64url[1:]
            }
        )


def test_target_factory_runner_seals_attested_lifecycle_and_b1_observation(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    anchor = _trust_anchor()
    adapter = _ProviderAdapter(manifest, anchor)
    outcome = asyncio.run(
        BenchmarkTargetFactoryRunner(
            output_root=tmp_path / "target",
            adapter=adapter,
            trust_anchor=anchor,
        ).run(
            manifest,
            arm_id=manifest.arms[0].arm_id,
            seed=7,
            repetition=1,
        )
    )
    authority = outcome.authority

    assert adapter.calls == ["reset", "isolation", "execution", "cleanup", "attestation"]
    assert authority.lifecycle_state == "completed-attested"
    assert authority.measurement_admission_eligible is True
    assert authority.observation.cleanup_succeeded is True
    assert verify_benchmark_measurement_attestation(
        authority.attestation,
        trust_anchor=anchor,
    ) == anchor.key_id
    assert load_benchmark_target_run_authority(manifest, outcome) == authority
    assert (
        load_walking_benchmark_run_observation(
            manifest,
            outcome.as_observation_outcome(),
        )
        == authority.observation
    )
    assert verify_run_integrity(outcome.run_path).valid
    assert [event.event_type for event in load_verified_run_events(outcome.run_path)] == [
        "campaign.started",
        "benchmark.target-factory.reset",
        "benchmark.target-factory.isolation",
        "benchmark.target-factory.execution",
        "benchmark.target-factory.cleanup",
        "benchmark.walking-run-observation.created",
        "benchmark.target-factory.measurement-attested",
        "campaign.completed",
    ]


def test_target_factory_runner_attempts_cleanup_after_execution_failure(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    anchor = _trust_anchor()
    adapter = _ProviderAdapter(manifest, anchor, execute_raises=True)

    with pytest.raises(BenchmarkTargetFactoryError):
        asyncio.run(
            BenchmarkTargetFactoryRunner(
                output_root=tmp_path / "target",
                adapter=adapter,
                trust_anchor=anchor,
            ).run(
                manifest,
                arm_id=manifest.arms[0].arm_id,
                seed=7,
                repetition=1,
            )
        )

    assert adapter.calls == ["reset", "isolation", "execution", "cleanup"]
    assert not (tmp_path / "target").exists()


def test_target_factory_runner_rejects_isolation_drift_before_execution(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    anchor = _trust_anchor()
    adapter = _ProviderAdapter(manifest, anchor, forged_isolation=True)

    with pytest.raises(BenchmarkTargetFactoryError):
        asyncio.run(
            BenchmarkTargetFactoryRunner(
                output_root=tmp_path / "target",
                adapter=adapter,
                trust_anchor=anchor,
            ).run(
                manifest,
                arm_id=manifest.arms[0].arm_id,
                seed=7,
                repetition=1,
            )
        )

    assert adapter.calls == ["reset", "isolation"]


def test_target_factory_runner_rejects_signature_and_output_mutation(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    anchor = _trust_anchor()
    forged = _ProviderAdapter(manifest, anchor, forged_signature=True)
    with pytest.raises(BenchmarkTargetFactoryError):
        asyncio.run(
            BenchmarkTargetFactoryRunner(
                output_root=tmp_path / "forged",
                adapter=forged,
                trust_anchor=anchor,
            ).run(
                manifest,
                arm_id=manifest.arms[0].arm_id,
                seed=7,
                repetition=1,
            )
        )

    adapter = _ProviderAdapter(manifest, anchor, cleanup_succeeded=False)
    outcome = asyncio.run(
        BenchmarkTargetFactoryRunner(
            output_root=tmp_path / "target",
            adapter=adapter,
            trust_anchor=anchor,
        ).run(
            manifest,
            arm_id=manifest.arms[0].arm_id,
            seed=7,
            repetition=1,
        )
    )
    assert outcome.authority.observation.cleanup_succeeded is False

    (outcome.run_path / outcome.authority_path).write_text("{}", encoding="utf-8")
    with pytest.raises(BenchmarkTargetFactoryError):
        load_benchmark_target_run_authority(manifest, outcome)


def test_target_factory_runner_rejects_foreign_raw_observation_after_cleanup(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    anchor = _trust_anchor()
    adapter = _ProviderAdapter(manifest, anchor, foreign_observation=True)

    with pytest.raises(BenchmarkTargetFactoryError):
        asyncio.run(
            BenchmarkTargetFactoryRunner(
                output_root=tmp_path / "target",
                adapter=adapter,
                trust_anchor=anchor,
            ).run(
                manifest,
                arm_id=manifest.arms[0].arm_id,
                seed=7,
                repetition=1,
            )
        )

    assert adapter.calls == ["reset", "isolation", "execution", "cleanup"]


def test_target_factory_runner_cleans_up_after_isolation_freshness_rejection(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    anchor = _trust_anchor()
    adapter = _ProviderAdapter(manifest, anchor, duplicate_isolation_identity=True)

    with pytest.raises(BenchmarkTargetFactoryError):
        asyncio.run(
            BenchmarkTargetFactoryRunner(
                output_root=tmp_path / "target",
                adapter=adapter,
                trust_anchor=anchor,
            ).run(
                manifest,
                arm_id=manifest.arms[0].arm_id,
                seed=7,
                repetition=1,
            )
        )

    assert adapter.calls == ["reset", "isolation", "cleanup"]
