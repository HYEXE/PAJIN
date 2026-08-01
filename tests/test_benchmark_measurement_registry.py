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
    BenchmarkTargetFactoryRunner,
    BenchmarkTargetStageReceipt,
    RegisteredBenchmarkTargetFactoryAdapter,
    WalkingBenchmarkRunObservation,
    benchmark_measurement_public_key_base64url,
)
from pajin.benchmark.measurement_registry import (
    BenchmarkMeasurementAdmissionMode,
    BenchmarkMeasurementKeyState,
    BenchmarkMeasurementRegistryAdmissionRunner,
    BenchmarkMeasurementRegistryError,
    BenchmarkMeasurementRegistryKey,
    BenchmarkMeasurementTrustRegistry,
    BenchmarkRegistryTargetFactoryRunner,
    load_benchmark_measurement_registry_admission,
    verify_benchmark_measurement_registry_transition,
)

NOW = datetime(2026, 8, 1, 8, 0, tzinfo=UTC)
KEY_A = bytes(range(32))
KEY_B = bytes(range(32, 64))


def _manifest() -> BenchmarkManifest:
    return BenchmarkManifest(
        benchmarkId="benchmark:measurement-registry-v1",
        targetFactoryId="target-factory:registry-test",
        targetFactoryVersion="1.0.0",
        targetFactoryDigest="a" * 64,
        targetProfileId="hybrid:file-rag-mcp",
        targetProfileVersion="1.0.0",
        mutationProfileId=None,
        campaignDigest="b" * 64,
        groundTruthDigest="c" * 64,
        protocol=BenchmarkRunProtocol(
            protocolId="pajin:measurement-registry-protocol",
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
                armId="arm:registry-baseline",
                kind=BenchmarkArmKind.DETERMINISTIC_BASELINE,
                implementationId="pajin:registry-baseline",
                implementationVersion="1.0.0",
                configurationDigest="d" * 64,
                adaptiveSupervisor=False,
            )
        ],
    )


def _anchor(key_id: str, private_key: bytes) -> BenchmarkMeasurementTrustAnchor:
    return BenchmarkMeasurementTrustAnchor(
        authorityId="measurement-authority:registry-test",
        authorityVersion="1.0.0",
        keyId=key_id,
        publicKeyBase64url=benchmark_measurement_public_key_base64url(private_key),
    )


def _registry_one() -> BenchmarkMeasurementTrustRegistry:
    return BenchmarkMeasurementTrustRegistry(
        registryId="measurement-registry:provider-test",
        registryRevision=1,
        measurementAuthorityId="measurement-authority:registry-test",
        measurementAuthorityVersion="1.0.0",
        issuedAt=NOW - timedelta(hours=1),
        keys=[
            BenchmarkMeasurementRegistryKey(
                trustAnchor=_anchor("measurement-key:2026-a", KEY_A),
                state=BenchmarkMeasurementKeyState.ACTIVE,
                notBefore=NOW - timedelta(hours=2),
            )
        ],
    )


def _registry_two(previous: BenchmarkMeasurementTrustRegistry) -> BenchmarkMeasurementTrustRegistry:
    rotation = NOW + timedelta(minutes=10)
    return BenchmarkMeasurementTrustRegistry(
        registryId=previous.registry_id,
        registryRevision=2,
        previousRegistryDigest=previous.registry_digest,
        measurementAuthorityId=previous.measurement_authority_id,
        measurementAuthorityVersion=previous.measurement_authority_version,
        issuedAt=rotation,
        keys=[
            BenchmarkMeasurementRegistryKey(
                trustAnchor=_anchor("measurement-key:2026-a", KEY_A),
                state=BenchmarkMeasurementKeyState.RETIRED,
                notBefore=NOW - timedelta(hours=2),
                notAfter=rotation,
            ),
            BenchmarkMeasurementRegistryKey(
                trustAnchor=_anchor("measurement-key:2026-b", KEY_B),
                state=BenchmarkMeasurementKeyState.ACTIVE,
                notBefore=rotation,
            ),
        ],
    )


def _registry_three(
    previous: BenchmarkMeasurementTrustRegistry,
) -> BenchmarkMeasurementTrustRegistry:
    issued_at = NOW + timedelta(minutes=20)
    return BenchmarkMeasurementTrustRegistry(
        registryId=previous.registry_id,
        registryRevision=3,
        previousRegistryDigest=previous.registry_digest,
        measurementAuthorityId=previous.measurement_authority_id,
        measurementAuthorityVersion=previous.measurement_authority_version,
        issuedAt=issued_at,
        keys=[
            BenchmarkMeasurementRegistryKey(
                trustAnchor=_anchor("measurement-key:2026-a", KEY_A),
                state=BenchmarkMeasurementKeyState.REVOKED,
                notBefore=NOW - timedelta(hours=2),
                notAfter=NOW + timedelta(minutes=10),
                revokedAt=NOW + timedelta(minutes=15),
            ),
            previous.keys[1],
        ],
    )


class _Provider:
    def __init__(
        self,
        manifest: BenchmarkManifest,
        anchor: BenchmarkMeasurementTrustAnchor,
        private_key: bytes,
    ) -> None:
        self.definition = RegisteredBenchmarkTargetFactoryAdapter(
            adapterId="target-adapter:measurement-registry",
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
            private_key=private_key,
            trust_anchor=anchor,
        )
        self.calls: list[str] = []

    def _receipt(
        self,
        coordinate: BenchmarkTargetCoordinate,
        stage: str,
        offset: int,
    ) -> BenchmarkTargetStageReceipt:
        return BenchmarkTargetStageReceipt(
            adapterDigest=self.definition.adapter_digest,
            coordinateDigest=coordinate.coordinate_digest,
            stage=stage,
            operationId=f"provider-registry-operation:{stage}",
            environmentId="environment:registry-7-1",
            isolationId=(None if stage == "reset" else "isolation:registry-7-1"),
            status="succeeded",
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
        assert reset.environment_id == "environment:registry-7-1"
        return self._receipt(coordinate, "isolation", 1)

    async def execute(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
    ) -> tuple[BenchmarkTargetStageReceipt, WalkingBenchmarkRunObservation]:
        self.calls.append("execution")
        assert isolation.isolation_id == "isolation:registry-7-1"
        receipt = self._receipt(coordinate, "execution", 2)
        arm = coordinate.arm
        return receipt, WalkingBenchmarkRunObservation(
            benchmarkId=self._manifest.benchmark_id,
            manifestDigest=self._manifest.digest(),
            armId=arm.arm_id,
            armKind=arm.kind,
            configurationDigest=arm.configuration_digest,
            targetFactoryDigest=self._manifest.target_factory_digest,
            campaignDigest=self._manifest.campaign_digest,
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

    async def cleanup(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
    ) -> BenchmarkTargetStageReceipt:
        self.calls.append("cleanup")
        return self._receipt(coordinate, "cleanup", 3)

    async def attest(
        self,
        statement: BenchmarkMeasurementAttestationStatement,
    ) -> BenchmarkMeasurementAttestation:
        self.calls.append("attestation")
        return self._attestor.attest(statement)


def _run_source(tmp_path: Path):
    manifest = _manifest()
    registry = _registry_one()
    provider = _Provider(manifest, registry.active_key.trust_anchor, KEY_A)
    outcome = asyncio.run(
        BenchmarkRegistryTargetFactoryRunner(
            output_root=tmp_path / "runs",
            target_runner=BenchmarkTargetFactoryRunner(
                output_root=tmp_path / "runs",
                adapter=provider,
                trust_anchor=registry.active_key.trust_anchor,
            ),
            registry=registry,
        ).run(
            manifest,
            arm_id=manifest.arms[0].arm_id,
            seed=7,
            repetition=1,
        )
    )
    return manifest, registry, provider, outcome


def test_registry_bound_runner_requires_active_key_and_seals_fresh_admission(
    tmp_path: Path,
) -> None:
    manifest, registry, provider, outcome = _run_source(tmp_path)

    authority = load_benchmark_measurement_registry_admission(
        manifest,
        outcome.target,
        outcome.admission,
    )
    assert provider.calls == ["reset", "isolation", "execution", "cleanup", "attestation"]
    assert authority.registry == registry
    assert authority.key_state is BenchmarkMeasurementKeyState.ACTIVE
    assert authority.admission_mode is BenchmarkMeasurementAdmissionMode.FRESH_MEASUREMENT
    assert authority.measurement_admission_eligible is True
    assert outcome.as_observation_outcome().observation == outcome.target.authority.observation


def test_registry_preflight_rejects_non_active_adapter_before_reset(tmp_path: Path) -> None:
    manifest = _manifest()
    first = _registry_one()
    rotated = _registry_two(first)
    provider = _Provider(manifest, first.active_key.trust_anchor, KEY_A)

    with pytest.raises(BenchmarkMeasurementRegistryError, match="active measurement registry key"):
        asyncio.run(
            BenchmarkRegistryTargetFactoryRunner(
                output_root=tmp_path / "runs",
                target_runner=BenchmarkTargetFactoryRunner(
                    output_root=tmp_path / "runs",
                    adapter=provider,
                    trust_anchor=first.active_key.trust_anchor,
                ),
                registry=rotated,
                predecessor_registry=first,
            ).run(
                manifest,
                arm_id=manifest.arms[0].arm_id,
                seed=7,
                repetition=1,
            )
        )
    assert provider.calls == []


def test_rotation_preserves_retired_history_but_revocation_rejects_it(tmp_path: Path) -> None:
    manifest, first, _provider, outcome = _run_source(tmp_path)
    rotated = _registry_two(first)
    verify_benchmark_measurement_registry_transition(first, rotated)

    historical = BenchmarkMeasurementRegistryAdmissionRunner(
        output_root=tmp_path / "historical"
    ).admit(
        manifest,
        outcome.target,
        rotated,
        predecessor_registry=first,
        mode=BenchmarkMeasurementAdmissionMode.HISTORICAL_VERIFICATION,
    )
    authority = load_benchmark_measurement_registry_admission(
        manifest,
        outcome.target,
        historical,
    )
    assert authority.key_state is BenchmarkMeasurementKeyState.RETIRED
    assert authority.measurement_admission_eligible is False
    assert authority.historical_verification_eligible is True

    revoked = _registry_three(rotated)
    verify_benchmark_measurement_registry_transition(rotated, revoked)
    with pytest.raises(BenchmarkMeasurementRegistryError, match="key is revoked"):
        BenchmarkMeasurementRegistryAdmissionRunner(
            output_root=tmp_path / "revoked"
        ).admit(
            manifest,
            outcome.target,
            revoked,
            predecessor_registry=rotated,
            mode=BenchmarkMeasurementAdmissionMode.HISTORICAL_VERIFICATION,
        )


def test_registry_admission_requires_exact_predecessor_after_bootstrap(tmp_path: Path) -> None:
    manifest, first, _provider, outcome = _run_source(tmp_path)
    rotated = _registry_two(first)

    with pytest.raises(BenchmarkMeasurementRegistryError, match="exact predecessor"):
        BenchmarkMeasurementRegistryAdmissionRunner(
            output_root=tmp_path / "missing-predecessor"
        ).admit(
            manifest,
            outcome.target,
            rotated,
            mode=BenchmarkMeasurementAdmissionMode.HISTORICAL_VERIFICATION,
        )


def test_registry_admission_rejects_future_registry_revision(tmp_path: Path) -> None:
    manifest, first, _provider, outcome = _run_source(tmp_path)
    future = first.model_copy(
        update={
            "issued_at": datetime.now(UTC) + timedelta(days=1),
            "registry_digest": "",
        }
    )
    future = BenchmarkMeasurementTrustRegistry.model_validate(
        future.model_dump(mode="json", by_alias=True)
    )

    with pytest.raises(BenchmarkMeasurementRegistryError, match="has not been issued"):
        BenchmarkMeasurementRegistryAdmissionRunner(
            output_root=tmp_path / "future-registry"
        ).admit(
            manifest,
            outcome.target,
            future,
            mode=BenchmarkMeasurementAdmissionMode.HISTORICAL_VERIFICATION,
        )


def test_registry_transition_rejects_rollback_gap_and_key_substitution() -> None:
    first = _registry_one()
    rotated = _registry_two(first)

    with pytest.raises(BenchmarkMeasurementRegistryError, match="rollback, gap"):
        verify_benchmark_measurement_registry_transition(rotated, first)

    gap = rotated.model_copy(
        update={
            "registry_revision": 4,
            "previous_registry_digest": rotated.registry_digest,
            "registry_digest": "",
            "issued_at": rotated.issued_at + timedelta(minutes=1),
        }
    )
    gap = BenchmarkMeasurementTrustRegistry.model_validate(
        gap.model_dump(mode="json", by_alias=True)
    )
    with pytest.raises(BenchmarkMeasurementRegistryError, match="rollback, gap"):
        verify_benchmark_measurement_registry_transition(rotated, gap)

    substituted_key = rotated.keys[0].model_copy(
        update={"trust_anchor": _anchor("measurement-key:2026-a", KEY_B)}
    )
    substituted = BenchmarkMeasurementTrustRegistry(
        registryId=rotated.registry_id,
        registryRevision=3,
        previousRegistryDigest=rotated.registry_digest,
        measurementAuthorityId=rotated.measurement_authority_id,
        measurementAuthorityVersion=rotated.measurement_authority_version,
        issuedAt=rotated.issued_at + timedelta(minutes=1),
        keys=[substituted_key, rotated.keys[1]],
    )
    with pytest.raises(BenchmarkMeasurementRegistryError, match="substitutes"):
        verify_benchmark_measurement_registry_transition(rotated, substituted)

    revoked = _registry_three(rotated)
    resurrected_key = revoked.keys[0].model_copy(
        update={
            "state": BenchmarkMeasurementKeyState.RETIRED,
            "revoked_at": None,
        }
    )
    resurrected = BenchmarkMeasurementTrustRegistry(
        registryId=revoked.registry_id,
        registryRevision=4,
        previousRegistryDigest=revoked.registry_digest,
        measurementAuthorityId=revoked.measurement_authority_id,
        measurementAuthorityVersion=revoked.measurement_authority_version,
        issuedAt=NOW + timedelta(minutes=30),
        keys=[resurrected_key, revoked.keys[1]],
    )
    with pytest.raises(BenchmarkMeasurementRegistryError, match="resurrects"):
        verify_benchmark_measurement_registry_transition(revoked, resurrected)


def test_registry_rejects_unknown_source_key_and_cross_authority(tmp_path: Path) -> None:
    manifest, first, _provider, outcome = _run_source(tmp_path)
    foreign_anchor = BenchmarkMeasurementTrustAnchor(
        authorityId="measurement-authority:foreign",
        authorityVersion="1.0.0",
        keyId="measurement-key:foreign",
        publicKeyBase64url=benchmark_measurement_public_key_base64url(KEY_B),
    )
    foreign = BenchmarkMeasurementTrustRegistry(
        registryId="measurement-registry:foreign",
        registryRevision=1,
        measurementAuthorityId=foreign_anchor.authority_id,
        measurementAuthorityVersion=foreign_anchor.authority_version,
        issuedAt=NOW - timedelta(hours=1),
        keys=[
            BenchmarkMeasurementRegistryKey(
                trustAnchor=foreign_anchor,
                state=BenchmarkMeasurementKeyState.ACTIVE,
                notBefore=NOW - timedelta(hours=2),
            )
        ],
    )

    with pytest.raises(BenchmarkMeasurementRegistryError, match="absent"):
        BenchmarkMeasurementRegistryAdmissionRunner(
            output_root=tmp_path / "foreign"
        ).admit(
            manifest,
            outcome.target,
            foreign,
            mode=BenchmarkMeasurementAdmissionMode.HISTORICAL_VERIFICATION,
        )
    with pytest.raises(BenchmarkMeasurementRegistryError, match="authority identity"):
        verify_benchmark_measurement_registry_transition(first, foreign)


def test_registry_admission_reader_rejects_source_and_output_mutation(tmp_path: Path) -> None:
    manifest, _registry, _provider, outcome = _run_source(tmp_path)
    admission_path = outcome.admission.run_path / outcome.admission.authority_path
    admission_path.write_text("{}", encoding="utf-8")
    with pytest.raises(BenchmarkMeasurementRegistryError):
        load_benchmark_measurement_registry_admission(
            manifest,
            outcome.target,
            outcome.admission,
        )

    manifest, _registry, _provider, second = _run_source(tmp_path / "second")
    source_path = second.target.run_path / second.target.authority_path
    source_path.write_text("{}", encoding="utf-8")
    with pytest.raises(BenchmarkMeasurementRegistryError):
        load_benchmark_measurement_registry_admission(
            manifest,
            second.target,
            second.admission,
        )

    manifest, _registry, _provider, third = _run_source(tmp_path / "third")
    (third.admission.run_path / "events.jsonl").write_text("{}\n", encoding="utf-8")
    with pytest.raises(BenchmarkMeasurementRegistryError):
        load_benchmark_measurement_registry_admission(
            manifest,
            third.target,
            third.admission,
        )
