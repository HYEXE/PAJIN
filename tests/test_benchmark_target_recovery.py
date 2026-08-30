from __future__ import annotations

import asyncio
import multiprocessing
import os
import sqlite3
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
    BenchmarkTargetStageReceipt,
    RegisteredBenchmarkTargetFactoryAdapter,
    WalkingBenchmarkRunObservation,
    benchmark_measurement_public_key_base64url,
    load_benchmark_target_run_authority,
)
from pajin.benchmark.target_recovery import (
    BenchmarkTargetOperation,
    BenchmarkTargetOperationJournal,
    BenchmarkTargetRecoveryError,
    BenchmarkTargetRecoveryRequest,
    RecoverableBenchmarkTargetFactoryRunner,
    load_benchmark_target_recovery_authority,
)
from pajin.runtime.store import verify_run_integrity

NOW = datetime(2026, 8, 1, 9, 0, tzinfo=UTC)
PRIVATE_KEY = bytes(range(32))


class _HardExit(BaseException):
    pass


def _manifest() -> BenchmarkManifest:
    return BenchmarkManifest(
        benchmarkId="benchmark:recoverable-provider-v1",
        targetFactoryId="target-factory:recoverable-provider",
        targetFactoryVersion="1.0.0",
        targetFactoryDigest="a" * 64,
        targetProfileId="hybrid:file-rag-mcp",
        targetProfileVersion="1.0.0",
        mutationProfileId=None,
        campaignDigest="b" * 64,
        groundTruthDigest="c" * 64,
        protocol=BenchmarkRunProtocol(
            protocolId="pajin:recoverable-provider-protocol",
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
                armId="arm:recoverable-baseline",
                kind=BenchmarkArmKind.DETERMINISTIC_BASELINE,
                implementationId="pajin:recoverable-baseline",
                implementationVersion="1.0.0",
                configurationDigest="d" * 64,
                adaptiveSupervisor=False,
            )
        ],
    )


def _trust_anchor() -> BenchmarkMeasurementTrustAnchor:
    return BenchmarkMeasurementTrustAnchor(
        authorityId="measurement-authority:recoverable-provider",
        authorityVersion="1.0.0",
        keyId="measurement-key:2026-recovery",
        publicKeyBase64url=benchmark_measurement_public_key_base64url(PRIVATE_KEY),
    )


class _RecoverableProvider:
    def __init__(
        self,
        manifest: BenchmarkManifest,
        anchor: BenchmarkMeasurementTrustAnchor,
        *,
        hard_exit_once: bool = False,
        cleanup_status: str = "succeeded",
        recovery_results: tuple[str, ...] = (),
    ) -> None:
        self.definition = RegisteredBenchmarkTargetFactoryAdapter(
            adapterId="target-adapter:recoverable-provider",
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
        self._hard_exit_once = hard_exit_once
        self._cleanup_status = cleanup_status
        self._recovery_results = list(recovery_results)
        self.calls: list[tuple[str, int, int]] = []
        self.highest_fence = 0

    def _accept(self, operation: BenchmarkTargetOperation) -> None:
        if operation.fence < self.highest_fence:
            raise RuntimeError("provider rejected stale fence")
        self.highest_fence = operation.fence
        self.calls.append((operation.stage, operation.fence, operation.ordinal))

    def _receipt(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
        offset: int,
        *,
        status: str = "succeeded",
        isolation_id: str | None = "isolation:recoverable-7-1",
    ) -> BenchmarkTargetStageReceipt:
        return BenchmarkTargetStageReceipt(
            adapterDigest=self.definition.adapter_digest,
            coordinateDigest=coordinate.coordinate_digest,
            stage=operation.stage,
            operationId=operation.operation_id,
            environmentId="environment:recoverable-7-1",
            isolationId=isolation_id,
            status=status,
            startedAt=NOW + timedelta(seconds=offset),
            completedAt=NOW + timedelta(seconds=offset + 1),
            providerEvidenceDigest=operation.operation_digest,
        )

    async def reset(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt:
        self._accept(operation)
        return self._receipt(coordinate, operation, 0, isolation_id=None)

    async def establish_isolation(
        self,
        coordinate: BenchmarkTargetCoordinate,
        reset: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt:
        self._accept(operation)
        assert reset.environment_id == "environment:recoverable-7-1"
        return self._receipt(coordinate, operation, 1)

    async def execute(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> tuple[BenchmarkTargetStageReceipt, WalkingBenchmarkRunObservation]:
        self._accept(operation)
        assert isolation.isolation_id == "isolation:recoverable-7-1"
        if self._hard_exit_once:
            self._hard_exit_once = False
            raise _HardExit("simulated process loss")
        receipt = self._receipt(coordinate, operation, 2)
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
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt:
        self._accept(operation)
        assert isolation.isolation_id == "isolation:recoverable-7-1"
        return self._receipt(coordinate, operation, 3, status=self._cleanup_status)

    async def reconcile_cleanup(
        self,
        coordinate: BenchmarkTargetCoordinate,
        request: BenchmarkTargetRecoveryRequest,
    ) -> BenchmarkTargetStageReceipt:
        operation = request.cleanup_operation
        self._accept(operation)
        result = self._recovery_results.pop(0) if self._recovery_results else "succeeded"
        if result == "exception":
            raise RuntimeError("transient provider cleanup failure")
        if result == "hard-exit":
            raise _HardExit("simulated recovery process loss")
        known = request.known_isolation_receipt
        isolation_id = known.isolation_id if known is not None else "isolation:recoverable-7-1"
        return self._receipt(
            coordinate,
            operation,
            10 + operation.ordinal,
            status=result,
            isolation_id=isolation_id,
        )

    async def attest(
        self,
        statement: BenchmarkMeasurementAttestationStatement,
    ) -> BenchmarkMeasurementAttestation:
        return self._attestor.attest(statement)


def _runner(
    tmp_path: Path,
    provider: _RecoverableProvider,
) -> RecoverableBenchmarkTargetFactoryRunner:
    return RecoverableBenchmarkTargetFactoryRunner(
        output_root=tmp_path / "runs",
        journal_path=tmp_path / "state" / "target-operations.sqlite3",
        adapter=provider,
        trust_anchor=_trust_anchor(),
    )


def _hard_exit_after_execution_intent(
    journal_path: str,
    manifest_data: dict[str, object],
    adapter_data: dict[str, object],
) -> None:
    manifest = BenchmarkManifest.model_validate(manifest_data)
    adapter = RegisteredBenchmarkTargetFactoryAdapter.model_validate(adapter_data)
    coordinate = BenchmarkTargetCoordinate(
        benchmarkId=manifest.benchmark_id,
        manifestDigest=manifest.digest(),
        arm=manifest.arms[0],
        seed=7,
        repetition=1,
    )
    journal = BenchmarkTargetOperationJournal(Path(journal_path))
    attempt = journal.begin_attempt(adapter, coordinate)
    previous_receipt: BenchmarkTargetStageReceipt | None = None
    for offset, stage in enumerate(("reset", "isolation")):
        operation = BenchmarkTargetOperation(
            attemptId=attempt.attempt_id,
            attemptDigest=attempt.attempt_digest,
            adapterDigest=attempt.adapter_digest,
            coordinateDigest=attempt.coordinate_digest,
            fence=attempt.fence,
            stage=stage,
            ordinal=1,
        )
        journal.append_intent(operation)
        previous_receipt = BenchmarkTargetStageReceipt(
            adapterDigest=adapter.adapter_digest,
            coordinateDigest=coordinate.coordinate_digest,
            stage=stage,
            operationId=operation.operation_id,
            environmentId="environment:recoverable-7-1",
            isolationId=(None if stage == "reset" else "isolation:recoverable-7-1"),
            status="succeeded",
            startedAt=NOW + timedelta(seconds=offset),
            completedAt=NOW + timedelta(seconds=offset + 1),
            providerEvidenceDigest=operation.operation_digest,
        )
        journal.append_receipt(operation, previous_receipt)
    assert previous_receipt is not None
    execution = BenchmarkTargetOperation(
        attemptId=attempt.attempt_id,
        attemptDigest=attempt.attempt_digest,
        adapterDigest=attempt.adapter_digest,
        coordinateDigest=attempt.coordinate_digest,
        fence=attempt.fence,
        stage="execution",
        ordinal=1,
    )
    journal.append_intent(execution)
    os._exit(23)


def test_recoverable_runner_preserves_completed_p0_c1_authority(tmp_path: Path) -> None:
    manifest = _manifest()
    provider = _RecoverableProvider(manifest, _trust_anchor())
    outcome = asyncio.run(
        _runner(tmp_path, provider).run(
            manifest,
            arm_id=manifest.arms[0].arm_id,
            seed=7,
            repetition=1,
        )
    )

    assert load_benchmark_target_run_authority(manifest, outcome) == outcome.authority
    assert provider.calls == [
        ("reset", 1, 1),
        ("isolation", 1, 1),
        ("execution", 1, 1),
        ("cleanup", 1, 1),
    ]
    journal_path = tmp_path / "state" / "target-operations.sqlite3"
    journal = BenchmarkTargetOperationJournal.open_existing(journal_path)
    assert journal.pending() == ()
    adapter, coordinate, attempt, records = journal.completed_attempt_for_operation(
        outcome.authority.execution_receipt.operation_id
    )
    assert adapter == outcome.authority.adapter
    assert coordinate == outcome.authority.coordinate
    assert attempt.fence == 1
    assert len(records) == 8
    assert [record.record_type for record in records] == ["intent", "receipt"] * 4
    assert [record.operation.stage for record in records[::2]] == [
        "reset",
        "isolation",
        "execution",
        "cleanup",
    ]
    assert records[-1].receipt == outcome.authority.cleanup_receipt
    with pytest.raises(BenchmarkTargetRecoveryError, match="absent or ambiguous"):
        journal.completed_attempt_for_operation("benchmark-target-operation:missing")


def test_completed_attempt_reader_rejects_foreign_canonical_record_chain(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    provider = _RecoverableProvider(manifest, _trust_anchor())
    runner = _runner(tmp_path, provider)
    first = asyncio.run(
        runner.run(
            manifest,
            arm_id=manifest.arms[0].arm_id,
            seed=7,
            repetition=1,
        )
    )
    second = asyncio.run(
        runner.run(
            manifest,
            arm_id=manifest.arms[0].arm_id,
            seed=7,
            repetition=1,
        )
    )
    journal_path = tmp_path / "state" / "target-operations.sqlite3"
    with sqlite3.connect(journal_path) as connection:
        attempts = connection.execute(
            "SELECT attempt_id FROM attempts WHERE state = 'completed' ORDER BY rowid"
        ).fetchall()
        assert len(attempts) == 2
        first_attempt_id, second_attempt_id = (str(row[0]) for row in attempts)
        assert first_attempt_id != second_attempt_id
        connection.execute(
            "DELETE FROM records WHERE attempt_id = ?",
            (first_attempt_id,),
        )
        connection.execute(
            "UPDATE records SET attempt_id = ? WHERE attempt_id = ?",
            (first_attempt_id, second_attempt_id),
        )

    journal = BenchmarkTargetOperationJournal.open_existing(journal_path)
    with pytest.raises(BenchmarkTargetRecoveryError, match="durable attempt"):
        journal.completed_attempt_for_operation(second.authority.execution_receipt.operation_id)
    assert first.authority.execution_receipt.operation_id != (
        second.authority.execution_receipt.operation_id
    )


def test_hard_exit_is_fenced_retried_sealed_and_allows_next_run(tmp_path: Path) -> None:
    manifest = _manifest()
    provider = _RecoverableProvider(
        manifest,
        _trust_anchor(),
        hard_exit_once=True,
        recovery_results=("exception", "failed", "succeeded"),
    )
    runner = _runner(tmp_path, provider)
    with pytest.raises(_HardExit):
        asyncio.run(
            runner.run(
                manifest,
                arm_id=manifest.arms[0].arm_id,
                seed=7,
                repetition=1,
            )
        )

    recovery_paths = asyncio.run(runner.reconcile_pending())
    assert len(recovery_paths) == 1
    authority = load_benchmark_target_recovery_authority(recovery_paths[0])
    assert verify_run_integrity(recovery_paths[0]).valid
    assert authority.lifecycle_state == "cleanup-reconciled"
    assert authority.measurement_admission_eligible is False
    assert authority.abandoned_attempt.fence == 1
    assert authority.resolution_fence == 2
    assert authority.cleanup_receipt is not None
    assert authority.cleanup_receipt.status == "succeeded"
    assert [record.record_type for record in authority.journal_records[-6:]] == [
        "intent",
        "provider-error",
        "intent",
        "receipt",
        "intent",
        "receipt",
    ]

    outcome = asyncio.run(
        runner.run(
            manifest,
            arm_id=manifest.arms[0].arm_id,
            seed=7,
            repetition=1,
        )
    )
    assert outcome.authority.measurement_admission_eligible is True
    assert provider.highest_fence == 3


def test_process_hard_exit_preserves_intent_for_startup_reconciliation(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    provider = _RecoverableProvider(manifest, _trust_anchor())
    journal_path = tmp_path / "state" / "target-operations.sqlite3"
    process = multiprocessing.get_context("spawn").Process(
        target=_hard_exit_after_execution_intent,
        args=(
            str(journal_path),
            manifest.model_dump(mode="json", by_alias=True),
            provider.definition.model_dump(mode="json", by_alias=True),
        ),
    )
    process.start()
    process.join(timeout=15)

    assert process.exitcode == 23
    recovery_path = asyncio.run(_runner(tmp_path, provider).reconcile_pending())[0]
    authority = load_benchmark_target_recovery_authority(recovery_path)
    original_records = [
        record
        for record in authority.journal_records
        if record.operation.fence == authority.abandoned_attempt.fence
    ]
    assert original_records[-1].record_type == "intent"
    assert original_records[-1].operation.stage == "execution"
    assert authority.lifecycle_state == "cleanup-reconciled"
    assert authority.resolution_fence > authority.abandoned_attempt.fence


def test_failed_inline_cleanup_is_reconciled_before_runner_returns(tmp_path: Path) -> None:
    manifest = _manifest()
    provider = _RecoverableProvider(
        manifest,
        _trust_anchor(),
        cleanup_status="failed",
    )
    runner = _runner(tmp_path, provider)
    outcome = asyncio.run(
        runner.run(
            manifest,
            arm_id=manifest.arms[0].arm_id,
            seed=7,
            repetition=1,
        )
    )

    assert outcome.authority.observation.cleanup_succeeded is False
    assert provider.calls[-2:] == [("cleanup", 1, 1), ("cleanup", 2, 1)]
    recovery_runs = tuple((tmp_path / "runs" / "benchmark-target-recovery").iterdir())
    recovery = load_benchmark_target_recovery_authority(recovery_runs[0])
    assert recovery.lifecycle_state == "cleanup-reconciled"
    assert recovery.cleanup_receipt is not None
    assert recovery.cleanup_receipt.status == "succeeded"
    assert (
        BenchmarkTargetOperationJournal(tmp_path / "state" / "target-operations.sqlite3").pending()
        == ()
    )


def test_unresolved_recovery_seals_failure_and_blocks_new_reset(tmp_path: Path) -> None:
    manifest = _manifest()
    provider = _RecoverableProvider(
        manifest,
        _trust_anchor(),
        hard_exit_once=True,
        recovery_results=("exception", "failed", "exception"),
    )
    runner = _runner(tmp_path, provider)
    with pytest.raises(_HardExit):
        asyncio.run(
            runner.run(
                manifest,
                arm_id=manifest.arms[0].arm_id,
                seed=7,
                repetition=1,
            )
        )

    reset_count = sum(stage == "reset" for stage, _fence, _ordinal in provider.calls)
    with pytest.raises(BenchmarkTargetRecoveryError, match="remains unresolved"):
        asyncio.run(
            runner.run(
                manifest,
                arm_id=manifest.arms[0].arm_id,
                seed=7,
                repetition=1,
            )
        )
    assert sum(stage == "reset" for stage, _fence, _ordinal in provider.calls) == reset_count
    recovery_runs = tuple((tmp_path / "runs" / "benchmark-target-recovery").iterdir())
    assert len(recovery_runs) == 1
    authority = load_benchmark_target_recovery_authority(recovery_runs[0])
    assert authority.lifecycle_state == "cleanup-unresolved"
    assert authority.cleanup_receipt is None
    assert BenchmarkTargetOperationJournal(
        tmp_path / "state" / "target-operations.sqlite3"
    ).pending()


def test_recovery_does_not_swallow_base_exception_or_claim_it_as_provider_error(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    provider = _RecoverableProvider(
        manifest,
        _trust_anchor(),
        hard_exit_once=True,
        recovery_results=("hard-exit",),
    )
    runner = _runner(tmp_path, provider)
    with pytest.raises(_HardExit):
        asyncio.run(
            runner.run(
                manifest,
                arm_id=manifest.arms[0].arm_id,
                seed=7,
                repetition=1,
            )
        )
    with pytest.raises(_HardExit):
        asyncio.run(runner.reconcile_pending())

    recovery_path = asyncio.run(runner.reconcile_pending())[0]
    authority = load_benchmark_target_recovery_authority(recovery_path)
    fence_two = [record for record in authority.journal_records if record.operation.fence == 2]
    assert [record.record_type for record in fence_two] == ["intent"]
    assert authority.resolution_fence == 3


def test_new_recovery_fence_rejects_stale_journal_writer(tmp_path: Path) -> None:
    manifest = _manifest()
    provider = _RecoverableProvider(manifest, _trust_anchor())
    coordinate = BenchmarkTargetCoordinate(
        benchmarkId=manifest.benchmark_id,
        manifestDigest=manifest.digest(),
        arm=manifest.arms[0],
        seed=7,
        repetition=1,
    )
    journal = BenchmarkTargetOperationJournal(tmp_path / "state" / "target-operations.sqlite3")
    attempt = journal.begin_attempt(provider.definition, coordinate)
    reset = BenchmarkTargetOperation(
        attemptId=attempt.attempt_id,
        attemptDigest=attempt.attempt_digest,
        adapterDigest=attempt.adapter_digest,
        coordinateDigest=attempt.coordinate_digest,
        fence=attempt.fence,
        stage="reset",
        ordinal=1,
    )
    journal.append_intent(reset)
    recovery_fence = journal.claim_recovery(attempt)

    assert recovery_fence > attempt.fence
    with pytest.raises(BenchmarkTargetRecoveryError, match="Stale or foreign operation"):
        journal.append_provider_error(reset)


def test_current_attempt_reader_rejects_coercible_noncanonical_wire(tmp_path: Path) -> None:
    manifest = _manifest()
    provider = _RecoverableProvider(manifest, _trust_anchor())
    coordinate = BenchmarkTargetCoordinate(
        benchmarkId=manifest.benchmark_id,
        manifestDigest=manifest.digest(),
        arm=manifest.arms[0],
        seed=7,
        repetition=1,
    )
    database = tmp_path / "state" / "target-operations.sqlite3"
    journal = BenchmarkTargetOperationJournal(database)
    attempt = journal.begin_attempt(provider.definition, coordinate)
    canonical = attempt.model_dump_json(by_alias=True)
    noncanonical = canonical.replace(f'"fence":{attempt.fence}', f'"fence":"{attempt.fence}"')
    assert noncanonical != canonical
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE attempts SET attempt_json = ? WHERE attempt_id = ?",
            (noncanonical, attempt.attempt_id),
        )

    with pytest.raises(BenchmarkTargetRecoveryError, match="identity differs"):
        journal.current_open_attempt(attempt.attempt_id)


def test_current_attempt_reader_rejects_coercible_fence_column(tmp_path: Path) -> None:
    manifest = _manifest()
    provider = _RecoverableProvider(manifest, _trust_anchor())
    coordinate = BenchmarkTargetCoordinate(
        benchmarkId=manifest.benchmark_id,
        manifestDigest=manifest.digest(),
        arm=manifest.arms[0],
        seed=7,
        repetition=1,
    )
    database = tmp_path / "state" / "target-operations.sqlite3"
    journal = BenchmarkTargetOperationJournal(database)
    attempt = journal.begin_attempt(provider.definition, coordinate)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE attempts SET fence = ? WHERE attempt_id = ?",
            (sqlite3.Binary(str(attempt.fence).encode("ascii")), attempt.attempt_id),
        )

    with pytest.raises(BenchmarkTargetRecoveryError, match="identity differs"):
        journal.current_open_attempt(attempt.attempt_id)


def test_recovery_reader_rejects_sealed_authority_mutation(tmp_path: Path) -> None:
    manifest = _manifest()
    provider = _RecoverableProvider(manifest, _trust_anchor(), hard_exit_once=True)
    runner = _runner(tmp_path, provider)
    with pytest.raises(_HardExit):
        asyncio.run(
            runner.run(
                manifest,
                arm_id=manifest.arms[0].arm_id,
                seed=7,
                repetition=1,
            )
        )
    recovery_path = asyncio.run(runner.reconcile_pending())[0]
    authority_path = recovery_path / "benchmark-target-recovery-authority.json"
    authority_path.write_text("{}", encoding="utf-8")

    with pytest.raises(BenchmarkTargetRecoveryError):
        load_benchmark_target_recovery_authority(recovery_path)


def test_operation_journal_rejects_non_regular_database_and_sidecar(tmp_path: Path) -> None:
    database = tmp_path / "state" / "target-operations.sqlite3"
    database.mkdir(parents=True)
    with pytest.raises(BenchmarkTargetRecoveryError, match="single-link regular file"):
        BenchmarkTargetOperationJournal(database)

    database.rmdir()
    database.parent.mkdir(exist_ok=True)
    Path(f"{database}-journal").mkdir()
    with pytest.raises(BenchmarkTargetRecoveryError, match="sidecar"):
        BenchmarkTargetOperationJournal(database)
