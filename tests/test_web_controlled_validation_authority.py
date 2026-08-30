from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from pajin.benchmark.docker_provider import (
    DockerBenchmarkProviderError,
    DockerBenchmarkProviderEvidence,
)
from pajin.benchmark.scanner_docker_provider import (
    CatalogBoundDockerZAPScannerTargetFactoryAdapter,
    DockerZAPScannerTargetFactoryAdapter,
    require_production_zap_catalog_provider,
)
from pajin.benchmark.target_catalog import registered_traditional_web_api_target_catalog
from pajin.benchmark.target_factory import (
    BenchmarkTargetStageReceipt,
    RegisteredBenchmarkTargetFactoryAdapter,
)
from pajin.benchmark.target_recovery import (
    BenchmarkTargetOperation,
    BenchmarkTargetOperationJournal,
)
from pajin.workflow.web_controlled_validation_authority import (
    WebCleanupBeforeRouteDenialLifecycle,
    WebControlledValidationAuthorityError,
    WebControlledValidationAuthorityOutcome,
    WebControlledValidationTargetLifecycle,
    build_web_controlled_validation_authority,
    build_web_controlled_validation_execution_receipt,
    load_web_controlled_validation_authority,
    observe_web_cleanup_route_denial,
)
from pajin.workflow.web_controlled_validation_route import (
    WebControlledValidationRouteClaimError,
    WebControlledValidationRouteClaimLedger,
    WebControlledValidationRouteDenialReceipt,
    load_web_controlled_validation_route_denial_receipt,
)
from pajin.workflow.web_controlled_validation_runtime import (
    DockerWebControlledValidationAdapter,
    WebControlledValidationWorkerEvidence,
)
from pajin.workflow.web_proxy_route_authority import (
    WebProxyRouteAuthorityError,
    WebProxyRouteLiveAuthorityContext,
    WebProxyRouteTargetCleanupInvalidated,
)
from pajin.workflow.web_source_measurement_authority import (
    WebZAPSourceMeasurementReopenContext,
)
from tests.test_benchmark_zap_scanner import MEASUREMENT_KEY
from tests.test_bug_bounty_runtime import ContractBugBountyWorker
from tests.test_web_controlled_validation_runtime import (
    _backend,
    _FakeBoundaryInspector,
    _runtime_context,
)
from tests.test_web_proxy_route_authority import (
    RouteContext,
    _campaign,
    _issue,
    _operation,
    _with_campaign,
)

pytest_plugins = (
    "tests.test_web_proxy_route_authority",
    "tests.test_web_validation_evaluation",
)


@dataclass(frozen=True, slots=True)
class _EvidenceProvider:
    definition: RegisteredBenchmarkTargetFactoryAdapter
    durable_evidence: dict[str, DockerBenchmarkProviderEvidence]

    def evidence(
        self,
        receipt: BenchmarkTargetStageReceipt,
    ) -> DockerBenchmarkProviderEvidence:
        return self.durable_evidence[receipt.receipt_id].model_copy(deep=True)


@dataclass(frozen=True, slots=True)
class _DelegatingEvidenceProvider:
    provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter

    @property
    def definition(self) -> RegisteredBenchmarkTargetFactoryAdapter:
        return self.provider.definition

    def evidence(
        self,
        receipt: BenchmarkTargetStageReceipt,
    ) -> DockerBenchmarkProviderEvidence:
        return self.provider.evidence(receipt)


def _source_bound_route_context(
    route_context: RouteContext,
    web002d_context: SimpleNamespace,
) -> RouteContext:
    source_context = web002d_context.source_context
    profile = source_context.concrete_provider.profile
    context = replace(
        route_context,
        measured_case=source_context.measured_case,
        capability_bundle=source_context.capability_bundle,
        capability_lifecycle=source_context.lifecycle,
        capability_release=source_context.measured_case.capability_release,
        private_ground_truth_profile=source_context.private_profile,
        scanner_plan=source_context.measured_case.scanner_plan,
        scanner_registration=source_context.measured_case.scanner_registration,
        target_adapter=source_context.target_adapter,
        target_profile=profile,
    )
    journal = BenchmarkTargetOperationJournal.open_existing(source_context.journal_path)
    attempt = journal.begin_attempt(context.target_adapter, context.coordinate)
    reset_operation = _operation(attempt, "reset", 1)
    journal.append_intent(reset_operation)
    reset_at = journal.current_open_attempt(attempt.attempt_id)[4][-1].occurred_at
    reset_evidence = DockerBenchmarkProviderEvidence(
        adapterDigest=context.target_adapter.adapter_digest,
        coordinateDigest=context.coordinate.coordinate_digest,
        operationId=reset_operation.operation_id,
        operationDigest=reset_operation.operation_digest,
        fence=attempt.fence,
        stage="reset",
        environmentId="environment.web002d",
        dockerServerVersion="27.3.1",
        targetImageId=profile.target_image_id,
        workerImageId=profile.worker_image_id,
        resourcesAbsent=True,
        observedAt=reset_at,
    )
    reset_receipt = BenchmarkTargetStageReceipt(
        adapterDigest=context.target_adapter.adapter_digest,
        coordinateDigest=context.coordinate.coordinate_digest,
        stage="reset",
        operationId=reset_operation.operation_id,
        environmentId=reset_evidence.environment_id,
        status="succeeded",
        startedAt=reset_at,
        completedAt=reset_at,
        providerEvidenceDigest=reset_evidence.evidence_digest,
    )
    journal.append_receipt(reset_operation, reset_receipt)

    isolation_operation = _operation(attempt, "isolation", 1)
    journal.append_intent(isolation_operation)
    isolation_at = journal.current_open_attempt(attempt.attempt_id)[4][-1].occurred_at
    isolation_evidence = DockerBenchmarkProviderEvidence(
        adapterDigest=context.target_adapter.adapter_digest,
        coordinateDigest=context.coordinate.coordinate_digest,
        operationId=isolation_operation.operation_id,
        operationDigest=isolation_operation.operation_digest,
        fence=attempt.fence,
        stage="isolation",
        environmentId="environment.web002d",
        isolationId="isolation.web002d",
        dockerServerVersion="27.3.1",
        targetImageId=profile.target_image_id,
        workerImageId=profile.worker_image_id,
        targetContainerId="7" * 64,
        networkId="8" * 64,
        networkInternal=True,
        publishedPortCount=0,
        networkContainerCount=1,
        targetHealthy=True,
        observedAt=isolation_at,
    )
    isolation_receipt = BenchmarkTargetStageReceipt(
        adapterDigest=context.target_adapter.adapter_digest,
        coordinateDigest=context.coordinate.coordinate_digest,
        stage="isolation",
        operationId=isolation_operation.operation_id,
        environmentId=isolation_evidence.environment_id,
        isolationId=isolation_evidence.isolation_id,
        status="succeeded",
        startedAt=isolation_at,
        completedAt=isolation_at,
        providerEvidenceDigest=isolation_evidence.evidence_digest,
    )
    journal.append_receipt(isolation_operation, isolation_receipt)

    execution_operation = _operation(attempt, "execution", 1)
    journal.append_intent(execution_operation)
    issued_at = journal.current_open_attempt(attempt.attempt_id)[4][-1].occurred_at
    context = replace(
        context,
        target_journal=journal,
        target_attempt_id=attempt.attempt_id,
        attempt=attempt,
        reset_operation=reset_operation,
        reset_receipt=reset_receipt,
        reset_evidence=reset_evidence,
        isolation_operation=isolation_operation,
        execution_operation=execution_operation,
        isolation_receipt=isolation_receipt,
        isolation_evidence=isolation_evidence,
        issued_at=issued_at + timedelta(microseconds=1),
    )
    return _with_campaign(context, _campaign(context.issued_at))


def _complete_lifecycle(
    context: RouteContext,
    *,
    worker_evidence: WebControlledValidationWorkerEvidence,
) -> tuple[
    BenchmarkTargetStageReceipt,
    BenchmarkTargetOperation,
    BenchmarkTargetStageReceipt,
    DockerBenchmarkProviderEvidence,
]:
    execution_receipt = build_web_controlled_validation_execution_receipt(
        context.execution_operation,
        isolation_receipt=context.isolation_receipt,
        worker_evidence=worker_evidence,
    )
    context.target_journal.append_receipt(context.execution_operation, execution_receipt)

    cleanup_operation = _operation(context.attempt, "cleanup", 1)
    context.target_journal.append_intent(cleanup_operation)
    cleanup_started_at = max(worker_evidence.worker_result.finished_at, datetime.now(UTC))
    cleanup_evidence = DockerBenchmarkProviderEvidence(
        adapterDigest=context.target_adapter.adapter_digest,
        coordinateDigest=context.coordinate.coordinate_digest,
        operationId=cleanup_operation.operation_id,
        operationDigest=cleanup_operation.operation_digest,
        fence=context.attempt.fence,
        stage="cleanup",
        environmentId=context.isolation_receipt.environment_id,
        isolationId=context.isolation_receipt.isolation_id,
        dockerServerVersion="27.3.1",
        targetImageId=context.target_profile.target_image_id,
        workerImageId=context.target_profile.worker_image_id,
        resourcesAbsent=True,
        observedAt=cleanup_started_at,
    )
    cleanup_receipt = BenchmarkTargetStageReceipt(
        adapterDigest=context.target_adapter.adapter_digest,
        coordinateDigest=context.coordinate.coordinate_digest,
        stage="cleanup",
        operationId=cleanup_operation.operation_id,
        environmentId=context.isolation_receipt.environment_id,
        isolationId=context.isolation_receipt.isolation_id,
        status="succeeded",
        startedAt=cleanup_started_at,
        completedAt=cleanup_started_at,
        providerEvidenceDigest=cleanup_evidence.evidence_digest,
    )
    context.target_journal.append_receipt(cleanup_operation, cleanup_receipt)
    context.target_journal.mark_completed(context.attempt.attempt_id)
    return execution_receipt, cleanup_operation, cleanup_receipt, cleanup_evidence


def _complete_denial_lifecycle(
    context: RouteContext,
) -> tuple[
    WebCleanupBeforeRouteDenialLifecycle,
    DockerBenchmarkProviderEvidence,
]:
    cleanup_operation = _operation(context.attempt, "cleanup", 1)
    context.target_journal.append_intent(cleanup_operation)
    cleanup_started_at = datetime.now(UTC)
    cleanup_evidence = DockerBenchmarkProviderEvidence(
        adapterDigest=context.target_adapter.adapter_digest,
        coordinateDigest=context.coordinate.coordinate_digest,
        operationId=cleanup_operation.operation_id,
        operationDigest=cleanup_operation.operation_digest,
        fence=context.attempt.fence,
        stage="cleanup",
        environmentId=context.isolation_receipt.environment_id,
        isolationId=context.isolation_receipt.isolation_id,
        dockerServerVersion="27.3.1",
        targetImageId=context.target_profile.target_image_id,
        workerImageId=context.target_profile.worker_image_id,
        resourcesAbsent=True,
        observedAt=cleanup_started_at,
    )
    cleanup_receipt = BenchmarkTargetStageReceipt(
        adapterDigest=context.target_adapter.adapter_digest,
        coordinateDigest=context.coordinate.coordinate_digest,
        stage="cleanup",
        operationId=cleanup_operation.operation_id,
        environmentId=context.isolation_receipt.environment_id,
        isolationId=context.isolation_receipt.isolation_id,
        status="succeeded",
        startedAt=cleanup_started_at,
        completedAt=cleanup_started_at,
        providerEvidenceDigest=cleanup_evidence.evidence_digest,
    )
    context.target_journal.append_receipt(cleanup_operation, cleanup_receipt)
    context.target_journal.mark_completed(context.attempt.attempt_id)
    return (
        WebCleanupBeforeRouteDenialLifecycle(
            adapter=context.target_adapter,
            coordinate=context.coordinate,
            attempt=context.attempt,
            resetOperation=context.reset_operation,
            resetReceipt=context.reset_receipt,
            resetEvidence=context.reset_evidence,
            isolationOperation=context.isolation_operation,
            isolationReceipt=context.isolation_receipt,
            isolationEvidence=context.isolation_evidence,
            executionOperation=context.execution_operation,
            cleanupOperation=cleanup_operation,
            cleanupReceipt=cleanup_receipt,
            cleanupEvidence=cleanup_evidence,
        ),
        cleanup_evidence,
    )


def _live_route_context(context: RouteContext) -> WebProxyRouteLiveAuthorityContext:
    return WebProxyRouteLiveAuthorityContext(
        trust_anchor=context.trust_anchor,
        measured_case=context.measured_case,
        capability_bundle=context.capability_bundle,
        capability_lifecycle=context.capability_lifecycle,
        capability_release=context.capability_release,
        private_ground_truth_profile=context.private_ground_truth_profile,
        scanner_plan=context.scanner_plan,
        scanner_registration=context.scanner_registration,
        runtime_policy=context.runtime_policy,
        target_profile=context.target_profile,
        target_journal=context.target_journal,
        target_attempt_id=context.target_attempt_id,
        isolation_evidence=context.isolation_evidence,
        campaign=context.campaign,
        approval_store=context.approval_store,
        approval_id=context.authorization.approval.approval_id,
        permit_id=context.authorization.action.permit.permit_id,
        request=context.request,
    )


def _source_reopen_context(context: SimpleNamespace) -> WebZAPSourceMeasurementReopenContext:
    source = context.source_context
    return WebZAPSourceMeasurementReopenContext(
        outcome=source.outcome,
        measured_case=source.measured_case,
        capability_bundle=source.capability_bundle,
        lifecycle=source.lifecycle,
        release=source.measured_case.capability_release,
        target_adapter=source.target_adapter,
        private_ground_truth_profile=source.private_profile,
        scanner_plan=source.measured_case.scanner_plan,
        scanner_registration=source.measured_case.scanner_registration,
        journal_path=source.journal_path,
        catalog_provider=source.catalog_provider,
        measurement_trust_anchor=source.measurement_anchor,
        activation_store=source.activation_store,
        distribution_bundle=source.distribution_bundle,
        distribution_trust_anchor=source.distribution_anchor,
    )


def test_web_002d_unit_double_cannot_cross_production_authority_boundary(
    web002d_context: SimpleNamespace,
    route_context: RouteContext,
    tmp_path: Path,
) -> None:
    context = _source_bound_route_context(route_context, web002d_context)
    worker = ContractBugBountyWorker()
    inspector = _FakeBoundaryInspector(context)
    backend = _backend(context, worker, inspector)
    claim_ledger = WebControlledValidationRouteClaimLedger(tmp_path / "route-claims.sqlite3")
    context = _runtime_context(context, backend, claim_ledger=claim_ledger)
    bundle = _issue(context)
    adapter = DockerWebControlledValidationAdapter._for_test(
        backend=backend,
        inspector=inspector,
        route_authority=_live_route_context(context),
        claim_ledger=claim_ledger,
        deployment_id="deployment.web002",
        gateway_policy_id="gateway-policy.web002.controlled",
        gateway_policy_version="1.0.0",
        worker_backend_id="docker-worker-backend.web002",
        worker_backend_version="1.0.0",
        evaluated_at=context.issued_at + timedelta(seconds=31),
    )
    runtime = asyncio.run(
        adapter.execute(
            bundle=bundle,
            coordinate=context.coordinate,
            request=context.request,
        )
    )
    (
        execution_receipt,
        cleanup_operation,
        cleanup_receipt,
        cleanup_evidence,
    ) = _complete_lifecycle(context, worker_evidence=runtime.evidence)
    lifecycle = WebControlledValidationTargetLifecycle(
        adapter=context.target_adapter,
        coordinate=context.coordinate,
        attempt=context.attempt,
        resetOperation=context.reset_operation,
        resetReceipt=context.reset_receipt,
        resetEvidence=context.reset_evidence,
        isolationOperation=context.isolation_operation,
        isolationReceipt=context.isolation_receipt,
        isolationEvidence=context.isolation_evidence,
        executionOperation=context.execution_operation,
        executionReceipt=execution_receipt,
        workerEvidence=runtime.evidence,
        cleanupOperation=cleanup_operation,
        cleanupReceipt=cleanup_receipt,
        cleanupEvidence=cleanup_evidence,
    )

    denial_request = context.request.model_copy(update={"request_id": "tool_web002_route_denial"})
    denial_context = _source_bound_route_context(
        replace(route_context, request=denial_request),
        web002d_context,
    )
    denial_context = _runtime_context(denial_context, backend, claim_ledger=claim_ledger)
    denial_bundle = _issue(denial_context, route_nonce="e" * 32)
    denial_lifecycle, denial_cleanup_evidence = _complete_denial_lifecycle(denial_context)
    provider = _EvidenceProvider(
        definition=context.target_adapter,
        durable_evidence={
            context.reset_receipt.receipt_id: context.reset_evidence,
            context.isolation_receipt.receipt_id: context.isolation_evidence,
            cleanup_receipt.receipt_id: cleanup_evidence,
            denial_context.reset_receipt.receipt_id: denial_context.reset_evidence,
            denial_context.isolation_receipt.receipt_id: denial_context.isolation_evidence,
            denial_lifecycle.cleanup_receipt.receipt_id: denial_cleanup_evidence,
        },
    )
    denial_completed_attempt = denial_context.target_journal.completed_attempt_for_operation(
        denial_lifecycle.cleanup_operation.operation_id
    )
    denial_evaluated_at = denial_completed_attempt[3][-1].occurred_at + timedelta(microseconds=1)
    denial = observe_web_cleanup_route_denial(
        floor_policy=web002d_context.floor,
        bundle=denial_bundle,
        lifecycle=denial_lifecycle,
        route_authority=_live_route_context(denial_context),
        claim_ledger=claim_ledger,
        provider=provider,
        evaluated_at=denial_evaluated_at,
    )

    durable_denial_receipt = load_web_controlled_validation_route_denial_receipt(
        ledger=claim_ledger,
        receipt=denial.route_denial_receipt,
    )
    success_statement = bundle.route.statement
    denial_statement = denial_bundle.route.statement
    assert durable_denial_receipt == denial.route_denial_receipt
    assert durable_denial_receipt.slot_digest == (denial_statement.consumption_slot_digest)
    assert durable_denial_receipt.route_digest == denial_statement.route_digest
    assert durable_denial_receipt.denied_at == denial.evaluated_at
    with pytest.raises(WebControlledValidationRouteClaimError, match="durably denied"):
        claim_ledger.claim_once(
            slot_digest=denial_statement.consumption_slot_digest,
            route_digest=denial_statement.route_digest,
            verification_digest="7" * 64,
            claimed_at=denial.evaluated_at,
        )

    mismatched_receipt = WebControlledValidationRouteDenialReceipt(
        slotDigest=denial_statement.consumption_slot_digest,
        routeDigest=denial_statement.route_digest,
        deniedAt=denial.evaluated_at + timedelta(microseconds=1),
    )
    denial_material = denial.model_dump(mode="python", by_alias=True)
    denial_material["routeDenialReceipt"] = mismatched_receipt.model_dump(
        mode="python",
        by_alias=True,
    )
    with pytest.raises(ValueError, match="route lineage"):
        type(denial).model_validate(denial_material)

    later_attempt = denial_context.target_journal.begin_attempt(
        denial_context.target_adapter,
        denial_context.coordinate,
    )
    assert later_attempt.fence > denial_lifecycle.attempt.fence
    denial_route_authority = _live_route_context(denial_context)
    with pytest.raises(WebProxyRouteAuthorityError) as stale_route:
        denial_route_authority.verify(
            denial_bundle,
            evaluated_at=denial.evaluated_at,
        )
    assert not isinstance(
        stale_route.value,
        WebProxyRouteTargetCleanupInvalidated,
    )
    denial_route_authority.verify_cleanup_invalidated_history(
        denial_bundle,
        evaluated_at=denial.evaluated_at,
    )

    assert lifecycle.attempt.attempt_id != denial_lifecycle.attempt.attempt_id
    assert lifecycle.attempt.fence < denial_lifecycle.attempt.fence
    assert (
        lifecycle.execution_operation.operation_id
        != denial_lifecycle.execution_operation.operation_id
    )
    assert (
        lifecycle.cleanup_operation.operation_id != denial_lifecycle.cleanup_operation.operation_id
    )
    assert success_statement.route_id != denial_statement.route_id
    assert success_statement.approval_id != denial_statement.approval_id
    assert success_statement.permit_id != denial_statement.permit_id
    assert success_statement.dispatch_id != denial_statement.dispatch_id
    assert success_statement.consumption_slot_digest != denial_statement.consumption_slot_digest
    assert success_statement.request_id != denial_statement.request_id
    assert denial.worker_dispatched is False
    assert denial.controlled_provider_execution_performed is False
    assert denial.network_access_performed is False
    assert len(worker.jobs) == 1

    missing_denial_ledger = WebControlledValidationRouteClaimLedger(
        tmp_path / "missing-denial-route-claims.sqlite3"
    )
    recreated_claim = missing_denial_ledger.claim_once(
        slot_digest=runtime.route_claim_receipt.slot_digest,
        route_digest=runtime.route_claim_receipt.route_digest,
        verification_digest=runtime.route_claim_receipt.verification_digest,
        claimed_at=runtime.route_claim_receipt.claimed_at,
    )
    assert recreated_claim == runtime.route_claim_receipt
    with pytest.raises(WebControlledValidationRouteClaimError, match="not present"):
        load_web_controlled_validation_route_denial_receipt(
            ledger=missing_denial_ledger,
            receipt=denial.route_denial_receipt,
        )
    with pytest.raises(WebControlledValidationAuthorityError, match="failed closed"):
        build_web_controlled_validation_authority(
            validation_run_id="validation-run.web002d.missing-denial",
            measured_case_authority=web002d_context.source_context.measured_case,
            private_ground_truth_profile=web002d_context.source_context.private_profile,
            source_reopen_context=_source_reopen_context(web002d_context),
            floor_policy=web002d_context.floor,
            mapping=web002d_context.mapping,
            route_bundle=bundle,
            route_verification=runtime.verification,
            route_claim_receipt=runtime.route_claim_receipt,
            target_lifecycle=lifecycle,
            denial_evidence=denial,
            denial_route_authority=denial_route_authority,
            trust_anchor=context.trust_anchor,
            claim_ledger=missing_denial_ledger,
            target_journal=context.target_journal,
            provider=cast(
                CatalogBoundDockerZAPScannerTargetFactoryAdapter,
                provider,
            ),
            adapter=adapter,
        )
    with pytest.raises(WebControlledValidationRouteClaimError, match="not present"):
        load_web_controlled_validation_route_denial_receipt(
            ledger=missing_denial_ledger,
            receipt=denial.route_denial_receipt,
        )

    source_reopen_context = _source_reopen_context(web002d_context)
    source = web002d_context.source_context
    ground_truth = source.private_profile.private_ground_truth.ground_truth
    foreign_concrete = DockerZAPScannerTargetFactoryAdapter(
        state_path=tmp_path / "foreign-provider.sqlite3",
        profile=source.concrete_provider.profile,
        plan=source.measured_case.scanner_plan,
        registration=source.measured_case.scanner_registration,
        trust_anchor=source.measurement_anchor,
        measurement_private_key=MEASUREMENT_KEY,
    )
    foreign_provider = CatalogBoundDockerZAPScannerTargetFactoryAdapter(
        provider=foreign_concrete,
        catalog=registered_traditional_web_api_target_catalog(
            foreign_concrete.profile,
            ground_truth,
        ),
        ground_truth=ground_truth,
    )
    require_production_zap_catalog_provider(foreign_provider)
    invalid_providers: tuple[object, ...] = (
        provider,
        _DelegatingEvidenceProvider(source_reopen_context.catalog_provider),
        foreign_provider,
    )
    for invalid_provider in invalid_providers:
        with pytest.raises(
            WebControlledValidationAuthorityError,
            match="failed closed",
        ) as rejected_test_adapter:
            build_web_controlled_validation_authority(
                validation_run_id="validation-run.web002d.unit-boundary",
                measured_case_authority=web002d_context.source_context.measured_case,
                private_ground_truth_profile=web002d_context.source_context.private_profile,
                source_reopen_context=source_reopen_context,
                floor_policy=web002d_context.floor,
                mapping=web002d_context.mapping,
                route_bundle=bundle,
                route_verification=runtime.verification,
                route_claim_receipt=runtime.route_claim_receipt,
                target_lifecycle=lifecycle,
                denial_evidence=denial,
                denial_route_authority=denial_route_authority,
                trust_anchor=context.trust_anchor,
                claim_ledger=claim_ledger,
                target_journal=context.target_journal,
                provider=cast(
                    CatalogBoundDockerZAPScannerTargetFactoryAdapter,
                    invalid_provider,
                ),
                adapter=adapter,
            )
        assert rejected_test_adapter.value.__cause__ is not None
        assert "source-owned catalog provider" in str(rejected_test_adapter.value.__cause__)

    with pytest.raises(
        WebControlledValidationAuthorityError,
        match="could not be verified",
    ) as rejected_load_provider:
        load_web_controlled_validation_authority(
            cast(WebControlledValidationAuthorityOutcome, object()),
            measured_case_authority=web002d_context.source_context.measured_case,
            private_ground_truth_profile=web002d_context.source_context.private_profile,
            source_reopen_context=source_reopen_context,
            floor_policy=web002d_context.floor,
            mapping=web002d_context.mapping,
            trust_anchor=context.trust_anchor,
            claim_ledger=claim_ledger,
            target_journal=context.target_journal,
            provider=cast(
                CatalogBoundDockerZAPScannerTargetFactoryAdapter,
                provider,
            ),
            adapter=adapter,
            denial_route_authority=denial_route_authority,
        )
    assert rejected_load_provider.value.__cause__ is not None
    assert "source-owned catalog provider" in str(rejected_load_provider.value.__cause__)


def test_web_002d_production_provider_guard_requires_exact_unshadowed_docker_custody(
    web002d_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = web002d_context.source_context
    ground_truth = source.private_profile.private_ground_truth.ground_truth
    concrete = DockerZAPScannerTargetFactoryAdapter(
        state_path=tmp_path / "production-provider.sqlite3",
        profile=source.concrete_provider.profile,
        plan=source.measured_case.scanner_plan,
        registration=source.measured_case.scanner_registration,
        trust_anchor=source.measurement_anchor,
        measurement_private_key=MEASUREMENT_KEY,
    )
    provider = CatalogBoundDockerZAPScannerTargetFactoryAdapter(
        provider=concrete,
        catalog=registered_traditional_web_api_target_catalog(
            concrete.profile,
            ground_truth,
        ),
        ground_truth=ground_truth,
    )

    require_production_zap_catalog_provider(provider)

    with pytest.raises(DockerBenchmarkProviderError, match="subprocess Docker runner"):
        require_production_zap_catalog_provider(source.catalog_provider)
    with pytest.raises(DockerBenchmarkProviderError, match="exact catalog-bound provider"):
        require_production_zap_catalog_provider(
            cast(
                CatalogBoundDockerZAPScannerTargetFactoryAdapter,
                _DelegatingEvidenceProvider(provider),
            )
        )

    with monkeypatch.context() as patch:
        patch.setattr(provider, "evidence", provider.evidence)
        with pytest.raises(DockerBenchmarkProviderError, match="shadowed"):
            require_production_zap_catalog_provider(provider)
    delattr(provider, "evidence")

    with monkeypatch.context() as patch:
        patch.setattr(concrete, "evidence", concrete.evidence)
        with pytest.raises(DockerBenchmarkProviderError, match="shadowed"):
            require_production_zap_catalog_provider(provider)
    delattr(concrete, "evidence")

    runner = concrete._docker
    with monkeypatch.context() as patch:
        patch.setattr(runner, "run", runner.run)
        with pytest.raises(DockerBenchmarkProviderError, match="shadowed"):
            require_production_zap_catalog_provider(provider)
    delattr(runner, "run")

    with monkeypatch.context() as patch:
        patch.setattr(runner, "unexpected", True, raising=False)
        with pytest.raises(DockerBenchmarkProviderError, match="shadowed"):
            require_production_zap_catalog_provider(provider)

    with monkeypatch.context() as patch:
        patch.setattr(
            CatalogBoundDockerZAPScannerTargetFactoryAdapter,
            "evidence",
            lambda _self, _receipt: None,
        )
        with pytest.raises(DockerBenchmarkProviderError, match="shadowed"):
            require_production_zap_catalog_provider(provider)

    original_getattribute = CatalogBoundDockerZAPScannerTargetFactoryAdapter.__getattribute__

    def forged_getattribute(self: object, name: str) -> object:
        if name == "__dict__":
            forged_state = original_getattribute(self, name).copy()
            forged_state.pop("evidence", None)
            return forged_state
        if name == "evidence":
            return lambda _receipt: None
        return original_getattribute(self, name)

    with monkeypatch.context() as patch:
        patch.setattr(provider, "evidence", provider.evidence)
        patch.setattr(
            CatalogBoundDockerZAPScannerTargetFactoryAdapter,
            "__getattribute__",
            forged_getattribute,
        )
        with pytest.raises(DockerBenchmarkProviderError, match="shadowed"):
            require_production_zap_catalog_provider(provider)
    delattr(provider, "evidence")

    with monkeypatch.context() as patch:
        patch.setattr(concrete._docker, "_executable", "podman")
        with pytest.raises(DockerBenchmarkProviderError, match="state differs"):
            require_production_zap_catalog_provider(provider)

    with monkeypatch.context() as patch:
        patch.setattr(runner, "_timeout_seconds", runner._timeout_seconds + 1)
        with pytest.raises(DockerBenchmarkProviderError, match="state differs"):
            require_production_zap_catalog_provider(provider)

    require_production_zap_catalog_provider(provider)
