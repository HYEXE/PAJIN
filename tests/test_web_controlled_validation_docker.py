from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
import subprocess
from contextlib import suppress
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from pajin.benchmark.docker_provider import DockerBugBountyTargetProfile
from pajin.benchmark.target_factory import (
    BenchmarkTargetCoordinate,
    benchmark_target_coordinate,
)
from pajin.benchmark.target_recovery import BenchmarkTargetOperationJournal
from pajin.runtime.store import AuditEvent, RunStore
from pajin.runtime.worker import DockerWorkerBackend
from pajin.workflow.web_controlled_validation_authority import (
    WebCleanupBeforeRouteDenialLifecycle,
    WebControlledValidationTargetLifecycle,
    build_and_seal_web_controlled_validation_authority,
    build_web_controlled_validation_execution_receipt,
    load_web_controlled_validation_authority,
    observe_web_cleanup_route_denial,
)
from pajin.workflow.web_controlled_validation_route import (
    WebControlledValidationRouteClaimLedger,
    load_web_controlled_validation_route_denial_receipt,
)
from pajin.workflow.web_controlled_validation_runtime import (
    DockerWebControlledValidationAdapter,
    SubprocessWebControlledDockerBoundaryInspector,
    web_controlled_gateway_policy_digest,
    web_controlled_worker_backend_context_digest,
)
from pajin.workflow.web_measured_product_flow import (
    WebMeasuredProductFlowOutcome,
    WebMeasuredProductFlowProjector,
    WebMeasuredProductSourceReopenContext,
)
from pajin.workflow.web_proxy_route_authority import (
    WebProxyRouteLiveAuthorityContext,
    WebProxyRouteRuntimePolicy,
    registered_web_proxy_route_runtime_policy,
)
from pajin.workflow.web_source_measurement_authority import (
    WebZAPSourceMeasurementReopenContext,
)
from pajin.workflow.web_validation_floor import (
    bind_web_expected_finding_projection_policy,
    registered_web_benchmark_validation_floor_policy,
)
from tests.test_benchmark_zap_scanner import _reload_web_source, _run_web_source
from tests.test_web_proxy_route_authority import (
    RouteContext,
    _campaign,
    _issue,
    _operation,
    _with_campaign,
)
from tests.web_measured_product_fresh_process import (
    FreshWebMeasuredProductFailureCase,
    FreshWebMeasuredProductRecipe,
    run_fresh_web_measured_product_probe,
)

pytest_plugins = ("tests.test_web_proxy_route_authority",)

_TARGET_IMAGE = "pajin-bug-bounty-target:dev"
_BENCHMARK_WORKER_IMAGE = "pajin-benchmark-worker:dev"
_ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
_CONTROLLED_WORKER_IMAGE = "pajin-worker:dev"
_EGRESS_PROXY_IMAGE = "pajin-egress-proxy:dev"
_DEPLOYMENT_ID = "deployment.web002"
_GATEWAY_POLICY_ID = "gateway-policy.web002.controlled"
_GATEWAY_POLICY_VERSION = "1.0.0"
_WORKER_BACKEND_ID = "docker-worker-backend.web002"
_WORKER_BACKEND_VERSION = "1.0.0"
_FRESH_PRODUCT_FAILURE_CASE_IDS = (
    "strict-boolean",
    "claim-ceiling",
    "impact-escalation",
    "severity-escalation",
    "metric-drift",
    "product-event-equivocation",
    "source-event-equivocation",
    "stale-product-root",
    "stale-source-root",
    "foreign-run-path-pair",
    "noncanonical-json",
    "duplicate-key-json",
    "oversized-json",
)


def _canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _copied_product_outcome(
    outcome: WebMeasuredProductFlowOutcome,
    *,
    case_root: Path,
    source_run_path: Path | None = None,
) -> WebMeasuredProductFlowOutcome:
    case_root.mkdir(parents=True, exist_ok=False)
    product_run_path = case_root / "product-run"
    shutil.copytree(outcome.run_path, product_run_path)
    source = (
        replace(outcome.source, run_path=source_run_path)
        if source_run_path is not None
        else outcome.source
    )
    return replace(
        outcome,
        run_path=product_run_path,
        source=source,
    )


def _reseal_rewritten_run(*, run_id: str, run_path: Path) -> None:
    run_path.joinpath("run-integrity.jsonl").unlink()
    RunStore(run_id=run_id, path=run_path).seal()


def _rewrite_events_and_reseal(
    *,
    run_id: str,
    run_path: Path,
    events: list[AuditEvent],
) -> None:
    previous_hash: str | None = None
    encoded: list[str] = []
    for sequence, event in enumerate(events, start=1):
        pending = event.model_copy(
            update={
                "sequence": sequence,
                "previous_hash": previous_hash,
                "event_hash": "0" * 64,
            }
        )
        finalized = pending.model_copy(update={"event_hash": pending.computed_hash()})
        encoded.append(finalized.model_dump_json())
        previous_hash = finalized.event_hash
    run_path.joinpath("events.jsonl").write_text(
        "\n".join(encoded) + "\n",
        encoding="utf-8",
    )
    _reseal_rewritten_run(run_id=run_id, run_path=run_path)


def _fresh_product_integrity_failure_cases(
    accepted: WebMeasuredProductFlowOutcome,
    *,
    foreign: WebMeasuredProductFlowOutcome,
    output_root: Path,
) -> tuple[FreshWebMeasuredProductFailureCase, ...]:
    output_root.mkdir(parents=True, exist_ok=False)
    cases: list[FreshWebMeasuredProductFailureCase] = []

    for case_id, section_name, field_name, value in (
        (
            "strict-boolean",
            "authorityBoundary",
            "additionalExecutionAuthorized",
            0,
        ),
        (
            "claim-ceiling",
            "finding",
            "claimCeiling",
            "production-vulnerability",
        ),
        ("impact-escalation", "finding", "impactAssurance", "high"),
        ("severity-escalation", "finding", "severityAssurance", "critical"),
    ):
        case_outcome = _copied_product_outcome(
            accepted,
            case_root=output_root / case_id,
        )
        artifact_path = case_outcome.run_path / case_outcome.artifact_path
        material = cast(
            dict[str, object],
            json.loads(artifact_path.read_text(encoding="utf-8")),
        )
        section = cast(dict[str, object], material[section_name])
        section[field_name] = value
        artifact_path.write_bytes(_canonical_json_bytes(material))
        _reseal_rewritten_run(
            run_id=case_outcome.run_id,
            run_path=case_outcome.run_path,
        )
        cases.append(FreshWebMeasuredProductFailureCase(case_id, case_outcome))

    metric_outcome = _copied_product_outcome(
        accepted,
        case_root=output_root / "metric-drift",
    )
    metric_artifact = metric_outcome.run_path / metric_outcome.artifact_path
    metric_material = cast(
        dict[str, object],
        json.loads(metric_artifact.read_text(encoding="utf-8")),
    )
    floor = cast(dict[str, object], metric_material["floor"])
    metrics = cast(list[object], floor["metrics"])
    for metric_value in metrics:
        metric = cast(dict[str, object], metric_value)
        if type(metric.get("numerator")) is int:
            metric["numerator"] = cast(int, metric["numerator"]) + 1
            break
    else:
        raise AssertionError("fresh WEB product fixture has no rational metric")
    metric_artifact.write_bytes(_canonical_json_bytes(metric_material))
    _reseal_rewritten_run(
        run_id=metric_outcome.run_id,
        run_path=metric_outcome.run_path,
    )
    cases.append(FreshWebMeasuredProductFailureCase("metric-drift", metric_outcome))

    equivocation_outcome = _copied_product_outcome(
        accepted,
        case_root=output_root / "product-event-equivocation",
    )
    events = [
        AuditEvent.model_validate_json(line)
        for line in equivocation_outcome.run_path.joinpath("events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    projected = events[1]
    events[1] = projected.model_copy(
        update={
            "payload": {
                **projected.payload,
                "flowDigest": "0" * 64,
            }
        }
    )
    _rewrite_events_and_reseal(
        run_id=equivocation_outcome.run_id,
        run_path=equivocation_outcome.run_path,
        events=events,
    )
    cases.append(
        FreshWebMeasuredProductFailureCase(
            "product-event-equivocation",
            equivocation_outcome,
        )
    )

    source_equivocation_root = output_root / "source-event-equivocation"
    source_equivocation_run_path = source_equivocation_root / "source-run"
    source_equivocation_root.mkdir(parents=True, exist_ok=False)
    shutil.copytree(accepted.source.run_path, source_equivocation_run_path)
    source_equivocation_outcome = _copied_product_outcome(
        accepted,
        case_root=source_equivocation_root / "selected",
        source_run_path=source_equivocation_run_path,
    )
    source_events = [
        AuditEvent.model_validate_json(line)
        for line in source_equivocation_run_path.joinpath("events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    source_sealed = source_events[1]
    source_events[1] = source_sealed.model_copy(
        update={
            "payload": {
                **source_sealed.payload,
                "authorityDigest": "0" * 64,
            }
        }
    )
    _rewrite_events_and_reseal(
        run_id=source_equivocation_outcome.source.run_id,
        run_path=source_equivocation_outcome.source.run_path,
        events=source_events,
    )
    cases.append(
        FreshWebMeasuredProductFailureCase(
            "source-event-equivocation",
            source_equivocation_outcome,
        )
    )

    stale_product_outcome = _copied_product_outcome(
        accepted,
        case_root=output_root / "stale-product-root",
    )
    RunStore(
        run_id=stale_product_outcome.run_id,
        path=stale_product_outcome.run_path,
    ).append_event(
        "product.web-measured-flow.projected",
        {"staleSelectedOutcome": True},
    )
    RunStore(
        run_id=stale_product_outcome.run_id,
        path=stale_product_outcome.run_path,
    ).seal()
    cases.append(
        FreshWebMeasuredProductFailureCase(
            "stale-product-root",
            stale_product_outcome,
        )
    )

    stale_source_root = output_root / "stale-source-root"
    stale_source_run_path = stale_source_root / "source-run"
    stale_source_root.mkdir(parents=True, exist_ok=False)
    shutil.copytree(accepted.source.run_path, stale_source_run_path)
    stale_source_outcome = _copied_product_outcome(
        accepted,
        case_root=stale_source_root / "selected",
        source_run_path=stale_source_run_path,
    )
    RunStore(
        run_id=stale_source_outcome.source.run_id,
        path=stale_source_outcome.source.run_path,
    ).append_event(
        "benchmark.web-controlled-validation.sealed",
        {"staleSelectedOutcome": True},
    )
    RunStore(
        run_id=stale_source_outcome.source.run_id,
        path=stale_source_outcome.source.run_path,
    ).seal()
    cases.append(
        FreshWebMeasuredProductFailureCase(
            "stale-source-root",
            stale_source_outcome,
        )
    )

    foreign_pair_root = output_root / "foreign-run-path-pair"
    foreign_pair_root.mkdir(parents=True, exist_ok=False)
    foreign_run_path = foreign_pair_root / "product-run"
    shutil.copytree(foreign.run_path, foreign_run_path)
    foreign_pair_outcome = replace(accepted, run_path=foreign_run_path)
    cases.append(
        FreshWebMeasuredProductFailureCase(
            "foreign-run-path-pair",
            foreign_pair_outcome,
        )
    )

    noncanonical_outcome = _copied_product_outcome(
        accepted,
        case_root=output_root / "noncanonical-json",
    )
    noncanonical_artifact = noncanonical_outcome.run_path / noncanonical_outcome.artifact_path
    noncanonical_artifact.write_bytes(noncanonical_artifact.read_bytes() + b"\n")
    _reseal_rewritten_run(
        run_id=noncanonical_outcome.run_id,
        run_path=noncanonical_outcome.run_path,
    )
    cases.append(
        FreshWebMeasuredProductFailureCase(
            "noncanonical-json",
            noncanonical_outcome,
        )
    )

    duplicate_key_outcome = _copied_product_outcome(
        accepted,
        case_root=output_root / "duplicate-key-json",
    )
    duplicate_key_artifact = duplicate_key_outcome.run_path / duplicate_key_outcome.artifact_path
    duplicate_key_bytes = duplicate_key_artifact.read_bytes()
    if not duplicate_key_bytes.startswith(b"{\n"):
        raise AssertionError("fresh WEB product fixture is not canonical JSON")
    duplicate_key_artifact.write_bytes(
        b'{\n  "kind": "WebMeasuredProductFlowProjection",\n' + duplicate_key_bytes[2:]
    )
    _reseal_rewritten_run(
        run_id=duplicate_key_outcome.run_id,
        run_path=duplicate_key_outcome.run_path,
    )
    cases.append(
        FreshWebMeasuredProductFailureCase(
            "duplicate-key-json",
            duplicate_key_outcome,
        )
    )

    oversized_outcome = _copied_product_outcome(
        accepted,
        case_root=output_root / "oversized-json",
    )
    oversized_artifact = oversized_outcome.run_path / oversized_outcome.artifact_path
    oversized_artifact.write_bytes(b'{"padding":"' + b"x" * (4 * 1024 * 1024) + b'"}\n')
    _reseal_rewritten_run(
        run_id=oversized_outcome.run_id,
        run_path=oversized_outcome.run_path,
    )
    cases.append(FreshWebMeasuredProductFailureCase("oversized-json", oversized_outcome))

    if tuple(case.case_id for case in cases) != _FRESH_PRODUCT_FAILURE_CASE_IDS:
        raise AssertionError("fresh WEB product failure case set differs")
    return tuple(cases)


def _docker_image_id(reference: str) -> str:
    return subprocess.run(
        ["docker", "image", "inspect", reference, "--format", "{{.Id}}"],
        capture_output=True,
        check=True,
        text=True,
        timeout=30,
    ).stdout.strip()


def _source_reopen_context(context: object) -> WebZAPSourceMeasurementReopenContext:
    return WebZAPSourceMeasurementReopenContext(
        outcome=context.outcome,
        measured_case=context.measured_case,
        capability_bundle=context.capability_bundle,
        lifecycle=context.lifecycle,
        release=context.measured_case.capability_release,
        target_adapter=context.target_adapter,
        private_ground_truth_profile=context.private_profile,
        scanner_plan=context.measured_case.scanner_plan,
        scanner_registration=context.measured_case.scanner_registration,
        journal_path=context.journal_path,
        catalog_provider=context.catalog_provider,
        measurement_trust_anchor=context.measurement_anchor,
        activation_store=context.activation_store,
        distribution_bundle=context.distribution_bundle,
        distribution_trust_anchor=context.distribution_anchor,
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


def _production_boundary(
    coordinate: BenchmarkTargetCoordinate,
    *,
    claim_ledger_identity_digest: str,
    worker_image_id: str,
    proxy_image_id: str,
) -> tuple[
    SubprocessWebControlledDockerBoundaryInspector,
    DockerWorkerBackend,
    WebProxyRouteRuntimePolicy,
]:
    from pajin.benchmark.docker_provider import docker_benchmark_target_network_name

    inspector = SubprocessWebControlledDockerBoundaryInspector()
    backend = DockerWorkerBackend(
        allowed_images={_CONTROLLED_WORKER_IMAGE},
        egress_proxy_image=_EGRESS_PROXY_IMAGE,
        external_network_routes={
            "bug-bounty-sqli-probe": docker_benchmark_target_network_name(coordinate)
        },
        egress_lifecycle_observer=inspector,
    )
    policy = registered_web_proxy_route_runtime_policy(
        deployment_id=_DEPLOYMENT_ID,
        claim_ledger_identity_digest=claim_ledger_identity_digest,
        gateway_policy_id=_GATEWAY_POLICY_ID,
        gateway_policy_version=_GATEWAY_POLICY_VERSION,
        gateway_policy_digest=web_controlled_gateway_policy_digest(),
        worker_backend_id=_WORKER_BACKEND_ID,
        worker_backend_version=_WORKER_BACKEND_VERSION,
        worker_backend_digest=web_controlled_worker_backend_context_digest(backend),
        worker_image_id=worker_image_id,
        proxy_image_id=proxy_image_id,
    )
    return inspector, backend, policy


async def _start_target_attempt(
    base: RouteContext,
    *,
    source_context: object,
    coordinate: BenchmarkTargetCoordinate,
    journal: BenchmarkTargetOperationJournal,
    runtime_policy: WebProxyRouteRuntimePolicy,
    request_id: str,
) -> RouteContext:
    provider = source_context.catalog_provider
    adapter = source_context.target_adapter
    profile = source_context.concrete_provider.profile
    attempt = journal.begin_attempt(adapter, coordinate)

    reset_operation = _operation(attempt, "reset", 1)
    journal.append_intent(reset_operation)
    reset_receipt = await provider.reset(coordinate, reset_operation)
    journal.append_receipt(reset_operation, reset_receipt)
    reset_evidence = provider.evidence(reset_receipt)

    isolation_operation = _operation(attempt, "isolation", 1)
    journal.append_intent(isolation_operation)
    isolation_receipt = await provider.establish_isolation(
        coordinate,
        reset_receipt,
        isolation_operation,
    )
    journal.append_receipt(isolation_operation, isolation_receipt)
    isolation_evidence = provider.evidence(isolation_receipt)

    execution_operation = _operation(attempt, "execution", 1)
    journal.append_intent(execution_operation)
    records = journal.current_open_attempt(attempt.attempt_id)[4]
    issued_at = max(datetime.now(UTC), records[-1].occurred_at + timedelta(microseconds=1))
    request = base.request.model_copy(update={"request_id": request_id})
    context = replace(
        base,
        measured_case=source_context.measured_case,
        capability_bundle=source_context.capability_bundle,
        capability_lifecycle=source_context.lifecycle,
        capability_release=source_context.measured_case.capability_release,
        private_ground_truth_profile=source_context.private_profile,
        scanner_plan=source_context.measured_case.scanner_plan,
        scanner_registration=source_context.measured_case.scanner_registration,
        runtime_policy=runtime_policy,
        target_adapter=adapter,
        target_profile=profile,
        coordinate=coordinate,
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
        request=request,
        issued_at=issued_at,
    )
    return _with_campaign(context, _campaign(issued_at))


async def _complete_success_target(
    context: RouteContext,
    *,
    provider: object,
    worker_evidence: object,
) -> WebControlledValidationTargetLifecycle:
    execution_receipt = build_web_controlled_validation_execution_receipt(
        context.execution_operation,
        isolation_receipt=context.isolation_receipt,
        worker_evidence=worker_evidence,
    )
    context.target_journal.append_receipt(context.execution_operation, execution_receipt)
    cleanup_operation = _operation(context.attempt, "cleanup", 1)
    context.target_journal.append_intent(cleanup_operation)
    cleanup_receipt = await provider.cleanup(
        context.coordinate,
        context.isolation_receipt,
        cleanup_operation,
    )
    context.target_journal.append_receipt(cleanup_operation, cleanup_receipt)
    context.target_journal.mark_completed(context.attempt.attempt_id)
    return WebControlledValidationTargetLifecycle(
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
        workerEvidence=worker_evidence,
        cleanupOperation=cleanup_operation,
        cleanupReceipt=cleanup_receipt,
        cleanupEvidence=provider.evidence(cleanup_receipt),
    )


async def _complete_denial_target(
    context: RouteContext,
    *,
    provider: object,
) -> WebCleanupBeforeRouteDenialLifecycle:
    cleanup_operation = _operation(context.attempt, "cleanup", 1)
    context.target_journal.append_intent(cleanup_operation)
    cleanup_receipt = await provider.cleanup(
        context.coordinate,
        context.isolation_receipt,
        cleanup_operation,
    )
    context.target_journal.append_receipt(cleanup_operation, cleanup_receipt)
    context.target_journal.mark_completed(context.attempt.attempt_id)
    return WebCleanupBeforeRouteDenialLifecycle(
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
        cleanupEvidence=provider.evidence(cleanup_receipt),
    )


async def _emergency_cleanup(context: RouteContext, *, provider: object) -> None:
    operation = _operation(context.attempt, "cleanup", 10)
    with suppress(Exception):
        await provider.cleanup(context.coordinate, context.isolation_receipt, operation)


def _production_adapter(
    context: RouteContext,
    *,
    claim_ledger: WebControlledValidationRouteClaimLedger,
    evidence_store_path: Path,
    worker_image_id: str,
    proxy_image_id: str,
) -> tuple[
    DockerWebControlledValidationAdapter,
    SubprocessWebControlledDockerBoundaryInspector,
]:
    inspector, backend, policy = _production_boundary(
        context.coordinate,
        claim_ledger_identity_digest=claim_ledger.identity_digest(deployment_id=_DEPLOYMENT_ID),
        worker_image_id=worker_image_id,
        proxy_image_id=proxy_image_id,
    )
    assert policy == context.runtime_policy
    return (
        DockerWebControlledValidationAdapter(
            backend=backend,
            inspector=inspector,
            route_authority=_live_route_context(context),
            claim_ledger=claim_ledger,
            evidence_store_path=evidence_store_path,
            deployment_id=_DEPLOYMENT_ID,
            gateway_policy_id=_GATEWAY_POLICY_ID,
            gateway_policy_version=_GATEWAY_POLICY_VERSION,
            worker_backend_id=_WORKER_BACKEND_ID,
            worker_backend_version=_WORKER_BACKEND_VERSION,
        ),
        inspector,
    )


@pytest.mark.skipif(
    os.environ.get("PAJIN_TEST_DOCKER_WEB_002D") != "1",
    reason="real Docker WEB-002D controlled validation conformance is opt-in",
)
def test_real_docker_web_002d_controlled_validation_conformance(
    tmp_path: Path,
    route_context: RouteContext,
) -> None:
    target_image_id = _docker_image_id(_TARGET_IMAGE)
    benchmark_worker_image_id = _docker_image_id(_BENCHMARK_WORKER_IMAGE)
    zap_image_id = _docker_image_id(_ZAP_IMAGE)
    controlled_worker_image_id = _docker_image_id(_CONTROLLED_WORKER_IMAGE)
    proxy_image_id = _docker_image_id(_EGRESS_PROXY_IMAGE)
    profile = DockerBugBountyTargetProfile(
        targetImage=_TARGET_IMAGE,
        targetImageId=target_image_id,
        workerImage=_BENCHMARK_WORKER_IMAGE,
        workerImageId=benchmark_worker_image_id,
    )
    source_context = _run_web_source(
        tmp_path / "source",
        target_profile=profile,
        scanner_image_id=zap_image_id,
        real_docker=True,
    )
    source_authority = _reload_web_source(source_context)
    floor_policy = registered_web_benchmark_validation_floor_policy(
        source_context.measured_case,
        capability_bundle=source_context.capability_bundle,
        lifecycle=source_context.lifecycle,
        release=source_context.measured_case.capability_release,
        target_adapter=source_context.target_adapter,
        private_ground_truth_profile=source_context.private_profile,
        scanner_plan=source_context.measured_case.scanner_plan,
        scanner_registration=source_context.measured_case.scanner_registration,
    )
    mapping = bind_web_expected_finding_projection_policy(
        measured_case=source_context.measured_case,
        floor_policy=floor_policy,
        capability_bundle=source_context.capability_bundle,
        lifecycle=source_context.lifecycle,
        release=source_context.measured_case.capability_release,
        target_adapter=source_context.target_adapter,
        private_ground_truth_profile=source_context.private_profile,
        scanner_plan=source_context.measured_case.scanner_plan,
        scanner_registration=source_context.measured_case.scanner_registration,
    )
    manifest = source_context.measured_case.scanner_plan.manifest
    coordinate = benchmark_target_coordinate(
        manifest,
        arm_id=manifest.arms[0].arm_id,
        seed=7,
        repetition=1,
    )
    journal = BenchmarkTargetOperationJournal.open_existing(source_context.journal_path)
    claim_store_path = tmp_path / "route-claims.sqlite3"
    evidence_store_path = tmp_path / "worker-evidence.sqlite3"
    execution_claims = WebControlledValidationRouteClaimLedger(claim_store_path)
    _, _, runtime_policy = _production_boundary(
        coordinate,
        claim_ledger_identity_digest=execution_claims.identity_digest(deployment_id=_DEPLOYMENT_ID),
        worker_image_id=controlled_worker_image_id,
        proxy_image_id=proxy_image_id,
    )
    active: list[RouteContext] = []
    completed_attempt_ids: set[str] = set()

    async def exercise() -> tuple[object, object, object, object, object, object, object]:
        success_context = await _start_target_attempt(
            route_context,
            source_context=source_context,
            coordinate=coordinate,
            journal=journal,
            runtime_policy=runtime_policy,
            request_id="tool_web002_route_real_success",
        )
        active.append(success_context)
        success_bundle = _issue(success_context, route_nonce="d" * 32)
        execution_adapter, execution_inspector = _production_adapter(
            success_context,
            claim_ledger=execution_claims,
            evidence_store_path=evidence_store_path,
            worker_image_id=controlled_worker_image_id,
            proxy_image_id=proxy_image_id,
        )
        worker_outcome = await execution_adapter.execute(
            bundle=success_bundle,
            coordinate=coordinate,
            request=success_context.request,
        )
        success_lifecycle = await _complete_success_target(
            success_context,
            provider=source_context.catalog_provider,
            worker_evidence=worker_outcome.evidence,
        )
        completed_attempt_ids.add(success_context.attempt.attempt_id)

        denial_context = await _start_target_attempt(
            route_context,
            source_context=source_context,
            coordinate=coordinate,
            journal=journal,
            runtime_policy=runtime_policy,
            request_id="tool_web002_route_real_denial",
        )
        active.append(denial_context)
        denial_bundle = _issue(denial_context, route_nonce="e" * 32)
        denial_lifecycle = await _complete_denial_target(
            denial_context,
            provider=source_context.catalog_provider,
        )
        completed_attempt_ids.add(denial_context.attempt.attempt_id)
        denial_evidence = observe_web_cleanup_route_denial(
            floor_policy=floor_policy,
            bundle=denial_bundle,
            lifecycle=denial_lifecycle,
            route_authority=_live_route_context(denial_context),
            claim_ledger=execution_claims,
            provider=source_context.catalog_provider,
            evaluated_at=max(
                datetime.now(UTC),
                denial_lifecycle.cleanup_receipt.completed_at + timedelta(microseconds=1),
            ),
        )
        return (
            success_context,
            success_bundle,
            worker_outcome,
            success_lifecycle,
            denial_context,
            denial_evidence,
            execution_inspector,
        )

    try:
        (
            success_context,
            success_bundle,
            worker_outcome,
            success_lifecycle,
            denial_context,
            denial_evidence,
            execution_inspector,
        ) = asyncio.run(exercise())
        build_claims = WebControlledValidationRouteClaimLedger(claim_store_path)
        build_adapter, build_inspector = _production_adapter(
            success_context,
            claim_ledger=build_claims,
            evidence_store_path=evidence_store_path,
            worker_image_id=controlled_worker_image_id,
            proxy_image_id=proxy_image_id,
        )
        outcome = build_and_seal_web_controlled_validation_authority(
            tmp_path / "authority-runs",
            validation_run_id="validation-run.web002d.real-docker",
            measured_case_authority=source_context.measured_case,
            private_ground_truth_profile=source_context.private_profile,
            source_reopen_context=_source_reopen_context(source_context),
            floor_policy=floor_policy,
            mapping=mapping,
            route_bundle=success_bundle,
            route_verification=worker_outcome.verification,
            route_claim_receipt=worker_outcome.route_claim_receipt,
            target_lifecycle=success_lifecycle,
            denial_evidence=denial_evidence,
            denial_route_authority=_live_route_context(denial_context),
            trust_anchor=success_context.trust_anchor,
            claim_ledger=build_claims,
            target_journal=BenchmarkTargetOperationJournal.open_existing(
                source_context.journal_path
            ),
            provider=source_context.catalog_provider,
            adapter=build_adapter,
        )
        load_claims = WebControlledValidationRouteClaimLedger(claim_store_path)
        load_adapter, load_inspector = _production_adapter(
            success_context,
            claim_ledger=load_claims,
            evidence_store_path=evidence_store_path,
            worker_image_id=controlled_worker_image_id,
            proxy_image_id=proxy_image_id,
        )
        authority = load_web_controlled_validation_authority(
            outcome,
            measured_case_authority=source_context.measured_case,
            private_ground_truth_profile=source_context.private_profile,
            source_reopen_context=_source_reopen_context(source_context),
            floor_policy=floor_policy,
            mapping=mapping,
            trust_anchor=success_context.trust_anchor,
            claim_ledger=load_claims,
            target_journal=BenchmarkTargetOperationJournal.open_existing(
                source_context.journal_path
            ),
            provider=source_context.catalog_provider,
            adapter=load_adapter,
            denial_route_authority=_live_route_context(denial_context),
        )

        success_records = journal.completed_attempt_for_operation(
            success_lifecycle.execution_operation.operation_id
        )[3]
        denial_records = journal.completed_attempt_for_operation(
            denial_evidence.target_lifecycle.execution_operation.operation_id
        )[3]
        source_target = source_context.outcome.source_outcomes[0].target.authority
        source_cleanup = source_context.catalog_provider.evidence(source_target.cleanup_receipt)
        denial_receipt = load_web_controlled_validation_route_denial_receipt(
            ledger=load_claims,
            receipt=authority.denial_evidence.route_denial_receipt,
        )
        execution_id = authority.target_lifecycle.worker_evidence.worker_job.execution_id

        assert authority == outcome.authority
        assert authority.benchmark_validation_floor_satisfied is True
        assert authority.floor_evaluation.benchmark_validation_floor_satisfied is True
        assert authority.finding.product_finding_confirmed is True
        assert authority.finding.claim_ceiling == "benchmark-ground-truth-match"
        assert authority.finding.graph_mutation_authorized is False
        assert authority.finding.reporting_authorized is False
        assert authority.finding.external_delivery_authorized is False
        assert authority.additional_execution_authorized is False
        assert denial_receipt == authority.denial_evidence.route_denial_receipt
        assert denial_receipt.slot_digest == (
            authority.denial_evidence.route_bundle.route.statement.consumption_slot_digest
        )
        assert len(success_records) == 8
        assert len(denial_records) == 7
        assert source_authority.lineages[0].cleanup_resources_absent is True
        assert source_cleanup.resources_absent is True
        assert success_lifecycle.cleanup_evidence.resources_absent is True
        assert denial_evidence.target_lifecycle.cleanup_evidence.resources_absent is True
        assert execution_inspector.ephemeral_resources_absent(execution_id)
        assert build_inspector.ephemeral_resources_absent(execution_id)
        assert load_inspector.ephemeral_resources_absent(execution_id)

        product_reopen_context = WebMeasuredProductSourceReopenContext(
            measured_case_authority=source_context.measured_case,
            private_ground_truth_profile=source_context.private_profile,
            source_reopen_context=_source_reopen_context(source_context),
            floor_policy=floor_policy,
            mapping=mapping,
            trust_anchor=success_context.trust_anchor,
            claim_ledger=load_claims,
            target_journal=BenchmarkTargetOperationJournal.open_existing(
                source_context.journal_path
            ),
            provider=source_context.catalog_provider,
            adapter=load_adapter,
            denial_route_authority=_live_route_context(denial_context),
        )
        first_product = WebMeasuredProductFlowProjector(
            output_root=tmp_path / "first-product-runs"
        ).project(
            outcome,
            reopen_context=product_reopen_context,
        )
        second_product = WebMeasuredProductFlowProjector(
            output_root=tmp_path / "second-product-runs"
        ).project(
            outcome,
            reopen_context=product_reopen_context,
        )
        first_bytes = first_product.run_path.joinpath(first_product.artifact_path).read_bytes()
        second_bytes = second_product.run_path.joinpath(second_product.artifact_path).read_bytes()
        assert first_product.run_id != second_product.run_id
        assert first_product.projection == second_product.projection
        assert first_bytes == second_bytes
        failure_cases = _fresh_product_integrity_failure_cases(
            first_product,
            foreign=second_product,
            output_root=tmp_path / "fresh-product-integrity-failures",
        )

        first_recipe = FreshWebMeasuredProductRecipe.from_runtime(
            audit_root=tmp_path,
            process_root=tmp_path / "fresh-product-process-one",
            deployment_id=_DEPLOYMENT_ID,
            product_outcome=first_product,
            source_context=source_context,
            coordinate=coordinate,
            claim_ledger_path=claim_store_path,
            worker_evidence_store_path=evidence_store_path,
            success_route_authority=_live_route_context(success_context),
            denial_route_authority=_live_route_context(denial_context),
        )
        second_recipe = FreshWebMeasuredProductRecipe.from_runtime(
            audit_root=tmp_path,
            process_root=tmp_path / "fresh-product-process-two",
            deployment_id=_DEPLOYMENT_ID,
            product_outcome=first_product,
            source_context=source_context,
            coordinate=coordinate,
            claim_ledger_path=claim_store_path,
            worker_evidence_store_path=evidence_store_path,
            success_route_authority=_live_route_context(success_context),
            denial_route_authority=_live_route_context(denial_context),
        )
        failure_recipe = FreshWebMeasuredProductRecipe.from_runtime(
            audit_root=tmp_path,
            process_root=tmp_path / "fresh-product-process-integrity",
            deployment_id=_DEPLOYMENT_ID,
            product_outcome=first_product,
            source_context=source_context,
            coordinate=coordinate,
            claim_ledger_path=claim_store_path,
            worker_evidence_store_path=evidence_store_path,
            success_route_authority=_live_route_context(success_context),
            denial_route_authority=_live_route_context(denial_context),
            integrity_failure_cases=failure_cases,
        )
        first_probe = run_fresh_web_measured_product_probe(
            first_recipe,
            hash_seed=7,
            timeout_seconds=300,
        )
        second_probe = run_fresh_web_measured_product_probe(
            second_recipe,
            hash_seed=31,
            timeout_seconds=300,
        )
        failure_probe = run_fresh_web_measured_product_probe(
            failure_recipe,
            hash_seed=53,
            timeout_seconds=1200,
        )
        expected_base64 = base64.b64encode(first_bytes).decode("ascii")
        assert first_probe.process_id != second_probe.process_id
        assert first_probe.process_id != os.getpid()
        assert second_probe.process_id != os.getpid()
        assert failure_probe.process_id != os.getpid()
        assert first_probe.canonical_bytes_base64 == expected_base64
        assert second_probe.canonical_bytes_base64 == expected_base64
        assert failure_probe.canonical_bytes_base64 == expected_base64
        assert first_probe.result_digest == second_probe.result_digest
        assert failure_probe.result_digest == first_probe.result_digest
        assert first_probe.flow_id == second_probe.flow_id
        assert first_probe.flow_digest == second_probe.flow_digest
        assert first_probe.source_run_id == second_probe.source_run_id
        assert first_probe.source_authority_id == second_probe.source_authority_id
        assert first_probe.source_authority_digest == second_probe.source_authority_digest
        assert first_probe.docker_argv == second_probe.docker_argv
        assert first_probe.integrity_failure_case_ids == ()
        assert first_probe.integrity_failure_statuses == ()
        assert second_probe.integrity_failure_case_ids == ()
        assert second_probe.integrity_failure_statuses == ()
        expected_failure_ids = tuple(case.case_id for case in failure_cases)
        assert expected_failure_ids == _FRESH_PRODUCT_FAILURE_CASE_IDS
        assert failure_probe.integrity_failure_case_ids == expected_failure_ids
        assert failure_probe.integrity_failure_statuses == (409,) * len(
            _FRESH_PRODUCT_FAILURE_CASE_IDS
        )
        expected_once = first_probe.docker_argv[: len(first_probe.docker_argv) // 2]
        assert first_probe.docker_argv == expected_once * 2
        assert failure_probe.docker_argv == (
            first_probe.docker_argv + expected_once * len(failure_cases)
        )
        assert failure_probe.reader_calls == 2 + len(failure_cases)
        assert failure_probe.source_reload_calls == 2 + len(failure_cases)
    finally:
        for context in reversed(active):
            if context.attempt.attempt_id not in completed_attempt_ids:
                asyncio.run(
                    _emergency_cleanup(
                        context,
                        provider=source_context.catalog_provider,
                    )
                )
