from __future__ import annotations

import asyncio
import json
import os
from base64 import b64decode, b64encode
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_network_fixture_runtime import _runtime
from test_network_source_measurement import (
    _all_keys,
    _digest,
    _DockerConformanceAuthorizer,
    _InProcessBoundaryInspector,
    _StableAuthority,
)

from pajin.domain.manifest import load_manifest
from pajin.domain.models import CampaignManifest
from pajin.runtime.worker import (
    DockerEgressLifecycleObservation,
    DockerWorkerBackend,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.base import EGRESS_HTTPS_CONNECT_RECEIPT_VERSION
from pajin.workflow.network_fixture_runtime import (
    NetworkFixtureDockerProvider,
    NetworkFixtureOperationJournal,
    NetworkFixtureTargetCoordinate,
    NetworkFixtureTargetLifecycleRunner,
    NetworkSourceImageBinding,
    registered_network_source_image_binding,
)
from pajin.workflow.network_measured_case_authority import (
    NetworkMeasuredCaseMapping,
    NetworkMeasuredCaseRef,
    registered_network_measured_case_mapping,
)
from pajin.workflow.network_replay_evaluation import (
    NETWORK_REPLAY_REQUIRED_CASE_EVIDENCE_NAMES,
    NetworkPrivateReplayCaseEvaluation,
    NetworkReplayEvaluationError,
    NetworkReplayEvaluationMapping,
    NetworkReplayEvaluationOutcome,
    NetworkReplayEvaluationRunner,
    NetworkReplayFloorEvaluation,
    _build_mapping,
    _reopen_measurement_set,
    _validate_mapping,
    load_network_replay_floor_evaluation,
)
from pajin.workflow.network_source_measurement import (
    NetworkSourceApprovedAction,
    NetworkSourceMeasurementOutcome,
    NetworkSourceMeasurementRunner,
    _foreign_image_binding,
)

_PUBLIC_PRIVATE_KEYS = {
    "rawBannerBase64",
    "observedServiceName",
    "sourceIdentity",
    "replayIdentity",
    "workerResult",
    "toolResult",
    "lifecycle",
    "targetContainerId",
    "targetNetworkId",
    "workerContainerId",
    "proxyContainerId",
    "internalNetworkId",
    "requestId",
    "approvalId",
    "permitId",
    "dispatchId",
    "privateGroundTruthBindingId",
    "sourcePrivateBindingId",
    "replayPrivateBindingId",
}
_PUBLIC_FALSE_FIELDS = (
    "imageBuildAuthorized",
    "providerSelectionAuthorized",
    "callerConfigurationAuthorized",
    "replayExecutionAuthorized",
    "serviceConfirmationAuthorized",
    "graphAdmissionAuthorized",
    "graphMutationAuthorized",
    "findingAuthority",
    "productProjectionAuthorized",
    "reportingAuthorized",
    "externalDeliveryAuthorized",
    "dnsAuthorized",
    "udpAuthorized",
    "portRangeAuthorized",
    "portEnumerationAuthorized",
    "rawSocketAuthorized",
    "applicationProtocolWriteAuthorized",
    "credentialAccessAuthorized",
    "externalTargetAuthorized",
    "productionTargetAuthorized",
    "generalScannerAuthorized",
    "permitIssuanceAuthorized",
    "additionalExecutionAuthorized",
)


@dataclass(frozen=True)
class _ReplayContext:
    root: Path
    measured: NetworkMeasuredCaseMapping
    images: NetworkSourceImageBinding
    provider: NetworkFixtureDockerProvider
    lifecycle: NetworkFixtureTargetLifecycleRunner
    authorizer: _DockerConformanceAuthorizer
    source: NetworkSourceMeasurementOutcome
    outcome: NetworkReplayEvaluationOutcome
    inspectors: tuple[_InProcessBoundaryInspector, ...]


async def _run_in_process_worker(
    backend: DockerWorkerBackend,
    job,
    *,
    private_by_case,
    secrets=None,
) -> WorkerResult:
    del secrets
    observer = backend._egress_lifecycle_observer
    assert isinstance(observer, _InProcessBoundaryInspector)
    identity = _digest(job.execution_id)[:16]
    observation = DockerEgressLifecycleObservation(
        execution_id=job.execution_id,
        worker_container_name=backend._container_name(job.execution_id),
        proxy_container_name=f"pajin-proxy-{identity}",
        internal_network_name=f"pajin-egress-{identity}",
        external_network_name=observer.coordinate.target_network_name,
    )
    await observer.attached(observation)
    payload = json.loads(job.stdin)
    ground_truth = private_by_case[observer.coordinate.case.case_id]
    banner = b64decode(ground_truth.fixture.banner_base64)
    output: dict[str, object] = {
        "target": payload["target"],
        "addressFamily": payload["addressFamily"],
        "host": payload["host"],
        "transportProtocol": payload["transportProtocol"],
        "port": payload["port"],
        "protocolProfile": payload["protocolProfile"],
        "connected": True,
        "bannerBytes": len(banner),
        "bannerBase64": b64encode(banner).decode("ascii"),
        "bannerSha256": sha256(banner).hexdigest(),
    }
    if ground_truth.fixture.expected_service_name is not None:
        output["serviceName"] = ground_truth.fixture.expected_service_name
    authority = f"{payload['host']}:{payload['port']}"
    network_log = "\n".join(
        (
            json.dumps({"event": "ready", "port": 8080}),
            json.dumps(
                {
                    "event": "allow",
                    "receiptVersion": EGRESS_HTTPS_CONNECT_RECEIPT_VERSION,
                    "sequence": 1,
                    "method": "CONNECT",
                    "authority": authority,
                    "authoritySha256": sha256(authority.encode()).hexdigest(),
                    "address": payload["host"],
                    "applicationVisibility": "opaque",
                    "methodEnforcement": "trusted-worker-only",
                    "pathEnforcement": "authority-only",
                }
            ),
        )
    )
    await observer.cleaned(observation)
    now = datetime.now(UTC)
    return WorkerResult(
        execution_id=job.execution_id,
        backend="docker",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        stdout=json.dumps(output, separators=(",", ":")),
        network_log=network_log,
        started_at=now,
        finished_at=now + timedelta(milliseconds=1),
    )


@pytest.fixture(scope="module")
def network_replay_context(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[_ReplayContext]:
    root = tmp_path_factory.mktemp("net002c")
    campaign = load_manifest(Path("examples/ai-redteam.yaml"))
    docker, provider, images = _runtime()
    measured = registered_network_measured_case_mapping()
    private_by_case = {item.case_id: item for item in measured.private_binding.cases}
    inspectors: list[_InProcessBoundaryInspector] = []
    patch = pytest.MonkeyPatch()

    def boundary_inspector(
        *,
        coordinate: NetworkFixtureTargetCoordinate,
        images: NetworkSourceImageBinding,
    ) -> _InProcessBoundaryInspector:
        inspector = _InProcessBoundaryInspector(
            coordinate=coordinate,
            images=images,
            docker=docker,
        )
        inspectors.append(inspector)
        return inspector

    async def run_worker(
        backend: DockerWorkerBackend,
        job,
        *,
        secrets=None,
    ) -> WorkerResult:
        return await _run_in_process_worker(
            backend,
            job,
            private_by_case=private_by_case,
            secrets=secrets,
        )

    patch.setattr(provider, "boundary_inspector", boundary_inspector)
    patch.setattr(DockerWorkerBackend, "run", run_worker)
    lifecycle = NetworkFixtureTargetLifecycleRunner(
        provider=provider,
        journal=NetworkFixtureOperationJournal(root / "journal.sqlite3"),
    )
    authorizer = _DockerConformanceAuthorizer(root / "plans", campaign)

    async def execute() -> tuple[
        NetworkSourceMeasurementOutcome,
        NetworkReplayEvaluationOutcome,
    ]:
        source = await NetworkSourceMeasurementRunner(
            measured_cases=measured,
            images=images,
            lifecycle=lifecycle,
            authorizer=authorizer,
            source_runs_root=root / "source-runs",
            authority_runs_root=root / "source-authority-runs",
        ).run()
        outcome = await NetworkReplayEvaluationRunner(
            source=source,
            measured_cases=measured,
            images=images,
            lifecycle=lifecycle,
            authorizer=authorizer,
            replay_source_runs_root=root / "replay-runs",
            replay_measurement_runs_root=root / "replay-authority-runs",
            evaluation_runs_root=root / "evaluation-runs",
        ).run()
        return source, outcome

    try:
        source, outcome = asyncio.run(execute())
        reopened = load_network_replay_floor_evaluation(
            outcome,
            measured_cases=measured,
            provider=provider,
        )
        assert reopened == outcome.mapping.public_evaluation
        yield _ReplayContext(
            root=root,
            measured=measured,
            images=images,
            provider=provider,
            lifecycle=lifecycle,
            authorizer=authorizer,
            source=source,
            outcome=outcome,
            inspectors=tuple(inspectors),
        )
    finally:
        patch.undo()


def test_full_twelve_execution_replay_floor_is_exact_and_reopenable(
    network_replay_context: _ReplayContext,
) -> None:
    context = network_replay_context
    outcome = context.outcome
    public = outcome.mapping.public_evaluation
    private = outcome.mapping.private_binding
    reopened = load_network_replay_floor_evaluation(
        outcome,
        measured_cases=context.measured,
        provider=context.provider,
    )

    assert reopened == public
    assert public.source_measurement == context.source.mapping.public_authority.reference()
    assert public.replay_measurement == outcome.replay.mapping.public_authority.reference()
    assert public.source_measurement != public.replay_measurement
    assert len(context.inspectors) == 12
    assert all(item.observation is not None for item in context.inspectors)
    assert all(item.topology is not None for item in context.inspectors)
    assert context.provider.managed_resources_absent()
    assert tuple(item.case.case_id for item in public.cases) == (
        "network-fixture:ftp-known-positive",
        "network-fixture:imap-known-positive",
        "network-fixture:pop3-known-positive",
        "network-fixture:smtp-known-positive",
        "network-fixture:ssh-known-positive",
        "network-fixture:unknown-negative-control",
    )
    assert tuple(item.comparison_state for item in public.cases) == (
        "synthetic-known-positive-matched",
        "synthetic-known-positive-matched",
        "synthetic-known-positive-matched",
        "synthetic-known-positive-matched",
        "synthetic-known-positive-matched",
        "synthetic-negative-control-unresolved",
    )
    assert all(item.replay_succeeded for item in public.cases)
    assert all(item.source_replay_identity_disjoint for item in public.cases)
    assert all(
        item.source_measurement.lifecycle.cleanup.resources_absent
        and item.replay_measurement.lifecycle.cleanup.resources_absent
        for item in private.cases
    )
    source_values = {
        value for item in private.cases for value in item.source_identity.dynamic_values()
    }
    replay_values = {
        value for item in private.cases for value in item.replay_identity.dynamic_values()
    }
    assert source_values.isdisjoint(replay_values)

    metrics = {item.metric.metric_id: item for item in public.observations}
    assert tuple(metrics) == (
        "common.ground-truth-coverage",
        "common.detection-recall",
        "common.task-success-rate",
        "common.false-positive-rate",
        "common.detection-precision",
        "common.replay-or-reanalysis-success-rate",
        "common.time-to-first-valid-result",
        "common.total-request-units",
        "common.total-tool-calls",
        "common.total-cost-usd",
        "common.evidence-completeness",
        "common.policy-denial-correctness",
        "common.cleanup-success-rate",
        "network.service-identification-accuracy",
    )
    assert (
        metrics["common.ground-truth-coverage"].numerator,
        metrics["common.ground-truth-coverage"].denominator,
    ) == (6, 6)
    assert (
        metrics["common.detection-recall"].numerator,
        metrics["common.detection-recall"].denominator,
    ) == (5, 5)
    assert (
        metrics["common.false-positive-rate"].numerator,
        metrics["common.false-positive-rate"].denominator,
    ) == (0, 1)
    assert (
        metrics["common.detection-precision"].numerator,
        metrics["common.detection-precision"].denominator,
    ) == (5, 5)
    assert (
        metrics["common.replay-or-reanalysis-success-rate"].numerator,
        metrics["common.replay-or-reanalysis-success-rate"].denominator,
    ) == (6, 6)
    assert (
        metrics["common.total-request-units"].numerator,
        metrics["common.total-request-units"].denominator,
    ) == (12, 1)
    assert (
        metrics["common.total-tool-calls"].numerator,
        metrics["common.total-tool-calls"].denominator,
    ) == (12, 1)
    assert (
        metrics["common.evidence-completeness"].numerator,
        metrics["common.evidence-completeness"].denominator,
    ) == (
        12 * len(NETWORK_REPLAY_REQUIRED_CASE_EVIDENCE_NAMES),
        12 * len(NETWORK_REPLAY_REQUIRED_CASE_EVIDENCE_NAMES),
    )
    assert (
        metrics["common.policy-denial-correctness"].numerator,
        metrics["common.policy-denial-correctness"].denominator,
    ) == (5, 5)
    assert (
        metrics["network.service-identification-accuracy"].numerator,
        metrics["network.service-identification-accuracy"].denominator,
    ) == (6, 6)
    assert metrics["common.time-to-first-valid-result"].numerator == 1_000
    assert metrics["common.time-to-first-valid-result"].denominator == 1_000_000
    assert {
        metric_id: item.not_applicable_reason.value
        for metric_id, item in metrics.items()
        if item.applicability.value == "not-applicable"
    } == {
        "common.task-success-rate": "detection-recall-is-primary-outcome",
        "common.total-cost-usd": "no-monetary-cost-model",
        "common.cleanup-success-rate": "read-only-no-cleanup-required",
    }


def test_public_floor_is_private_safe_and_grants_no_follow_on_authority(
    network_replay_context: _ReplayContext,
) -> None:
    public = network_replay_context.outcome.mapping.public_evaluation
    payload = public.model_dump(mode="json", by_alias=True)
    keys = _all_keys(payload)

    assert not keys.intersection(_PUBLIC_PRIVATE_KEYS)
    assert all(payload[field] is False for field in _PUBLIC_FALSE_FIELDS)
    assert payload["syntheticBenchmarkOnly"] is True
    assert payload["validationFloorSatisfied"] is True
    assert payload["cases"][-1]["comparisonState"] == ("synthetic-negative-control-unresolved")
    assert "ftp" not in json.dumps(payload["cases"][-1], sort_keys=True)
    assert public.required_case_evidence_names == NETWORK_REPLAY_REQUIRED_CASE_EVIDENCE_NAMES


def test_wire_rejects_order_metric_digest_identity_and_unknown_substitution(
    network_replay_context: _ReplayContext,
) -> None:
    mapping = network_replay_context.outcome.mapping
    public_payload = mapping.public_evaluation.model_dump(mode="json", by_alias=True)
    public_payload["evaluationId"] = ""
    public_payload["evaluationDigest"] = ""
    public_payload["cases"][0], public_payload["cases"][1] = (
        public_payload["cases"][1],
        public_payload["cases"][0],
    )
    with pytest.raises(ValidationError, match="membership"):
        NetworkReplayFloorEvaluation.model_validate_json(json.dumps(public_payload))

    metric_payload = mapping.public_evaluation.model_dump(mode="json", by_alias=True)
    metric_payload["evaluationId"] = ""
    metric_payload["evaluationDigest"] = ""
    metric_payload["observations"][0]["numerator"] = 7
    with pytest.raises(ValidationError, match="fixed metric rational"):
        NetworkReplayFloorEvaluation.model_validate_json(json.dumps(metric_payload))

    private_case = mapping.private_binding.cases[0]
    identity_payload = private_case.model_dump(mode="json", by_alias=True)
    identity_payload["evaluationDigest"] = ""
    identity_payload["replayIdentity"] = identity_payload["sourceIdentity"]
    with pytest.raises(ValidationError, match="comparison differs"):
        NetworkPrivateReplayCaseEvaluation.model_validate_json(json.dumps(identity_payload))

    unknown = mapping.private_binding.cases[-1]
    unknown_payload = unknown.model_dump(mode="json", by_alias=True)
    unknown_payload["evaluationDigest"] = ""
    unknown_payload["replayMeasurement"]["caseMeasurementDigest"] = ""
    unknown_payload["replayMeasurement"]["observedServiceName"] = "ftp"
    unknown_payload["replayMeasurement"]["toolResult"]["data"]["serviceName"] = "ftp"
    with pytest.raises(ValidationError):
        NetworkPrivateReplayCaseEvaluation.model_validate_json(json.dumps(unknown_payload))


def test_reused_source_set_never_becomes_replay_or_floor(
    network_replay_context: _ReplayContext,
) -> None:
    context = network_replay_context
    source_public, source_private, source_cases = _reopen_measurement_set(
        context.source,
        measured_cases=context.measured,
        provider=context.provider,
    )
    with pytest.raises(NetworkReplayEvaluationError, match="identities overlap"):
        _build_mapping(
            measured_authority=context.measured.public_authority,
            private_ground_truth=context.measured.private_binding,
            source_public=source_public,
            source_private=source_private,
            source_cases=source_cases,
            replay_public=source_public,
            replay_private=source_private,
            replay_cases=source_cases,
        )


class _ChangedAuthority:
    def stable_authority_context(self) -> Mapping[str, object]:
        context = dict(_StableAuthority().stable_authority_context())
        context["authorityVersion"] = "2.0.0"
        return context

    def authorize(
        self,
        *,
        case: NetworkMeasuredCaseRef,
        target: NetworkFixtureTargetCoordinate,
        run_id: str,
        request_id: str,
    ) -> NetworkSourceApprovedAction:
        del case, target, run_id, request_id
        raise AssertionError("foreign authority must fail before execution")


def test_foreign_image_and_authorizer_fail_before_replay(
    network_replay_context: _ReplayContext,
) -> None:
    context = network_replay_context
    common = {
        "source": context.source,
        "measured_cases": context.measured,
        "lifecycle": context.lifecycle,
        "replay_source_runs_root": context.root / "forbidden-replay-runs",
        "replay_measurement_runs_root": context.root / "forbidden-replay-authority",
        "evaluation_runs_root": context.root / "forbidden-evaluation",
    }
    with pytest.raises(NetworkReplayEvaluationError, match="image"):
        NetworkReplayEvaluationRunner(
            **common,
            images=_foreign_image_binding(context.images),
            authorizer=context.authorizer,
        )
    with pytest.raises(NetworkReplayEvaluationError, match="authority"):
        NetworkReplayEvaluationRunner(
            **common,
            images=context.images,
            authorizer=_ChangedAuthority(),
        )
    assert not (context.root / "forbidden-replay-runs").exists()
    assert context.provider.managed_resources_absent()


def test_nested_hidden_state_and_mapping_substitution_fail_closed(
    network_replay_context: _ReplayContext,
) -> None:
    context = network_replay_context
    mapping = context.outcome.mapping
    smuggled_case = mapping.public_evaluation.cases[0].model_copy(deep=True)
    smuggled_case.__dict__["privateLabel"] = "ftp"
    with pytest.raises(
        (NetworkReplayEvaluationError, ValidationError),
        match="unmodeled instance state",
    ):
        NetworkReplayFloorEvaluation(
            **mapping.public_evaluation.model_dump(
                mode="python",
                by_alias=True,
                exclude={"cases", "evaluation_id", "evaluation_digest"},
            ),
            cases=(smuggled_case, *mapping.public_evaluation.cases[1:]),
        )

    substituted = NetworkReplayEvaluationMapping(
        public_evaluation=mapping.public_evaluation,
        private_binding=context.outcome.mapping.private_binding.model_copy(
            update={
                "source_private_binding_digest": (
                    "0" * 64
                    if mapping.private_binding.source_private_binding_digest != "0" * 64
                    else "f" * 64
                )
            }
        ),
    )
    with pytest.raises(NetworkReplayEvaluationError):
        _validate_mapping(
            substituted,
            measured_authority=context.measured.public_authority,
            private_ground_truth=context.measured.private_binding,
            source_public=context.source.mapping.public_authority,
            source_private=context.source.mapping.private_binding,
            replay_public=context.outcome.replay.mapping.public_authority,
            replay_private=context.outcome.replay.mapping.private_binding,
        )


@pytest.mark.asyncio
async def test_real_docker_source_and_replay_floor_is_opt_in(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    if os.environ.get("PAJIN_NETWORK_002C_REAL_DOCKER") != "1":
        pytest.skip("set PAJIN_NETWORK_002C_REAL_DOCKER=1 with the three fixed images")
    provider = NetworkFixtureDockerProvider()
    images = registered_network_source_image_binding(provider)
    measured = registered_network_measured_case_mapping()
    lifecycle = NetworkFixtureTargetLifecycleRunner(
        provider=provider,
        journal=NetworkFixtureOperationJournal(tmp_path / "docker-journal.sqlite3"),
    )
    authorizer = _DockerConformanceAuthorizer(tmp_path / "plans", sample_campaign)
    source = await NetworkSourceMeasurementRunner(
        measured_cases=measured,
        images=images,
        lifecycle=lifecycle,
        authorizer=authorizer,
        source_runs_root=tmp_path / "source-runs",
        authority_runs_root=tmp_path / "source-authority-runs",
    ).run()
    outcome = await NetworkReplayEvaluationRunner(
        source=source,
        measured_cases=measured,
        images=images,
        lifecycle=lifecycle,
        authorizer=authorizer,
        replay_source_runs_root=tmp_path / "replay-runs",
        replay_measurement_runs_root=tmp_path / "replay-authority-runs",
        evaluation_runs_root=tmp_path / "evaluation-runs",
    ).run()
    reopened = load_network_replay_floor_evaluation(
        outcome,
        measured_cases=measured,
        provider=provider,
    )
    assert reopened == outcome.mapping.public_evaluation
    assert len(outcome.source.executions) + len(outcome.replay.executions) == 12
    assert provider.managed_resources_absent()
