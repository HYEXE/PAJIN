from __future__ import annotations

import asyncio
import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest

from pajin.runtime.worker import (
    DockerEgressLifecycleObservation,
    DockerWorkerBackend,
    WorkerJob,
    WorkerResult,
)
from pajin.workflow.web_controlled_validation_route import (
    WebControlledValidationRouteClaimLedger,
    WebControlledValidationRouteClaimReceipt,
)
from pajin.workflow.web_controlled_validation_runtime import (
    DockerWebControlledValidationAdapter,
    SubprocessWebControlledDockerBoundaryInspector,
    WebControlledProxyTopologyObservation,
    WebControlledTargetBoundaryObservation,
    WebControlledValidationRuntimeError,
    WebControlledValidationWorkerEvidence,
    _build_worker_evidence_record,
    _WebControlledValidationWorkerEvidenceStore,
    require_production_web_controlled_validation_adapter,
    web_controlled_gateway_policy_digest,
    web_controlled_worker_backend_context_digest,
)
from pajin.workflow.web_proxy_route_authority import (
    WebProxyRouteBundle,
    WebProxyRouteLiveAuthorityContext,
    WebProxyRouteVerification,
    registered_web_proxy_route_runtime_policy,
)
from tests.test_bug_bounty_runtime import (
    ContractBugBountyWorker,
    _proxy_receipt_log,
)
from tests.test_web_proxy_route_authority import (
    RouteContext,
    _issue,
)

pytest_plugins = ("tests.test_web_proxy_route_authority",)


class _FakeBoundaryInspector:
    def __init__(self, context: RouteContext, *, wrong_worker_image: bool = False) -> None:
        self.context = context
        self.wrong_worker_image = wrong_worker_image
        self.observer_version = "1.0.0"
        self.execution_ids: list[str] = []
        self.attached_observation: DockerEgressLifecycleObservation | None = None
        self.attached_at: datetime | None = None
        self.target_before_at: datetime | None = None
        self.completed_topology: WebControlledProxyTopologyObservation | None = None

    def stable_observer_context(self) -> dict[str, object]:
        return {
            "observerId": "test.web-controlled-boundary",
            "observerVersion": self.observer_version,
        }

    async def attached(self, observation: DockerEgressLifecycleObservation) -> None:
        self.attached_observation = observation
        self.attached_at = datetime.now(UTC)

    async def cleaned(self, observation: DockerEgressLifecycleObservation) -> None:
        assert observation == self.attached_observation
        assert self.attached_at is not None
        detached_at = datetime.now(UTC)
        self.completed_topology = WebControlledProxyTopologyObservation(
            executionId=observation.execution_id,
            workerContainerName=observation.worker_container_name,
            workerContainerId="d" * 64,
            workerImageId="sha256:" + "b" * 64,
            proxyContainerName=observation.proxy_container_name,
            proxyContainerId="e" * 64,
            proxyImageId="sha256:" + "c" * 64,
            internalNetworkName=observation.internal_network_name,
            internalNetworkId="f" * 64,
            targetNetworkName=observation.external_network_name,
            targetNetworkId=self.context.isolation_evidence.network_id,
            targetContainerId=self.context.isolation_evidence.target_container_id,
            targetImageId=self.context.isolation_evidence.target_image_id,
            workerNetworkIds=("f" * 64,),
            proxyNetworkIds=("8" * 64, "f" * 64),
            targetNetworkIds=("8" * 64,),
            attachedAt=self.attached_at,
            proxyDetachedAt=detached_at,
            resourcesAbsentAt=datetime.now(UTC),
        )

    def topology_observation(
        self,
        execution_id: str,
    ) -> WebControlledProxyTopologyObservation:
        assert self.completed_topology is not None
        assert self.completed_topology.execution_id == execution_id
        return self.completed_topology

    def image_id(self, reference: str) -> str:
        if reference == "pajin-worker:dev":
            return "sha256:" + ("f" if self.wrong_worker_image else "b") * 64
        if reference == "pajin-egress-proxy:dev":
            return "sha256:" + "c" * 64
        raise AssertionError(reference)

    def observe_target(
        self,
        *,
        network_name: str,
        expected_network_id: str,
        expected_target_container_id: str,
        expected_target_image_id: str,
    ) -> WebControlledTargetBoundaryObservation:
        assert network_name.startswith("pajin-bench-")
        observed_at = datetime.now(UTC)
        if self.target_before_at is None:
            self.target_before_at = observed_at
        return WebControlledTargetBoundaryObservation(
            targetNetworkDigest=sha256(network_name.encode()).hexdigest(),
            targetNetworkId=expected_network_id,
            targetContainerId=expected_target_container_id,
            targetImageId=expected_target_image_id,
            observedAt=observed_at,
        )

    def ephemeral_resources_absent(self, execution_id: str) -> bool:
        self.execution_ids.append(execution_id)
        return True


def _backend(
    context: RouteContext,
    worker: ContractBugBountyWorker,
    inspector: _FakeBoundaryInspector,
) -> DockerWorkerBackend:
    network = f"pajin-bench-{context.coordinate.coordinate_digest[:24]}-net"
    backend = DockerWorkerBackend(
        allowed_images={"pajin-worker:dev"},
        egress_proxy_image="pajin-egress-proxy:dev",
        external_network_routes={"bug-bounty-sqli-probe": network},
        egress_lifecycle_observer=inspector,
    )

    async def run(
        job: WorkerJob,
        *,
        secrets: object = None,
    ) -> WorkerResult:
        del secrets
        observation = DockerEgressLifecycleObservation(
            execution_id=job.execution_id,
            worker_container_name=backend._container_name(job.execution_id),
            proxy_container_name="pajin-proxy-test",
            internal_network_name="pajin-egress-test",
            external_network_name=network,
        )
        await inspector.attached(observation)
        result = await worker.run(job)
        output = json.loads(result.stdout)
        output["vulnerable"] = True
        output["checks"] = {
            "baselineSingleRecord": True,
            "negativeControlEmpty": True,
            "booleanProbeExpanded": True,
            "syntheticLabOnly": True,
        }
        result = result.model_copy(update={"stdout": json.dumps(output, separators=(",", ":"))})
        assert inspector.attached_at is not None
        assert inspector.target_before_at is not None
        result = result.model_copy(
            update={
                "backend": "docker",
                "network_log": _proxy_receipt_log(job, result),
                "started_at": inspector.target_before_at,
            }
        )
        await inspector.cleaned(observation)
        return result

    backend.run = run  # type: ignore[method-assign]
    return backend


def _runtime_context(
    context: RouteContext,
    backend: DockerWorkerBackend,
    *,
    claim_ledger: WebControlledValidationRouteClaimLedger,
) -> RouteContext:
    policy = registered_web_proxy_route_runtime_policy(
        deployment_id="deployment.web002",
        gateway_policy_id="gateway-policy.web002.controlled",
        gateway_policy_version="1.0.0",
        gateway_policy_digest=web_controlled_gateway_policy_digest(),
        worker_backend_id="docker-worker-backend.web002",
        worker_backend_version="1.0.0",
        worker_backend_digest=web_controlled_worker_backend_context_digest(backend),
        claim_ledger_identity_digest=claim_ledger.identity_digest(
            deployment_id="deployment.web002"
        ),
        worker_image_id="sha256:" + "b" * 64,
        proxy_image_id="sha256:" + "c" * 64,
    )
    return replace(context, runtime_policy=policy)


def _live_route_authority(context: RouteContext) -> WebProxyRouteLiveAuthorityContext:
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


async def _execute(
    context: RouteContext,
    *,
    tmp_path: Path,
    wrong_worker_image: bool = False,
):
    worker = ContractBugBountyWorker()
    inspector = _FakeBoundaryInspector(context, wrong_worker_image=wrong_worker_image)
    backend = _backend(context, worker, inspector)
    claim_ledger = WebControlledValidationRouteClaimLedger(tmp_path / "route-claims.sqlite3")
    context = _runtime_context(context, backend, claim_ledger=claim_ledger)
    bundle = _issue(context)
    adapter = DockerWebControlledValidationAdapter._for_test(
        backend=backend,
        inspector=inspector,
        route_authority=_live_route_authority(context),
        claim_ledger=claim_ledger,
        deployment_id="deployment.web002",
        gateway_policy_id="gateway-policy.web002.controlled",
        gateway_policy_version="1.0.0",
        worker_backend_id="docker-worker-backend.web002",
        worker_backend_version="1.0.0",
        evaluated_at=context.issued_at + timedelta(seconds=31),
    )
    outcome = await adapter.execute(
        bundle=bundle,
        coordinate=context.coordinate,
        request=context.request,
    )
    return outcome, worker, inspector, adapter, bundle, context


def test_web_002d_worker_uses_only_exact_proxy_route_and_seals_receipts(
    route_context: RouteContext,
    tmp_path: Path,
) -> None:
    outcome, worker, inspector, _, bundle, _ = asyncio.run(
        _execute(route_context, tmp_path=tmp_path)
    )
    evidence = outcome.evidence

    assert len(worker.jobs) == 1
    assert len(inspector.execution_ids) == 2
    assert inspector.execution_ids[0] == inspector.execution_ids[1]
    assert evidence.worker_job.network.value == "egress-proxy"
    assert evidence.worker_job.egress_policy is not None
    assert evidence.worker_job.egress_policy.max_requests == 3
    assert evidence.worker_job.egress_policy.allowed_methods == {"GET"}
    assert len(evidence.host_http_receipt_digests) == 3
    assert [item.stage for item in evidence.bridge_receipts] == [
        "target-boundary-before",
        "proxy-bridge-attached",
        "proxy-bridge-detached",
        "ephemeral-resources-absent",
    ]
    assert evidence.route_consumed is True
    assert evidence.worker_proxy_only is True
    assert evidence.ephemeral_resources_absent is True
    assert evidence.graph_write_authorized is False
    assert evidence.report_delivery_authorized is False
    assert outcome.production_boundary_verified is False
    assert outcome.verification.route_digest == bundle.route.statement.route_digest
    assert outcome.route_claim_receipt.route_digest == bundle.route.statement.route_digest


def test_web_002d_test_adapter_cannot_reopen_worker_evidence(
    route_context: RouteContext,
    tmp_path: Path,
) -> None:
    outcome, _, _, adapter, bundle, context = asyncio.run(
        _execute(route_context, tmp_path=tmp_path)
    )

    with pytest.raises(
        WebControlledValidationRuntimeError,
        match="production adapter boundary",
    ):
        adapter.reopen_worker_evidence(
            outcome.evidence,
            bundle=bundle,
            verification=outcome.verification,
            route_claim_receipt=outcome.route_claim_receipt,
            coordinate=context.coordinate,
        )


def test_web_002d_worker_evidence_store_is_exact_and_append_only(
    route_context: RouteContext,
    tmp_path: Path,
) -> None:
    outcome, _, inspector, _, _, _ = asyncio.run(_execute(route_context, tmp_path=tmp_path))
    evidence = outcome.evidence
    record = _build_worker_evidence_record(evidence, inspector=inspector)
    path = tmp_path / "worker-evidence.sqlite3"
    store = _WebControlledValidationWorkerEvidenceStore(path)

    assert store.append(record=record, evidence=evidence) == record
    assert store.append(record=record, evidence=evidence) == record
    assert store.load(evidence.evidence_digest) == (record, evidence)

    inspector.observer_version = "2.0.0"
    with pytest.raises(
        WebControlledValidationRuntimeError,
        match="durable identity was reused",
    ):
        store.append(
            record=_build_worker_evidence_record(evidence, inspector=inspector),
            evidence=evidence,
        )

    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE web_controlled_worker_evidence SET record_json = '{}'")
        connection.rollback()
        connection.execute("DROP TRIGGER web_controlled_worker_evidence_no_update")
        connection.execute(
            """
            CREATE TRIGGER web_controlled_worker_evidence_no_update
            BEFORE UPDATE ON web_controlled_worker_evidence
            WHEN OLD.record_digest != NEW.record_digest
            BEGIN SELECT RAISE(ABORT, 'WEB controlled Worker Evidence is append-only'); END
            """
        )

    with pytest.raises(
        WebControlledValidationRuntimeError,
        match="append-only guard definitions differ",
    ):
        store.load(evidence.evidence_digest)

    schema_path = tmp_path / "worker-evidence-schema.sqlite3"
    schema_store = _WebControlledValidationWorkerEvidenceStore(schema_path)
    with sqlite3.connect(schema_path) as connection:
        connection.execute("PRAGMA writable_schema = ON")
        connection.execute(
            """
            UPDATE sqlite_master
            SET sql = replace(
                sql,
                'backend_context_digest TEXT NOT NULL',
                'backend_context_digest TEXT'
            )
            WHERE type = 'table' AND name = 'web_controlled_worker_evidence'
            """
        )
        connection.execute("PRAGMA writable_schema = OFF")
    with pytest.raises(
        WebControlledValidationRuntimeError,
        match="store table contract differs",
    ):
        schema_store.load("0" * 64)


def test_web_002d_existing_worker_evidence_store_never_repairs_missing_contract(
    tmp_path: Path,
) -> None:
    trigger_path = tmp_path / "worker-evidence-missing-trigger.sqlite3"
    _WebControlledValidationWorkerEvidenceStore(trigger_path)
    _WebControlledValidationWorkerEvidenceStore(trigger_path)
    with sqlite3.connect(trigger_path) as connection:
        connection.execute("DROP TRIGGER web_controlled_worker_evidence_no_update")

    with pytest.raises(
        WebControlledValidationRuntimeError,
        match="append-only guards differ",
    ):
        _WebControlledValidationWorkerEvidenceStore(trigger_path)

    with sqlite3.connect(trigger_path) as connection:
        trigger_names = {
            str(row[0])
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'trigger'
                  AND tbl_name = 'web_controlled_worker_evidence'
                """
            ).fetchall()
        }
    assert "web_controlled_worker_evidence_no_update" not in trigger_names

    table_path = tmp_path / "worker-evidence-missing-table.sqlite3"
    _WebControlledValidationWorkerEvidenceStore(table_path)
    with sqlite3.connect(table_path) as connection:
        connection.execute("DROP TABLE web_controlled_worker_evidence")

    with pytest.raises(
        WebControlledValidationRuntimeError,
        match="store table contract differs",
    ):
        _WebControlledValidationWorkerEvidenceStore(table_path)

    with sqlite3.connect(table_path) as connection:
        table = connection.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'web_controlled_worker_evidence'
            """
        ).fetchone()
    assert table is None


def test_web_002d_production_adapter_rejects_class_shadow_and_state_drift(
    route_context: RouteContext,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network_name = f"pajin-bench-{route_context.coordinate.coordinate_digest[:24]}-net"
    inspector = SubprocessWebControlledDockerBoundaryInspector()
    backend = DockerWorkerBackend(
        allowed_images={"pajin-worker:dev"},
        egress_proxy_image="pajin-egress-proxy:dev",
        external_network_routes={"bug-bounty-sqli-probe": network_name},
        egress_lifecycle_observer=inspector,
    )
    ledger = WebControlledValidationRouteClaimLedger(tmp_path / "production-custody-claims.sqlite3")
    context = _runtime_context(route_context, backend, claim_ledger=ledger)
    bundle = _issue(context)

    def build_adapter(evidence_store_name: str) -> DockerWebControlledValidationAdapter:
        return DockerWebControlledValidationAdapter(
            backend=backend,
            inspector=inspector,
            route_authority=_live_route_authority(context),
            claim_ledger=ledger,
            evidence_store_path=tmp_path / evidence_store_name,
            deployment_id="deployment.web002",
            gateway_policy_id="gateway-policy.web002.controlled",
            gateway_policy_version="1.0.0",
            worker_backend_id="docker-worker-backend.web002",
            worker_backend_version="1.0.0",
        )

    adapter = build_adapter("production-custody-evidence.sqlite3")
    require_production_web_controlled_validation_adapter(adapter)

    with monkeypatch.context() as patch:
        patch.setattr(
            SubprocessWebControlledDockerBoundaryInspector,
            "image_id",
            lambda _inspector, _reference: "sha256:" + "b" * 64,
        )
        with pytest.raises(WebControlledValidationRuntimeError, match="shadowed"):
            build_adapter("constructor-shadow-evidence.sqlite3")

    async def forged_run(
        _backend: DockerWorkerBackend,
        _job: WorkerJob,
        *,
        secrets: object = None,
    ) -> WorkerResult:
        raise AssertionError(f"shadowed Docker run must not execute: {secrets!r}")

    with monkeypatch.context() as patch:
        patch.setattr(DockerWorkerBackend, "run", forged_run)
        with pytest.raises(WebControlledValidationRuntimeError, match="shadowed"):
            asyncio.run(
                adapter.execute(
                    bundle=bundle,
                    coordinate=context.coordinate,
                    request=context.request,
                )
            )
        ledger.require_unclaimed(
            slot_digest=bundle.route.statement.consumption_slot_digest,
            route_digest=bundle.route.statement.route_digest,
        )

    evidence_store = object.__getattribute__(adapter, "_evidence_store")

    def unexpected_store_read(_evidence_digest: str) -> object:
        raise AssertionError("Worker Evidence store was read before custody verification")

    with monkeypatch.context() as patch:
        patch.setattr(evidence_store, "load", unexpected_store_read)
        patch.setattr(
            SubprocessWebControlledDockerBoundaryInspector,
            "ephemeral_resources_absent",
            lambda _inspector, _execution_id: True,
        )
        with pytest.raises(WebControlledValidationRuntimeError, match="shadowed"):
            adapter.reopen_worker_evidence(
                cast(WebControlledValidationWorkerEvidence, object()),
                bundle=bundle,
                verification=cast(WebProxyRouteVerification, object()),
                route_claim_receipt=cast(
                    WebControlledValidationRouteClaimReceipt,
                    object(),
                ),
                coordinate=context.coordinate,
            )

    with monkeypatch.context() as patch:
        patch.setattr(inspector, "_timeout_seconds", 21)
        with pytest.raises(WebControlledValidationRuntimeError, match="state differs"):
            require_production_web_controlled_validation_adapter(adapter)
        with pytest.raises(WebControlledValidationRuntimeError, match="state differs"):
            asyncio.run(
                adapter.execute(
                    bundle=bundle,
                    coordinate=context.coordinate,
                    request=context.request,
                )
            )
        ledger.require_unclaimed(
            slot_digest=bundle.route.statement.consumption_slot_digest,
            route_digest=bundle.route.statement.route_digest,
        )

    with monkeypatch.context() as patch:
        patch.setattr(backend, "_docker", "podman")
        with pytest.raises(WebControlledValidationRuntimeError, match="state differs"):
            require_production_web_controlled_validation_adapter(adapter)

    with monkeypatch.context() as patch:
        patch.setattr(
            backend,
            "_runtime_image_bindings",
            {"pajin-worker:dev": "sha256:" + "d" * 64},
        )
        with pytest.raises(WebControlledValidationRuntimeError, match="state differs"):
            require_production_web_controlled_validation_adapter(adapter)

    with monkeypatch.context() as patch:
        patch.setattr(backend, "_egress_lifecycle_observer", object())
        with pytest.raises(WebControlledValidationRuntimeError, match="state differs"):
            require_production_web_controlled_validation_adapter(adapter)

    with monkeypatch.context() as patch:
        patch.setattr(backend, "unexpected", True, raising=False)
        with pytest.raises(WebControlledValidationRuntimeError, match="shadowed"):
            require_production_web_controlled_validation_adapter(adapter)

    with monkeypatch.context() as patch:
        patch.setattr(
            DockerWebControlledValidationAdapter,
            "_execute",
            lambda _adapter, **_kwargs: None,
        )
        with pytest.raises(WebControlledValidationRuntimeError, match="shadowed"):
            require_production_web_controlled_validation_adapter(adapter)


def test_web_002d_production_adapter_rejects_same_route_with_split_claim_ledger(
    route_context: RouteContext,
    tmp_path: Path,
) -> None:
    network_name = f"pajin-bench-{route_context.coordinate.coordinate_digest[:24]}-net"
    inspector = SubprocessWebControlledDockerBoundaryInspector()
    backend = DockerWorkerBackend(
        allowed_images={"pajin-worker:dev"},
        egress_proxy_image="pajin-egress-proxy:dev",
        external_network_routes={"bug-bounty-sqli-probe": network_name},
        egress_lifecycle_observer=inspector,
    )
    primary_ledger = WebControlledValidationRouteClaimLedger(
        tmp_path / "primary-route-claims.sqlite3"
    )
    context = _runtime_context(route_context, backend, claim_ledger=primary_ledger)
    bundle = _issue(context)
    route_authority = _live_route_authority(context)
    primary_adapter = DockerWebControlledValidationAdapter(
        backend=backend,
        inspector=inspector,
        route_authority=route_authority,
        claim_ledger=primary_ledger,
        evidence_store_path=tmp_path / "primary-worker-evidence.sqlite3",
        deployment_id="deployment.web002",
        gateway_policy_id="gateway-policy.web002.controlled",
        gateway_policy_version="1.0.0",
        worker_backend_id="docker-worker-backend.web002",
        worker_backend_version="1.0.0",
    )
    assert primary_adapter.production_boundary_verified is True
    assert (
        bundle.route.statement.runtime_policy.claim_ledger_identity_digest
        == primary_ledger.identity_digest(deployment_id="deployment.web002")
    )

    split_ledger = WebControlledValidationRouteClaimLedger(tmp_path / "split-route-claims.sqlite3")
    with pytest.raises(ValueError, match="signed route policy"):
        DockerWebControlledValidationAdapter(
            backend=backend,
            inspector=inspector,
            route_authority=route_authority,
            claim_ledger=split_ledger,
            evidence_store_path=tmp_path / "split-worker-evidence.sqlite3",
            deployment_id="deployment.web002",
            gateway_policy_id="gateway-policy.web002.controlled",
            gateway_policy_version="1.0.0",
            worker_backend_id="docker-worker-backend.web002",
            worker_backend_version="1.0.0",
        )

    split_ledger.require_unclaimed(
        slot_digest=bundle.route.statement.consumption_slot_digest,
        route_digest=bundle.route.statement.route_digest,
    )


@pytest.mark.parametrize(
    "attribute",
    (
        "_route_authority",
        "_claim_ledger",
        "_now",
        "_deployment_id",
        "_gateway_policy_id",
        "_gateway_policy_version",
        "_worker_backend_id",
        "_worker_backend_version",
    ),
)
def test_web_002d_production_adapter_rejects_critical_state_drift_before_dispatch(
    route_context: RouteContext,
    tmp_path: Path,
    attribute: str,
) -> None:
    network_name = f"pajin-bench-{route_context.coordinate.coordinate_digest[:24]}-net"
    inspector = SubprocessWebControlledDockerBoundaryInspector()
    backend = DockerWorkerBackend(
        allowed_images={"pajin-worker:dev"},
        egress_proxy_image="pajin-egress-proxy:dev",
        external_network_routes={"bug-bounty-sqli-probe": network_name},
        egress_lifecycle_observer=inspector,
    )
    claim_ledger = WebControlledValidationRouteClaimLedger(
        tmp_path / f"state-drift-{attribute}-claims.sqlite3"
    )
    context = _runtime_context(route_context, backend, claim_ledger=claim_ledger)
    adapter = DockerWebControlledValidationAdapter(
        backend=backend,
        inspector=inspector,
        route_authority=_live_route_authority(context),
        claim_ledger=claim_ledger,
        evidence_store_path=tmp_path / f"state-drift-{attribute}-evidence.sqlite3",
        deployment_id="deployment.web002",
        gateway_policy_id="gateway-policy.web002.controlled",
        gateway_policy_version="1.0.0",
        worker_backend_id="docker-worker-backend.web002",
        worker_backend_version="1.0.0",
    )
    replacements: dict[str, object] = {
        "_route_authority": object(),
        "_claim_ledger": WebControlledValidationRouteClaimLedger(
            tmp_path / f"state-drift-{attribute}-foreign-claims.sqlite3"
        ),
        "_now": lambda: context.issued_at + timedelta(seconds=31),
        "_deployment_id": "deployment.foreign",
        "_gateway_policy_id": "gateway-policy.foreign",
        "_gateway_policy_version": "2.0.0",
        "_worker_backend_id": "docker-worker-backend.foreign",
        "_worker_backend_version": "2.0.0",
    }
    setattr(adapter, attribute, replacements[attribute])

    with pytest.raises(WebControlledValidationRuntimeError):
        require_production_web_controlled_validation_adapter(adapter)


def test_web_002d_worker_rejects_image_drift_before_dispatch(
    route_context: RouteContext,
    tmp_path: Path,
) -> None:
    with pytest.raises(
        WebControlledValidationRuntimeError,
        match="Worker or proxy image identity differs",
    ):
        asyncio.run(_execute(route_context, tmp_path=tmp_path, wrong_worker_image=True))


def test_web_002d_worker_rejects_claim_replay_before_second_dispatch(
    route_context: RouteContext,
    tmp_path: Path,
) -> None:
    outcome, worker, _, adapter, bundle, context = asyncio.run(
        _execute(route_context, tmp_path=tmp_path)
    )
    assert outcome.route_claim_receipt.route_digest == bundle.route.statement.route_digest

    with pytest.raises(WebControlledValidationRuntimeError):
        asyncio.run(
            adapter.execute(
                bundle=bundle,
                coordinate=context.coordinate,
                request=context.request,
            )
        )
    assert len(worker.jobs) == 1


def test_web_002d_worker_rejects_forged_signature_before_claim_or_dispatch(
    route_context: RouteContext,
    tmp_path: Path,
) -> None:
    worker = ContractBugBountyWorker()
    inspector = _FakeBoundaryInspector(route_context)
    backend = _backend(route_context, worker, inspector)
    ledger = WebControlledValidationRouteClaimLedger(tmp_path / "forged-claims.sqlite3")
    context = _runtime_context(route_context, backend, claim_ledger=ledger)
    bundle = _issue(context)
    raw = bundle.model_dump(mode="python", by_alias=True)
    signature = raw["route"]["signatureBase64url"]
    raw["route"]["signatureBase64url"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    forged = WebProxyRouteBundle.model_validate(raw)
    adapter = DockerWebControlledValidationAdapter._for_test(
        backend=backend,
        inspector=inspector,
        route_authority=_live_route_authority(context),
        claim_ledger=ledger,
        deployment_id="deployment.web002",
        gateway_policy_id="gateway-policy.web002.controlled",
        gateway_policy_version="1.0.0",
        worker_backend_id="docker-worker-backend.web002",
        worker_backend_version="1.0.0",
        evaluated_at=context.issued_at + timedelta(seconds=31),
    )

    with pytest.raises(WebControlledValidationRuntimeError):
        asyncio.run(
            adapter.execute(
                bundle=forged,
                coordinate=context.coordinate,
                request=context.request,
            )
        )
    ledger.require_unclaimed(
        slot_digest=bundle.route.statement.consumption_slot_digest,
        route_digest=bundle.route.statement.route_digest,
    )
    assert worker.jobs == []


def test_web_002d_production_adapter_rejects_test_doubles(
    route_context: RouteContext,
    tmp_path: Path,
) -> None:
    worker = ContractBugBountyWorker()
    inspector = _FakeBoundaryInspector(route_context)
    backend = _backend(route_context, worker, inspector)
    ledger = WebControlledValidationRouteClaimLedger(tmp_path / "production-claims.sqlite3")
    context = _runtime_context(route_context, backend, claim_ledger=ledger)

    with pytest.raises(TypeError, match="code-owned Docker inspector"):
        DockerWebControlledValidationAdapter(
            backend=backend,
            inspector=inspector,
            route_authority=_live_route_authority(context),
            claim_ledger=ledger,
            evidence_store_path=tmp_path / "production-worker-evidence.sqlite3",
            deployment_id="deployment.web002",
            gateway_policy_id="gateway-policy.web002.controlled",
            gateway_policy_version="1.0.0",
            worker_backend_id="docker-worker-backend.web002",
            worker_backend_version="1.0.0",
        )
