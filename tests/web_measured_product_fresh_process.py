"""Fresh-spawn real-Docker conformance support for UX-009D.

This module is deliberately test-owned.  The value sent through ``spawn`` contains
only immutable authorities and durable coordinates; provider, adapter, registry,
reader, and application objects are always constructed in the child interpreter.
"""

from __future__ import annotations

import base64
import json
import multiprocessing
import os
import pickle
import re
import stat
import subprocess
import sys
import tempfile
import traceback
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

from fastapi.testclient import TestClient

from pajin.benchmark import (
    BenchmarkMeasurementRegistryActivationStore,
    BenchmarkMeasurementRegistryDistributionBundle,
    BenchmarkMeasurementRegistryDistributionTrustAnchor,
    BenchmarkMeasurementTrustAnchor,
    CatalogBoundDockerZAPScannerTargetFactoryAdapter,
    DockerZAPScannerTargetFactoryAdapter,
    registered_traditional_web_api_target_catalog,
)
from pajin.benchmark.docker_provider import (
    DockerBenchmarkProviderEvidence,
    DockerBugBountyTargetProfile,
    docker_benchmark_target_network_name,
)
from pajin.benchmark.target_factory import BenchmarkTargetCoordinate
from pajin.benchmark.target_recovery import BenchmarkTargetOperationJournal
from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.models import Principal, PrincipalRole
from pajin.domain.models import CampaignManifest, ToolRequest
from pajin.graph.admission import GraphAdmissionAuthority
from pajin.graph.approval import ActionApprovalAuthorization
from pajin.graph.sqlite_store import SQLiteGraphEventLog, SQLiteGraphSnapshotStore
from pajin.reporting.delivery import ExternalDeliveryCoordinator, HTTPSExternalDeliveryTransport
from pajin.reporting.sarif import write_verified_sarif_export
from pajin.runtime.store import RunStore
from pajin.runtime.worker import DockerWorkerBackend
from pajin.workflow.web_controlled_validation_authority import (
    load_web_controlled_validation_authority,
)
from pajin.workflow.web_controlled_validation_route import (
    WebControlledValidationRouteClaimLedger,
)
from pajin.workflow.web_controlled_validation_runtime import (
    DockerWebControlledValidationAdapter,
    SubprocessWebControlledDockerBoundaryInspector,
    web_controlled_worker_backend_context_digest,
)
from pajin.workflow.web_measured_product_flow import (
    WebMeasuredProductFlowOutcome,
    WebMeasuredProductFlowProjection,
    WebMeasuredProductSourceReopenContext,
    _strict_run_json_bytes,
)
from pajin.workflow.web_measured_product_reader import (
    WebMeasuredProductReader,
    WebMeasuredProductReadRegistration,
    WebMeasuredProductReadRegistry,
)
from pajin.workflow.web_proxy_route_authority import (
    WebProxyRouteLiveAuthorityContext,
    WebProxyRouteRuntimePolicy,
    WebProxyRouteTrustAnchor,
)
from pajin.workflow.web_source_measurement_authority import (
    WebZAPSourceMeasurementOutcome,
    WebZAPSourceMeasurementReopenContext,
)
from pajin.workflow.web_validation_floor import (
    bind_web_expected_finding_projection_policy,
    registered_web_benchmark_validation_floor_policy,
)
from tests.test_benchmark_zap_scanner import MEASUREMENT_KEY
from tests.test_control_plane_web import (
    APPROVER_TOKEN,
    AUDITOR_TOKEN,
    OPERATOR_TOKEN,
    WORKER_TOKEN,
    _auth,
    _settings,
)
from tests.test_web_measured_case_authority import _case as measured_case_fixture

_PRODUCT_PATH = "/v1/products/web-measured-flow"
_GETUID = getattr(os, "getuid", None)
_LOCK_ROOT_NAME = f".pajin-run-locks-{_GETUID()}" if _GETUID is not None else ".pajin-run-locks"
_LOCK_FILE = re.compile(r"^[0-9a-f]{64}\.lock$")
_REPLAY_WORKER_TOKEN = "web-replay-worker-token-that-is-long-and-distinct"
_REPLAY_WORKER_SUBJECT = "web-replay-worker"


def _fresh_settings(path: Path) -> ControlPlaneSettings:
    settings = _settings(path)
    credentials = dict(settings.credentials)
    credentials[_REPLAY_WORKER_TOKEN] = Principal(
        subject=_REPLAY_WORKER_SUBJECT,
        roles=frozenset({PrincipalRole.WORKER}),
    )
    return replace(
        settings,
        credentials=credentials,
        replay_executor_profiles={_REPLAY_WORKER_SUBJECT: frozenset({"web002d-product-read"})},
    )


@dataclass(frozen=True, slots=True)
class FreshWebMeasuredProductRouteRecipe:
    """Picklable live-route material without a store, journal, provider, or lock."""

    trust_anchor: WebProxyRouteTrustAnchor
    runtime_policy: WebProxyRouteRuntimePolicy
    target_attempt_id: str
    isolation_evidence: DockerBenchmarkProviderEvidence
    campaign: CampaignManifest
    authorization: ActionApprovalAuthorization
    request: ToolRequest

    @classmethod
    def from_runtime(
        cls,
        context: WebProxyRouteLiveAuthorityContext,
    ) -> FreshWebMeasuredProductRouteRecipe:
        if type(context) is not WebProxyRouteLiveAuthorityContext:
            raise TypeError("fresh WEB product route requires the exact live authority context")
        authorization = context.approval_store.approved_authorization(
            context.approval_id,
            context.permit_id,
        )
        if type(authorization) is not ActionApprovalAuthorization:
            raise ValueError("fresh WEB product route approval is unavailable")
        if (
            authorization.approval.approval_id != context.approval_id
            or authorization.action.permit.permit_id != context.permit_id
        ):
            raise ValueError("fresh WEB product route approval identities differ")
        return cls(
            trust_anchor=context.trust_anchor.model_copy(deep=True),
            runtime_policy=context.runtime_policy.model_copy(deep=True),
            target_attempt_id=context.target_attempt_id,
            isolation_evidence=context.isolation_evidence.model_copy(deep=True),
            campaign=context.campaign.model_copy(deep=True),
            authorization=authorization.model_copy(deep=True),
            request=context.request.model_copy(deep=True),
        )


@dataclass(frozen=True, slots=True)
class FreshWebMeasuredProductFailureCase:
    """One isolated, sealed product coordinate that must fail through the endpoint."""

    case_id: str
    product_outcome: WebMeasuredProductFlowOutcome

    def _validate(self, *, audit_root: Path) -> None:
        if (
            type(self.case_id) is not str
            or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", self.case_id) is None
            or type(self.product_outcome) is not WebMeasuredProductFlowOutcome
        ):
            raise ValueError("fresh WEB product failure case identity differs")
        for path in (
            self.product_outcome.run_path,
            self.product_outcome.source.run_path,
        ):
            if not Path(path).resolve(strict=True).is_relative_to(audit_root):
                raise ValueError("fresh WEB product failure case escapes its audit root")


@dataclass(frozen=True, slots=True)
class FreshWebMeasuredProductRecipe:
    """Deployment-private, pickle-safe coordinates for one child composition."""

    audit_root: Path
    process_root: Path
    deployment_id: str
    product_outcome: WebMeasuredProductFlowOutcome
    source_outcome: WebZAPSourceMeasurementOutcome
    source_root: Path
    target_profile: DockerBugBountyTargetProfile
    scanner_image_id: str
    provider_state_path: Path
    activation_store_path: Path
    source_journal_path: Path
    measurement_trust_anchor: BenchmarkMeasurementTrustAnchor
    distribution_bundle: BenchmarkMeasurementRegistryDistributionBundle
    distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor
    coordinate: BenchmarkTargetCoordinate
    claim_ledger_path: Path
    worker_evidence_store_path: Path
    success_route: FreshWebMeasuredProductRouteRecipe
    denial_route: FreshWebMeasuredProductRouteRecipe
    integrity_failure_cases: tuple[FreshWebMeasuredProductFailureCase, ...] = ()

    @classmethod
    def from_runtime(
        cls,
        *,
        audit_root: Path,
        process_root: Path,
        deployment_id: str,
        product_outcome: WebMeasuredProductFlowOutcome,
        source_context: Any,
        coordinate: BenchmarkTargetCoordinate,
        claim_ledger_path: Path,
        worker_evidence_store_path: Path,
        success_route_authority: WebProxyRouteLiveAuthorityContext,
        denial_route_authority: WebProxyRouteLiveAuthorityContext,
        integrity_failure_cases: tuple[FreshWebMeasuredProductFailureCase, ...] = (),
    ) -> FreshWebMeasuredProductRecipe:
        """Extract models and paths while intentionally dropping unpicklable runtime objects."""

        source_outcome = cast(WebZAPSourceMeasurementOutcome, source_context.outcome)
        target_profile = cast(
            DockerBugBountyTargetProfile,
            source_context.concrete_provider.profile,
        )
        measured_case = source_context.measured_case
        provider_state_path = Path(source_context.provider_state_path)
        recipe = cls(
            audit_root=audit_root.resolve(),
            process_root=process_root.resolve(),
            deployment_id=deployment_id,
            product_outcome=product_outcome,
            source_outcome=source_outcome,
            source_root=provider_state_path.parent.resolve(),
            target_profile=target_profile.model_copy(deep=True),
            scanner_image_id=measured_case.scanner_registration.scanner_image_id,
            provider_state_path=provider_state_path.resolve(),
            activation_store_path=Path(source_context.activation_store.path).resolve(),
            source_journal_path=Path(source_context.journal_path).resolve(),
            measurement_trust_anchor=source_context.measurement_anchor.model_copy(deep=True),
            distribution_bundle=source_context.distribution_bundle.model_copy(deep=True),
            distribution_trust_anchor=source_context.distribution_anchor.model_copy(deep=True),
            coordinate=coordinate.model_copy(deep=True),
            claim_ledger_path=claim_ledger_path.resolve(),
            worker_evidence_store_path=worker_evidence_store_path.resolve(),
            success_route=FreshWebMeasuredProductRouteRecipe.from_runtime(success_route_authority),
            denial_route=FreshWebMeasuredProductRouteRecipe.from_runtime(denial_route_authority),
            integrity_failure_cases=integrity_failure_cases,
        )
        recipe._validate()
        return recipe

    def _validate(self) -> None:
        for path in (
            self.product_outcome.run_path,
            self.product_outcome.source.run_path,
            self.source_outcome.run_path,
            self.provider_state_path,
            self.activation_store_path,
            self.source_journal_path,
            self.claim_ledger_path,
            self.worker_evidence_store_path,
        ):
            if not Path(path).resolve(strict=True).is_relative_to(self.audit_root):
                raise ValueError("fresh WEB product durable path escapes its audit root")
        if not self.source_outcome.run_path.resolve(strict=True).is_relative_to(self.source_root):
            raise ValueError("fresh WEB product source Run escapes its source root")
        policy = self.success_route.runtime_policy
        if (
            self.denial_route.runtime_policy != policy
            or policy.deployment_id != self.deployment_id
            or self.success_route.trust_anchor != self.denial_route.trust_anchor
            or not self.process_root.is_relative_to(self.audit_root)
        ):
            raise ValueError("fresh WEB product deployment composition differs")
        case_ids: set[str] = set()
        for case in self.integrity_failure_cases:
            if type(case) is not FreshWebMeasuredProductFailureCase:
                raise TypeError("fresh WEB product failure case type differs")
            case._validate(audit_root=self.audit_root)
            if (
                case.case_id in case_ids
                or case.product_outcome.run_path.resolve()
                == self.product_outcome.run_path.resolve()
            ):
                raise ValueError("fresh WEB product failure case is duplicated or accepted")
            case_ids.add(case.case_id)


@dataclass(frozen=True, slots=True)
class FreshWebMeasuredProductProbeResult:
    process_id: int
    canonical_bytes_base64: str
    canonical_bytes_sha256: str
    result_digest: str
    flow_id: str
    flow_digest: str
    source_run_id: str
    source_authority_id: str
    source_authority_digest: str
    statuses: tuple[int, ...]
    resolver_calls: tuple[str, ...]
    source_reload_calls: int
    reader_calls: int
    integrity_failure_case_ids: tuple[str, ...]
    integrity_failure_statuses: tuple[int, ...]
    docker_argv: tuple[tuple[str, ...], ...]
    filesystem_write_events: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _FrozenApprovalLookup:
    authorization: ActionApprovalAuthorization

    def approved_authorization(
        self,
        approval_id: str,
        permit_id: str,
    ) -> ActionApprovalAuthorization | None:
        if (
            approval_id != self.authorization.approval.approval_id
            or permit_id != self.authorization.action.permit.permit_id
        ):
            return None
        return self.authorization.model_copy(deep=True)


@dataclass(frozen=True, slots=True)
class _TreeEntry:
    relative_path: str
    kind: str
    mode: int
    size: int | None = None
    modified_ns: int | None = None
    digest: str | None = None


_FRESH_CHILD_STAGES = (
    "not-started",
    "child-entered",
    "recipe-validated",
    "environment-prepared",
    "fixtures-rebuilt",
    "provider-rebuilt",
    "source-context-rebuilt",
    "floor-policy-rebuilt",
    "projection-mapping-rebuilt",
    "journal-opened",
    "routes-rebuilt",
    "backend-rebuilt",
    "adapter-rebuilt",
    "reopen-context-rebuilt",
    "registration-rebuilt",
    "applications-created",
    "monitoring-started",
    "clients-started",
    "baseline-snapshotted",
    "denial-requests-complete",
    "first-product-read-complete",
    "second-product-read-complete",
    "integrity-cases-complete",
    "post-read-audit-complete",
    "clients-closed",
    "result-built",
)


def run_fresh_web_measured_product_probe(
    recipe: FreshWebMeasuredProductRecipe,
    *,
    hash_seed: int,
    timeout_seconds: int,
) -> FreshWebMeasuredProductProbeResult:
    """Run one independent ``spawn`` interpreter and surface child assertions."""

    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise ValueError("fresh WEB measured product timeout must be a positive integer")
    recipe._validate()
    pickle.dumps(recipe, protocol=pickle.HIGHEST_PROTOCOL)
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    progress = context.RawValue("i", 0)
    previous_hash_seed = os.environ.get("PYTHONHASHSEED")
    previous_no_bytecode = os.environ.get("PYTHONDONTWRITEBYTECODE")
    os.environ["PYTHONHASHSEED"] = str(hash_seed)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    process = context.Process(
        target=_child_entry,
        args=(send, recipe, progress),
    )
    try:
        process.start()
    finally:
        send.close()
        _restore_environment("PYTHONHASHSEED", previous_hash_seed)
        _restore_environment("PYTHONDONTWRITEBYTECODE", previous_no_bytecode)
    if not receive.poll(timeout_seconds):
        last_stage = _fresh_child_stage(progress)
        process.terminate()
        process.join(timeout=10)
        receive.close()
        raise TimeoutError(
            "fresh WEB measured product child did not finish within "
            f"{timeout_seconds}s (hash seed {hash_seed}, "
            f"integrity cases {len(recipe.integrity_failure_cases)}, "
            f"last stage {last_stage})"
        )
    try:
        state, payload = receive.recv()
    except EOFError as exc:
        process.join(timeout=10)
        raise RuntimeError(
            "fresh WEB measured product child exited without a result "
            f"(exit code {process.exitcode}, last stage {_fresh_child_stage(progress)})"
        ) from exc
    finally:
        receive.close()
    process.join(timeout=10)
    if process.is_alive():
        process.terminate()
        process.join(timeout=10)
        raise RuntimeError("fresh WEB measured product child did not exit")
    if state != "ok" or process.exitcode != 0:
        raise AssertionError(cast(str, payload))
    if type(payload) is not FreshWebMeasuredProductProbeResult:
        raise TypeError("fresh WEB measured product child returned another result type")
    return payload


def _restore_environment(name: str, previous: str | None) -> None:
    if previous is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = previous


def _child_entry(
    send: Any,
    recipe: FreshWebMeasuredProductRecipe,
    progress: Any,
) -> None:
    try:
        _mark_fresh_child_stage(progress, "child-entered")
        send.send(("ok", _run_child(recipe, progress=progress)))
    except BaseException:  # pragma: no cover - diagnostics cross the process boundary
        send.send(("error", traceback.format_exc()))
    finally:
        send.close()


def _run_child(
    recipe: FreshWebMeasuredProductRecipe,
    *,
    progress: Any,
) -> FreshWebMeasuredProductProbeResult:
    recipe._validate()
    _mark_fresh_child_stage(progress, "recipe-validated")
    recipe.process_root.mkdir(parents=True, exist_ok=True)
    temp_root = recipe.process_root / "TEMP"
    temp_root.mkdir(parents=True, exist_ok=True)
    for name in ("TMPDIR", "TEMP", "TMP"):
        os.environ[name] = str(temp_root)
    tempfile.tempdir = str(temp_root)
    _mark_fresh_child_stage(progress, "environment-prepared")

    measured_case, capability_bundle, lifecycle, private_profile, target_adapter = (
        measured_case_fixture(
            target_profile=recipe.target_profile,
            measurement_trust_anchor=recipe.measurement_trust_anchor,
            scanner_image_id=recipe.scanner_image_id,
        )
    )
    _mark_fresh_child_stage(progress, "fixtures-rebuilt")
    ground_truth = private_profile.private_ground_truth.ground_truth
    concrete_provider = DockerZAPScannerTargetFactoryAdapter(
        state_path=recipe.provider_state_path,
        profile=recipe.target_profile,
        plan=measured_case.scanner_plan,
        registration=measured_case.scanner_registration,
        trust_anchor=recipe.measurement_trust_anchor,
        measurement_private_key=MEASUREMENT_KEY,
    )
    provider = CatalogBoundDockerZAPScannerTargetFactoryAdapter(
        provider=concrete_provider,
        catalog=registered_traditional_web_api_target_catalog(
            recipe.target_profile,
            ground_truth,
        ),
        ground_truth=ground_truth,
    )
    _mark_fresh_child_stage(progress, "provider-rebuilt")
    activation_store = BenchmarkMeasurementRegistryActivationStore(recipe.activation_store_path)
    source_reopen_context = WebZAPSourceMeasurementReopenContext(
        outcome=recipe.source_outcome,
        measured_case=measured_case,
        capability_bundle=capability_bundle,
        lifecycle=lifecycle,
        release=measured_case.capability_release,
        target_adapter=target_adapter,
        private_ground_truth_profile=private_profile,
        scanner_plan=measured_case.scanner_plan,
        scanner_registration=measured_case.scanner_registration,
        journal_path=recipe.source_journal_path,
        catalog_provider=provider,
        measurement_trust_anchor=recipe.measurement_trust_anchor,
        activation_store=activation_store,
        distribution_bundle=recipe.distribution_bundle,
        distribution_trust_anchor=recipe.distribution_trust_anchor,
    )
    _mark_fresh_child_stage(progress, "source-context-rebuilt")
    floor_policy = registered_web_benchmark_validation_floor_policy(
        measured_case,
        capability_bundle=capability_bundle,
        lifecycle=lifecycle,
        release=measured_case.capability_release,
        target_adapter=target_adapter,
        private_ground_truth_profile=private_profile,
        scanner_plan=measured_case.scanner_plan,
        scanner_registration=measured_case.scanner_registration,
    )
    _mark_fresh_child_stage(progress, "floor-policy-rebuilt")
    mapping = bind_web_expected_finding_projection_policy(
        measured_case=measured_case,
        floor_policy=floor_policy,
        capability_bundle=capability_bundle,
        lifecycle=lifecycle,
        release=measured_case.capability_release,
        target_adapter=target_adapter,
        private_ground_truth_profile=private_profile,
        scanner_plan=measured_case.scanner_plan,
        scanner_registration=measured_case.scanner_registration,
    )
    _mark_fresh_child_stage(progress, "projection-mapping-rebuilt")
    journal = BenchmarkTargetOperationJournal.open_existing(recipe.source_journal_path)
    _mark_fresh_child_stage(progress, "journal-opened")
    claim_ledger = WebControlledValidationRouteClaimLedger(recipe.claim_ledger_path)
    success_route = _rebuild_route(
        recipe.success_route,
        measured_case=measured_case,
        capability_bundle=capability_bundle,
        lifecycle=lifecycle,
        private_profile=private_profile,
        target_adapter=target_adapter,
        journal=journal,
        target_profile=recipe.target_profile,
    )
    denial_route = _rebuild_route(
        recipe.denial_route,
        measured_case=measured_case,
        capability_bundle=capability_bundle,
        lifecycle=lifecycle,
        private_profile=private_profile,
        target_adapter=target_adapter,
        journal=journal,
        target_profile=recipe.target_profile,
    )
    _mark_fresh_child_stage(progress, "routes-rebuilt")
    inspector = SubprocessWebControlledDockerBoundaryInspector()
    policy = success_route.runtime_policy
    backend = DockerWorkerBackend(
        allowed_images={policy.worker_image},
        egress_proxy_image=policy.proxy_image,
        external_network_routes={
            policy.worker_action: docker_benchmark_target_network_name(recipe.coordinate)
        },
        egress_lifecycle_observer=inspector,
    )
    if policy.worker_backend_digest != web_controlled_worker_backend_context_digest(backend):
        raise AssertionError("fresh WEB product Worker backend digest differs")
    _mark_fresh_child_stage(progress, "backend-rebuilt")
    adapter = DockerWebControlledValidationAdapter(
        backend=backend,
        inspector=inspector,
        route_authority=success_route,
        claim_ledger=claim_ledger,
        evidence_store_path=recipe.worker_evidence_store_path,
        deployment_id=policy.deployment_id,
        gateway_policy_id=policy.gateway_policy_id,
        gateway_policy_version=policy.gateway_policy_version,
        worker_backend_id=policy.worker_backend_id,
        worker_backend_version=policy.worker_backend_version,
    )
    _mark_fresh_child_stage(progress, "adapter-rebuilt")
    reopen_context = WebMeasuredProductSourceReopenContext(
        measured_case_authority=measured_case,
        private_ground_truth_profile=private_profile,
        source_reopen_context=source_reopen_context,
        floor_policy=floor_policy,
        mapping=mapping,
        trust_anchor=success_route.trust_anchor,
        claim_ledger=claim_ledger,
        target_journal=journal,
        provider=provider,
        adapter=adapter,
        denial_route_authority=denial_route,
    )
    _mark_fresh_child_stage(progress, "reopen-context-rebuilt")
    registration = WebMeasuredProductReadRegistration.from_outcome(
        deployment_id=recipe.deployment_id,
        outcome=recipe.product_outcome,
        reopen_context=reopen_context,
    )
    _mark_fresh_child_stage(progress, "registration-rebuilt")
    registry = WebMeasuredProductReadRegistry((registration,))
    if type(registry) is not WebMeasuredProductReadRegistry or tuple(registry._registrations) != (
        recipe.deployment_id,
    ):
        raise AssertionError("fresh WEB product registry composition differs")
    reader = WebMeasuredProductReader(
        deployment_id=recipe.deployment_id,
        resolver=registry,
    )
    app = create_app(
        _fresh_settings(recipe.process_root / "control-plane.sqlite3"),
        web_measured_product_reader=reader,
    )
    failure_apps = _build_failure_apps(
        recipe,
        reopen_context=reopen_context,
    )
    _mark_fresh_child_stage(progress, "applications-created")

    counters: dict[str, int] = {}
    resolver_calls: list[str] = []
    filesystem_writes: list[str] = []
    socket_events: list[str] = []
    permitted_popen: list[tuple[str, ...]] = []
    audit_active = [False]
    sys.addaudithook(
        _audit_hook(
            audit_active=audit_active,
            temp_root=temp_root,
            filesystem_writes=filesystem_writes,
            socket_events=socket_events,
            permitted_popen=permitted_popen,
        )
    )
    real_subprocess_run = subprocess.run
    subprocess_module = cast(Any, subprocess)
    docker_argv: list[tuple[str, ...]] = []
    target_lifecycle = recipe.product_outcome.source.authority.target_lifecycle
    execution_id = target_lifecycle.worker_evidence.worker_job.execution_id
    expected_once = (
        (
            "docker",
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            f"label=pajin.execution-id={execution_id}",
        ),
        (
            "docker",
            "network",
            "ls",
            "--quiet",
            "--filter",
            f"label=pajin.execution-id={execution_id}",
        ),
        ("docker", "image", "inspect", policy.worker_image, "--format", "{{.Id}}"),
        ("docker", "image", "inspect", policy.proxy_image, "--format", "{{.Id}}"),
    )
    allowed_docker = frozenset(expected_once)

    def audited_subprocess_run(arguments: Any, *args: Any, **kwargs: Any) -> Any:
        if (
            type(arguments) is not list
            or args
            or kwargs
            != {
                "capture_output": True,
                "check": False,
                "timeout": 20,
            }
        ):
            raise AssertionError("fresh WEB product Docker subprocess options differ")
        argv = tuple(os.fspath(item) for item in arguments)
        docker_argv.append(argv)
        if argv not in allowed_docker:
            raise AssertionError(f"fresh WEB product invoked forbidden subprocess: {argv!r}")
        permitted_popen.append(argv)
        try:
            return real_subprocess_run(arguments, *args, **kwargs)
        finally:
            if permitted_popen and permitted_popen[-1] == argv:
                permitted_popen.pop()

    monitoring_session = _start_call_monitoring(
        counters,
        resolver_calls=resolver_calls,
    )
    _mark_fresh_child_stage(progress, "monitoring-started")
    try:
        with ExitStack() as stack:
            client = stack.enter_context(TestClient(app))
            failure_clients = tuple(
                (case, stack.enter_context(TestClient(failure_app)))
                for case, failure_app in failure_apps
            )
            _mark_fresh_child_stage(progress, "clients-started")
            counters.clear()
            before_tree = _tree_snapshot(recipe.audit_root, temp_root=temp_root)
            before_docker = _docker_inventory(real_subprocess_run)
            _mark_fresh_child_stage(progress, "baseline-snapshotted")
            subprocess_module.run = audited_subprocess_run
            audit_active[0] = True
            try:
                invalid = client.get(_PRODUCT_PATH, headers=_auth("invalid-bearer"))
                missing = client.get(_PRODUCT_PATH)
                approver = client.get(_PRODUCT_PATH, headers=_auth(APPROVER_TOKEN))
                auditor = client.get(_PRODUCT_PATH, headers=_auth(AUDITOR_TOKEN))
                worker = client.get(_PRODUCT_PATH, headers=_auth(WORKER_TOKEN))
                replay_worker = client.get(
                    _PRODUCT_PATH,
                    headers=_auth(_REPLAY_WORKER_TOKEN),
                )
                query = client.get(
                    f"{_PRODUCT_PATH}?runId=caller-selected",
                    headers=_auth(OPERATOR_TOKEN),
                )
                body = client.request(
                    "GET",
                    _PRODUCT_PATH,
                    headers=_auth(OPERATOR_TOKEN),
                    content=b"{}",
                )
                post = client.post(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN), json={})
                head = client.head(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN))
                _mark_fresh_child_stage(progress, "denial-requests-complete")
                if (
                    resolver_calls
                    or counters.get("resolver", 0)
                    or counters.get("reader", 0)
                    or counters.get("source", 0)
                ):
                    raise AssertionError("denied WEB product requests reached the reader")
                first = client.get(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN))
                _mark_fresh_child_stage(progress, "first-product-read-complete")
                second = client.get(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN))
                _mark_fresh_child_stage(progress, "second-product-read-complete")
                failure_statuses = _exercise_integrity_failure_cases(
                    recipe,
                    failure_clients=failure_clients,
                    counters=counters,
                    resolver_calls=resolver_calls,
                    docker_argv=docker_argv,
                    expected_once=expected_once,
                )
                _mark_fresh_child_stage(progress, "integrity-cases-complete")
            finally:
                audit_active[0] = False
                subprocess_module.run = real_subprocess_run
            statuses = tuple(
                response.status_code
                for response in (
                    invalid,
                    missing,
                    approver,
                    auditor,
                    worker,
                    replay_worker,
                    query,
                    body,
                    post,
                    head,
                    first,
                    second,
                )
            )
            if statuses != (
                401,
                401,
                403,
                403,
                403,
                403,
                400,
                400,
                405,
                405,
                200,
                200,
            ):
                raise AssertionError(f"fresh WEB product HTTP statuses differ: {statuses!r}")
            for response in (
                invalid,
                missing,
                approver,
                auditor,
                worker,
                replay_worker,
                query,
                body,
                post,
                head,
                first,
                second,
            ):
                _assert_non_cacheable(response)
            expected_projection = recipe.product_outcome.projection.model_dump(
                mode="json", by_alias=True
            )
            if first.json() != expected_projection or second.json() != expected_projection:
                raise AssertionError("fresh WEB product response differs from the selected outcome")
            projection = WebMeasuredProductFlowProjection.model_validate(first.json())
            canonical = _strict_run_json_bytes(projection.model_dump(mode="json", by_alias=True))
            expected_read_count = 2 + len(recipe.integrity_failure_cases)
            if (
                canonical
                != recipe.product_outcome.run_path.joinpath(
                    recipe.product_outcome.artifact_path
                ).read_bytes()
                or resolver_calls != [recipe.deployment_id] * expected_read_count
                or counters.get("resolver", 0) != expected_read_count
                or counters.get("reader", 0) != expected_read_count
                or counters.get("source", 0) != expected_read_count
                or any(
                    count
                    for name, count in counters.items()
                    if name not in {"reader", "resolver", "source"}
                )
                or tuple(docker_argv) != expected_once * expected_read_count
                or socket_events
            ):
                raise AssertionError(
                    "fresh WEB product read, reload, Docker, or socket audit differs"
                )
            after_docker = _docker_inventory(real_subprocess_run)
            after_tree = _tree_snapshot(recipe.audit_root, temp_root=temp_root)
            if before_tree != after_tree or before_docker != after_docker:
                raise AssertionError("fresh WEB product read mutated durable or Docker state")
            _mark_fresh_child_stage(progress, "post-read-audit-complete")
        _mark_fresh_child_stage(progress, "clients-closed")
    finally:
        _stop_call_monitoring(monitoring_session)
        subprocess_module.run = real_subprocess_run

    result_material = {
        "canonicalBytesSha256": sha256(canonical).hexdigest(),
        "flowId": projection.flow_id,
        "flowDigest": projection.flow_digest,
        "sourceRunId": projection.source_run_id,
        "sourceAuthorityId": projection.source_authority_id,
        "sourceAuthorityDigest": projection.source_authority_digest,
    }
    result_digest = sha256(
        json.dumps(
            result_material,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    ).hexdigest()
    _mark_fresh_child_stage(progress, "result-built")
    return FreshWebMeasuredProductProbeResult(
        process_id=os.getpid(),
        canonical_bytes_base64=base64.b64encode(canonical).decode("ascii"),
        canonical_bytes_sha256=sha256(canonical).hexdigest(),
        result_digest=result_digest,
        flow_id=projection.flow_id,
        flow_digest=projection.flow_digest,
        source_run_id=projection.source_run_id,
        source_authority_id=projection.source_authority_id,
        source_authority_digest=projection.source_authority_digest,
        statuses=statuses,
        resolver_calls=tuple(resolver_calls),
        source_reload_calls=counters["source"],
        reader_calls=counters["reader"],
        integrity_failure_case_ids=tuple(case.case_id for case in recipe.integrity_failure_cases),
        integrity_failure_statuses=failure_statuses,
        docker_argv=tuple(docker_argv),
        filesystem_write_events=tuple(filesystem_writes),
    )


def _mark_fresh_child_stage(progress: Any, stage: str) -> None:
    progress.value = _FRESH_CHILD_STAGES.index(stage)
    print(f"fresh WEB product child stage: {stage}", file=sys.stderr, flush=True)


def _fresh_child_stage(progress: Any) -> str:
    stage_index = int(progress.value)
    if 0 <= stage_index < len(_FRESH_CHILD_STAGES):
        return _FRESH_CHILD_STAGES[stage_index]
    return f"unknown-{stage_index}"


def _build_failure_apps(
    recipe: FreshWebMeasuredProductRecipe,
    *,
    reopen_context: WebMeasuredProductSourceReopenContext,
) -> list[tuple[FreshWebMeasuredProductFailureCase, Any]]:
    failure_apps: list[tuple[FreshWebMeasuredProductFailureCase, Any]] = []
    for case in recipe.integrity_failure_cases:
        registration = WebMeasuredProductReadRegistration.from_outcome(
            deployment_id=recipe.deployment_id,
            outcome=case.product_outcome,
            reopen_context=reopen_context,
        )
        registry = WebMeasuredProductReadRegistry((registration,))
        if type(registry) is not WebMeasuredProductReadRegistry or tuple(
            registry._registrations
        ) != (recipe.deployment_id,):
            raise AssertionError("fresh WEB product failure registry composition differs")
        reader = WebMeasuredProductReader(
            deployment_id=recipe.deployment_id,
            resolver=registry,
        )
        app = create_app(
            _fresh_settings(recipe.process_root / f"control-plane-{case.case_id}.sqlite3"),
            web_measured_product_reader=reader,
        )
        failure_apps.append((case, app))
    return failure_apps


def _exercise_integrity_failure_cases(
    recipe: FreshWebMeasuredProductRecipe,
    *,
    failure_clients: tuple[tuple[FreshWebMeasuredProductFailureCase, TestClient], ...],
    counters: dict[str, int],
    resolver_calls: list[str],
    docker_argv: list[tuple[str, ...]],
    expected_once: tuple[tuple[str, ...], ...],
) -> tuple[int, ...]:
    statuses: list[int] = []
    expected_body = {"detail": "Measured Web product authority is not integrity-valid"}
    for case, client in failure_clients:
        resolver_count = counters.get("resolver", 0)
        reader_count = counters.get("reader", 0)
        source_count = counters.get("source", 0)
        resolver_call_count = len(resolver_calls)
        docker_call_count = len(docker_argv)
        response = client.get(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN))
        _assert_non_cacheable(response)
        statuses.append(response.status_code)
        if (
            counters.get("resolver", 0) != resolver_count + 1
            or counters.get("reader", 0) != reader_count + 1
            or counters.get("source", 0) != source_count + 1
            or resolver_calls[resolver_call_count:] != [recipe.deployment_id]
            or tuple(docker_argv[docker_call_count:]) != expected_once
            or response.status_code != 409
            or response.json() != expected_body
            or any(
                marker in response.text
                for marker in (
                    str(case.product_outcome.run_path),
                    str(case.product_outcome.source.run_path),
                    str(recipe.provider_state_path),
                    str(recipe.source_journal_path),
                    str(recipe.claim_ledger_path),
                    str(recipe.worker_evidence_store_path),
                )
            )
        ):
            raise AssertionError(f"fresh WEB product failure audit differs for {case.case_id}")
    return tuple(statuses)


def _rebuild_route(
    recipe: FreshWebMeasuredProductRouteRecipe,
    *,
    measured_case: Any,
    capability_bundle: Any,
    lifecycle: Any,
    private_profile: Any,
    target_adapter: Any,
    journal: BenchmarkTargetOperationJournal,
    target_profile: DockerBugBountyTargetProfile,
) -> WebProxyRouteLiveAuthorityContext:
    return WebProxyRouteLiveAuthorityContext(
        trust_anchor=recipe.trust_anchor,
        measured_case=measured_case,
        capability_bundle=capability_bundle,
        capability_lifecycle=lifecycle,
        capability_release=measured_case.capability_release,
        private_ground_truth_profile=private_profile,
        scanner_plan=measured_case.scanner_plan,
        scanner_registration=measured_case.scanner_registration,
        runtime_policy=recipe.runtime_policy,
        target_profile=target_profile,
        target_journal=journal,
        target_attempt_id=recipe.target_attempt_id,
        isolation_evidence=recipe.isolation_evidence,
        campaign=recipe.campaign,
        approval_store=_FrozenApprovalLookup(recipe.authorization),
        approval_id=recipe.authorization.approval.approval_id,
        permit_id=recipe.authorization.action.permit.permit_id,
        request=recipe.request,
    )


def _monitor_recorder(
    counters: dict[str, int],
    *,
    resolver_calls: list[str],
) -> tuple[Callable[[Any, int], None], tuple[Any, ...]]:
    observed: dict[Any, str] = {
        WebMeasuredProductReader.read.__code__: "reader",
        WebMeasuredProductReadRegistry.resolve_for_product_read.__code__: "resolver",
        load_web_controlled_validation_authority.__code__: "source",
    }
    forbidden: tuple[tuple[type[Any], tuple[str, ...]], ...] = (
        (RunStore, ("create", "append_event", "write_json", "write_bytes", "seal")),
        (
            CatalogBoundDockerZAPScannerTargetFactoryAdapter,
            ("reset", "establish_isolation", "execute", "cleanup", "reconcile_cleanup", "attest"),
        ),
        (
            DockerZAPScannerTargetFactoryAdapter,
            ("reset", "establish_isolation", "execute", "cleanup", "reconcile_cleanup", "attest"),
        ),
        (BenchmarkMeasurementRegistryActivationStore, ("activate",)),
        (WebControlledValidationRouteClaimLedger, ("claim_once", "seal_denial_if_unclaimed")),
        (DockerWebControlledValidationAdapter, ("execute",)),
        (DockerWorkerBackend, ("run",)),
        (GraphAdmissionAuthority, ("submit",)),
        (SQLiteGraphEventLog, ("append",)),
        (SQLiteGraphSnapshotStore, ("append",)),
        (ExternalDeliveryCoordinator, ("register", "dispatch_once", "reconcile")),
        (HTTPSExternalDeliveryTransport, ("dispatch",)),
    )
    for owner, names in forbidden:
        for name in names:
            code = _callable_code(getattr(owner, name))
            observed[code] = f"forbidden:{owner.__name__}.{name}"
    observed[_callable_code(write_verified_sarif_export)] = "forbidden:write_verified_sarif_export"

    def monitor(code: Any, _instruction_offset: int) -> None:
        label = observed.get(code)
        if label is None:
            return
        counters[label] = counters.get(label, 0) + 1
        if label == "resolver":
            resolver_calls.append(cast(str, sys._getframe(1).f_locals.get("deployment_id")))
        if label.startswith("forbidden:"):
            raise AssertionError(f"fresh WEB product invoked {label}")

    return monitor, tuple(observed)


def _start_call_monitoring(
    counters: dict[str, int],
    *,
    resolver_calls: list[str],
) -> tuple[int, int, tuple[Any, ...]]:
    callback, codes = _monitor_recorder(counters, resolver_calls=resolver_calls)
    monitoring = sys.monitoring
    tool_id = monitoring.PROFILER_ID
    event = monitoring.events.PY_START
    enabled: list[Any] = []
    monitoring.use_tool_id(tool_id, "pajin-fresh-web-product")
    try:
        previous = monitoring.register_callback(tool_id, event, callback)
        if previous is not None:
            raise AssertionError("fresh WEB product monitoring callback is already registered")
        for code in codes:
            monitoring.set_local_events(tool_id, code, event)
            enabled.append(code)
    except BaseException:
        for code in reversed(enabled):
            monitoring.set_local_events(tool_id, code, 0)
        monitoring.register_callback(tool_id, event, None)
        monitoring.free_tool_id(tool_id)
        raise
    return tool_id, event, tuple(enabled)


def _stop_call_monitoring(session: tuple[int, int, tuple[Any, ...]]) -> None:
    tool_id, event, codes = session
    monitoring = sys.monitoring
    try:
        for code in reversed(codes):
            monitoring.set_local_events(tool_id, code, 0)
    finally:
        try:
            monitoring.register_callback(tool_id, event, None)
        finally:
            monitoring.free_tool_id(tool_id)


def _callable_code(value: Any) -> Any:
    function = getattr(value, "__func__", value)
    return function.__code__


def _audit_hook(
    *,
    audit_active: list[bool],
    temp_root: Path,
    filesystem_writes: list[str],
    socket_events: list[str],
    permitted_popen: list[tuple[str, ...]],
) -> Callable[[str, tuple[Any, ...]], None]:
    single_path_mutations = frozenset(
        {
            "os.chmod",
            "os.chown",
            "os.mkdir",
            "os.remove",
            "os.removexattr",
            "os.rmdir",
            "os.setxattr",
            "os.truncate",
            "os.unlink",
            "os.utime",
        }
    )
    two_path_mutations = frozenset({"os.rename", "os.replace"})

    def hook(event: str, args: tuple[Any, ...]) -> None:
        if not audit_active[0]:
            return
        if event in {
            "socket.bind",
            "socket.connect",
            "socket.connect_ex",
            "socket.getaddrinfo",
            "socket.gethostbyaddr",
            "socket.gethostbyname",
            "socket.gethostbyname_ex",
            "socket.sendto",
        }:
            socket_events.append(event)
            raise AssertionError("fresh WEB product attempted a network connection")
        if event in {"os.chdir", "os.putenv", "os.unsetenv", "os.link", "os.symlink"}:
            raise AssertionError(
                f"fresh WEB product attempted process or link mutation via {event}"
            )
        if (
            event in {"os.system", "os.posix_spawn", "os.fork", "os.forkpty"}
            or event.startswith("os.exec")
            or event.startswith("os.spawn")
        ):
            raise AssertionError(f"fresh WEB product attempted process launch via {event}")
        if event == "subprocess.Popen":
            if len(args) < 4 or args[0] != "docker" or args[2] is not None or args[3] is not None:
                raise AssertionError("fresh WEB product Docker process context differs")
            argv = tuple(os.fspath(item) for item in args[1])
            if not permitted_popen or permitted_popen.pop() != argv:
                raise AssertionError(f"fresh WEB product bypassed subprocess.run: {argv!r}")
            return
        paths: tuple[object, ...] = ()
        if (event == "open" and len(args) >= 3 and _open_is_writable(args[1], args[2])) or (
            event in single_path_mutations and args
        ):
            paths = (args[0],)
        elif event in two_path_mutations and len(args) >= 2:
            paths = (args[0], args[1])
        for path in paths:
            if isinstance(path, int):
                continue
            resolved = Path(os.fsdecode(path)).resolve(strict=False)
            filesystem_writes.append(f"{event}:{resolved}")
            if not _is_lock_mutation(event, resolved, temp_root=temp_root):
                raise AssertionError(f"fresh WEB product attempted filesystem mutation: {resolved}")

    return hook


def _open_is_writable(mode: object, flags: object) -> bool:
    if isinstance(mode, str) and any(marker in mode for marker in ("w", "a", "x", "+")):
        return True
    if isinstance(flags, int):
        writable = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
        return bool(flags & writable)
    return False


def _is_lock_mutation(event: str, path: Path, *, temp_root: Path) -> bool:
    try:
        relative = path.relative_to(temp_root.resolve())
    except ValueError:
        return False
    if relative.parts == (_LOCK_ROOT_NAME,):
        return event in {"os.mkdir", "os.chmod"}
    return bool(
        len(relative.parts) == 2
        and relative.parts[0] == _LOCK_ROOT_NAME
        and _LOCK_FILE.fullmatch(relative.parts[1])
        and event == "open"
    )


def _validate_lock_tree(lock_root: Path, *, audit_root: Path) -> None:
    root_details = lock_root.lstat()
    relative_root = lock_root.relative_to(audit_root).as_posix()
    if lock_root.is_symlink() or not stat.S_ISDIR(root_details.st_mode):
        raise AssertionError(
            f"fresh WEB product lock root is not a real directory: {relative_root}"
        )
    getuid = getattr(os, "getuid", None)
    if getuid is not None and root_details.st_uid != getuid():
        raise AssertionError(f"fresh WEB product lock root owner differs: {relative_root}")
    if os.name == "posix" and stat.S_IMODE(root_details.st_mode) != 0o700:
        raise AssertionError(f"fresh WEB product lock root mode differs: {relative_root}")
    for lock_file in sorted(lock_root.iterdir(), key=lambda item: item.name):
        details = lock_file.lstat()
        relative = lock_file.relative_to(audit_root).as_posix()
        if (
            not _LOCK_FILE.fullmatch(lock_file.name)
            or lock_file.is_symlink()
            or not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
        ):
            raise AssertionError(f"fresh WEB product lock root has another entry: {relative}")
        if getuid is not None and details.st_uid != getuid():
            raise AssertionError(f"fresh WEB product lock file owner differs: {relative}")
        if os.name == "posix" and stat.S_IMODE(details.st_mode) != 0o600:
            raise AssertionError(f"fresh WEB product lock file mode differs: {relative}")


def _tree_snapshot(root: Path, *, temp_root: Path) -> tuple[_TreeEntry, ...]:
    root = root.resolve(strict=True)
    temp_root = temp_root.resolve(strict=True)
    entries: list[_TreeEntry] = []

    def visit(directory: Path) -> None:
        for child in sorted(directory.iterdir(), key=lambda item: item.name):
            if child.parent == temp_root and child.name == _LOCK_ROOT_NAME:
                _validate_lock_tree(child, audit_root=root)
                continue
            details = child.lstat()
            relative = child.relative_to(root).as_posix()
            mode = stat.S_IMODE(details.st_mode)
            if stat.S_ISLNK(details.st_mode):
                raise AssertionError(f"fresh WEB product audit root contains a symlink: {relative}")
            if stat.S_ISDIR(details.st_mode):
                entries.append(_TreeEntry(relative, "directory", mode))
                visit(child)
            elif stat.S_ISREG(details.st_mode):
                content = child.read_bytes()
                entries.append(
                    _TreeEntry(
                        relative,
                        "file",
                        mode,
                        len(content),
                        details.st_mtime_ns,
                        sha256(content).hexdigest(),
                    )
                )
            else:
                raise AssertionError(
                    f"fresh WEB product audit root contains a special file: {relative}"
                )

    visit(root)
    return tuple(entries)


def _docker_inventory(
    runner: Callable[..., subprocess.CompletedProcess[Any]],
) -> tuple[str, ...]:
    commands = (
        (
            "docker",
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            "label=pajin.benchmark.managed=true",
        ),
        (
            "docker",
            "network",
            "ls",
            "--quiet",
            "--filter",
            "label=pajin.benchmark.managed=true",
        ),
        ("docker", "container", "ls", "--all", "--quiet", "--filter", "label=pajin.execution-id"),
        ("docker", "network", "ls", "--quiet", "--filter", "label=pajin.execution-id"),
        ("docker", "container", "ls", "--all", "--quiet", "--filter", "name=^/pajin-bench-"),
        ("docker", "network", "ls", "--quiet", "--filter", "name=^pajin-bench-"),
    )
    return tuple(
        runner(
            list(command),
            capture_output=True,
            check=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        for command in commands
    )


def _assert_non_cacheable(response: Any) -> None:
    if (
        response.headers.get("cache-control") != "no-store, max-age=0"
        or response.headers.get("pragma") != "no-cache"
        or response.headers.get("referrer-policy") != "no-referrer"
        or response.headers.get("x-content-type-options") != "nosniff"
        or "set-cookie" in response.headers
        or "access-control-allow-origin" in response.headers
        or "etag" in response.headers
        or "last-modified" in response.headers
    ):
        raise AssertionError("fresh WEB product response cache or browser boundary differs")


__all__ = [
    "FreshWebMeasuredProductFailureCase",
    "FreshWebMeasuredProductProbeResult",
    "FreshWebMeasuredProductRecipe",
    "FreshWebMeasuredProductRouteRecipe",
    "run_fresh_web_measured_product_probe",
]
