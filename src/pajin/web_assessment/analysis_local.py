"""Least-authority local Docker Provider assembly for WEB-007 analysis."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import cast

from pydantic import AnyHttpUrl, BaseModel, JsonValue

from pajin.benchmark.effectiveness.docker import LocalModelRuntime
from pajin.benchmark.effectiveness.evidence import Lifecycle
from pajin.benchmark.effectiveness.runtime import LocalEvaluationTool
from pajin.benchmark.effectiveness.suite import (
    ENDPOINT,
    ModelPin,
    RuntimePin,
    model_pins,
)
from pajin.domain.models import CampaignManifest, ToolRequest, ToolRiskTier
from pajin.policy.capability import CapabilityLedger
from pajin.policy.engine import PolicyEngine
from pajin.providers.models import ProviderChatRequest, ProviderRegistration
from pajin.providers.usage import provider_model_usage_upper_bound
from pajin.runtime.control import BudgetController
from pajin.runtime.secrets import SecretBroker
from pajin.runtime.stable_context import stable_execution_context
from pajin.runtime.store import RunStore
from pajin.runtime.worker import DockerWorkerBackend, WorkerBackend, WorkerJob
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import ToolGateway
from pajin.web_assessment.analysis_proposal import build_web_analysis_snapshot
from pajin.web_assessment.analysis_runtime import (
    WebAnalysisInvocationPin,
    WebAnalysisProviderExecutionContext,
    WebAnalysisProviderRuntime,
    build_web_analysis_chat_request,
)
from pajin.web_assessment.analysis_transport import (
    WEB_ANALYSIS_PINNED_PROVIDER_ACTION,
    WebAnalysisTransportRuntimePin,
    bind_web_analysis_transport_job,
    expected_web_analysis_provider_worker_context,
    verify_web_analysis_provider_worker_context,
    verify_web_analysis_transport_runtime_pin,
)
from pajin.web_assessment.discovery_artifact import (
    VerifiedAuthenticatedDiscoveryRun,
    load_verified_authenticated_discovery,
)

WEB_ANALYSIS_LOCAL_PROVIDER_ID = "web-analysis-local"
WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT = ENDPOINT
WEB_ANALYSIS_LOCAL_SECRET_REF = "web-analysis/local-provider-api-key"
WEB_ANALYSIS_LOCAL_DURATION_SECONDS = 180
WEB_ANALYSIS_LOCAL_MAX_MODEL_TOKENS = 65_536

_DOCKER_OBJECT_ID_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_DOCKER_IMAGE_ID_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
_WORKER_EXECUTION_ID_PATTERN = re.compile(r"^exec_[a-f0-9]{32}$")
_PROVIDER_ACTION = "openai-chat-completion"
_FINALIZATION_ARTIFACT = "local-provider-finalization.json"
_FINALIZATION_EVENT = "web-analysis.local-provider.finalized"


class WebAnalysisLocalRuntimeError(ValueError):
    """Raised when a local-only WEB-007 Provider assembly fails closed."""


class _PinnedWebAnalysisProviderWorker:
    """Re-attest one exact Docker backend without replacing its host provenance."""

    def __init__(
        self,
        backend: DockerWorkerBackend,
        *,
        transport_pin: WebAnalysisTransportRuntimePin,
        expected_external_network: str,
        expected_context: dict[str, JsonValue],
    ) -> None:
        if type(backend) is not DockerWorkerBackend:
            raise TypeError("successor Provider Worker backend type differs")
        self.__backend = backend
        self.__transport_pin = transport_pin
        self.__expected_external_network = expected_external_network
        self.__expected_context = json.loads(
            json.dumps(
                expected_context,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        self._require_live_context()

    def stable_execution_context(self) -> dict[str, object]:
        verified = self._require_live_context()
        return cast(dict[str, object], verified["context"])

    def guard_dispatch(self, candidate: WorkerBackend) -> None:
        if candidate is not self.__backend:
            raise WebAnalysisLocalRuntimeError(
                "local WEB-007 successor Gateway Worker identity changed"
            )
        self._require_live_context()

    def _require_live_context(self) -> dict[str, JsonValue]:
        live = {
            "type": "pajin.runtime.worker.DockerWorkerBackend",
            "context": self.__backend.stable_execution_context(),
        }
        verified = verify_web_analysis_provider_worker_context(
            live,
            transport_pin=self.__transport_pin,
            expected_external_network=self.__expected_external_network,
        )
        if verified != self.__expected_context:
            raise WebAnalysisLocalRuntimeError(
                "local WEB-007 successor Worker changed after assembly"
            )
        return verified


class _PinnedWebAnalysisProviderTool(LocalEvaluationTool):
    """Bind the fixed model revision and weights alongside EFFECT runtime pins."""

    def __init__(
        self,
        registration: ProviderRegistration,
        runtime_pin: RuntimePin,
        model_pin: ModelPin,
        transport_pin: WebAnalysisTransportRuntimePin | None = None,
        expected_transport_pin_digest: str | None = None,
        provider_worker_context: dict[str, JsonValue] | None = None,
        provider_worker: _PinnedWebAnalysisProviderWorker | None = None,
        expected_external_network: str | None = None,
    ) -> None:
        super().__init__(registration, runtime_pin)
        self.model_pin = ModelPin.model_validate_json(model_pin.model_dump_json())
        successor_values = (
            transport_pin,
            expected_transport_pin_digest,
            provider_worker_context,
            provider_worker,
            expected_external_network,
        )
        if any(value is None for value in successor_values) and any(
            value is not None for value in successor_values
        ):
            raise WebAnalysisLocalRuntimeError(
                "local WEB-007 successor transport anchors must be supplied together"
            )
        self.transport_pin = (
            verify_web_analysis_transport_runtime_pin(
                transport_pin,
                runtime=self.runtime,
                expected_pin_digest=cast(str, expected_transport_pin_digest),
            )
            if transport_pin is not None
            else None
        )
        self.expected_transport_pin_digest = expected_transport_pin_digest
        self.provider_worker = provider_worker
        self.expected_external_network = expected_external_network
        self.provider_worker_context = (
            verify_web_analysis_provider_worker_context(
                provider_worker_context,
                transport_pin=cast(WebAnalysisTransportRuntimePin, self.transport_pin),
                expected_external_network=cast(str, expected_external_network),
            )
            if provider_worker_context is not None
            else None
        )
        self.__closed = False
        self.__owned_execution_ids: tuple[str, ...] = ()
        self.__prepare_lock = Lock()

    @property
    def owned_execution_ids(self) -> tuple[str, ...]:
        """Return only IDs produced by this exact Tool instance's successful prepare."""

        with self.__prepare_lock:
            return _validated_execution_ids(self.__owned_execution_ids)

    def freeze_and_get_owned_execution_ids(self) -> tuple[str, ...]:
        """Close preparation atomically and return only already-owned Worker IDs."""

        with self.__prepare_lock:
            self.__closed = True
            return _validated_execution_ids(self.__owned_execution_ids)

    def prepare(self, request: ToolRequest) -> WorkerJob:
        with self.__prepare_lock:
            if self.__closed or self.__owned_execution_ids or self.execution_ids:
                raise WebAnalysisLocalRuntimeError(
                    "local WEB-007 Provider Tool is closed or already prepared"
                )
            if self.provider_worker is not None:
                self.provider_worker.stable_execution_context()
            job = super().prepare(request)
            if self.transport_pin is not None:
                job = bind_web_analysis_transport_job(
                    job,
                    runtime=self.runtime,
                    transport_pin=self.transport_pin,
                    expected_transport_pin_digest=cast(
                        str,
                        self.expected_transport_pin_digest,
                    ),
                )
            if (
                self.execution_ids != [job.execution_id]
                or _WORKER_EXECUTION_ID_PATTERN.fullmatch(job.execution_id) is None
            ):
                raise WebAnalysisLocalRuntimeError(
                    "local WEB-007 Provider Tool did not produce one exact Worker ID"
                )
            self.__owned_execution_ids = (job.execution_id,)
            return job

    def stable_execution_context(self) -> dict[str, object]:
        spec = self.spec.model_dump(mode="json")
        spec["categories"] = sorted(self.spec.categories)
        spec["evidence_types"] = sorted(self.spec.evidence_types)
        registration = self.registration
        registration_context = registration.model_dump(mode="json")
        registration_context["allowed_function_tools"] = sorted(registration.allowed_function_tools)
        context: dict[str, object] = {
            "implementationVersion": (
                "pajin.tool-adapter/web-analysis-transport-v2"
                if self.transport_pin is not None
                else "pajin.tool-adapter/v1"
            ),
            "spec": spec,
            "registration": registration_context,
            "effectModel": self.model_pin.model_dump(mode="json"),
            "effectRuntime": self.runtime.model_dump(mode="json"),
        }
        if self.transport_pin is not None:
            context["webAnalysisTransport"] = self.transport_pin.model_dump(
                mode="json",
                by_alias=True,
            )
            context["providerWorker"] = cast(
                dict[str, JsonValue],
                self.provider_worker_context,
            )
        return context


@dataclass(frozen=True, slots=True)
class LocalWebAnalysisProviderCleanup:
    """Immutable evidence that exact owned Docker resources were cleaned."""

    execution_ids: tuple[str, ...]
    lifecycle: Lifecycle


class LocalWebAnalysisProviderAssembly:
    """Provider runtime plus one exact, owned cleanup boundary."""

    __slots__ = (
        "__claim_lock",
        "__finalizer",
        "__skill_bound_claimed",
        "provider_runtime",
    )

    def __init__(
        self,
        *,
        provider_runtime: WebAnalysisProviderRuntime,
        finalizer: _OwnedLocalProviderFinalizer,
    ) -> None:
        self.provider_runtime = provider_runtime
        self.__finalizer = finalizer
        self.__claim_lock = Lock()
        self.__skill_bound_claimed = False

    def claim_skill_bound_invocation(self) -> None:
        """Atomically grant the single successor owner for this Provider authority."""

        with self.__claim_lock:
            if self.__skill_bound_claimed:
                raise WebAnalysisLocalRuntimeError(
                    "local Provider authority already has a Skill-bound invocation owner"
                )
            self.__skill_bound_claimed = True

    @property
    def execution_ids(self) -> tuple[str, ...]:
        """Return only the exact Worker IDs produced by the pinned Provider Tool."""

        return self.__finalizer.execution_ids

    def cleanup(self) -> LocalWebAnalysisProviderCleanup:
        """Clean the exact owned model/Worker resources once and verify the result."""

        return self.__finalizer.cleanup()


class _OwnedLocalProviderFinalizer:
    """One-shot exact-owner cleanup callback consumed by the invocation runtime."""

    __slots__ = (
        "__artifact_written",
        "__cleanup",
        "__event_written",
        "__execution_context",
        "__lock",
        "__model_runtime",
        "__registration",
        "__started_lifecycle",
        "__store",
        "__tool",
    )

    def __init__(
        self,
        *,
        registration: ProviderRegistration,
        execution_context: WebAnalysisProviderExecutionContext,
        tool: _PinnedWebAnalysisProviderTool,
        model_runtime: LocalModelRuntime,
        started_lifecycle: Lifecycle,
        store: RunStore,
    ) -> None:
        self.__registration = registration.model_copy(deep=True)
        self.__execution_context = WebAnalysisProviderExecutionContext.model_validate(
            execution_context.model_dump(mode="json", by_alias=True)
        )
        self.__tool = tool
        self.__model_runtime = model_runtime
        self.__started_lifecycle = _canonical_exact_model(
            started_lifecycle,
            Lifecycle,
            "initial model lifecycle",
        )
        self.__store = store
        self.__lock = Lock()
        self.__cleanup: LocalWebAnalysisProviderCleanup | None = None
        self.__artifact_written = False
        self.__event_written = False

    @property
    def execution_ids(self) -> tuple[str, ...]:
        return self.__tool.owned_execution_ids

    def finalize_provider_run(self) -> None:
        """Invocation callback: clean and append evidence; the runtime owns sealing."""

        self.cleanup()

    def cleanup(self) -> LocalWebAnalysisProviderCleanup:
        with self.__lock:
            if self.__cleanup is None:
                runtime_pin, model_pin, network_name, current_lifecycle = (
                    _require_started_model_runtime(self.__model_runtime)
                )
                if (
                    runtime_pin != self.__execution_context.effect_runtime_pin
                    or model_pin != self.__execution_context.model_pin
                    or current_lifecycle != self.__started_lifecycle
                ):
                    raise WebAnalysisLocalRuntimeError(
                        "local WEB-007 model runtime changed after assembly"
                    )
                execution_ids = self.__tool.freeze_and_get_owned_execution_ids()
                self.__model_runtime.cleanup(list(execution_ids))
                lifecycle = _require_cleaned_model_runtime(
                    self.__model_runtime,
                    runtime_pin=runtime_pin,
                    model_pin=model_pin,
                    network_name=network_name,
                    started_lifecycle=self.__started_lifecycle,
                    execution_ids=execution_ids,
                )
                self.__cleanup = LocalWebAnalysisProviderCleanup(
                    execution_ids=execution_ids,
                    lifecycle=lifecycle,
                )
            cleanup = self.__cleanup
            artifact = {
                "apiVersion": "pajin.dev/web-analysis-local-provider-finalization/v1alpha1",
                "kind": "WebAnalysisLocalProviderFinalization",
                "providerRunId": self.__store.run_id,
                "providerId": self.__registration.provider_id,
                "providerExecutionContextId": self.__execution_context.context_id,
                "providerExecutionContextDigest": self.__execution_context.context_digest,
                "executionIds": list(cleanup.execution_ids),
                "lifecycle": cleanup.lifecycle.model_dump(mode="json"),
                "cleanupObserved": True,
                "externalDeliveryPerformed": False,
            }
            event = {
                "providerExecutionContextId": self.__execution_context.context_id,
                "providerExecutionContextDigest": self.__execution_context.context_digest,
                "executionIds": list(cleanup.execution_ids),
                "cleanupObserved": True,
                "externalDeliveryPerformed": False,
            }
            if not self.__artifact_written:
                self.__store.write_json_create_only(_FINALIZATION_ARTIFACT, artifact)
                self.__artifact_written = True
            if not self.__event_written:
                self.__store.append_event(_FINALIZATION_EVENT, event)
                self.__event_written = True
            return cleanup


def build_local_web_analysis_provider_runtime(
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    expected_run_id: str,
    expected_root_digest: str,
    model_runtime: LocalModelRuntime,
    api_key: str,
    provider_store_root: Path,
    analysis_output_root: Path,
    transport_pin: WebAnalysisTransportRuntimePin | None = None,
    expected_transport_pin_digest: str | None = None,
) -> LocalWebAnalysisProviderAssembly:
    """Build one source-bound local Provider runtime without starting Docker resources.

    The caller-supplied Run/root anchors must independently match ``source``. ``model_runtime``
    must be an already-started, healthy EFFECT-001 runtime on its owned internal Docker network.
    The returned runtime can dispatch only the pinned OpenAI-compatible Provider Tool to the fixed
    model endpoint; it carries no browser, assessment-target, arbitrary private-network, or
    function-tool authority.
    """

    try:
        verified_source = _require_current_discovery_source(
            source,
            expected_run_id=expected_run_id,
            expected_root_digest=expected_root_digest,
        )
        pin, selected_model, selected_network, started_lifecycle = _require_started_model_runtime(
            model_runtime
        )
        if (transport_pin is None) != (expected_transport_pin_digest is None):
            raise ValueError(
                "Web analysis transport Pin and independent digest must be supplied together"
            )
        canonical_transport_pin = None
        if transport_pin is not None:
            canonical_transport_pin = verify_web_analysis_transport_runtime_pin(
                transport_pin,
                runtime=pin,
                expected_pin_digest=cast(str, expected_transport_pin_digest),
            )
        provider_root = _require_separate_output_root(
            provider_store_root,
            source_path=verified_source.run_path,
            label="Provider store root",
        )
        analysis_root = _require_separate_output_root(
            analysis_output_root,
            source_path=verified_source.run_path,
            label="analysis output root",
        )

        registration = build_local_web_analysis_provider_registration(
            runtime=pin,
            model=selected_model,
        )
        _require_request_fits_model_budget(
            verified_source,
            registration=registration,
            expected_run_id=expected_run_id,
            expected_root_digest=expected_root_digest,
        )
        secrets = SecretBroker()
        secrets.register(registration.secret_ref, api_key)
        worker = DockerWorkerBackend(
            allowed_images={
                canonical_transport_pin.worker_image
                if canonical_transport_pin is not None
                else pin.worker_image
            },
            egress_proxy_image=(
                canonical_transport_pin.proxy_image
                if canonical_transport_pin is not None
                else pin.proxy_image
            ),
            external_network=selected_network,
            external_network_routes={
                (
                    WEB_ANALYSIS_PINNED_PROVIDER_ACTION
                    if canonical_transport_pin is not None
                    else _PROVIDER_ACTION
                ): selected_network
            },
        )
        provider_worker_context = None
        provider_worker = None
        if canonical_transport_pin is not None:
            provider_worker_context = _json_safe_provider_worker_context(
                worker,
                transport_pin=canonical_transport_pin,
                external_network=selected_network,
            )
            provider_worker = _PinnedWebAnalysisProviderWorker(
                worker,
                transport_pin=canonical_transport_pin,
                expected_external_network=selected_network,
                expected_context=provider_worker_context,
            )
        tool = _PinnedWebAnalysisProviderTool(
            registration,
            pin,
            selected_model,
            canonical_transport_pin,
            expected_transport_pin_digest,
            provider_worker_context,
            provider_worker,
            selected_network if canonical_transport_pin is not None else None,
        )
        tool_context = _json_safe_provider_tool_context(tool)
        execution_context = WebAnalysisProviderExecutionContext(
            providerId=registration.provider_id,
            model=registration.model,
            toolId=tool.spec.tool_id,
            effectRuntimePin=pin,
            modelPin=selected_model,
            invocationPin=WebAnalysisInvocationPin(),
            toolStableExecutionContext=tool_context,
            secretMaterialEmbedded=False,
            executionAuthority=False,
        )
        registry = ToolRegistry()
        registry.register(tool)

        issued_at = datetime.now(UTC)
        campaign = _local_analysis_campaign(verified_source, issued_at=issued_at)
        budget = BudgetController(campaign.spec.budgets)
        ledger = CapabilityLedger(max_depth=1)
        root_grant = ledger.issue_root(
            campaign,
            subject="controller:web-analysis-local",
            tools={tool.spec.tool_id},
            targets={WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT},
        )
        grant = ledger.delegate(
            root_grant.grant_id,
            subject=f"agent:web-analysis-{verified_source.index.index_digest[:16]}",
            tools={tool.spec.tool_id},
            targets={WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT},
            max_risk_tier=ToolRiskTier.T1,
            max_calls=1,
            expires_at=campaign.spec.authorization.expires_at,
        )

        store = RunStore.create(provider_root, campaign.metadata.name)
        gateway = ToolGateway(
            policy=PolicyEngine(),
            tools=registry,
            worker=worker,
            store=store,
            secrets=secrets,
            worker_dispatch_guard=(
                provider_worker.guard_dispatch if provider_worker is not None else None
            ),
        )
        finalizer = _OwnedLocalProviderFinalizer(
            registration=registration,
            execution_context=execution_context,
            tool=tool,
            model_runtime=model_runtime,
            started_lifecycle=started_lifecycle,
            store=store,
        )
        provider_runtime = WebAnalysisProviderRuntime(
            registration=registration,
            campaign=campaign,
            grant=grant,
            ledger=ledger,
            budget=budget,
            gateway=gateway,
            store=store,
            analysis_output_root=analysis_root,
            execution_context=execution_context,
            finalize_provider_run=finalizer.finalize_provider_run,
        )
        return LocalWebAnalysisProviderAssembly(
            provider_runtime=provider_runtime,
            finalizer=finalizer,
        )
    except WebAnalysisLocalRuntimeError:
        raise
    except Exception as exc:
        raise WebAnalysisLocalRuntimeError(
            "local WEB-007 Provider runtime construction failed closed"
        ) from exc


def _require_current_discovery_source(
    source: VerifiedAuthenticatedDiscoveryRun,
    *,
    expected_run_id: str,
    expected_root_digest: str,
) -> VerifiedAuthenticatedDiscoveryRun:
    if type(source) is not VerifiedAuthenticatedDiscoveryRun:
        raise WebAnalysisLocalRuntimeError(
            "local WEB-007 runtime requires the exact verified discovery source type"
        )
    if (
        type(expected_run_id) is not str
        or type(expected_root_digest) is not str
        or expected_run_id != source.verification.run_id
        or expected_root_digest != source.verification.root_digest
    ):
        raise WebAnalysisLocalRuntimeError(
            "local WEB-007 independent discovery anchors differ from the supplied source"
        )
    try:
        loaded = load_verified_authenticated_discovery(
            source.run_path,
            expected_run_id=expected_run_id,
            expected_root_digest=expected_root_digest,
        )
    except Exception as exc:
        raise WebAnalysisLocalRuntimeError(
            "local WEB-007 runtime could not reload the sealed discovery source"
        ) from exc
    if type(loaded) is not VerifiedAuthenticatedDiscoveryRun or loaded != source:
        raise WebAnalysisLocalRuntimeError(
            "local WEB-007 runtime discovery source changed during strict reload"
        )
    return loaded


def _require_started_model_runtime(
    value: LocalModelRuntime,
) -> tuple[RuntimePin, ModelPin, str, Lifecycle]:
    if type(value) is not LocalModelRuntime:
        raise WebAnalysisLocalRuntimeError(
            "local WEB-007 requires the exact started EFFECT-001 model runtime type"
        )
    runtime_pin = _canonical_exact_model(value.runtime, RuntimePin, "runtime pin")
    model_pin = _canonical_exact_model(value.model, ModelPin, "model pin")
    lifecycle = _canonical_exact_model(value.lifecycle, Lifecycle, "model lifecycle")
    if model_pin not in model_pins():
        raise WebAnalysisLocalRuntimeError(
            "local WEB-007 model pin is not in the installed immutable model allowlist"
        )

    owner = lifecycle.owner
    expected_label = f"pajin.effect-001-owner={owner}"
    expected_network = f"pajin-effect-{owner}"
    expected_container = f"pajin-effect-model-{owner}"
    if (
        value.owner != owner
        or value.label != expected_label
        or value.network_name != expected_network
        or value.container_name != expected_container
        or lifecycle.container_id is None
        or _DOCKER_OBJECT_ID_PATTERN.fullmatch(lifecycle.container_id) is None
        or lifecycle.network_id is None
        or _DOCKER_OBJECT_ID_PATTERN.fullmatch(lifecycle.network_id) is None
        or lifecycle.model_image_id is None
        or _DOCKER_IMAGE_ID_PATTERN.fullmatch(lifecycle.model_image_id) is None
        or lifecycle.healthy is not True
        or lifecycle.startup_seconds <= 0
        or lifecycle.internal_network is not True
        or lifecycle.published_ports is not False
        or lifecycle.read_only is not True
        or lifecycle.memory_bytes != runtime_pin.model_memory_mb * 1024 * 1024
        or lifecycle.nano_cpus != runtime_pin.model_cpus * 1_000_000_000
        or lifecycle.pids_limit != runtime_pin.model_pids
        or lifecycle.cleanup_observed is not False
        or lifecycle.remaining_containers
        or lifecycle.remaining_networks
    ):
        raise WebAnalysisLocalRuntimeError(
            "local WEB-007 model runtime is not a healthy owned internal lifecycle"
        )
    return runtime_pin, model_pin, expected_network, lifecycle


def _validated_execution_ids(values: tuple[str, ...]) -> tuple[str, ...]:
    if type(values) is not tuple:
        raise WebAnalysisLocalRuntimeError(
            "local WEB-007 Provider Tool execution ID collection differs"
        )
    execution_ids = values
    if (
        len(execution_ids) > 1
        or len(set(execution_ids)) != len(execution_ids)
        or any(
            type(value) is not str or _WORKER_EXECUTION_ID_PATTERN.fullmatch(value) is None
            for value in execution_ids
        )
    ):
        raise WebAnalysisLocalRuntimeError(
            "local WEB-007 Provider Tool execution IDs exceed exact owned authority"
        )
    return execution_ids


def _require_cleaned_model_runtime(
    value: LocalModelRuntime,
    *,
    runtime_pin: RuntimePin,
    model_pin: ModelPin,
    network_name: str,
    started_lifecycle: Lifecycle,
    execution_ids: tuple[str, ...],
) -> Lifecycle:
    if type(value) is not LocalModelRuntime:
        raise WebAnalysisLocalRuntimeError(
            "local WEB-007 cleanup changed the EFFECT-001 model runtime type"
        )
    current_runtime = _canonical_exact_model(value.runtime, RuntimePin, "runtime pin")
    current_model = _canonical_exact_model(value.model, ModelPin, "model pin")
    lifecycle = _canonical_exact_model(value.lifecycle, Lifecycle, "model lifecycle")
    owner = lifecycle.owner
    if (
        current_runtime != runtime_pin
        or current_model != model_pin
        or value.owner != owner
        or value.label != f"pajin.effect-001-owner={owner}"
        or network_name != f"pajin-effect-{owner}"
        or value.network_name != network_name
        or value.container_name != f"pajin-effect-model-{owner}"
        or any(
            getattr(lifecycle, field_name) != getattr(started_lifecycle, field_name)
            for field_name in Lifecycle.model_fields
            if field_name
            not in {
                "cleanup_observed",
                "execution_ids",
                "remaining_containers",
                "remaining_networks",
            }
        )
        or lifecycle.execution_ids != execution_ids
        or lifecycle.cleanup_observed is not True
        or lifecycle.clean is not True
    ):
        raise WebAnalysisLocalRuntimeError(
            "local WEB-007 owned model runtime cleanup evidence differs"
        )
    return lifecycle


def _canonical_exact_model[T: BaseModel](value: T, model: type[T], label: str) -> T:
    if type(value) is not model or set(vars(value)) != set(model.model_fields):
        raise WebAnalysisLocalRuntimeError(f"local WEB-007 {label} type or state differs")
    try:
        canonical = model.model_validate_json(value.model_dump_json())
    except Exception as exc:
        raise WebAnalysisLocalRuntimeError(f"local WEB-007 {label} is invalid") from exc
    if canonical != value:
        raise WebAnalysisLocalRuntimeError(f"local WEB-007 {label} differs after strict reload")
    return canonical


def _require_request_fits_model_budget(
    source: VerifiedAuthenticatedDiscoveryRun,
    *,
    registration: ProviderRegistration,
    expected_run_id: str,
    expected_root_digest: str,
) -> None:
    snapshot = build_web_analysis_snapshot(
        source,
        expected_run_id=expected_run_id,
        expected_root_digest=expected_root_digest,
    )
    request = build_web_analysis_chat_request(snapshot)
    require_local_web_analysis_request_fits_model_budget(
        request,
        registration=registration,
    )


def build_local_web_analysis_provider_registration(
    *,
    runtime: RuntimePin,
    model: ModelPin,
) -> ProviderRegistration:
    """Reconstruct the one code-owned local Provider registration before startup."""

    canonical_runtime = RuntimePin.model_validate_json(runtime.model_dump_json())
    canonical_model = ModelPin.model_validate_json(model.model_dump_json())
    return ProviderRegistration(
        provider_id=WEB_ANALYSIS_LOCAL_PROVIDER_ID,
        endpoint=AnyHttpUrl(WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT),
        model=canonical_model.name,
        secret_ref=WEB_ANALYSIS_LOCAL_SECRET_REF,
        allow_streaming=False,
        allowed_function_tools=set(),
        lease_ttl_seconds=canonical_runtime.request_timeout_seconds,
        allow_private_networks=True,
        input_cost_per_million_usd=0,
        output_cost_per_million_usd=0,
    )


def require_local_web_analysis_request_fits_model_budget(
    request: ProviderChatRequest,
    *,
    registration: ProviderRegistration,
) -> None:
    """Reject any local Provider request whose conservative bound exceeds its Campaign."""

    canonical_request = ProviderChatRequest.model_validate(request.model_dump(mode="python"))
    canonical_registration = ProviderRegistration.model_validate(
        registration.model_dump(mode="python")
    )
    upper_bound = provider_model_usage_upper_bound(canonical_registration, canonical_request)
    if (
        upper_bound.prompt_tokens + upper_bound.completion_tokens
        > WEB_ANALYSIS_LOCAL_MAX_MODEL_TOKENS
    ):
        raise WebAnalysisLocalRuntimeError(
            "local WEB-007 fixed Provider request exceeds its model-token budget"
        )


def require_local_web_analysis_request_fits_runtime_context(
    request: ProviderChatRequest,
    *,
    registration: ProviderRegistration,
    runtime: RuntimePin,
) -> None:
    """Fail closed unless the conservative request bound fits the pinned context."""

    canonical_request = ProviderChatRequest.model_validate(request.model_dump(mode="python"))
    canonical_registration = ProviderRegistration.model_validate(
        registration.model_dump(mode="python")
    )
    canonical_runtime = RuntimePin.model_validate_json(runtime.model_dump_json())
    upper_bound = provider_model_usage_upper_bound(canonical_registration, canonical_request)
    if upper_bound.prompt_tokens + upper_bound.completion_tokens > canonical_runtime.context_size:
        raise WebAnalysisLocalRuntimeError(
            "local WEB-007 fixed Provider request lacks a conservative proof that it fits "
            "the pinned model context"
        )


def _json_safe_provider_tool_context(
    tool: _PinnedWebAnalysisProviderTool,
) -> dict[str, JsonValue]:
    """Detach the stable Tool context through strict JSON before digest binding."""

    try:
        encoded = json.dumps(
            stable_execution_context(
                tool,
                component="local WEB-007 Provider Tool",
            ),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        decoded = json.loads(encoded)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WebAnalysisLocalRuntimeError(
            "local WEB-007 Provider Tool context is not strict JSON"
        ) from exc
    if type(decoded) is not dict:
        raise WebAnalysisLocalRuntimeError(
            "local WEB-007 Provider Tool context is not a JSON object"
        )
    return cast(dict[str, JsonValue], decoded)


def _json_safe_provider_worker_context(
    worker: DockerWorkerBackend,
    *,
    transport_pin: WebAnalysisTransportRuntimePin,
    external_network: str,
) -> dict[str, JsonValue]:
    """Bind the successor Tool to the actual configured Docker backend context."""

    try:
        raw = worker.stable_execution_context()
        encoded = json.dumps(
            {
                "type": "pajin.runtime.worker.DockerWorkerBackend",
                "context": raw,
            },
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        decoded = json.loads(encoded)
        expected = expected_web_analysis_provider_worker_context(
            transport_pin,
            external_network=external_network,
        )
        if decoded != expected:
            raise ValueError("configured Docker Worker context differs from successor Pin")
        return verify_web_analysis_provider_worker_context(
            decoded,
            transport_pin=transport_pin,
            expected_external_network=external_network,
        )
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WebAnalysisLocalRuntimeError(
            "local WEB-007 Provider Worker context is not the pinned successor backend"
        ) from exc


def _require_separate_output_root(
    value: Path,
    *,
    source_path: Path,
    label: str,
) -> Path:
    if not isinstance(value, Path):
        raise WebAnalysisLocalRuntimeError(f"{label} must be a filesystem Path")
    normalized = value.resolve(strict=False)
    sealed_source = source_path.resolve(strict=False)
    if normalized == sealed_source or sealed_source in normalized.parents:
        raise WebAnalysisLocalRuntimeError(f"{label} cannot be inside the sealed source Run")
    return normalized


def _local_analysis_campaign(
    source: VerifiedAuthenticatedDiscoveryRun,
    *,
    issued_at: datetime,
) -> CampaignManifest:
    source_digest = source.index.index_digest
    return CampaignManifest.model_validate(
        {
            "apiVersion": "pajin.dev/v1alpha1",
            "kind": "Campaign",
            "metadata": {"name": f"web-analysis-local-{source_digest[:12]}"},
            "spec": {
                "mode": "ai-redteam",
                "autonomy": "assisted",
                "authorization": {
                    "approvedBy": "local-web-analysis-operator",
                    "approvedAt": issued_at,
                    "expiresAt": issued_at + timedelta(seconds=WEB_ANALYSIS_LOCAL_DURATION_SECONDS),
                    "evidence": f"sealed-authenticated-discovery:{source_digest}",
                },
                "targets": [
                    {
                        "type": "local-llm",
                        "id": WEB_ANALYSIS_LOCAL_PROVIDER_ID,
                        "endpoint": WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT,
                    }
                ],
                "scope": {"allow": [WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT], "deny": []},
                "accessProfile": "sealed-discovery-analysis",
                "objectives": [
                    "Rank and assess every installed WEB-007 hypothesis without execution"
                ],
                "rulesOfEngagement": {
                    "maxToolRiskTier": "T1",
                    "allowedMethods": ["POST"],
                    "allowedToolCategories": ["chat-completions", "model-provider"],
                    "prohibit": ["browser", "shell", "target-execution"],
                    "allowPrivateNetworks": True,
                    "maxRequestsPerMinute": 1,
                },
                "budgets": {
                    "durationSeconds": WEB_ANALYSIS_LOCAL_DURATION_SECONDS,
                    "maxCostUsd": 0,
                    "maxAgents": 1,
                    "maxSpawnDepth": 0,
                    "maxToolCalls": 1,
                    "maxModelCalls": 1,
                    "maxModelTokens": WEB_ANALYSIS_LOCAL_MAX_MODEL_TOKENS,
                },
                "outputs": [],
            },
        }
    )


__all__ = [
    "WEB_ANALYSIS_LOCAL_DURATION_SECONDS",
    "WEB_ANALYSIS_LOCAL_MAX_MODEL_TOKENS",
    "WEB_ANALYSIS_LOCAL_PROVIDER_ENDPOINT",
    "WEB_ANALYSIS_LOCAL_PROVIDER_ID",
    "WEB_ANALYSIS_LOCAL_SECRET_REF",
    "LocalWebAnalysisProviderAssembly",
    "LocalWebAnalysisProviderCleanup",
    "WebAnalysisLocalRuntimeError",
    "build_local_web_analysis_provider_registration",
    "build_local_web_analysis_provider_runtime",
    "require_local_web_analysis_request_fits_model_budget",
    "require_local_web_analysis_request_fits_runtime_context",
]
