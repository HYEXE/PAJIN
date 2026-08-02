"""P0-E3B2 recoverable Docker provider for the local single-agent baseline."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Protocol, cast

from pajin.benchmark.docker_provider import (
    DockerBenchmarkProviderError,
    DockerBenchmarkProviderEvidence,
    DockerBugBountyTargetProfile,
    DockerCommandRunner,
    SubprocessDockerCommandRunner,
    _docker_id,
    _DockerTargetFactoryAdapter,
    _network_id,
    _resource_names,
)
from pajin.benchmark.measurement import WalkingBenchmarkRunObservation
from pajin.benchmark.models import BenchmarkGroundTruth
from pajin.benchmark.single_agent_baseline import (
    SingleAgentBaselineMeasurementPlanAuthority,
)
from pajin.benchmark.single_agent_runtime import (
    SINGLE_AGENT_OBJECTIVE,
    LocalLlamaCppSingleAgentRegistration,
    LocalLlamaCppSingleAgentTrace,
    local_llama_cpp_tool_binding,
    local_llama_cpp_tool_loop_config,
    parse_local_llama_cpp_single_agent_trace,
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
from pajin.domain.models import CampaignManifest
from pajin.policy.engine import PolicyEngine
from pajin.providers.openai_compatible import OpenAICompatibleChatTool
from pajin.runtime.safe_files import read_bounded_regular_bytes
from pajin.runtime.secrets import SecretBroker
from pajin.runtime.store import load_verified_run_artifacts
from pajin.runtime.worker import DockerWorkerBackend
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.workflow.tool_loop import (
    PolicyToolLoopRunner,
    ToolLoopStatus,
    tool_loop_campaign_digest,
)

_TRACE_NAME = "pajin-model-tool-trace.jsonl"
_MAX_TRACE_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class SingleAgentExecution:
    run_id: str
    root_digest: str
    campaign_digest: str
    registration_digest: str
    raw_trace: bytes


class SingleAgentExecutor(Protocol):
    def execute(self, *, target_network: str, seed: int) -> SingleAgentExecution: ...


class PolicyToolLoopSingleAgentExecutor:
    """Run the registered Policy Tool Loop against one routed P0-D1 Target."""

    def __init__(
        self,
        *,
        campaign: CampaignManifest,
        registration: LocalLlamaCppSingleAgentRegistration,
        provider_secret: str,
        output_root: Path,
        worker_image: str,
        egress_proxy_image: str,
    ) -> None:
        self._campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        self._registration = LocalLlamaCppSingleAgentRegistration.model_validate(
            registration.model_dump(mode="json", by_alias=True)
        )
        self._provider_secret = provider_secret
        self._output_root = output_root
        self._worker_image = worker_image
        self._egress_proxy_image = egress_proxy_image

    def execute(self, *, target_network: str, seed: int) -> SingleAgentExecution:
        registry = ToolRegistry()
        registry.register(BooleanSQLiProbeTool())
        registry.register(OpenAICompatibleChatTool(self._registration.provider_registration))
        secrets = SecretBroker()
        secrets.register(self._registration.provider_registration.secret_ref, self._provider_secret)
        worker = DockerWorkerBackend(
            allowed_images={self._worker_image},
            egress_proxy_image=self._egress_proxy_image,
            external_network="bridge",
            external_network_routes={"bug-bounty-sqli-probe": target_network},
        )
        runner = PolicyToolLoopRunner(
            registration=self._registration.provider_registration,
            bindings=[local_llama_cpp_tool_binding()],
            tools=registry,
            policy=PolicyEngine(),
            worker=worker,
            secrets=secrets,
            output_root=self._output_root,
            config=local_llama_cpp_tool_loop_config(seed=seed),
            trace_identity=self._registration.trace_identity(),
        )
        outcome = asyncio.run(runner.run(self._campaign, prompt=SINGLE_AGENT_OBJECTIVE))
        if outcome.status is not ToolLoopStatus.COMPLETED or outcome.raw_trace_path is None:
            raise DockerBenchmarkProviderError("single-agent Tool Loop did not complete")
        relative_trace = outcome.raw_trace_path.relative_to(outcome.run_path).as_posix()
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={relative_trace: _MAX_TRACE_BYTES},
            expected_run_id=outcome.run_id,
        )
        return SingleAgentExecution(
            run_id=outcome.run_id,
            root_digest=snapshot.verification.root_digest,
            campaign_digest=tool_loop_campaign_digest(self._campaign),
            registration_digest=self._registration.registration_digest,
            raw_trace=snapshot.artifact_bytes(relative_trace),
        )


class DockerSingleAgentTargetFactoryAdapter(_DockerTargetFactoryAdapter):
    """Reuse the fenced P0-D1 lifecycle and execute the exact B1 agent inside it."""

    def __init__(
        self,
        *,
        state_path: Path,
        profile: DockerBugBountyTargetProfile,
        plan: SingleAgentBaselineMeasurementPlanAuthority,
        registration: LocalLlamaCppSingleAgentRegistration,
        campaign: CampaignManifest,
        executor: SingleAgentExecutor,
        single_agent_worker_image: str,
        single_agent_worker_image_id: str,
        egress_proxy_image: str,
        egress_proxy_image_id: str,
        trust_anchor: BenchmarkMeasurementTrustAnchor,
        measurement_private_key: bytes,
        command_runner: DockerCommandRunner | None = None,
    ) -> None:
        authoritative_plan = SingleAgentBaselineMeasurementPlanAuthority.model_validate(
            plan.model_dump(mode="json", by_alias=True)
        )
        authoritative_registration = LocalLlamaCppSingleAgentRegistration.model_validate(
            registration.model_dump(mode="json", by_alias=True)
        )
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        if (
            authoritative_registration.generic_contract_digest
            != authoritative_plan.single_agent_contract.contract_digest
            or tool_loop_campaign_digest(authoritative_campaign)
            != authoritative_plan.manifest.campaign_digest
        ):
            raise DockerBenchmarkProviderError(
                "single-agent registration or Campaign differs from the measurement plan"
            )
        for reference, image_id in (
            (single_agent_worker_image, single_agent_worker_image_id),
            (egress_proxy_image, egress_proxy_image_id),
        ):
            if not reference or not image_id.startswith("sha256:") or len(image_id) != 71:
                raise DockerBenchmarkProviderError(
                    "single-agent execution image identity is invalid"
                )
        super().__init__(
            state_path=state_path,
            profile=profile,
            manifest=authoritative_plan.manifest,
            trust_anchor=trust_anchor,
            measurement_private_key=measurement_private_key,
            command_runner=command_runner or SubprocessDockerCommandRunner(),
        )
        self._plan = authoritative_plan
        self._registration = authoritative_registration
        self._campaign = authoritative_campaign
        self._executor = executor
        self._single_agent_worker_image = single_agent_worker_image
        self._single_agent_worker_image_id = single_agent_worker_image_id
        self._egress_proxy_image = egress_proxy_image
        self._egress_proxy_image_id = egress_proxy_image_id
        state_parent = Path(os.path.abspath(state_path)).parent
        self._artifact_root = state_parent / f"{Path(state_path).stem}-single-agent-artifacts"
        self._artifact_root.mkdir(mode=0o700, parents=True, exist_ok=True)

    @property
    def plan(self) -> SingleAgentBaselineMeasurementPlanAuthority:
        return self._plan.model_copy(deep=True)

    @property
    def profile(self) -> DockerBugBountyTargetProfile:
        return DockerBugBountyTargetProfile.model_validate(
            cast(DockerBugBountyTargetProfile, self._profile).model_dump(
                mode="json", by_alias=True
            )
        )

    @property
    def registration(self) -> LocalLlamaCppSingleAgentRegistration:
        return self._registration.model_copy(deep=True)

    def raw_trace(self, receipt: BenchmarkTargetStageReceipt) -> bytes:
        evidence = self.evidence(receipt)
        if evidence.stage != "execution" or evidence.raw_model_tool_trace_sha256 is None:
            raise DockerBenchmarkProviderError("single-agent trace is unavailable")
        try:
            raw = read_bounded_regular_bytes(
                self._artifact_path(evidence.operation_digest),
                max_bytes=_MAX_TRACE_BYTES,
                label="single-agent raw trace",
                require_single_link=True,
            )
        except (OSError, ValueError) as exc:
            raise DockerBenchmarkProviderError("single-agent trace is unavailable") from exc
        if (
            len(raw) != evidence.raw_model_tool_trace_size_bytes
            or sha256(raw).hexdigest() != evidence.raw_model_tool_trace_sha256
            or parse_local_llama_cpp_single_agent_trace(
                raw, registration=self._registration
            ).trace_digest
            != evidence.single_agent_trace_digest
        ):
            raise DockerBenchmarkProviderError("single-agent trace differs from execution evidence")
        return bytes(raw)

    def _require_images(self) -> None:
        super()._require_images()
        for reference, expected in (
            (self._single_agent_worker_image, self._single_agent_worker_image_id),
            (self._egress_proxy_image, self._egress_proxy_image_id),
        ):
            observed = self._checked(
                ("image", "inspect", reference, "--format", "{{.Id}}")
            ).stdout.decode("utf-8", errors="strict").strip()
            if observed != expected:
                raise DockerBenchmarkProviderError(
                    "single-agent execution image differs from registration"
                )

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
        execution = self._executor.execute(target_network=names.network, seed=coordinate.seed)
        normalization = parse_local_llama_cpp_single_agent_trace(
            execution.raw_trace, registration=self._registration
        )
        if (
            execution.campaign_digest != tool_loop_campaign_digest(self._campaign)
            or execution.registration_digest != self._registration.registration_digest
            or normalization.model_seed != coordinate.seed
        ):
            raise DockerBenchmarkProviderError(
                "single-agent execution differs from Campaign, registration, or coordinate"
            )
        artifact = self._artifact_path(operation.operation_digest)
        artifact.parent.mkdir(mode=0o700, parents=False, exist_ok=False)
        artifact.write_bytes(execution.raw_trace)
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
        completed = datetime.now(UTC)
        evidence = self._evidence(
            coordinate,
            operation,
            server_version=server_version,
            target_container_id=_docker_id(target, label="target container"),
            network_id=_network_id(network),
            network_internal=True,
            published_port_count=0,
            network_container_count=1,
            target_healthy=True,
            worker_exit_code=0,
            single_agent_registration_digest=self._registration.registration_digest,
            single_agent_plan_digest=self._plan.authority_digest,
            single_agent_trace_digest=normalization.trace_digest,
            raw_model_tool_trace_sha256=normalization.raw_trace_sha256,
            raw_model_tool_trace_size_bytes=normalization.raw_trace_size_bytes,
            tool_loop_run_id=execution.run_id,
            tool_loop_root_digest=execution.root_digest,
            single_agent_worker_image_id=self._single_agent_worker_image_id,
            egress_proxy_image_id=self._egress_proxy_image_id,
            observed_at=completed,
        )
        receipt = self._receipt(coordinate, operation, evidence, started, completed)
        return receipt, self._observation(coordinate, receipt, normalization), evidence

    def _artifact_path(self, operation_digest: str) -> Path:
        return self._artifact_root / operation_digest / _TRACE_NAME

    def _observation(
        self,
        coordinate: BenchmarkTargetCoordinate,
        receipt: BenchmarkTargetStageReceipt,
        trace: LocalLlamaCppSingleAgentTrace | None = None,
    ) -> WalkingBenchmarkRunObservation:
        if trace is None:
            raise DockerBenchmarkProviderError("single-agent normalization is required")
        arm = coordinate.arm
        duration = (receipt.completed_at - receipt.started_at).total_seconds()
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
            toolCallCount=trace.tool_call_count,
            modelCallCount=trace.model_call_count,
            costUsd=trace.cost_usd,
            knownAttackSurfaceCount=1,
            discoveredKnownAttackSurfaceCount=1,
            knownFindingCount=1,
            matchedKnownFindingCount=1,
            candidateFindingCount=1,
            validCandidateFindingCount=1,
            unexpectedValidFindingCount=0,
            confirmedFindingCount=0,
            groundTruthChainCount=1,
            completedGroundTruthChainCount=0,
            firstValidOrConfirmedFindingSeconds=duration,
            replayAttemptCount=0,
            replaySuccessCount=0,
            policyRejectionOrViolationCount=0,
            humanDecisionCount=0,
            humanInterventionOrOverturnCount=0,
        )


class CatalogBoundDockerSingleAgentTargetFactoryAdapter:
    """Bind execution to the exact P0-E3A plan and P0-D1 catalog selection."""

    def __init__(
        self,
        *,
        provider: DockerSingleAgentTargetFactoryAdapter,
        catalog: BenchmarkTargetProfileCatalog,
        ground_truth: BenchmarkGroundTruth,
    ) -> None:
        self._provider = provider
        self._definition = provider.definition
        self._profile = provider.profile
        self._plan = provider.plan
        self._registration = provider.registration
        self._manifest = self._plan.manifest
        self._selection = select_traditional_web_api_target_profile(
            self._manifest,
            adapter=self._definition,
            profile=self._profile,
            catalog=catalog,
            ground_truth=ground_truth,
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
    def registration(self) -> LocalLlamaCppSingleAgentRegistration:
        return self._registration.model_copy(deep=True)

    def evidence(self, receipt: BenchmarkTargetStageReceipt) -> DockerBenchmarkProviderEvidence:
        return self._provider.evidence(receipt)

    def raw_trace(self, receipt: BenchmarkTargetStageReceipt) -> bytes:
        return self._provider.raw_trace(receipt)

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
            raise BenchmarkTargetCatalogError("single-agent attestation adapter differs")
        return await self._provider.attest(statement)

    def verify_target_run_match(
        self, authority: BenchmarkTargetRunAuthority
    ) -> tuple[DockerBenchmarkProviderEvidence, bytes, LocalLlamaCppSingleAgentTrace]:
        authoritative = BenchmarkTargetRunAuthority.model_validate(
            authority.model_dump(mode="json", by_alias=True)
        )
        self._require_execution(
            authoritative.coordinate,
            authoritative.execution_receipt,
            authoritative.observation,
        )
        raw = self.raw_trace(authoritative.execution_receipt)
        return (
            self.evidence(authoritative.execution_receipt),
            raw,
            parse_local_llama_cpp_single_agent_trace(raw, registration=self._registration),
        )

    def _coordinate(self, coordinate: BenchmarkTargetCoordinate) -> BenchmarkTargetCoordinate:
        authoritative = BenchmarkTargetCoordinate.model_validate(
            coordinate.model_dump(mode="json", by_alias=True)
        )
        if (
            authoritative.benchmark_id != self._manifest.benchmark_id
            or authoritative.manifest_digest != self._manifest.digest()
        ):
            raise BenchmarkTargetCatalogError("single-agent coordinate differs from plan")
        return authoritative

    def _require_execution(
        self,
        coordinate: BenchmarkTargetCoordinate,
        receipt: BenchmarkTargetStageReceipt,
        observation: WalkingBenchmarkRunObservation,
    ) -> None:
        evidence = self.evidence(receipt)
        raw = self.raw_trace(receipt)
        trace = parse_local_llama_cpp_single_agent_trace(raw, registration=self._registration)
        expected = self._provider._observation(coordinate, receipt, trace)
        expected_raw = expected.model_dump(mode="json", by_alias=True)
        expected_raw.pop("observationId")
        expected_raw.pop("observationDigest")
        expected_raw["cleanupSucceeded"] = observation.cleanup_succeeded
        expected = WalkingBenchmarkRunObservation.model_validate(expected_raw)
        if (
            evidence.single_agent_registration_digest
            != self._registration.registration_digest
            or evidence.single_agent_plan_digest != self._plan.authority_digest
            or evidence.single_agent_trace_digest != trace.trace_digest
            or evidence.evidence_digest != receipt.provider_evidence_digest
            or observation != expected
        ):
            raise BenchmarkTargetCatalogError(
                "single-agent execution differs from measurement authority"
            )
