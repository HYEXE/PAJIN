from __future__ import annotations

import asyncio
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from test_benchmark_docker_provider import _FakeDocker
from test_benchmark_single_agent_runtime import _raw_trace

from pajin.benchmark import (
    BenchmarkArm,
    BenchmarkArmKind,
    BenchmarkManifest,
    BenchmarkMeasurementKeyState,
    BenchmarkMeasurementRegistryActivationStore,
    BenchmarkMeasurementRegistryDistributionKey,
    BenchmarkMeasurementRegistryDistributionSigner,
    BenchmarkMeasurementRegistryDistributionTrustAnchor,
    BenchmarkMeasurementRegistryKey,
    BenchmarkMeasurementTrustAnchor,
    BenchmarkMeasurementTrustRegistry,
    BenchmarkMetric,
    BenchmarkMetricStatus,
    BenchmarkRegistryGovernedHarnessRunner,
    BenchmarkRunProtocol,
    BenchmarkTargetFactoryError,
    CatalogBoundDockerSingleAgentTargetFactoryAdapter,
    DockerBenchmarkProviderError,
    DockerBugBountyTargetProfile,
    DockerSingleAgentTargetFactoryAdapter,
    PolicyToolLoopSingleAgentExecutor,
    RecoverableBenchmarkTargetFactoryRunner,
    RegisteredBenchmarkTargetFactoryAdapter,
    SingleAgentBaselineMeasurementError,
    SingleAgentBaselineMeasurementRunner,
    SingleAgentExecution,
    benchmark_measurement_public_key_base64url,
    benchmark_measurement_registry_distribution_public_key_base64url,
    load_single_agent_baseline_measurement_authority,
    plan_generic_single_agent_baseline,
    registered_generic_single_agent_adapter_contract,
    registered_local_llama_cpp_single_agent,
    registered_traditional_web_api_ground_truth,
    registered_traditional_web_api_target_catalog,
)
from pajin.benchmark.single_agent_runtime import LLAMA_CPP_IMAGE
from pajin.domain.models import CampaignManifest
from pajin.workflow.tool_loop import tool_loop_campaign_digest

NOW = datetime(2026, 8, 2, 9, 0, tzinfo=UTC)
MEASUREMENT_KEY = bytes(range(32))
DISTRIBUTION_KEY = bytes(range(32, 64))
TARGET_IMAGE_ID = "sha256:" + "a" * 64
BENCHMARK_WORKER_IMAGE_ID = "sha256:" + "b" * 64
LLAMA_IMAGE_ID = "sha256:" + "c" * 64
AGENT_WORKER_IMAGE_ID = "sha256:" + "d" * 64
PROXY_IMAGE_ID = "sha256:" + "e" * 64


class _FakeSingleAgentExecutor:
    def __init__(
        self,
        registration,
        *,
        trace_seed: int = 17,
        campaign_digest: str | None = None,
    ) -> None:
        self._raw = _raw_trace(registration, seed=trace_seed)
        self._registration_digest = registration.registration_digest
        self._campaign_digest = campaign_digest or tool_loop_campaign_digest(_campaign())

    def execute(self, *, target_network: str, seed: int) -> SingleAgentExecution:
        assert target_network.startswith("pajin-bench-")
        assert seed == 17
        return SingleAgentExecution(
            run_id="run_single_agent_fixture",
            root_digest="f" * 64,
            campaign_digest=self._campaign_digest,
            registration_digest=self._registration_digest,
            raw_trace=self._raw,
        )


def _campaign() -> CampaignManifest:
    return CampaignManifest.model_validate(
        {
            "apiVersion": "pajin.dev/v1alpha1",
            "kind": "Campaign",
            "metadata": {
                "name": "single-agent-benchmark",
                "description": "Bounded local single-agent measurement fixture.",
            },
            "spec": {
                "mode": "bug-bounty",
                "autonomy": "supervised",
                "authorization": {
                    "approvedBy": "local-project-owner",
                    "approvedAt": "2026-01-01T00:00:00Z",
                    "expiresAt": "2030-01-01T00:00:00Z",
                    "evidence": "local synthetic benchmark authorization",
                },
                "targets": [
                    {
                        "type": "synthetic-web-api",
                        "id": "boolean-sqli-lab",
                        "endpoint": "http://target:8080/v1/users/lookup",
                    }
                ],
                "scope": {
                    "allow": ["http://target:8080/v1/users/lookup"],
                    "deny": [],
                },
                "objectives": ["Measure the fixed local single-agent baseline."],
                "rulesOfEngagement": {
                    "maxToolRiskTier": "T2",
                    "allowedMethods": ["GET", "POST"],
                    "allowedToolCategories": [
                        "active-test",
                        "bug-bounty",
                        "http",
                        "injection",
                        "chat-completions",
                        "model-provider",
                    ],
                    "allowPrivateNetworks": True,
                },
                "budgets": {
                    "durationSeconds": 300,
                    "maxCostUsd": 0,
                    "maxToolCalls": 3,
                    "maxModelCalls": 2,
                    "maxModelTokens": 32768,
                },
            },
        }
    )


def _profile() -> DockerBugBountyTargetProfile:
    return DockerBugBountyTargetProfile(
        targetImage="pajin-bug-bounty-target:dev",
        targetImageId=TARGET_IMAGE_ID,
        workerImage="pajin-benchmark-worker:dev",
        workerImageId=BENCHMARK_WORKER_IMAGE_ID,
    )


def _anchor() -> BenchmarkMeasurementTrustAnchor:
    return BenchmarkMeasurementTrustAnchor(
        authorityId="measurement-authority:single-agent-baseline",
        authorityVersion="1.0.0",
        keyId="measurement-key:single-agent-baseline",
        publicKeyBase64url=benchmark_measurement_public_key_base64url(MEASUREMENT_KEY),
    )


def _plan(profile: DockerBugBountyTargetProfile, campaign: CampaignManifest):
    ground_truth = registered_traditional_web_api_ground_truth(
        profile, benchmark_id="benchmark:single-agent-baseline-v1"
    )
    definition = RegisteredBenchmarkTargetFactoryAdapter(
        adapterId="target-adapter:docker-bug-bounty",
        adapterVersion="1.0.0",
        targetFactoryId="target-factory:docker-bug-bounty",
        targetFactoryVersion=profile.profile_version,
        targetFactoryDigest=profile.target_factory_digest,
        measurementAuthorityId=_anchor().authority_id,
        measurementAuthorityVersion=_anchor().authority_version,
        measurementAuthorityDigest=_anchor().anchor_digest,
    )
    contract = registered_generic_single_agent_adapter_contract()
    manifest = BenchmarkManifest(
        benchmarkId=ground_truth.benchmark_id,
        targetFactoryId=definition.target_factory_id,
        targetFactoryVersion=definition.target_factory_version,
        targetFactoryDigest=definition.target_factory_digest,
        targetProfileId=profile.profile_id,
        targetProfileVersion=profile.profile_version,
        mutationProfileId=None,
        campaignDigest=tool_loop_campaign_digest(campaign),
        groundTruthDigest=ground_truth.digest(),
        protocol=BenchmarkRunProtocol(
            protocolId="pajin:single-agent-baseline-protocol",
            protocolVersion="1.0.0",
            seeds=[17],
            repetitionsPerSeed=1,
            timeoutSeconds=300,
            maxCostUsd=0,
            maxToolCalls=1,
            maxModelCalls=2,
        ),
        arms=[
            BenchmarkArm(
                armId="arm:generic-single-agent-baseline",
                kind=BenchmarkArmKind.DETERMINISTIC_BASELINE,
                implementationId=contract.benchmark_implementation_id,
                implementationVersion=contract.benchmark_implementation_version,
                configurationDigest=contract.benchmark_configuration_digest,
                adaptiveSupervisor=False,
            )
        ],
    )
    return (
        plan_generic_single_agent_baseline(
            manifest,
            adapter=definition,
            profile=profile,
            catalog=registered_traditional_web_api_target_catalog(profile, ground_truth),
            ground_truth=ground_truth,
        ),
        ground_truth,
    )


def _distribution():
    registry = BenchmarkMeasurementTrustRegistry(
        registryId="measurement-registry:single-agent-baseline",
        registryRevision=1,
        measurementAuthorityId=_anchor().authority_id,
        measurementAuthorityVersion=_anchor().authority_version,
        issuedAt=NOW - timedelta(minutes=10),
        keys=[
            BenchmarkMeasurementRegistryKey(
                trustAnchor=_anchor(),
                state=BenchmarkMeasurementKeyState.ACTIVE,
                notBefore=NOW - timedelta(hours=1),
            )
        ],
    )
    anchor = BenchmarkMeasurementRegistryDistributionTrustAnchor(
        trustDomain="benchmark-registry:single-agent-baseline",
        issuer="benchmark-registry-issuer:single-agent-baseline",
        keys=[
            BenchmarkMeasurementRegistryDistributionKey(
                keyId="distribution-key:single-agent-baseline",
                publicKeyBase64url=(
                    benchmark_measurement_registry_distribution_public_key_base64url(
                        DISTRIBUTION_KEY
                    )
                ),
                state=BenchmarkMeasurementKeyState.ACTIVE,
                notBefore=NOW - timedelta(hours=1),
            )
        ],
    )
    signer = BenchmarkMeasurementRegistryDistributionSigner.from_private_key_bytes(
        active_key_id=anchor.active_key.key_id,
        private_key=DISTRIBUTION_KEY,
        trust_anchor=anchor,
    )
    return anchor, signer.sign(
        registry=registry,
        issued_at=NOW - timedelta(minutes=1),
        not_before=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(days=1),
    )


def _run(
    tmp_path: Path,
    *,
    trace_seed: int = 17,
    execution_campaign_digest: str | None = None,
):
    campaign = _campaign()
    profile = _profile()
    plan, ground_truth = _plan(profile, campaign)
    registration = registered_local_llama_cpp_single_agent(
        plan.single_agent_contract, runtime_image_id=LLAMA_IMAGE_ID
    )
    docker = _FakeDocker()
    docker.image_ids.update(
        {
            "pajin-worker:dev": AGENT_WORKER_IMAGE_ID,
            "pajin-egress-proxy:dev": PROXY_IMAGE_ID,
        }
    )
    provider = DockerSingleAgentTargetFactoryAdapter(
        state_path=tmp_path / "provider.sqlite3",
        profile=profile,
        plan=plan,
        registration=registration,
        campaign=campaign,
        executor=_FakeSingleAgentExecutor(
            registration,
            trace_seed=trace_seed,
            campaign_digest=execution_campaign_digest,
        ),
        single_agent_worker_image="pajin-worker:dev",
        single_agent_worker_image_id=AGENT_WORKER_IMAGE_ID,
        egress_proxy_image="pajin-egress-proxy:dev",
        egress_proxy_image_id=PROXY_IMAGE_ID,
        trust_anchor=_anchor(),
        measurement_private_key=MEASUREMENT_KEY,
        command_runner=docker,
    )
    catalog_provider = CatalogBoundDockerSingleAgentTargetFactoryAdapter(
        provider=provider,
        catalog=registered_traditional_web_api_target_catalog(profile, ground_truth),
        ground_truth=ground_truth,
    )
    activation_store = BenchmarkMeasurementRegistryActivationStore(
        tmp_path / "registry.sqlite3"
    )
    distribution_anchor, bundle = _distribution()
    source = asyncio.run(
        BenchmarkRegistryGovernedHarnessRunner(
            output_root=tmp_path / "runs",
            activation_store=activation_store,
            bundle=bundle,
            distribution_trust_anchor=distribution_anchor,
            target_runner=RecoverableBenchmarkTargetFactoryRunner(
                output_root=tmp_path / "runs",
                journal_path=tmp_path / "journal.sqlite3",
                adapter=catalog_provider,
                trust_anchor=_anchor(),
            ),
        ).run(plan.manifest, arm_id=plan.manifest.arms[0].arm_id, seed=17, repetition=1)
    )
    return plan, catalog_provider, activation_store, distribution_anchor, source, provider


def test_single_agent_measurement_seals_completed_result_and_exact_trace(
    tmp_path: Path,
) -> None:
    plan, provider, store, anchor, source, _ = _run(tmp_path)
    outcome = SingleAgentBaselineMeasurementRunner(
        output_root=tmp_path / "measurement"
    ).run(
        plan,
        catalog_provider=provider,
        source_outcomes=(source,),
        activation_store=store,
        distribution_trust_anchor=anchor,
    )
    authority = load_single_agent_baseline_measurement_authority(
        plan,
        outcome,
        catalog_provider=provider,
        source_outcomes=(source,),
        activation_store=store,
        distribution_trust_anchor=anchor,
    )

    metrics = {item.metric: item for item in authority.baseline_result.metrics}
    assert authority.baseline_result.status.value == "completed"
    assert authority.sources[0].normalization.model_seed == 17
    assert authority.sources[0].normalization.model_call_count == 2
    assert metrics[BenchmarkMetric.ATTACK_SURFACE_RECALL].value == 1
    assert metrics[BenchmarkMetric.FINDING_RECALL].value == 1
    assert metrics[BenchmarkMetric.COST_PER_CONFIRMED_FINDING].status is (
        BenchmarkMetricStatus.NOT_APPLICABLE
    )
    assert authority.candidate_comparison_eligible is False
    assert authority.supervisor_activation_eligible is False


def test_single_agent_measurement_reader_rejects_provider_trace_mutation(
    tmp_path: Path,
) -> None:
    plan, catalog_provider, store, anchor, source, provider = _run(tmp_path)
    outcome = SingleAgentBaselineMeasurementRunner(
        output_root=tmp_path / "measurement"
    ).run(
        plan,
        catalog_provider=catalog_provider,
        source_outcomes=(source,),
        activation_store=store,
        distribution_trust_anchor=anchor,
    )
    evidence = provider.evidence(source.target.authority.execution_receipt)
    provider._artifact_path(evidence.operation_digest).write_bytes(b"{}\n")

    with pytest.raises(SingleAgentBaselineMeasurementError):
        load_single_agent_baseline_measurement_authority(
            plan,
            outcome,
            catalog_provider=catalog_provider,
            source_outcomes=(source,),
            activation_store=store,
            distribution_trust_anchor=anchor,
        )


def test_single_agent_provider_rejects_campaign_substitution(tmp_path: Path) -> None:
    campaign = _campaign()
    profile = _profile()
    plan, _ = _plan(profile, campaign)
    registration = registered_local_llama_cpp_single_agent(
        plan.single_agent_contract, runtime_image_id=LLAMA_IMAGE_ID
    )
    executor = _FakeSingleAgentExecutor(registration)
    substituted = campaign.model_copy(
        update={
            "metadata": campaign.metadata.model_copy(
                update={"description": "Substituted campaign."}
            )
        }
    )

    with pytest.raises(DockerBenchmarkProviderError, match="Campaign differs"):
        DockerSingleAgentTargetFactoryAdapter(
            state_path=tmp_path / "provider.sqlite3",
            profile=profile,
            plan=plan,
            registration=registration,
            campaign=substituted,
            executor=executor,
            single_agent_worker_image="pajin-worker:dev",
            single_agent_worker_image_id=AGENT_WORKER_IMAGE_ID,
            egress_proxy_image="pajin-egress-proxy:dev",
            egress_proxy_image_id=PROXY_IMAGE_ID,
            trust_anchor=_anchor(),
            measurement_private_key=MEASUREMENT_KEY,
        )


def test_single_agent_provider_rejects_trace_seed_substitution(tmp_path: Path) -> None:
    with pytest.raises(
        BenchmarkTargetFactoryError,
        match="execution failed after mandatory cleanup",
    ):
        _run(tmp_path, trace_seed=18)


def test_single_agent_provider_rejects_executor_campaign_substitution(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        BenchmarkTargetFactoryError,
        match="execution failed after mandatory cleanup",
    ):
        _run(tmp_path, execution_campaign_digest="a" * 64)


@pytest.mark.skipif(
    os.environ.get("PAJIN_TEST_DOCKER_SINGLE_AGENT") != "1",
    reason="real Docker local single-agent measurement is opt-in",
)
def test_real_docker_single_agent_measurement_conformance(tmp_path: Path) -> None:
    def image_id(reference: str) -> str:
        return subprocess.run(
            ["docker", "image", "inspect", reference, "--format", "{{.Id}}"],
            capture_output=True,
            check=True,
            text=True,
            timeout=30,
        ).stdout.strip()

    campaign = _campaign()
    profile = DockerBugBountyTargetProfile(
        targetImage="pajin-bug-bounty-target:dev",
        targetImageId=image_id("pajin-bug-bounty-target:dev"),
        workerImage="pajin-benchmark-worker:dev",
        workerImageId=image_id("pajin-benchmark-worker:dev"),
    )
    plan, ground_truth = _plan(profile, campaign)
    registration = registered_local_llama_cpp_single_agent(
        plan.single_agent_contract,
        runtime_image_id=image_id(LLAMA_CPP_IMAGE),
    )
    provider = DockerSingleAgentTargetFactoryAdapter(
        state_path=tmp_path / "provider.sqlite3",
        profile=profile,
        plan=plan,
        registration=registration,
        campaign=campaign,
        executor=PolicyToolLoopSingleAgentExecutor(
            campaign=campaign,
            registration=registration,
            provider_secret="pajin-local-single-agent-conformance-key",
            output_root=tmp_path / "tool-loop-runs",
            worker_image="pajin-worker:dev",
            egress_proxy_image="pajin-egress-proxy:dev",
        ),
        single_agent_worker_image="pajin-worker:dev",
        single_agent_worker_image_id=image_id("pajin-worker:dev"),
        egress_proxy_image="pajin-egress-proxy:dev",
        egress_proxy_image_id=image_id("pajin-egress-proxy:dev"),
        trust_anchor=_anchor(),
        measurement_private_key=MEASUREMENT_KEY,
    )
    catalog_provider = CatalogBoundDockerSingleAgentTargetFactoryAdapter(
        provider=provider,
        catalog=registered_traditional_web_api_target_catalog(profile, ground_truth),
        ground_truth=ground_truth,
    )
    activation_store = BenchmarkMeasurementRegistryActivationStore(
        tmp_path / "registry.sqlite3"
    )
    distribution_anchor, bundle = _distribution()
    source = asyncio.run(
        BenchmarkRegistryGovernedHarnessRunner(
            output_root=tmp_path / "runs",
            activation_store=activation_store,
            bundle=bundle,
            distribution_trust_anchor=distribution_anchor,
            target_runner=RecoverableBenchmarkTargetFactoryRunner(
                output_root=tmp_path / "runs",
                journal_path=tmp_path / "journal.sqlite3",
                adapter=catalog_provider,
                trust_anchor=_anchor(),
            ),
        ).run(plan.manifest, arm_id=plan.manifest.arms[0].arm_id, seed=17, repetition=1)
    )
    outcome = SingleAgentBaselineMeasurementRunner(
        output_root=tmp_path / "measurement"
    ).run(
        plan,
        catalog_provider=catalog_provider,
        source_outcomes=(source,),
        activation_store=activation_store,
        distribution_trust_anchor=distribution_anchor,
    )
    authority = load_single_agent_baseline_measurement_authority(
        plan,
        outcome,
        catalog_provider=catalog_provider,
        source_outcomes=(source,),
        activation_store=activation_store,
        distribution_trust_anchor=distribution_anchor,
    )
    assert authority.baseline_result.status.value == "completed"
    assert authority.sources[0].normalization.model_seed == 17
