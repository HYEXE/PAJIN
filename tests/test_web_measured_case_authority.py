from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from pydantic import ValidationError

from pajin.benchmark.docker_provider import DockerBugBountyTargetProfile
from pajin.benchmark.domain_metrics import DomainBenchmarkMetricApplicability
from pajin.benchmark.models import (
    BenchmarkArm,
    BenchmarkArmKind,
    BenchmarkManifest,
    BenchmarkRunProtocol,
)
from pajin.benchmark.scanner_baseline import (
    plan_generic_scanner_baseline,
    registered_generic_scanner_adapter_contract,
)
from pajin.benchmark.scanner_sarif import registered_zap_scanner
from pajin.benchmark.target_catalog import (
    registered_traditional_web_api_target_catalog,
)
from pajin.benchmark.target_factory import (
    BenchmarkMeasurementTrustAnchor,
    RegisteredBenchmarkTargetFactoryAdapter,
)
from pajin.capabilities.existing import existing_mode_capability_bundle
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleKeyRole,
    CapabilityLifecycleKeyState,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleRegistry,
    CapabilityLifecycleSigner,
    CapabilityLifecycleTrustKey,
    CapabilityReleaseBundle,
    CapabilityReleaseStatement,
    CapabilityReviewDecision,
    CapabilityReviewStatement,
    capability_lifecycle_public_key,
)
from pajin.capabilities.models import CapabilityMaturity
from pajin.capabilities.web_measured_validation import (
    WEB_MEASURED_VALIDATION_CAPABILITY_ID,
    WEB_MEASURED_VALIDATION_TARGET,
    WebMeasuredValidationProfile,
    registered_web_measured_validation_capability_definition,
    registered_web_measured_validation_profile,
    resolve_web_measured_validation_profile,
    web_measured_validation_capability_bundle,
)
from pajin.control_plane.redteam_profiles import (
    REDTEAM_WEB_CAPABILITY_ID,
    REDTEAM_WEB_PROFILE_DIGEST,
    REDTEAM_WEB_TARGET_ENDPOINT,
)
from pajin.domain.models import ToolRequest
from pajin.runtime.worker import NetworkMode
from pajin.tools.ai import AIChatProbeTool
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import BOOLEAN_SQLI_SCENARIO, BooleanSQLiProbeTool
from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool
from pajin.tools.mock import MockAgentProbe
from pajin.workflow.web_measured_case_authority import (
    WebMeasuredCaseAuthority,
    WebMeasuredCaseAuthorityError,
    bind_web_measured_case_authority,
    load_web_measured_case_authority,
)
from pajin.workflow.web_replay_benchmark import (
    registered_web_api_benchmark_ground_truth_profile,
)
from pajin.workflow.web_validation_floor import (
    WebBenchmarkFindingProjectionPolicy,
    WebBenchmarkValidationFloorPolicy,
    WebPolicyDenialControlRegistry,
    WebPrivateExpectedFindingBinding,
    WebValidationFloorError,
    bind_web_expected_finding_projection_policy,
    registered_web_benchmark_validation_floor_policy,
    registered_web_policy_denial_control_registry,
    resolve_web_benchmark_validation_floor_policy,
)

NOW = datetime(2026, 8, 28, 12, tzinfo=UTC)
TARGET_IMAGE_ID = "sha256:" + "a" * 64
BENCHMARK_WORKER_IMAGE_ID = "sha256:" + "b" * 64
ZAP_IMAGE_ID = "sha256:" + "c" * 64
MEASUREMENT_DIGEST = "d" * 64


def _tools() -> ToolRegistry:
    registry = ToolRegistry()
    for tool in (
        MockAgentProbe(),
        AIChatProbeTool(),
        BooleanSQLiProbeTool(),
        CTFWebBackupProbeTool(),
        CTFCryptoXORTool(),
    ):
        registry.register(tool)
    return registry


def _profile() -> DockerBugBountyTargetProfile:
    return DockerBugBountyTargetProfile(
        targetImage="pajin-bug-bounty-target:dev",
        targetImageId=TARGET_IMAGE_ID,
        workerImage="pajin-benchmark-worker:dev",
        workerImageId=BENCHMARK_WORKER_IMAGE_ID,
    )


def _adapter(
    profile: DockerBugBountyTargetProfile,
    *,
    measurement_trust_anchor: BenchmarkMeasurementTrustAnchor | None = None,
) -> RegisteredBenchmarkTargetFactoryAdapter:
    authority_id = (
        "measurement-authority:web-002"
        if measurement_trust_anchor is None
        else measurement_trust_anchor.authority_id
    )
    authority_version = (
        "1.0.0" if measurement_trust_anchor is None else measurement_trust_anchor.authority_version
    )
    authority_digest = (
        MEASUREMENT_DIGEST
        if measurement_trust_anchor is None
        else measurement_trust_anchor.anchor_digest
    )
    return RegisteredBenchmarkTargetFactoryAdapter(
        adapterId="target-adapter:docker-bug-bounty",
        adapterVersion="1.0.0",
        targetFactoryId="target-factory:docker-bug-bounty",
        targetFactoryVersion=profile.profile_version,
        targetFactoryDigest=profile.target_factory_digest,
        measurementAuthorityId=authority_id,
        measurementAuthorityVersion=authority_version,
        measurementAuthorityDigest=authority_digest,
    )


def _scanner_plan(
    profile: DockerBugBountyTargetProfile,
    *,
    measurement_trust_anchor: BenchmarkMeasurementTrustAnchor | None = None,
    scanner_image_id: str = ZAP_IMAGE_ID,
):
    private_profile = registered_web_api_benchmark_ground_truth_profile(
        profile,
        benchmark_id="benchmark:web-002-p0-d1-v1",
    )
    ground_truth = private_profile.private_ground_truth.ground_truth
    contract = registered_generic_scanner_adapter_contract()
    adapter = _adapter(profile, measurement_trust_anchor=measurement_trust_anchor)
    manifest = BenchmarkManifest(
        benchmarkId=ground_truth.benchmark_id,
        targetFactoryId=adapter.target_factory_id,
        targetFactoryVersion=adapter.target_factory_version,
        targetFactoryDigest=adapter.target_factory_digest,
        targetProfileId=profile.profile_id,
        targetProfileVersion=profile.profile_version,
        mutationProfileId=None,
        campaignDigest="e" * 64,
        groundTruthDigest=ground_truth.digest(),
        protocol=BenchmarkRunProtocol(
            protocolId="pajin:web-002-zap-source",
            protocolVersion="1.0.0",
            seeds=[7],
            repetitionsPerSeed=1,
            timeoutSeconds=180,
            maxCostUsd=1,
            maxToolCalls=10,
            maxModelCalls=0,
        ),
        arms=[
            BenchmarkArm(
                armId="arm:web-002-zap-source",
                kind=BenchmarkArmKind.DETERMINISTIC_BASELINE,
                implementationId=contract.benchmark_implementation_id,
                implementationVersion=contract.benchmark_implementation_version,
                configurationDigest=contract.benchmark_configuration_digest,
                adaptiveSupervisor=False,
            )
        ],
    )
    plan = plan_generic_scanner_baseline(
        manifest,
        adapter=adapter,
        profile=profile,
        catalog=registered_traditional_web_api_target_catalog(profile, ground_truth),
        ground_truth=ground_truth,
    )
    scanner = registered_zap_scanner(
        scanner_image_id,
        parser_contract_digest=plan.scanner_contract.parser_contract_digest,
    )
    return private_profile, adapter, plan, scanner


def _seed(label: str) -> bytes:
    return sha256(label.encode()).digest()


def _signed_lifecycle(bundle):
    policy = CapabilityLifecyclePolicy.reference_policy()
    publisher_key = CapabilityLifecycleTrustKey(
        keyId="web002.publisher",
        principalId="web002.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
        publicKeyBase64url=capability_lifecycle_public_key(_seed("publisher")),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=30),
    )
    reviewer_key = CapabilityLifecycleTrustKey(
        keyId="web002.reviewer",
        principalId="web002.reviewer",
        role=CapabilityLifecycleKeyRole.REVIEWER,
        publicKeyBase64url=capability_lifecycle_public_key(_seed("reviewer")),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=30),
    )
    publisher = CapabilityLifecycleSigner.from_private_key_bytes(
        key=publisher_key,
        private_key=_seed("publisher"),
    )
    reviewer = CapabilityLifecycleSigner.from_private_key_bytes(
        key=reviewer_key,
        private_key=_seed("reviewer"),
    )
    reference = bundle.capability.reference()
    review = CapabilityReviewStatement(
        capability=reference,
        targetMaturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewerPrincipalId=reviewer_key.principal_id,
        checklistDigest=sha256(b"web-002a-capability-review").hexdigest(),
        decision=CapabilityReviewDecision.APPROVED,
        issuedAt=NOW - timedelta(days=2),
        expiresAt=NOW + timedelta(days=5),
    )
    signed_review = reviewer.sign_review(review)
    release = CapabilityReleaseStatement(
        capability=reference,
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewDigests=(review.review_digest,),
        publisherPrincipalId=publisher_key.principal_id,
        issuedAt=NOW - timedelta(days=1),
    )
    release_bundle = CapabilityReleaseBundle(
        release=publisher.sign_release(release),
        reviews=(signed_review,),
    )
    lifecycle = CapabilityLifecycleRegistry(
        definitions=bundle.definitions,
        authorities=bundle.authorities,
        policy=policy,
        trust_keys=(publisher_key, reviewer_key),
        releases=(release_bundle,),
        clock=lambda: NOW,
    )
    return lifecycle, release.reference()


def _case(
    *,
    target_profile: DockerBugBountyTargetProfile | None = None,
    measurement_trust_anchor: BenchmarkMeasurementTrustAnchor | None = None,
    scanner_image_id: str = ZAP_IMAGE_ID,
):
    capability_bundle = web_measured_validation_capability_bundle(_tools())
    lifecycle, release = _signed_lifecycle(capability_bundle)
    private_profile, adapter, plan, scanner = _scanner_plan(
        target_profile or _profile(),
        measurement_trust_anchor=measurement_trust_anchor,
        scanner_image_id=scanner_image_id,
    )
    authority = bind_web_measured_case_authority(
        capability_bundle=capability_bundle,
        lifecycle=lifecycle,
        release=release,
        target_adapter=adapter,
        private_ground_truth_profile=private_profile,
        scanner_plan=plan,
        scanner_registration=scanner,
    )
    return authority, capability_bundle, lifecycle, private_profile, adapter


def _registered_floor(authority, bundle, lifecycle, private_profile, adapter):
    return registered_web_benchmark_validation_floor_policy(
        authority,
        capability_bundle=bundle,
        lifecycle=lifecycle,
        release=authority.capability_release,
        target_adapter=adapter,
        private_ground_truth_profile=private_profile,
        scanner_plan=authority.scanner_plan,
        scanner_registration=authority.scanner_registration,
    )


def test_additive_capability_and_profile_preserve_existing_redteam_identity() -> None:
    tools = _tools()
    old = existing_mode_capability_bundle(tools)
    old_boolean = next(
        item
        for item in old.capabilities()
        if item.capability.capability_id == REDTEAM_WEB_CAPABILITY_ID
    )
    new = web_measured_validation_capability_bundle(tools)
    definition = registered_web_measured_validation_capability_definition()
    profile = registered_web_measured_validation_profile(new)

    assert new.capability.capability.capability_id == WEB_MEASURED_VALIDATION_CAPABILITY_ID
    assert new.capability.capability != old_boolean.capability
    assert definition.tool == old.definitions.resolve(old_boolean.capability).tool
    assert definition.approval_required is True
    assert definition.request_unit_cost == 3
    assert profile.target_endpoint == WEB_MEASURED_VALIDATION_TARGET
    assert profile.target_endpoint != REDTEAM_WEB_TARGET_ENDPOINT
    assert REDTEAM_WEB_PROFILE_DIGEST
    assert resolve_web_measured_validation_profile(profile.reference(), bundle=new) == profile
    assert all(
        getattr(profile, name) is False
        for name in (
            "capability_activation_authorized",
            "approval_satisfied",
            "permit_issuance_authorized",
            "proxy_route_materialized",
            "network_access_authorized",
            "profile_validation_floor_satisfied",
            "finding_authority",
            "execution_authorized",
        )
    )


def test_additive_capability_materializes_only_the_fixed_scenario_and_prepares_network_none() -> (
    None
):
    bundle = web_measured_validation_capability_bundle(_tools())
    reference = bundle.capability.reference()
    materializer = bundle.authorities.authority(reference, "materializer")
    compiler = bundle.authorities.authority(reference, "action-compiler")
    executor = bundle.authorities.authority(reference, "executor-adapter")
    arguments = materializer.materialize({"scenario_id": BOOLEAN_SQLI_SCENARIO})
    request = ToolRequest(
        request_id="tool_web002_case",
        agent_id="agent.web002",
        tool_id=BooleanSQLiProbeTool.spec.tool_id,
        target=WEB_MEASURED_VALIDATION_TARGET,
        method="GET",
        arguments={},
    )
    compiled = compiler.compile(request, arguments)
    job = executor.prepare(compiled)

    assert compiled.arguments == {"scenario_id": BOOLEAN_SQLI_SCENARIO}
    assert job.network is NetworkMode.NONE
    assert job.egress_policy is None
    with pytest.raises(Exception, match="internal target"):
        compiler.compile(
            request.model_copy(update={"target": REDTEAM_WEB_TARGET_ENDPOINT}),
            arguments,
        )
    with pytest.raises(Exception, match="parameters"):
        materializer.materialize({"scenario_id": "other", "payload": "x"})


def test_measured_case_rebuilds_all_predecessors_and_stays_public_safe() -> None:
    authority, bundle, lifecycle, private_profile, adapter = _case()
    reloaded = load_web_measured_case_authority(
        authority,
        capability_bundle=bundle,
        lifecycle=lifecycle,
        release=authority.capability_release,
        target_adapter=adapter,
        private_ground_truth_profile=private_profile,
        scanner_plan=authority.scanner_plan,
        scanner_registration=authority.scanner_registration,
    )
    public = json.dumps(authority.model_dump(mode="json", by_alias=True), sort_keys=True)

    assert reloaded == authority
    assert authority.surface.locator.url == WEB_MEASURED_VALIDATION_TARGET
    assert authority.scanner_registration.target_url == f"{WEB_MEASURED_VALIDATION_TARGET}?id=1"
    assert "expectedFindingId" not in public
    assert '"privateGroundTruth":' not in public
    assert "matcher:docker-boolean-sqli-probe" not in public
    assert "finding:boolean-sqli-user-lookup" not in public
    assert all(
        getattr(authority, name) is False
        for name in WebMeasuredCaseAuthority.model_fields
        if name.endswith("authorized")
        or name
        in {
            "approval_satisfied",
            "proxy_route_materialized",
            "worker_selected",
            "measurement_observed",
            "raw_sarif_bound",
            "profile_validation_floor_satisfied",
            "finding_authority",
        }
    )


def test_measured_case_rejects_scanner_or_release_substitution_and_boolean_coercion() -> None:
    authority, bundle, lifecycle, private_profile, adapter = _case()
    foreign_scanner = registered_zap_scanner(
        "sha256:" + "f" * 64,
        parser_contract_digest=authority.scanner_plan.scanner_contract.parser_contract_digest,
    )
    foreign_authority = bind_web_measured_case_authority(
        capability_bundle=bundle,
        lifecycle=lifecycle,
        release=authority.capability_release,
        target_adapter=adapter,
        private_ground_truth_profile=private_profile,
        scanner_plan=authority.scanner_plan,
        scanner_registration=foreign_scanner,
    )
    assert foreign_authority.reference() != authority.reference()
    with pytest.raises(WebMeasuredCaseAuthorityError):
        load_web_measured_case_authority(
            foreign_authority,
            capability_bundle=bundle,
            lifecycle=lifecycle,
            release=authority.capability_release,
            target_adapter=adapter,
            private_ground_truth_profile=private_profile,
            scanner_plan=authority.scanner_plan,
            scanner_registration=authority.scanner_registration,
        )
    forged_release = authority.capability_release.model_copy(update={"release_digest": "f" * 64})
    with pytest.raises(WebMeasuredCaseAuthorityError):
        bind_web_measured_case_authority(
            capability_bundle=bundle,
            lifecycle=lifecycle,
            release=forged_release,
            target_adapter=adapter,
            private_ground_truth_profile=private_profile,
            scanner_plan=authority.scanner_plan,
            scanner_registration=authority.scanner_registration,
        )
    raw = authority.model_dump(mode="json", by_alias=True)
    raw["executionAuthorized"] = 0
    with pytest.raises(ValidationError):
        WebMeasuredCaseAuthority.model_validate(raw)


def test_floor_registers_exact_domain_metrics_without_claiming_measurement() -> None:
    authority, bundle, lifecycle, private_profile, adapter = _case()
    policy = _registered_floor(authority, bundle, lifecycle, private_profile, adapter)
    by_id = {item.metric.metric_id: item for item in policy.requirements}
    denial_controls = policy.policy_denial_control_registry

    assert len(policy.requirements) == 14
    assert (
        sum(
            item.applicability is DomainBenchmarkMetricApplicability.REQUIRED
            for item in policy.requirements
        )
        == 11
    )
    assert by_id["common.ground-truth-coverage"].threshold_numerator == 1
    assert by_id["common.ground-truth-coverage"].threshold_denominator == 1
    assert by_id["common.false-positive-rate"].threshold_numerator == 0
    assert by_id["common.false-positive-rate"].minimum_denominator == 1
    assert by_id["common.total-request-units"].threshold_numerator is None
    assert by_id["common.task-success-rate"].not_applicable_reason is not None
    assert (
        by_id["common.policy-denial-correctness"].denominator_semantics
        == "registered-code-owned-policy-denial-control-cases"
    )
    assert denial_controls == registered_web_policy_denial_control_registry()
    assert len(denial_controls.cases) == 1
    assert denial_controls.cases[0].case_id.startswith("web-policy-denial-control_")
    assert (
        denial_controls.cases[0].expected_denial_semantics
        == "reject-before-route-materialization-without-provider-execution"
    )
    assert denial_controls.denial_observed is False
    assert (
        resolve_web_benchmark_validation_floor_policy(
            policy.reference(),
            measured_case=authority,
            capability_bundle=bundle,
            lifecycle=lifecycle,
            release=authority.capability_release,
            target_adapter=adapter,
            private_ground_truth_profile=private_profile,
            scanner_plan=authority.scanner_plan,
            scanner_registration=authority.scanner_registration,
        )
        == policy
    )
    assert all(
        getattr(policy, field) is False
        for field in (
            "measurement_evaluation_authorized",
            "benchmark_validation_floor_satisfied",
            "finding_projection_authorized",
            "product_finding_confirmed",
            "finding_authority",
            "execution_authorized",
        )
    )


def test_private_expected_finding_maps_to_distinct_public_unproduced_projection() -> None:
    authority, bundle, lifecycle, private_profile, adapter = _case()
    floor = _registered_floor(authority, bundle, lifecycle, private_profile, adapter)
    mapping = bind_web_expected_finding_projection_policy(
        measured_case=authority,
        floor_policy=floor,
        capability_bundle=bundle,
        lifecycle=lifecycle,
        release=authority.capability_release,
        target_adapter=adapter,
        private_ground_truth_profile=private_profile,
        scanner_plan=authority.scanner_plan,
        scanner_registration=authority.scanner_registration,
    )
    public = json.dumps(
        mapping.public_policy.model_dump(mode="json", by_alias=True),
        sort_keys=True,
    )
    private = mapping.private_binding.model_dump(mode="json", by_alias=True)

    assert mapping.public_policy.projection_id.startswith("web-benchmark-finding_")
    assert mapping.public_policy.projection_id != "finding:boolean-sqli-user-lookup"
    assert "finding:boolean-sqli-user-lookup" not in public
    assert "ground-truth:boolean-sqli-user-lookup" not in public
    assert "matcher:docker-boolean-sqli-probe" not in public
    assert private["expectedFindingId"] == "finding:boolean-sqli-user-lookup"
    assert mapping.public_policy.finding_projection_authorized is False
    assert mapping.public_policy.product_finding_confirmed is False


def test_floor_and_projection_reject_threshold_commitment_and_marker_forgery() -> None:
    authority, bundle, lifecycle, private_profile, adapter = _case()
    floor = _registered_floor(authority, bundle, lifecycle, private_profile, adapter)
    mapping = bind_web_expected_finding_projection_policy(
        measured_case=authority,
        floor_policy=floor,
        capability_bundle=bundle,
        lifecycle=lifecycle,
        release=authority.capability_release,
        target_adapter=adapter,
        private_ground_truth_profile=private_profile,
        scanner_plan=authority.scanner_plan,
        scanner_registration=authority.scanner_registration,
    )
    floor_raw = floor.model_dump(mode="json", by_alias=True)
    floor_raw["requirements"][0]["thresholdNumerator"] = 0
    with pytest.raises(ValidationError):
        WebBenchmarkValidationFloorPolicy.model_validate(floor_raw)
    projection_raw = mapping.public_policy.model_dump(mode="json", by_alias=True)
    projection_raw["findingProjectionAuthorized"] = "false"
    with pytest.raises(ValidationError):
        WebBenchmarkFindingProjectionPolicy.model_validate(projection_raw)
    private_raw = mapping.private_binding.model_dump(mode="json", by_alias=True)
    private_raw["expectedReferenceCommitment"] = "f" * 64
    with pytest.raises(ValidationError):
        WebPrivateExpectedFindingBinding.model_validate(private_raw)


def test_floor_entrypoints_reopen_current_measured_case_predecessors() -> None:
    authority, bundle, lifecycle, private_profile, adapter = _case()
    floor = _registered_floor(authority, bundle, lifecycle, private_profile, adapter)
    foreign_scanner = registered_zap_scanner(
        "sha256:" + "f" * 64,
        parser_contract_digest=authority.scanner_plan.scanner_contract.parser_contract_digest,
    )
    foreign_authority = bind_web_measured_case_authority(
        capability_bundle=bundle,
        lifecycle=lifecycle,
        release=authority.capability_release,
        target_adapter=adapter,
        private_ground_truth_profile=private_profile,
        scanner_plan=authority.scanner_plan,
        scanner_registration=foreign_scanner,
    )

    with pytest.raises(WebValidationFloorError, match="trusted-context"):
        registered_web_benchmark_validation_floor_policy(
            foreign_authority,
            capability_bundle=bundle,
            lifecycle=lifecycle,
            release=authority.capability_release,
            target_adapter=adapter,
            private_ground_truth_profile=private_profile,
            scanner_plan=authority.scanner_plan,
            scanner_registration=authority.scanner_registration,
        )
    with pytest.raises(WebValidationFloorError, match="trusted-context"):
        resolve_web_benchmark_validation_floor_policy(
            floor.reference(),
            measured_case=foreign_authority,
            capability_bundle=bundle,
            lifecycle=lifecycle,
            release=authority.capability_release,
            target_adapter=adapter,
            private_ground_truth_profile=private_profile,
            scanner_plan=authority.scanner_plan,
            scanner_registration=authority.scanner_registration,
        )
    with pytest.raises(WebValidationFloorError, match="trusted-context"):
        bind_web_expected_finding_projection_policy(
            measured_case=foreign_authority,
            floor_policy=floor,
            capability_bundle=bundle,
            lifecycle=lifecycle,
            release=authority.capability_release,
            target_adapter=adapter,
            private_ground_truth_profile=private_profile,
            scanner_plan=authority.scanner_plan,
            scanner_registration=authority.scanner_registration,
        )


def test_denial_control_registry_and_numeric_wires_reject_forgery_and_coercion() -> None:
    authority, bundle, lifecycle, private_profile, adapter = _case()
    floor = _registered_floor(authority, bundle, lifecycle, private_profile, adapter)
    profile = registered_web_measured_validation_profile(bundle)
    registry = floor.policy_denial_control_registry
    control = registry.cases[0]
    forged_control = control.model_copy(
        update={"expected_denial_semantics": "allow-after-target-cleanup"}
    )

    with pytest.raises(ValidationError):
        WebPolicyDenialControlRegistry(cases=(forged_control,))

    metric_index = next(
        index
        for index, item in enumerate(floor.requirements)
        if item.metric.metric_id == "common.ground-truth-coverage"
    )
    for field in ("thresholdNumerator", "thresholdDenominator", "minimumDenominator"):
        for coerced in (True, "1", 1.0):
            raw = floor.model_dump(mode="json", by_alias=True)
            raw["requirements"][metric_index][field] = coerced
            with pytest.raises(ValidationError):
                WebBenchmarkValidationFloorPolicy.model_validate(raw)

    for field, values in (
        ("requestUnits", (True, "3", 3.0)),
        ("maxResponseBytesPerRequest", (True, "32768", 32768.0)),
    ):
        for coerced in values:
            raw = profile.model_dump(mode="json", by_alias=True)
            raw[field] = coerced
            with pytest.raises(ValidationError):
                WebMeasuredValidationProfile.model_validate(raw)
