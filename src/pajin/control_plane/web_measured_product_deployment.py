"""Data-only reconstruction of a completed WEB product's verification context."""

from __future__ import annotations

from pathlib import Path

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
from pajin.capabilities.lifecycle import CapabilityLifecycleRegistry
from pajin.capabilities.web_measured_validation import (
    WebMeasuredValidationCapabilityBundle,
    web_measured_validation_capability_bundle,
)
from pajin.control_plane.measured_product_sources import (
    CapabilityVerificationRecipe,
    _RecipeModel,
)
from pajin.domain.models import CampaignManifest, ToolRequest
from pajin.graph.approval import ActionApprovalAuthorization
from pajin.runtime.worker import DockerWorkerBackend
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.workflow.web_controlled_validation_route import WebControlledValidationRouteClaimLedger
from pajin.workflow.web_controlled_validation_runtime import (
    DockerWebControlledValidationAdapter,
    SubprocessWebControlledDockerBoundaryInspector,
)
from pajin.workflow.web_measured_case_authority import WebMeasuredCaseAuthority
from pajin.workflow.web_measured_product_flow import (
    WebMeasuredProductFlowOutcome,
    WebMeasuredProductSourceReopenContext,
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
from pajin.workflow.web_replay_benchmark import WebAPIBenchmarkGroundTruthProfile
from pajin.workflow.web_source_measurement_authority import (
    WebZAPSourceMeasurementOutcome,
    WebZAPSourceMeasurementReopenContext,
)
from pajin.workflow.web_validation_floor import (
    bind_web_expected_finding_projection_policy,
    registered_web_benchmark_validation_floor_policy,
)


class WebRouteReadRecipe(_RecipeModel):
    """Retained terminal approval tuple; no signer, issuer, writer, or dispatcher."""

    trust_anchor: WebProxyRouteTrustAnchor
    runtime_policy: WebProxyRouteRuntimePolicy
    target_attempt_id: str
    isolation_evidence: DockerBenchmarkProviderEvidence
    campaign: CampaignManifest
    authorization: ActionApprovalAuthorization
    request: ToolRequest

    @classmethod
    def from_context(cls, value: WebProxyRouteLiveAuthorityContext) -> WebRouteReadRecipe:
        authorization = value.approval_store.approved_authorization(
            value.approval_id, value.permit_id
        )
        if type(authorization) is not ActionApprovalAuthorization:
            raise ValueError("WEB terminal approval is unavailable")
        if (
            authorization.approval.approval_id != value.approval_id
            or authorization.action.permit.permit_id != value.permit_id
        ):
            raise ValueError("WEB terminal approval identity differs")
        return cls(
            trust_anchor=value.trust_anchor,
            runtime_policy=value.runtime_policy,
            target_attempt_id=value.target_attempt_id,
            isolation_evidence=value.isolation_evidence,
            campaign=value.campaign,
            authorization=authorization,
            request=value.request,
        )

    def approved_authorization(
        self, approval_id: str, permit_id: str
    ) -> ActionApprovalAuthorization | None:
        if (
            approval_id != self.authorization.approval.approval_id
            or permit_id != self.authorization.action.permit.permit_id
        ):
            return None
        return self.authorization.model_copy(deep=True)

    def reopen(
        self,
        *,
        recipe: WebProductRecipe,
        bundle: WebMeasuredValidationCapabilityBundle,
        lifecycle: CapabilityLifecycleRegistry,
        journal: BenchmarkTargetOperationJournal,
    ) -> WebProxyRouteLiveAuthorityContext:
        case = recipe.measured_case
        return WebProxyRouteLiveAuthorityContext(
            trust_anchor=self.trust_anchor,
            measured_case=case,
            capability_bundle=bundle,
            capability_lifecycle=lifecycle,
            capability_release=case.capability_release,
            private_ground_truth_profile=recipe.private_ground_truth_profile,
            scanner_plan=case.scanner_plan,
            scanner_registration=case.scanner_registration,
            runtime_policy=self.runtime_policy,
            target_profile=recipe.target_profile,
            target_journal=journal,
            target_attempt_id=self.target_attempt_id,
            isolation_evidence=self.isolation_evidence,
            campaign=self.campaign,
            approval_store=self,
            approval_id=self.authorization.approval.approval_id,
            permit_id=self.authorization.action.permit.permit_id,
            request=self.request,
        )


class WebProductRecipe(_RecipeModel):
    """Host-private verifier inputs, containing public keys and retained evidence only."""

    product: WebMeasuredProductFlowOutcome
    source: WebZAPSourceMeasurementOutcome
    measured_case: WebMeasuredCaseAuthority
    verification: CapabilityVerificationRecipe
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile
    target_profile: DockerBugBountyTargetProfile
    provider_state_path: Path
    activation_store_path: Path
    source_journal_path: Path
    measurement_trust_anchor: BenchmarkMeasurementTrustAnchor
    distribution_bundle: BenchmarkMeasurementRegistryDistributionBundle
    distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor
    coordinate: BenchmarkTargetCoordinate
    claim_ledger_path: Path
    worker_evidence_store_path: Path
    success_route: WebRouteReadRecipe
    denial_route: WebRouteReadRecipe

    @classmethod
    def from_outcome(
        cls,
        *,
        outcome: WebMeasuredProductFlowOutcome,
        reopen_context: WebMeasuredProductSourceReopenContext,
        provider_state_path: Path,
        worker_evidence_store_path: Path,
        coordinate: BenchmarkTargetCoordinate,
        success_route: WebProxyRouteLiveAuthorityContext,
    ) -> WebProductRecipe:
        source = reopen_context.source_reopen_context
        return cls(
            product=outcome,
            source=source.outcome,
            measured_case=source.measured_case,
            verification=CapabilityVerificationRecipe.from_registry(source.lifecycle),
            private_ground_truth_profile=source.private_ground_truth_profile,
            target_profile=source.catalog_provider.profile,
            provider_state_path=provider_state_path,
            activation_store_path=source.activation_store.path,
            source_journal_path=source.journal_path,
            measurement_trust_anchor=source.measurement_trust_anchor,
            distribution_bundle=source.distribution_bundle,
            distribution_trust_anchor=source.distribution_trust_anchor,
            coordinate=coordinate,
            claim_ledger_path=reopen_context.claim_ledger.path,
            worker_evidence_store_path=worker_evidence_store_path,
            success_route=WebRouteReadRecipe.from_context(success_route),
            denial_route=WebRouteReadRecipe.from_context(reopen_context.denial_route_authority),
        )

    def build_reader(self, *, deployment_id: str) -> WebMeasuredProductReader:
        if (
            self.success_route.runtime_policy != self.denial_route.runtime_policy
            or self.success_route.trust_anchor != self.denial_route.trust_anchor
            or self.success_route.runtime_policy.deployment_id != deployment_id
        ):
            raise ValueError("WEB deployment route composition differs")
        tools = ToolRegistry()
        tools.register(BooleanSQLiProbeTool())
        bundle = web_measured_validation_capability_bundle(tools)
        lifecycle = CapabilityLifecycleRegistry(
            definitions=bundle.definitions,
            authorities=bundle.authorities,
            policy=self.verification.policy,
            trust_keys=self.verification.trust_keys,
            releases=self.verification.releases,
        )
        case = self.measured_case
        ground_truth = self.private_ground_truth_profile.private_ground_truth.ground_truth
        concrete = DockerZAPScannerTargetFactoryAdapter(
            state_path=self.provider_state_path,
            profile=self.target_profile,
            plan=case.scanner_plan,
            registration=case.scanner_registration,
            trust_anchor=self.measurement_trust_anchor,
            measurement_private_key=None,
        )
        provider = CatalogBoundDockerZAPScannerTargetFactoryAdapter(
            provider=concrete,
            catalog=registered_traditional_web_api_target_catalog(
                self.target_profile, ground_truth
            ),
            ground_truth=ground_truth,
        )
        source_context = WebZAPSourceMeasurementReopenContext(
            outcome=self.source,
            measured_case=case,
            capability_bundle=bundle,
            lifecycle=lifecycle,
            release=case.capability_release,
            target_adapter=case.target_adapter,
            private_ground_truth_profile=self.private_ground_truth_profile,
            scanner_plan=case.scanner_plan,
            scanner_registration=case.scanner_registration,
            journal_path=self.source_journal_path,
            catalog_provider=provider,
            measurement_trust_anchor=self.measurement_trust_anchor,
            activation_store=BenchmarkMeasurementRegistryActivationStore(
                self.activation_store_path, initialize=False
            ),
            distribution_bundle=self.distribution_bundle,
            distribution_trust_anchor=self.distribution_trust_anchor,
        )
        floor = registered_web_benchmark_validation_floor_policy(
            case,
            capability_bundle=bundle,
            lifecycle=lifecycle,
            release=case.capability_release,
            target_adapter=case.target_adapter,
            private_ground_truth_profile=self.private_ground_truth_profile,
            scanner_plan=case.scanner_plan,
            scanner_registration=case.scanner_registration,
        )
        mapping = bind_web_expected_finding_projection_policy(
            measured_case=case,
            floor_policy=floor,
            capability_bundle=bundle,
            lifecycle=lifecycle,
            release=case.capability_release,
            target_adapter=case.target_adapter,
            private_ground_truth_profile=self.private_ground_truth_profile,
            scanner_plan=case.scanner_plan,
            scanner_registration=case.scanner_registration,
        )
        journal = BenchmarkTargetOperationJournal.open_existing(self.source_journal_path)
        ledger = WebControlledValidationRouteClaimLedger(self.claim_ledger_path, initialize=False)
        success = self.success_route.reopen(
            recipe=self, bundle=bundle, lifecycle=lifecycle, journal=journal
        )
        denial = self.denial_route.reopen(
            recipe=self, bundle=bundle, lifecycle=lifecycle, journal=journal
        )
        inspector = SubprocessWebControlledDockerBoundaryInspector()
        policy = success.runtime_policy
        backend = DockerWorkerBackend(
            allowed_images={policy.worker_image},
            egress_proxy_image=policy.proxy_image,
            external_network_routes={
                policy.worker_action: docker_benchmark_target_network_name(self.coordinate)
            },
            egress_lifecycle_observer=inspector,
        )
        adapter = DockerWebControlledValidationAdapter(
            backend=backend,
            inspector=inspector,
            route_authority=success,
            claim_ledger=ledger,
            evidence_store_path=self.worker_evidence_store_path,
            deployment_id=deployment_id,
            gateway_policy_id=policy.gateway_policy_id,
            gateway_policy_version=policy.gateway_policy_version,
            worker_backend_id=policy.worker_backend_id,
            worker_backend_version=policy.worker_backend_version,
            initialize_evidence_store=False,
        )
        context = WebMeasuredProductSourceReopenContext(
            measured_case_authority=case,
            private_ground_truth_profile=self.private_ground_truth_profile,
            source_reopen_context=source_context,
            floor_policy=floor,
            mapping=mapping,
            trust_anchor=success.trust_anchor,
            claim_ledger=ledger,
            target_journal=journal,
            provider=provider,
            adapter=adapter,
            denial_route_authority=denial,
        )
        registration = WebMeasuredProductReadRegistration.from_outcome(
            deployment_id=deployment_id,
            outcome=self.product,
            reopen_context=context,
        )
        return WebMeasuredProductReader(
            deployment_id=deployment_id,
            resolver=WebMeasuredProductReadRegistry((registration,)),
        )
