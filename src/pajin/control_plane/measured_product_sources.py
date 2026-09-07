"""Data-only deployment recipes for existing measured AI and Network readers."""

from __future__ import annotations

from pathlib import Path

from pydantic import ConfigDict, Field

from pajin.capabilities.lifecycle import (
    CapabilityLifecyclePolicy,
    CapabilityLifecycleRegistry,
    CapabilityLifecycleTrustKey,
    CapabilityReleaseBundle,
)
from pajin.capabilities.network_service import (
    NetworkServiceCapabilityActivation,
    NetworkServiceCapabilityActivationSet,
    NetworkServiceIdentificationPreparation,
    network_service_capability_bundle,
)
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.domain.models import CampaignManifest, StrictModel
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.target_attestation import (
    AIMeasurementTargetExecutionChallenge,
    AISourceTargetExecutionChallenge,
)
from pajin.tools.base import ToolRegistry
from pajin.tools.network import NetworkServiceIdentificationTool
from pajin.workflow.ai_analysis_admission import AIAnalysisObservationSourceInputs
from pajin.workflow.ai_fixture_runtime import (
    AIFixtureTargetLifecycleEvidence,
    AIMeasurementFixtureTargetLifecycleEvidence,
)
from pajin.workflow.ai_measured_product_flow import AIMeasuredProduct, AIMeasuredProductOutcome
from pajin.workflow.ai_replay_evaluation import (
    AIMeasurementExecutionContext,
    AIReplayEvaluationMapping,
    AIReplayEvaluationOutcome,
)
from pajin.workflow.ai_source_measurement import (
    AISourceExecutionContext,
    AISourceMeasurementMapping,
    AISourceMeasurementOutcome,
)
from pajin.workflow.network_fixture_runtime import NetworkFixtureTargetLifecycleEvidence
from pajin.workflow.network_measured_product_flow import (
    NetworkMeasuredProduct,
    NetworkMeasuredProductOutcome,
)
from pajin.workflow.network_replay_evaluation import (
    NetworkReplayEvaluationMapping,
    NetworkReplayEvaluationOutcome,
)
from pajin.workflow.network_service_admission import NetworkServiceObservationSourceInputs
from pajin.workflow.network_source_measurement import (
    NetworkSourceExecutionContext,
    NetworkSourceMeasurementMapping,
    NetworkSourceMeasurementOutcome,
)


class _RecipeModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class CapabilityVerificationRecipe(_RecipeModel):
    policy: CapabilityLifecyclePolicy
    trust_keys: tuple[CapabilityLifecycleTrustKey, ...] = Field(min_length=1, max_length=100)
    releases: tuple[CapabilityReleaseBundle, ...] = Field(min_length=1, max_length=100)

    @classmethod
    def from_registry(cls, registry: CapabilityLifecycleRegistry) -> CapabilityVerificationRecipe:
        if type(registry) is not CapabilityLifecycleRegistry:
            raise TypeError("measured deployment requires the exact Capability lifecycle")
        policy, keys, releases = registry.verification_material()
        return cls(policy=policy, trust_keys=keys, releases=releases)


class NetworkActivationRecipe(_RecipeModel):
    verification: CapabilityVerificationRecipe
    activation_set: NetworkServiceCapabilityActivationSet

    @classmethod
    def from_activation(cls, value: NetworkServiceCapabilityActivation) -> NetworkActivationRecipe:
        return cls(
            verification=CapabilityVerificationRecipe.from_registry(value.lifecycle),
            activation_set=value.activation_set,
        )

    def reopen(self) -> NetworkServiceCapabilityActivation:
        tools = ToolRegistry()
        tools.register(NetworkServiceIdentificationTool())
        bundle = network_service_capability_bundle(tools)
        lifecycle = CapabilityLifecycleRegistry(
            definitions=bundle.definitions,
            authorities=bundle.authorities,
            policy=self.verification.policy,
            trust_keys=self.verification.trust_keys,
            releases=self.verification.releases,
        )
        return NetworkServiceCapabilityActivation(
            bundle=bundle,
            lifecycle=lifecycle,
            activation_set=self.activation_set,
        )


class NetworkSourceInputsRecipe(_RecipeModel):
    run_path: Path
    expected_run_id: str
    activation: NetworkActivationRecipe
    campaign: CampaignManifest
    preparation: NetworkServiceIdentificationPreparation
    job: CapabilityGraphCampaignJobInput

    @classmethod
    def from_inputs(cls, value: NetworkServiceObservationSourceInputs) -> NetworkSourceInputsRecipe:
        return cls(
            run_path=value.run_path,
            expected_run_id=value.expected_run_id,
            activation=NetworkActivationRecipe.from_activation(value.activation),
            campaign=value.campaign,
            preparation=value.preparation,
            job=value.job,
        )

    def reopen(self) -> NetworkServiceObservationSourceInputs:
        return NetworkServiceObservationSourceInputs(
            run_path=self.run_path,
            expected_run_id=self.expected_run_id,
            activation=self.activation.reopen(),
            campaign=self.campaign,
            preparation=self.preparation,
            job=self.job,
        )


class GraphStoreReadCoordinate(_RecipeModel):
    """A deployment-pinned existing store; never create a missing Graph database."""

    path: Path
    campaign_id: str = Field(alias="campaignId", pattern=r"^[a-z0-9][a-z0-9-]{2,79}$")

    @classmethod
    def from_store(cls, store: SQLiteGraphStore) -> GraphStoreReadCoordinate:
        if type(store) is not SQLiteGraphStore:
            raise TypeError("measured deployment requires an exact SQLite Graph store")
        return cls(path=store.path, campaignId=store.campaign_id)

    def reopen(self) -> SQLiteGraphStore:
        if not self.path.is_file():
            raise ValueError("measured deployment Graph database is unavailable")
        return SQLiteGraphStore(self.path, campaign_id=self.campaign_id, initialize=False)


class NetworkExecutionRecipe(_RecipeModel):
    source_inputs: NetworkSourceInputsRecipe
    graph_store: GraphStoreReadCoordinate
    lifecycle: NetworkFixtureTargetLifecycleEvidence

    @classmethod
    def from_execution(cls, value: NetworkSourceExecutionContext) -> NetworkExecutionRecipe:
        return cls(
            source_inputs=NetworkSourceInputsRecipe.from_inputs(value.source_inputs),
            graph_store=GraphStoreReadCoordinate.from_store(value.graph_store),
            lifecycle=value.lifecycle,
        )

    def reopen(self) -> NetworkSourceExecutionContext:
        return NetworkSourceExecutionContext(
            source_inputs=self.source_inputs.reopen(),
            graph_store=self.graph_store.reopen(),
            lifecycle=self.lifecycle,
        )


class NetworkSourceRecipe(_RecipeModel):
    run_id: str
    run_path: Path
    authority_path: str
    private_binding_path: str
    mapping: NetworkSourceMeasurementMapping
    executions: tuple[NetworkExecutionRecipe, ...] = Field(min_length=6, max_length=6)

    @classmethod
    def from_outcome(cls, value: NetworkSourceMeasurementOutcome) -> NetworkSourceRecipe:
        return cls(
            run_id=value.run_id,
            run_path=value.run_path,
            authority_path=value.authority_path,
            private_binding_path=value.private_binding_path,
            mapping=value.mapping,
            executions=tuple(NetworkExecutionRecipe.from_execution(x) for x in value.executions),
        )

    def reopen(self) -> NetworkSourceMeasurementOutcome:
        return NetworkSourceMeasurementOutcome(
            run_id=self.run_id,
            run_path=self.run_path,
            authority_path=self.authority_path,
            private_binding_path=self.private_binding_path,
            mapping=self.mapping,
            executions=tuple(x.reopen() for x in self.executions),
        )


class NetworkEvaluationRecipe(_RecipeModel):
    run_id: str
    run_path: Path
    evaluation_path: str
    private_binding_path: str
    mapping: NetworkReplayEvaluationMapping
    source: NetworkSourceRecipe
    replay: NetworkSourceRecipe

    @classmethod
    def from_outcome(cls, value: NetworkReplayEvaluationOutcome) -> NetworkEvaluationRecipe:
        return cls(
            run_id=value.run_id,
            run_path=value.run_path,
            evaluation_path=value.evaluation_path,
            private_binding_path=value.private_binding_path,
            mapping=value.mapping,
            source=NetworkSourceRecipe.from_outcome(value.source),
            replay=NetworkSourceRecipe.from_outcome(value.replay),
        )

    def reopen(self) -> NetworkReplayEvaluationOutcome:
        return NetworkReplayEvaluationOutcome(
            run_id=self.run_id,
            run_path=self.run_path,
            evaluation_path=self.evaluation_path,
            private_binding_path=self.private_binding_path,
            mapping=self.mapping,
            source=self.source.reopen(),
            replay=self.replay.reopen(),
        )


class NetworkProductRecipe(_RecipeModel):
    run_id: str
    run_path: Path
    artifact_path: str
    product: NetworkMeasuredProduct
    source: NetworkEvaluationRecipe

    @classmethod
    def from_outcome(cls, value: NetworkMeasuredProductOutcome) -> NetworkProductRecipe:
        return cls(
            run_id=value.run_id,
            run_path=value.run_path,
            artifact_path=value.artifact_path,
            product=value.product,
            source=NetworkEvaluationRecipe.from_outcome(value.source),
        )

    def reopen(self) -> NetworkMeasuredProductOutcome:
        return NetworkMeasuredProductOutcome(
            run_id=self.run_id,
            run_path=self.run_path,
            artifact_path=self.artifact_path,
            product=self.product,
            source=self.source.reopen(),
        )


class AISourceExecutionRecipe(_RecipeModel):
    source_inputs: AIAnalysisObservationSourceInputs
    graph_store: GraphStoreReadCoordinate
    lifecycle: AIFixtureTargetLifecycleEvidence
    challenge: AISourceTargetExecutionChallenge

    @classmethod
    def from_execution(cls, value: AISourceExecutionContext) -> AISourceExecutionRecipe:
        return cls(
            source_inputs=value.source_inputs,
            graph_store=GraphStoreReadCoordinate.from_store(value.graph_store),
            lifecycle=value.lifecycle,
            challenge=value.challenge,
        )

    def reopen(self) -> AISourceExecutionContext:
        return AISourceExecutionContext(
            source_inputs=self.source_inputs,
            graph_store=self.graph_store.reopen(),
            lifecycle=self.lifecycle,
            challenge=self.challenge,
        )


class AIMeasurementExecutionRecipe(_RecipeModel):
    source_inputs: AIAnalysisObservationSourceInputs
    graph_store: GraphStoreReadCoordinate
    lifecycle: AIMeasurementFixtureTargetLifecycleEvidence
    challenge: AIMeasurementTargetExecutionChallenge

    @classmethod
    def from_execution(cls, value: AIMeasurementExecutionContext) -> AIMeasurementExecutionRecipe:
        return cls(
            source_inputs=value.source_inputs,
            graph_store=GraphStoreReadCoordinate.from_store(value.graph_store),
            lifecycle=value.lifecycle,
            challenge=value.challenge,
        )

    def reopen(self) -> AIMeasurementExecutionContext:
        return AIMeasurementExecutionContext(
            source_inputs=self.source_inputs,
            graph_store=self.graph_store.reopen(),
            lifecycle=self.lifecycle,
            challenge=self.challenge,
        )


class AISourceRecipe(_RecipeModel):
    run_id: str
    run_path: Path
    authority_path: str
    private_binding_path: str
    mapping: AISourceMeasurementMapping
    execution: AISourceExecutionRecipe

    @classmethod
    def from_outcome(cls, value: AISourceMeasurementOutcome) -> AISourceRecipe:
        return cls(
            run_id=value.run_id,
            run_path=value.run_path,
            authority_path=value.authority_path,
            private_binding_path=value.private_binding_path,
            mapping=value.mapping,
            execution=AISourceExecutionRecipe.from_execution(value.execution),
        )

    def reopen(self) -> AISourceMeasurementOutcome:
        return AISourceMeasurementOutcome(
            run_id=self.run_id,
            run_path=self.run_path,
            authority_path=self.authority_path,
            private_binding_path=self.private_binding_path,
            mapping=self.mapping,
            execution=self.execution.reopen(),
        )


class AIEvaluationRecipe(_RecipeModel):
    run_id: str
    run_path: Path
    evaluation_path: str
    private_binding_path: str
    mapping: AIReplayEvaluationMapping
    source: AISourceRecipe
    executions: tuple[AIMeasurementExecutionRecipe, ...] = Field(min_length=5, max_length=5)

    @classmethod
    def from_outcome(cls, value: AIReplayEvaluationOutcome) -> AIEvaluationRecipe:
        return cls(
            run_id=value.run_id,
            run_path=value.run_path,
            evaluation_path=value.evaluation_path,
            private_binding_path=value.private_binding_path,
            mapping=value.mapping,
            source=AISourceRecipe.from_outcome(value.source),
            executions=tuple(
                AIMeasurementExecutionRecipe.from_execution(x) for x in value.executions
            ),
        )

    def reopen(self) -> AIReplayEvaluationOutcome:
        return AIReplayEvaluationOutcome(
            run_id=self.run_id,
            run_path=self.run_path,
            evaluation_path=self.evaluation_path,
            private_binding_path=self.private_binding_path,
            mapping=self.mapping,
            source=self.source.reopen(),
            executions=tuple(x.reopen() for x in self.executions),
        )


class AIProductRecipe(_RecipeModel):
    run_id: str
    run_path: Path
    artifact_path: str
    product: AIMeasuredProduct
    source: AIEvaluationRecipe

    @classmethod
    def from_outcome(cls, value: AIMeasuredProductOutcome) -> AIProductRecipe:
        return cls(
            run_id=value.run_id,
            run_path=value.run_path,
            artifact_path=value.artifact_path,
            product=value.product,
            source=AIEvaluationRecipe.from_outcome(value.source),
        )

    def reopen(self) -> AIMeasuredProductOutcome:
        return AIMeasuredProductOutcome(
            run_id=self.run_id,
            run_path=self.run_path,
            artifact_path=self.artifact_path,
            product=self.product,
            source=self.source.reopen(),
        )
