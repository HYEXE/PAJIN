"""BENCH-003B2 binding from measured Results to the exact WALK-006 Shadow policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, model_validator

from pajin.benchmark.measurement import (
    WalkingBenchmarkMeasuredComparisonAuthority,
    WalkingBenchmarkMeasuredComparisonOutcome,
    WalkingBenchmarkMeasurementError,
    load_walking_benchmark_measured_comparison_authority,
)
from pajin.benchmark.models import BenchmarkArmKind, benchmark_digest, canonical_benchmark_json
from pajin.benchmark.shadow import (
    WalkingShadowBenchmarkComparisonAuthority,
    WalkingShadowBenchmarkComparisonError,
    WalkingShadowBenchmarkComparisonOutcome,
    load_walking_shadow_benchmark_comparison_authority,
)
from pajin.domain.models import CampaignManifest, StrictModel
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts

WALKING_SHADOW_MEASURED_BENCHMARK_API_VERSION: Literal[
    "pajin.dev/walking-shadow-measured-benchmark/v1alpha1"
] = "pajin.dev/walking-shadow-measured-benchmark/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_AUTHORITY_BYTES = 64 * 1024 * 1024
_STRUCTURAL_ARTIFACT = "walking-shadow-benchmark-comparison-authority.json"
_MEASURED_ARTIFACT = "walking-benchmark-measured-comparison-authority.json"
_AUTHORITY_ARTIFACT = "walking-shadow-measured-benchmark-authority.json"


class WalkingShadowMeasuredBenchmarkError(RuntimeError):
    """Raised when measured benchmark evidence is not the exact WALK-006 policy candidate."""


class WalkingShadowMeasuredBenchmarkAuthority(StrictModel):
    """Bind BENCH-003B1 numeric output to BENCH-003A and its WALK-006 policy."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/walking-shadow-measured-benchmark/v1alpha1"] = Field(
        default=WALKING_SHADOW_MEASURED_BENCHMARK_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WalkingShadowMeasuredBenchmarkAuthority"] = (
        "WalkingShadowMeasuredBenchmarkAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    structural_source: WalkingShadowBenchmarkComparisonAuthority = Field(
        alias="structuralSource"
    )
    structural_source_run_id: str = Field(
        alias="structuralSourceRunId",
        min_length=1,
        max_length=200,
    )
    structural_source_root_digest: _Sha256 = Field(alias="structuralSourceRootDigest")
    structural_source_artifact_path: Literal[
        "walking-shadow-benchmark-comparison-authority.json"
    ] = Field(
        default="walking-shadow-benchmark-comparison-authority.json",
        alias="structuralSourceArtifactPath",
    )
    structural_source_artifact_sha256: _Sha256 = Field(
        alias="structuralSourceArtifactSha256"
    )
    measured_source: WalkingBenchmarkMeasuredComparisonAuthority = Field(
        alias="measuredSource"
    )
    measured_source_run_id: str = Field(
        alias="measuredSourceRunId",
        min_length=1,
        max_length=200,
    )
    measured_source_root_digest: _Sha256 = Field(alias="measuredSourceRootDigest")
    measured_source_artifact_path: Literal[
        "walking-benchmark-measured-comparison-authority.json"
    ] = Field(
        default="walking-benchmark-measured-comparison-authority.json",
        alias="measuredSourceArtifactPath",
    )
    measured_source_artifact_sha256: _Sha256 = Field(alias="measuredSourceArtifactSha256")
    baseline_arm_id: str = Field(alias="baselineArmId", min_length=1, max_length=200)
    candidate_arm_id: str = Field(alias="candidateArmId", min_length=1, max_length=200)
    candidate_policy_id: str = Field(alias="candidatePolicyId", min_length=1, max_length=200)
    candidate_policy_version: str = Field(
        alias="candidatePolicyVersion",
        min_length=1,
        max_length=200,
    )
    candidate_policy_digest: _Sha256 = Field(alias="candidatePolicyDigest")
    measurement_state: Literal["measured-shadow-policy-bound"] = Field(
        default="measured-shadow-policy-bound",
        alias="measurementState",
    )
    benchmark_comparison_eligible: Literal[True] = Field(
        default=True,
        alias="benchmarkComparisonEligible",
    )
    supervisor_activation_eligible: Literal[False] = Field(
        default=False,
        alias="supervisorActivationEligible",
    )

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        _require_shadow_measurement_binding(self.structural_source, self.measured_source)
        baseline, candidate = self.measured_source.manifest.arms
        policy = self.structural_source.source.policy
        expected_structural_sha = sha256(
            _runstore_json_bytes(
                self.structural_source.model_dump(mode="json", by_alias=True)
            )
        ).hexdigest()
        expected_measured_sha = sha256(
            _runstore_json_bytes(self.measured_source.model_dump(mode="json", by_alias=True))
        ).hexdigest()
        if (
            self.baseline_arm_id != baseline.arm_id
            or self.candidate_arm_id != candidate.arm_id
            or self.candidate_policy_id != policy.policy_id
            or self.candidate_policy_version != policy.policy_version
            or self.candidate_policy_digest != policy.policy_digest
            or self.structural_source_artifact_sha256 != expected_structural_sha
            or self.measured_source_artifact_sha256 != expected_measured_sha
            or self.structural_source_run_id == self.measured_source_run_id
            or self.structural_source_root_digest == self.measured_source_root_digest
        ):
            raise ValueError("BENCH-003B2 policy identity differs from exact source authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.walking-shadow-measured-authority/v1",
            material,
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        authority_id = f"walking-shadow-measured:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Walking Shadow measured Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Walking Shadow measured Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        canonical_benchmark_json(
            self.model_dump(mode="json", by_alias=True),
            label="WalkingShadowMeasuredBenchmarkAuthority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        return self


@dataclass(frozen=True, slots=True)
class WalkingShadowMeasuredBenchmarkOutcome:
    run_id: str
    run_path: Path
    artifact_path: str
    authority: WalkingShadowMeasuredBenchmarkAuthority


class WalkingShadowMeasuredBenchmarkRunner:
    """Seal exact source bindings without changing any measured value or Decision."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = output_root

    def run(
        self,
        campaign: CampaignManifest,
        structural_outcome: WalkingShadowBenchmarkComparisonOutcome,
        measured_outcome: WalkingBenchmarkMeasuredComparisonOutcome,
    ) -> WalkingShadowMeasuredBenchmarkOutcome:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        measured_manifest = measured_outcome.authority.manifest.model_copy(deep=True)
        try:
            structural = load_walking_shadow_benchmark_comparison_authority(
                authoritative_campaign,
                structural_outcome,
            )
            measured = load_walking_benchmark_measured_comparison_authority(
                measured_manifest,
                measured_outcome,
            )
            structural_snapshot = load_verified_run_artifacts(
                structural_outcome.run_path,
                requests={structural_outcome.artifact_path: _MAX_AUTHORITY_BYTES},
                expected_run_id=structural_outcome.run_id,
            )
            measured_snapshot = load_verified_run_artifacts(
                measured_outcome.run_path,
                requests={measured_outcome.authority_path: _MAX_AUTHORITY_BYTES},
                expected_run_id=measured_outcome.run_id,
            )
            if structural_outcome.artifact_path != _STRUCTURAL_ARTIFACT:
                raise ValueError("BENCH-003B2 structural source path differs")
            if measured_outcome.authority_path != _MEASURED_ARTIFACT:
                raise ValueError("BENCH-003B2 measured source path differs")
            _require_shadow_measurement_binding(structural, measured)
            policy = structural.source.policy
            baseline, candidate = measured.manifest.arms
            authority = WalkingShadowMeasuredBenchmarkAuthority(
                structuralSource=structural,
                structuralSourceRunId=structural_snapshot.verification.run_id,
                structuralSourceRootDigest=structural_snapshot.verification.root_digest,
                structuralSourceArtifactSha256=sha256(
                    structural_snapshot.artifact_bytes(structural_outcome.artifact_path)
                ).hexdigest(),
                measuredSource=measured,
                measuredSourceRunId=measured_snapshot.verification.run_id,
                measuredSourceRootDigest=measured_snapshot.verification.root_digest,
                measuredSourceArtifactSha256=sha256(
                    measured_snapshot.artifact_bytes(measured_outcome.authority_path)
                ).hexdigest(),
                baselineArmId=baseline.arm_id,
                candidateArmId=candidate.arm_id,
                candidatePolicyId=policy.policy_id,
                candidatePolicyVersion=policy.policy_version,
                candidatePolicyDigest=policy.policy_digest,
            )
        except (
            OSError,
            RunIntegrityError,
            ValidationError,
            ValueError,
            WalkingBenchmarkMeasurementError,
            WalkingShadowBenchmarkComparisonError,
        ) as exc:
            raise WalkingShadowMeasuredBenchmarkError(
                "BENCH-003B2 Shadow measured binding could not be proven"
            ) from exc

        store = RunStore.create(self._output_root, authoritative_campaign.metadata.name)
        store.append_event(
            "campaign.started",
            {
                "campaign": authoritative_campaign.metadata.name,
                "mode": authoritative_campaign.spec.mode.value,
                "purpose": "walking-shadow-measured-benchmark",
            },
        )
        store.write_json(
            "campaign.json",
            authoritative_campaign.model_dump(mode="json", by_alias=True),
        )
        artifact_path = store.write_json(
            _AUTHORITY_ARTIFACT,
            authority.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "benchmark.walking-shadow-measured.created",
            _publication_event_payload(artifact_path, authority),
        )
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": "completed",
                "stage": "walking-shadow-measured-benchmark-sealed",
                "authorityId": authority.authority_id,
                "measurementState": authority.measurement_state,
            },
        )
        store.append_event(
            "campaign.completed",
            {"purpose": "walking-shadow-measured-benchmark", "artifact": artifact_path},
        )
        store.seal()
        return WalkingShadowMeasuredBenchmarkOutcome(
            run_id=store.run_id,
            run_path=store.path,
            artifact_path=artifact_path,
            authority=authority.model_copy(deep=True),
        )


def load_walking_shadow_measured_benchmark_authority(
    campaign: CampaignManifest,
    outcome: WalkingShadowMeasuredBenchmarkOutcome,
) -> WalkingShadowMeasuredBenchmarkAuthority:
    """Reload BENCH-003B2 from its exact sealed authority and publication event."""

    try:
        if outcome.artifact_path != _AUTHORITY_ARTIFACT:
            raise ValueError("BENCH-003B2 output artifact path differs")
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                "campaign.json": 256 * 1024,
                outcome.artifact_path: _MAX_AUTHORITY_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_campaign = CampaignManifest.model_validate_json(
            snapshot.artifact_bytes("campaign.json")
        )
        authority = WalkingShadowMeasuredBenchmarkAuthority.model_validate_json(
            snapshot.artifact_bytes(outcome.artifact_path)
        )
    except (OSError, RunIntegrityError, ValidationError, ValueError) as exc:
        raise WalkingShadowMeasuredBenchmarkError(
            "BENCH-003B2 Shadow measured authority is not sealed and valid"
        ) from exc
    if sealed_campaign != campaign or authority != outcome.authority:
        raise WalkingShadowMeasuredBenchmarkError(
            "BENCH-003B2 output differs from sealed authority"
        )
    created = [
        event
        for event in snapshot.events
        if event.event_type == "benchmark.walking-shadow-measured.created"
    ]
    expected = _publication_event_payload(outcome.artifact_path, authority)
    if len(created) != 1 or created[0].payload != expected:
        raise WalkingShadowMeasuredBenchmarkError("BENCH-003B2 publication event differs")
    return authority.model_copy(deep=True)


def _require_shadow_measurement_binding(
    structural: WalkingShadowBenchmarkComparisonAuthority,
    measured: WalkingBenchmarkMeasuredComparisonAuthority,
) -> None:
    structural_manifest = structural.manifest
    measured_manifest = measured.manifest
    if len(structural_manifest.arms) != 1 or len(measured_manifest.arms) != 2:
        raise ValueError("BENCH-003B2 requires one structural baseline and two measured arms")
    structural_baseline = structural_manifest.arms[0]
    measured_baseline, measured_candidate = measured_manifest.arms
    policy = structural.source.policy
    structural_envelope = structural_manifest.model_dump(mode="json", by_alias=True)
    measured_envelope = measured_manifest.model_dump(mode="json", by_alias=True)
    structural_envelope.pop("arms")
    measured_envelope.pop("arms")
    if (
        structural_envelope != measured_envelope
        or structural_baseline != measured_baseline
        or measured_candidate.kind is not BenchmarkArmKind.ADAPTIVE_CANDIDATE
        or measured_candidate.adaptive_supervisor is not True
        or measured_candidate.implementation_id != policy.policy_id
        or measured_candidate.implementation_version != policy.policy_version
        or measured_candidate.configuration_digest != policy.policy_digest
        or measured.manifest.campaign_digest != structural.source.campaign_digest
        or structural.benchmark_comparison_eligible is not False
        or structural.supervisor_activation_eligible is not False
        or measured.benchmark_comparison_eligible is not True
        or measured.supervisor_activation_eligible is not False
    ):
        raise ValueError("BENCH-003B2 measured candidate differs from WALK-006 policy authority")


def _publication_event_payload(
    artifact_path: str,
    authority: WalkingShadowMeasuredBenchmarkAuthority,
) -> dict[str, object]:
    return {
        "artifact": artifact_path,
        "authorityId": authority.authority_id,
        "authorityDigest": authority.authority_digest,
        "structuralSourceAuthorityId": authority.structural_source.authority_id,
        "measuredSourceAuthorityId": authority.measured_source.authority_id,
        "comparisonId": authority.measured_source.comparison.comparison_id,
        "comparisonDigest": authority.measured_source.comparison_digest,
        "candidatePolicyDigest": authority.candidate_policy_digest,
        "measurementState": authority.measurement_state,
        "supervisorActivationEligible": authority.supervisor_activation_eligible,
    }


def _runstore_json_bytes(value: object) -> bytes:
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
