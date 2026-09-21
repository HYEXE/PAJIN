"""Seal one attested offline tokenizer-only Capacity v2 proof for WEB-007."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol, cast

if TYPE_CHECKING or __package__:
    from scripts import operational_skill_bound_web_capacity as _v1
else:  # pragma: no cover - exercised by the standalone entrypoint
    import operational_skill_bound_web_capacity as _v1

from pajin.runtime.pinned_workspace import PinnedOutputRoot

_SUMMARY_API_VERSION: Final = "pajin.dev/operational-skill-bound-web-capacity-conformance/v1alpha2"
_AUTHORITY_FIELDS: Final = (
    "provider_dispatch_authority",
    "target_request_authority",
    "scope_expansion_authority",
    "tool_request_authority",
    "capability_authority",
    "permit_authority",
    "execution_authority",
    "graph_admission_authority",
    "finding_authority",
    "report_delivery_authority",
)

OperationalSkillBoundWebCapacityV2Inputs = _v1.OperationalSkillBoundWebCapacityInputs
VerifiedOperationalSkillBoundWebCapacityV2Inputs = (
    _v1.VerifiedOperationalSkillBoundWebCapacityInputs
)


class OperationalSkillBoundWebCapacityV2Error(ValueError):
    """Raised when the attested offline Capacity v2 boundary fails closed."""


@dataclass(frozen=True, slots=True)
class OperationalSkillBoundWebCapacityV2Result:
    """Secret-free terminal summary plus its process-success classification."""

    summary: dict[str, object]
    succeeded: bool


@dataclass(frozen=True, slots=True)
class _CapacityV2Api:
    build_pin: Callable[..., object]
    tokenizer_backend: Callable[..., object]
    create_run: Callable[..., object]
    load_run: Callable[..., object]
    system_sentinel: str
    user_sentinel: str


class _NoAuthorityContract(Protocol):
    provider_dispatch_authority: bool
    target_request_authority: bool
    scope_expansion_authority: bool
    tool_request_authority: bool
    capability_authority: bool
    permit_authority: bool
    execution_authority: bool
    graph_admission_authority: bool
    finding_authority: bool
    report_delivery_authority: bool


class _CapacityV2PinContract(_NoAuthorityContract, Protocol):
    pin_digest: str
    chat_request_digest: str
    tokenizer_runtime_digest: str
    context_tokens: int
    model_materialization_policy_digest: str
    offline: bool
    tokenizer_only: bool


class _MaterializationAttestationContract(_NoAuthorityContract, Protocol):
    attestation_digest: str
    model_pin_digest: str
    expected_model_sha256: str
    expected_model_size_bytes: int
    staged_model_sha256: str
    staged_model_size_bytes: int
    staged_model_uid: int
    staged_model_gid: int
    staged_model_mode: str
    mounted_model_sha256: str
    mounted_model_size_bytes: int
    mounted_model_uid: int
    mounted_model_gid: int
    mounted_model_mode: str
    tokenizer_image_id: str
    staging_strategy: str
    materialization_kind: str
    mount_type: str
    mount_destination: str
    read_only: bool
    digest_algorithm: str
    attested_before_tokenizer_endpoints: bool
    runtime_user_read_verified: bool
    cleanup_required: bool


class _CapacityV2EvidenceContract(_NoAuthorityContract, Protocol):
    evidence_digest: str
    model_materialization_attestation: _MaterializationAttestationContract


class _CapacityV2ProofContract(_NoAuthorityContract, Protocol):
    proof_digest: str
    evidence_digest: str
    request_digest: str
    chat_template_digest: str
    model_materialization_attestation_digest: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    remaining_tokens: int
    conservative_campaign_prompt_tokens: int
    conservative_campaign_total_tokens: int
    fits: bool
    model_inference_performed: bool
    provider_dispatch: bool
    target_requests: int


class _CapacityV2IndexContract(_NoAuthorityContract, Protocol):
    index_digest: str
    evidence_digest: str
    proof_digest: str
    model_materialization_attestation_digest: str
    model_inference_performed: bool
    provider_dispatch: bool
    target_requests: int


class _CapacityV2RunContract(Protocol):
    run_path: Path
    run_id: str
    root_digest: str
    projection_digest: str
    pin: _CapacityV2PinContract
    evidence: _CapacityV2EvidenceContract
    proof: _CapacityV2ProofContract
    index: _CapacityV2IndexContract
    model_materialization_attestation_digest: str
    started_event_hash: str
    model_mount_attested_event_hash: str
    completed_event_hash: str


@dataclass(frozen=True, slots=True)
class _CapacityV2View:
    semantics: str
    run_path: Path
    run_id: str
    root_digest: str
    projection_digest: str
    pin_digest: str
    evidence_digest: str
    proof_digest: str
    index_digest: str
    request_digest: str
    tokenizer_digest: str
    chat_template_digest: str
    prompt_token_count: int
    completion_token_limit: int
    context_token_limit: int
    total_token_count: int
    remaining_token_count: int
    conservative_campaign_prompt_tokens: int
    conservative_campaign_total_tokens: int
    fits_context: bool
    model_materialization_policy_digest: str
    model_materialization_attestation_digest: str
    model_pin_digest: str
    expected_model_sha256: str
    expected_model_size_bytes: int
    staged_model_sha256: str
    staged_model_size_bytes: int
    staged_model_uid: int
    staged_model_gid: int
    staged_model_mode: str
    mounted_model_sha256: str
    mounted_model_size_bytes: int
    mounted_model_uid: int
    mounted_model_gid: int
    mounted_model_mode: str
    tokenizer_image_id: str
    staging_strategy: str
    materialization_kind: str
    mount_type: str
    mount_destination: str
    read_only: bool
    digest_algorithm: str
    attested_before_tokenizer_endpoints: bool
    runtime_user_read_verified: bool
    cleanup_required: bool
    started_event_hash: str
    model_mount_attested_event_hash: str
    completed_event_hash: str


def _parser() -> argparse.ArgumentParser:
    """Use the v1 parser so v2 accepts no additional mutable authority."""

    return _v1._parser()


def _arguments(
    argv: Sequence[str] | None = None,
) -> OperationalSkillBoundWebCapacityV2Inputs:
    return _v1._arguments(argv)


def _verify_inputs(
    values: OperationalSkillBoundWebCapacityV2Inputs,
) -> VerifiedOperationalSkillBoundWebCapacityV2Inputs:
    try:
        return _v1._verify_inputs(values)
    except Exception as exc:
        raise OperationalSkillBoundWebCapacityV2Error(
            "compact WEB Capacity v2 inputs failed strict verification"
        ) from exc


def _conservative_campaign_prompt_tokens(
    verified: VerifiedOperationalSkillBoundWebCapacityV2Inputs,
) -> int:
    try:
        return _v1._conservative_campaign_prompt_tokens(verified)
    except Exception as exc:
        raise OperationalSkillBoundWebCapacityV2Error(
            "compact WEB Capacity v2 exceeds its conservative Campaign token budget"
        ) from exc


def _reserve_fresh_output_root(path: Path) -> PinnedOutputRoot:
    try:
        return _v1._reserve_fresh_output_root(path)
    except Exception as exc:
        raise OperationalSkillBoundWebCapacityV2Error(
            "Capacity v2 output root could not be reserved"
        ) from exc


def _capacity_v2_api() -> _CapacityV2Api:
    from pajin.web_assessment.analysis_capacity import (
        SubprocessLlamaCppTokenizerBackend,
    )
    from pajin.web_assessment.analysis_capacity_v2 import (
        build_web_analysis_capacity_v2_pin,
        create_web_analysis_capacity_v2_run,
        load_verified_web_analysis_capacity_v2_run,
    )
    from pajin.web_assessment.analysis_skill_compact import (
        COMPACT_SKILL_BOUND_SYSTEM_SENTINEL,
        COMPACT_SKILL_BOUND_USER_SENTINEL,
    )

    return _CapacityV2Api(
        build_pin=build_web_analysis_capacity_v2_pin,
        tokenizer_backend=SubprocessLlamaCppTokenizerBackend,
        create_run=create_web_analysis_capacity_v2_run,
        load_run=load_verified_web_analysis_capacity_v2_run,
        system_sentinel=COMPACT_SKILL_BOUND_SYSTEM_SENTINEL,
        user_sentinel=COMPACT_SKILL_BOUND_USER_SENTINEL,
    )


def _has_no_authority(value: _NoAuthorityContract) -> bool:
    return all(getattr(value, field) is False for field in _AUTHORITY_FIELDS)


def _capacity_v2_view(run: object) -> _CapacityV2View:
    try:
        capacity_run = cast(_CapacityV2RunContract, run)
        pin = capacity_run.pin
        evidence = capacity_run.evidence
        proof = capacity_run.proof
        index = capacity_run.index
        attestation = evidence.model_materialization_attestation
        if (
            not all(
                _has_no_authority(value) for value in (pin, evidence, proof, index, attestation)
            )
            or proof.model_inference_performed is not False
            or proof.provider_dispatch is not False
            or type(proof.target_requests) is not int
            or proof.target_requests != 0
            or index.model_inference_performed is not False
            or index.provider_dispatch is not False
            or type(index.target_requests) is not int
            or index.target_requests != 0
            or pin.offline is not True
            or pin.tokenizer_only is not True
            or proof.evidence_digest != evidence.evidence_digest
            or index.evidence_digest != evidence.evidence_digest
            or index.proof_digest != proof.proof_digest
            or proof.request_digest != pin.chat_request_digest
            or capacity_run.model_materialization_attestation_digest
            != attestation.attestation_digest
            or proof.model_materialization_attestation_digest != attestation.attestation_digest
            or index.model_materialization_attestation_digest != attestation.attestation_digest
            or not (
                attestation.expected_model_sha256
                == attestation.staged_model_sha256
                == attestation.mounted_model_sha256
            )
            or not (
                attestation.expected_model_size_bytes
                == attestation.staged_model_size_bytes
                == attestation.mounted_model_size_bytes
            )
            or attestation.staging_strategy != "descriptor-to-docker-volume"
            or attestation.materialization_kind != "docker-copy"
            or attestation.mount_type != "volume"
            or attestation.mount_destination != "/models"
            or attestation.read_only is not True
            or attestation.digest_algorithm != "sha256"
            or attestation.attested_before_tokenizer_endpoints is not True
            or attestation.runtime_user_read_verified is not True
            or attestation.cleanup_required is not True
            or attestation.staged_model_uid != 10001
            or attestation.staged_model_gid != 10001
            or attestation.staged_model_mode != "0400"
            or attestation.mounted_model_uid != 10001
            or attestation.mounted_model_gid != 10001
            or attestation.mounted_model_mode != "0400"
        ):
            raise OperationalSkillBoundWebCapacityV2Error(
                "Capacity v2 Run unexpectedly carries dispatch, target I/O, authority, "
                "or an invalid model materialization attestation"
            )
        return _CapacityV2View(
            semantics="offline-tokenizer-capacity-proof-v2-attested-no-dispatch",
            run_path=capacity_run.run_path,
            run_id=capacity_run.run_id,
            root_digest=capacity_run.root_digest,
            projection_digest=capacity_run.projection_digest,
            pin_digest=pin.pin_digest,
            evidence_digest=evidence.evidence_digest,
            proof_digest=proof.proof_digest,
            index_digest=index.index_digest,
            request_digest=pin.chat_request_digest,
            tokenizer_digest=pin.tokenizer_runtime_digest,
            chat_template_digest=proof.chat_template_digest,
            prompt_token_count=proof.prompt_tokens,
            completion_token_limit=proof.completion_tokens,
            context_token_limit=pin.context_tokens,
            total_token_count=proof.total_tokens,
            remaining_token_count=proof.remaining_tokens,
            conservative_campaign_prompt_tokens=proof.conservative_campaign_prompt_tokens,
            conservative_campaign_total_tokens=proof.conservative_campaign_total_tokens,
            fits_context=proof.fits,
            model_materialization_policy_digest=pin.model_materialization_policy_digest,
            model_materialization_attestation_digest=attestation.attestation_digest,
            model_pin_digest=attestation.model_pin_digest,
            expected_model_sha256=attestation.expected_model_sha256,
            expected_model_size_bytes=attestation.expected_model_size_bytes,
            staged_model_sha256=attestation.staged_model_sha256,
            staged_model_size_bytes=attestation.staged_model_size_bytes,
            staged_model_uid=attestation.staged_model_uid,
            staged_model_gid=attestation.staged_model_gid,
            staged_model_mode=attestation.staged_model_mode,
            mounted_model_sha256=attestation.mounted_model_sha256,
            mounted_model_size_bytes=attestation.mounted_model_size_bytes,
            mounted_model_uid=attestation.mounted_model_uid,
            mounted_model_gid=attestation.mounted_model_gid,
            mounted_model_mode=attestation.mounted_model_mode,
            tokenizer_image_id=attestation.tokenizer_image_id,
            staging_strategy=attestation.staging_strategy,
            materialization_kind=attestation.materialization_kind,
            mount_type=attestation.mount_type,
            mount_destination=attestation.mount_destination,
            read_only=attestation.read_only,
            digest_algorithm=attestation.digest_algorithm,
            attested_before_tokenizer_endpoints=(attestation.attested_before_tokenizer_endpoints),
            runtime_user_read_verified=attestation.runtime_user_read_verified,
            cleanup_required=attestation.cleanup_required,
            started_event_hash=capacity_run.started_event_hash,
            model_mount_attested_event_hash=(capacity_run.model_mount_attested_event_hash),
            completed_event_hash=capacity_run.completed_event_hash,
        )
    except OperationalSkillBoundWebCapacityV2Error:
        raise
    except (AttributeError, TypeError, ValueError) as exc:
        raise OperationalSkillBoundWebCapacityV2Error(
            "Capacity v2 Run does not expose the closed attested offline proof contract"
        ) from exc


def run_operational_skill_bound_web_capacity_v2(
    values: OperationalSkillBoundWebCapacityV2Inputs,
) -> OperationalSkillBoundWebCapacityV2Result:
    """Create and independently reload one attested, zero-dispatch Capacity v2 Run."""

    verified = _verify_inputs(values)
    pinned_output = _reserve_fresh_output_root(verified.output_root)
    try:
        with pinned_output, pinned_output.activate():
            api = _capacity_v2_api()
            conservative_prompt_tokens = _conservative_campaign_prompt_tokens(verified)
            pin = api.build_pin(
                skill_run=verified.skill_run,
                projection=verified.compact_projection,
                chat_request=verified.chat_request,
                runtime=verified.plan.runtime,
                model_pin=verified.model,
                transport_pin_digest=verified.expected_transport_pin_digest,
                conservative_campaign_prompt_tokens=conservative_prompt_tokens,
            )
            backend = api.tokenizer_backend(
                model_path=verified.model_path,
                timeout_seconds=verified.plan.runtime.request_timeout_seconds,
                cpus=verified.plan.runtime.model_cpus,
                memory_mb=verified.plan.runtime.model_memory_mb,
                pids_limit=verified.plan.runtime.model_pids,
            )
            created = api.create_run(
                Path("."),
                skill_run=verified.skill_run,
                projection=verified.compact_projection,
                chat_request=verified.chat_request,
                pin=pin,
                tokenizer_backend=backend,
                system_sentinel=api.system_sentinel,
                user_sentinel=api.user_sentinel,
            )
            created_view = _capacity_v2_view(created)
            loaded = api.load_run(
                created_view.run_path,
                skill_run=verified.skill_run,
                expected_run_id=created_view.run_id,
                expected_root_digest=created_view.root_digest,
                expected_pin_digest=created_view.pin_digest,
                expected_transport_pin_digest=verified.expected_transport_pin_digest,
                expected_proof_digest=created_view.proof_digest,
                expected_model_materialization_attestation_digest=(
                    created_view.model_materialization_attestation_digest
                ),
            )
            view = _capacity_v2_view(loaded)
            if view != created_view:
                raise OperationalSkillBoundWebCapacityV2Error(
                    "strictly reloaded Capacity v2 proof differs from its created Run"
                )
            pinned_output.require_original_path_identity()
    except OperationalSkillBoundWebCapacityV2Error:
        raise
    except Exception as exc:
        raise OperationalSkillBoundWebCapacityV2Error(
            "attested offline compact WEB Capacity v2 proof failed closed"
        ) from exc
    return OperationalSkillBoundWebCapacityV2Result(
        summary=_secret_free_summary(verified=verified, capacity=view),
        succeeded=view.fits_context,
    )


def _secret_free_summary(
    *,
    verified: VerifiedOperationalSkillBoundWebCapacityV2Inputs,
    capacity: _CapacityV2View,
) -> dict[str, object]:
    legacy_view = _v1._CapacityView(
        semantics=capacity.semantics,
        run_path=capacity.run_path,
        run_id=capacity.run_id,
        root_digest=capacity.root_digest,
        projection_digest=capacity.projection_digest,
        pin_digest=capacity.pin_digest,
        evidence_digest=capacity.evidence_digest,
        proof_digest=capacity.proof_digest,
        index_digest=capacity.index_digest,
        request_digest=capacity.request_digest,
        tokenizer_digest=capacity.tokenizer_digest,
        chat_template_digest=capacity.chat_template_digest,
        prompt_token_count=capacity.prompt_token_count,
        completion_token_limit=capacity.completion_token_limit,
        context_token_limit=capacity.context_token_limit,
        total_token_count=capacity.total_token_count,
        remaining_token_count=capacity.remaining_token_count,
        conservative_campaign_prompt_tokens=(capacity.conservative_campaign_prompt_tokens),
        conservative_campaign_total_tokens=(capacity.conservative_campaign_total_tokens),
        fits_context=capacity.fits_context,
    )
    summary = _v1._secret_free_summary(verified=verified, capacity=legacy_view)
    summary.update(
        {
            "apiVersion": _SUMMARY_API_VERSION,
            "kind": "OperationalSkillBoundWebCapacityV2Conformance",
            "capacityProofVersion": "v2",
            "modelMaterializationPolicyDigest": (capacity.model_materialization_policy_digest),
            "modelMaterializationAttestationVerified": True,
            "modelMaterializationAttestationDigest": (
                capacity.model_materialization_attestation_digest
            ),
            "modelMaterialization": {
                "modelPinDigest": capacity.model_pin_digest,
                "expectedModelSha256": capacity.expected_model_sha256,
                "expectedModelSizeBytes": capacity.expected_model_size_bytes,
                "stagedModelSha256": capacity.staged_model_sha256,
                "stagedModelSizeBytes": capacity.staged_model_size_bytes,
                "stagedModelUid": capacity.staged_model_uid,
                "stagedModelGid": capacity.staged_model_gid,
                "stagedModelMode": capacity.staged_model_mode,
                "mountedModelSha256": capacity.mounted_model_sha256,
                "mountedModelSizeBytes": capacity.mounted_model_size_bytes,
                "mountedModelUid": capacity.mounted_model_uid,
                "mountedModelGid": capacity.mounted_model_gid,
                "mountedModelMode": capacity.mounted_model_mode,
                "tokenizerImageId": capacity.tokenizer_image_id,
                "stagingStrategy": capacity.staging_strategy,
                "materializationKind": capacity.materialization_kind,
                "mountType": capacity.mount_type,
                "mountDestination": capacity.mount_destination,
                "readOnly": capacity.read_only,
                "digestAlgorithm": capacity.digest_algorithm,
                "attestedBeforeTokenizerEndpoints": (capacity.attested_before_tokenizer_endpoints),
                "runtimeUserReadVerified": capacity.runtime_user_read_verified,
                "cleanupRequired": capacity.cleanup_required,
            },
            "startedEventHash": capacity.started_event_hash,
            "modelMountAttestedEventHash": capacity.model_mount_attested_event_hash,
            "completedEventHash": capacity.completed_event_hash,
            "modelInferencePerformed": False,
            "providerDispatchAuthority": False,
            "targetRequestAuthority": False,
            "scopeExpansionAuthority": False,
            "toolRequestAuthority": False,
            "capabilityAuthority": False,
            "permitAuthority": False,
        }
    )
    return summary


def _error_summary(exc: BaseException) -> dict[str, object]:
    return {
        "apiVersion": _SUMMARY_API_VERSION,
        "kind": "OperationalSkillBoundWebCapacityV2Conformance",
        "capacityProofVersion": "v2",
        "status": "operational-error",
        "errorType": type(exc).__name__,
        "complete": False,
        "offlineTokenizerOnly": True,
        "modelMaterializationAttestationVerified": False,
        "modelCompletionsPerformed": 0,
        "modelInferencePerformed": False,
        "providerDispatchCount": 0,
        "targetRequestCount": 0,
        "targetRequestsPerformed": False,
        "externalDeliveryPerformed": False,
        "providerDispatchAuthority": False,
        "targetRequestAuthority": False,
        "scopeExpansionAuthority": False,
        "toolRequestAuthority": False,
        "capabilityAuthority": False,
        "permitAuthority": False,
        "executionAuthority": False,
        "graphAdmissionAuthority": False,
        "findingAuthority": False,
        "reportDeliveryAuthority": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    try:
        result = run_operational_skill_bound_web_capacity_v2(_arguments(argv))
    except (Exception, KeyboardInterrupt) as exc:
        print(json.dumps(_error_summary(exc), sort_keys=True))
        return 2
    print(json.dumps(result.summary, sort_keys=True))
    return 0 if result.succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
