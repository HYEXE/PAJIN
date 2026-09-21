"""Seal one offline tokenizer-only capacity proof for the compact WEB-007 request."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol, cast

if TYPE_CHECKING or __package__:
    from scripts import operational_web_analysis as _legacy
else:  # pragma: no cover - exercised by the standalone entrypoint
    import operational_web_analysis as _legacy

from pajin.benchmark.effectiveness.docker import verify_images, verify_model
from pajin.benchmark.effectiveness.suite import ModelPin, RuntimePin
from pajin.benchmark.effectiveness_structured.plan import ComparisonPlan
from pajin.providers.models import ProviderChatRequest
from pajin.runtime.pinned_workspace import PinnedOutputRoot
from pajin.skills.models import SkillRegistryRef
from pajin.web_assessment.analysis_local import (
    build_local_web_analysis_provider_registration,
)
from pajin.web_assessment.analysis_skill_projection import (
    SkillBoundWebAnalysisSnapshot,
    VerifiedWebAnalysisSkillProjectionRun,
    build_skill_bound_web_analysis_snapshot,
    load_verified_web_analysis_skill_projection,
)
from pajin.web_assessment.analysis_transport import (
    WebAnalysisTransportRuntimePin,
    load_verified_web_analysis_transport_runtime_pin,
)
from pajin.web_assessment.discovery_artifact import (
    VerifiedAuthenticatedDiscoveryRun,
    load_verified_authenticated_discovery,
)

if TYPE_CHECKING:
    from pajin.web_assessment.analysis_skill_compact import (
        CompactSkillBoundWebAnalysisProjection,
    )

_SUMMARY_API_VERSION: Final = "pajin.dev/operational-skill-bound-web-capacity-conformance/v1alpha1"


class OperationalSkillBoundWebCapacityError(ValueError):
    """Raised when the offline compact-capacity boundary fails closed."""


@dataclass(frozen=True, slots=True)
class OperationalSkillBoundWebCapacityResult:
    """Secret-free terminal summary plus its process-success classification."""

    summary: dict[str, object]
    succeeded: bool


@dataclass(frozen=True, slots=True)
class OperationalSkillBoundWebCapacityInputs:
    """Caller-supplied immutable inputs and independently retained anchors."""

    source_run_path: Path
    source_run_id: str
    source_root_digest: str
    comparison_plan_run_path: Path
    comparison_plan_run_id: str
    comparison_plan_root_digest: str
    skill_run_path: Path
    skill_run_id: str
    skill_root_digest: str
    transport_pin_path: Path
    expected_transport_pin_digest: str
    qwen_model_path: Path
    output_root: Path


@dataclass(frozen=True, slots=True)
class VerifiedOperationalSkillBoundWebCapacityInputs:
    """Strictly reloaded capacity inputs before the offline tokenizer backend runs."""

    source: VerifiedAuthenticatedDiscoveryRun
    plan: ComparisonPlan
    comparison_plan_run_id: str
    comparison_plan_root_digest: str
    skill_run: VerifiedWebAnalysisSkillProjectionRun
    expected_registry_ref: SkillRegistryRef
    expected_policy_digest: str
    transport_pin: WebAnalysisTransportRuntimePin
    expected_transport_pin_digest: str
    model: ModelPin
    model_path: Path
    output_root: Path
    compact_projection: CompactSkillBoundWebAnalysisProjection
    chat_request: ProviderChatRequest


@dataclass(frozen=True, slots=True)
class _CapacityView:
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


@dataclass(frozen=True, slots=True)
class _CapacityApi:
    build_pin: Callable[..., object]
    tokenizer_backend: Callable[..., object]
    create_run: Callable[..., object]
    load_run: Callable[..., object]
    system_sentinel: str
    user_sentinel: str


class _CapacityPinContract(Protocol):
    pin_digest: str
    chat_request_digest: str
    tokenizer_runtime_digest: str
    context_tokens: int
    provider_dispatch_authority: bool
    target_request_authority: bool
    execution_authority: bool
    graph_admission_authority: bool
    finding_authority: bool
    report_delivery_authority: bool


class _CapacityProofContract(Protocol):
    proof_digest: str
    evidence_digest: str
    request_digest: str
    chat_template_digest: str
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


class _CapacityEvidenceContract(Protocol):
    evidence_digest: str


class _CapacityIndexContract(Protocol):
    index_digest: str
    evidence_digest: str
    proof_digest: str
    model_inference_performed: bool
    provider_dispatch: bool
    target_requests: int


class _CapacityRunContract(Protocol):
    run_path: Path
    run_id: str
    root_digest: str
    projection_digest: str
    pin: _CapacityPinContract
    evidence: _CapacityEvidenceContract
    proof: _CapacityProofContract
    index: _CapacityIndexContract


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-run-path", required=True, type=Path)
    parser.add_argument("--source-run-id", required=True)
    parser.add_argument("--source-root-digest", required=True)
    parser.add_argument("--comparison-plan-run-path", required=True, type=Path)
    parser.add_argument("--comparison-plan-run-id", required=True)
    parser.add_argument("--comparison-plan-root-digest", required=True)
    parser.add_argument("--skill-run-path", required=True, type=Path)
    parser.add_argument("--skill-run-id", required=True)
    parser.add_argument("--skill-root-digest", required=True)
    parser.add_argument("--transport-pin-path", required=True, type=Path)
    parser.add_argument("--expected-transport-pin-digest", required=True)
    parser.add_argument("--qwen-model-path", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    return parser


def _arguments(argv: Sequence[str] | None = None) -> OperationalSkillBoundWebCapacityInputs:
    args = _parser().parse_args(argv)
    return OperationalSkillBoundWebCapacityInputs(
        source_run_path=args.source_run_path,
        source_run_id=args.source_run_id,
        source_root_digest=args.source_root_digest,
        comparison_plan_run_path=args.comparison_plan_run_path,
        comparison_plan_run_id=args.comparison_plan_run_id,
        comparison_plan_root_digest=args.comparison_plan_root_digest,
        skill_run_path=args.skill_run_path,
        skill_run_id=args.skill_run_id,
        skill_root_digest=args.skill_root_digest,
        transport_pin_path=args.transport_pin_path,
        expected_transport_pin_digest=args.expected_transport_pin_digest,
        qwen_model_path=args.qwen_model_path,
        output_root=args.output_root,
    )


def _verify_inputs(
    values: OperationalSkillBoundWebCapacityInputs,
) -> VerifiedOperationalSkillBoundWebCapacityInputs:
    """Strictly reload every immutable authority before tokenizer execution."""

    try:
        output_root = _legacy._fresh_output_root(
            values.output_root,
            label="capacity output root",
        )
        source = load_verified_authenticated_discovery(
            values.source_run_path,
            expected_run_id=values.source_run_id,
            expected_root_digest=values.source_root_digest,
        )
        plan = _legacy._load_verified_comparison_plan_run(
            values.comparison_plan_run_path,
            expected_run_id=values.comparison_plan_run_id,
            expected_root_digest=values.comparison_plan_root_digest,
        )
        expected_snapshot = build_skill_bound_web_analysis_snapshot(
            source,
            expected_source_run_id=values.source_run_id,
            expected_source_root_digest=values.source_root_digest,
        )
        registry_ref = expected_snapshot.selection_policy.registry
        policy_digest = expected_snapshot.selection_policy.policy_digest
        skill_run = load_verified_web_analysis_skill_projection(
            values.skill_run_path,
            source=source,
            expected_run_id=values.skill_run_id,
            expected_root_digest=values.skill_root_digest,
            expected_source_run_id=values.source_run_id,
            expected_source_root_digest=values.source_root_digest,
            expected_registry_ref=registry_ref,
            expected_policy_digest=policy_digest,
        )
        if skill_run.snapshot != expected_snapshot:
            raise ValueError("sealed SKILL-002 Run differs from code-owned projection")
        transport = load_verified_web_analysis_transport_runtime_pin(
            values.transport_pin_path,
            runtime=plan.runtime,
            expected_pin_digest=values.expected_transport_pin_digest,
        )
        _require_output_outside_inputs(
            output_root,
            source_run_path=source.run_path,
            comparison_plan_run_path=values.comparison_plan_run_path,
            skill_run_path=values.skill_run_path,
            transport_pin_path=values.transport_pin_path,
            model_path=values.qwen_model_path,
        )
        verify_images(plan.runtime)
        _verify_transport_images(transport, runtime=plan.runtime)
        model = _legacy._qwen_model_pin(plan)
        model_path = verify_model(values.qwen_model_path, model)
        compact_projection = _build_compact_projection(skill_run.snapshot)
        chat_request = _build_compact_chat_request(skill_run.snapshot)
        return VerifiedOperationalSkillBoundWebCapacityInputs(
            source=source,
            plan=plan,
            comparison_plan_run_id=values.comparison_plan_run_id,
            comparison_plan_root_digest=values.comparison_plan_root_digest,
            skill_run=skill_run,
            expected_registry_ref=registry_ref,
            expected_policy_digest=policy_digest,
            transport_pin=transport,
            expected_transport_pin_digest=values.expected_transport_pin_digest,
            model=model,
            model_path=model_path,
            output_root=output_root,
            compact_projection=compact_projection,
            chat_request=chat_request,
        )
    except OperationalSkillBoundWebCapacityError:
        raise
    except Exception as exc:
        raise OperationalSkillBoundWebCapacityError(
            "compact WEB capacity inputs failed strict verification"
        ) from exc


def _verify_transport_images(
    transport: WebAnalysisTransportRuntimePin,
    *,
    runtime: RuntimePin,
) -> None:
    material = runtime.model_dump(mode="python")
    material["worker_image"] = transport.worker_image
    material["proxy_image"] = transport.proxy_image
    verify_images(RuntimePin.model_validate(material))


def _build_compact_projection(
    snapshot: SkillBoundWebAnalysisSnapshot,
) -> CompactSkillBoundWebAnalysisProjection:
    from pajin.web_assessment.analysis_skill_compact import (
        build_compact_skill_bound_web_analysis_projection,
    )

    return build_compact_skill_bound_web_analysis_projection(snapshot)


def _build_compact_chat_request(
    projection: SkillBoundWebAnalysisSnapshot,
) -> ProviderChatRequest:
    from pajin.web_assessment.analysis_skill_compact import (
        build_compact_skill_bound_web_analysis_chat_request,
    )

    return build_compact_skill_bound_web_analysis_chat_request(projection)


def _capacity_api() -> _CapacityApi:
    from pajin.web_assessment.analysis_capacity import (
        SubprocessLlamaCppTokenizerBackend,
        build_web_analysis_capacity_pin,
        create_web_analysis_capacity_run,
        load_verified_web_analysis_capacity_run,
    )
    from pajin.web_assessment.analysis_skill_compact import (
        COMPACT_SKILL_BOUND_SYSTEM_SENTINEL,
        COMPACT_SKILL_BOUND_USER_SENTINEL,
    )

    return _CapacityApi(
        build_pin=build_web_analysis_capacity_pin,
        tokenizer_backend=SubprocessLlamaCppTokenizerBackend,
        create_run=create_web_analysis_capacity_run,
        load_run=load_verified_web_analysis_capacity_run,
        system_sentinel=COMPACT_SKILL_BOUND_SYSTEM_SENTINEL,
        user_sentinel=COMPACT_SKILL_BOUND_USER_SENTINEL,
    )


def _conservative_campaign_prompt_tokens(
    verified: VerifiedOperationalSkillBoundWebCapacityInputs,
) -> int:
    from pajin.providers.usage import provider_model_usage_upper_bound

    registration = build_local_web_analysis_provider_registration(
        runtime=verified.plan.runtime,
        model=verified.model,
    )
    bound = provider_model_usage_upper_bound(registration, verified.chat_request)
    total = bound.prompt_tokens + bound.completion_tokens
    if bound.completion_tokens != 1_024 or total > 65_536:
        raise OperationalSkillBoundWebCapacityError(
            "compact WEB request exceeds its conservative Campaign token budget"
        )
    return bound.prompt_tokens


def _require_output_outside_inputs(
    output_root: Path,
    *,
    source_run_path: Path,
    comparison_plan_run_path: Path,
    skill_run_path: Path,
    transport_pin_path: Path,
    model_path: Path,
) -> None:
    inputs = tuple(
        Path(os.path.abspath(value))
        for value in (
            source_run_path,
            comparison_plan_run_path,
            skill_run_path,
            transport_pin_path,
            model_path,
        )
    )
    if any(
        output_root == value or value in output_root.parents or output_root in value.parents
        for value in inputs
    ):
        raise OperationalSkillBoundWebCapacityError(
            "capacity output root must be outside immutable inputs"
        )


def _reserve_fresh_output_root(path: Path) -> PinnedOutputRoot:
    try:
        return PinnedOutputRoot.create(path)
    except Exception as exc:
        if isinstance(exc, OperationalSkillBoundWebCapacityError):
            raise
        raise OperationalSkillBoundWebCapacityError(
            "capacity output root could not be reserved"
        ) from exc


def run_operational_skill_bound_web_capacity(
    values: OperationalSkillBoundWebCapacityInputs,
) -> OperationalSkillBoundWebCapacityResult:
    """Create and independently reload one offline, zero-dispatch capacity proof."""

    verified = _verify_inputs(values)
    pinned_output = _reserve_fresh_output_root(verified.output_root)
    try:
        with pinned_output, pinned_output.activate():
            api = _capacity_api()
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
            created_view = _capacity_view(created)
            pin_digest = cast(_CapacityPinContract, pin).pin_digest
            loaded = api.load_run(
                created_view.run_path,
                skill_run=verified.skill_run,
                expected_run_id=created_view.run_id,
                expected_root_digest=created_view.root_digest,
                expected_pin_digest=pin_digest,
                expected_transport_pin_digest=verified.expected_transport_pin_digest,
            )
            view = _capacity_view(loaded)
            if view != created_view:
                raise OperationalSkillBoundWebCapacityError(
                    "strictly reloaded capacity proof differs from its created Run"
                )
            pinned_output.require_original_path_identity()
    except OperationalSkillBoundWebCapacityError:
        raise
    except Exception as exc:
        raise OperationalSkillBoundWebCapacityError(
            "offline compact WEB capacity proof failed closed"
        ) from exc
    return OperationalSkillBoundWebCapacityResult(
        summary=_secret_free_summary(verified=verified, capacity=view),
        succeeded=view.fits_context,
    )


def _capacity_view(run: object) -> _CapacityView:
    try:
        capacity_run = cast(_CapacityRunContract, run)
        pin = capacity_run.pin
        evidence = capacity_run.evidence
        proof = capacity_run.proof
        index = capacity_run.index
        zero_markers = (
            proof.target_requests,
            index.target_requests,
        )
        false_markers = (
            proof.model_inference_performed,
            proof.provider_dispatch,
            index.model_inference_performed,
            index.provider_dispatch,
            pin.provider_dispatch_authority,
            pin.target_request_authority,
            pin.execution_authority,
            pin.graph_admission_authority,
            pin.finding_authority,
            pin.report_delivery_authority,
        )
        if (
            zero_markers != (0, 0)
            or false_markers != (False,) * len(false_markers)
            or proof.evidence_digest != evidence.evidence_digest
            or index.evidence_digest != evidence.evidence_digest
            or index.proof_digest != proof.proof_digest
        ):
            raise OperationalSkillBoundWebCapacityError(
                "capacity Run unexpectedly carries dispatch, target I/O, or authority"
            )
        return _CapacityView(
            semantics="offline-tokenizer-capacity-proof-no-dispatch",
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
            conservative_campaign_prompt_tokens=(proof.conservative_campaign_prompt_tokens),
            conservative_campaign_total_tokens=(proof.conservative_campaign_total_tokens),
            fits_context=proof.fits,
        )
    except OperationalSkillBoundWebCapacityError:
        raise
    except (AttributeError, TypeError, ValueError) as exc:
        raise OperationalSkillBoundWebCapacityError(
            "capacity Run does not expose the closed offline proof contract"
        ) from exc


def _secret_free_summary(
    *,
    verified: VerifiedOperationalSkillBoundWebCapacityInputs,
    capacity: _CapacityView,
) -> dict[str, object]:
    return {
        "apiVersion": _SUMMARY_API_VERSION,
        "kind": "OperationalSkillBoundWebCapacityConformance",
        "status": (
            "compact-request-fits-context"
            if capacity.fits_context
            else "compact-request-exceeds-context"
        ),
        "semantics": capacity.semantics,
        "strictSourceReloaded": True,
        "comparisonPlanVerified": True,
        "comparisonPlanRunId": verified.comparison_plan_run_id,
        "comparisonPlanRootDigest": verified.comparison_plan_root_digest,
        "comparisonPlanCommitment": verified.plan.commitment,
        "skillProjectionVerified": True,
        "skillRunId": verified.skill_run.verification.run_id,
        "skillRootDigest": verified.skill_run.verification.root_digest,
        "transportPinVerified": True,
        "transportPinDigest": verified.expected_transport_pin_digest,
        "modelVerified": True,
        "model": {
            "name": verified.model.name,
            "repository": verified.model.repository,
            "revision": verified.model.revision,
            "sha256": verified.model.sha256,
            "sizeBytes": verified.model.size_bytes,
        },
        "compactProjectionDigest": capacity.projection_digest,
        "capacityPinDigest": capacity.pin_digest,
        "capacityEvidenceDigest": capacity.evidence_digest,
        "capacityProofDigest": capacity.proof_digest,
        "capacityIndexDigest": capacity.index_digest,
        "chatRequestDigest": capacity.request_digest,
        "tokenizerDigest": capacity.tokenizer_digest,
        "chatTemplateDigest": capacity.chat_template_digest,
        "promptTokenCount": capacity.prompt_token_count,
        "completionTokenLimit": capacity.completion_token_limit,
        "contextTokenLimit": capacity.context_token_limit,
        "totalTokenCount": capacity.total_token_count,
        "remainingTokenCount": capacity.remaining_token_count,
        "conservativeCampaignPromptTokens": (capacity.conservative_campaign_prompt_tokens),
        "conservativeCampaignTotalTokens": (capacity.conservative_campaign_total_tokens),
        "fitsContext": capacity.fits_context,
        "capacityRunId": capacity.run_id,
        "capacityRootDigest": capacity.root_digest,
        "strictCapacityReloaded": True,
        "offlineTokenizerOnly": True,
        "modelCompletionsPerformed": 0,
        "providerDispatchCount": 0,
        "targetRequestCount": 0,
        "targetRequestsPerformed": False,
        "externalDeliveryPerformed": False,
        "executionAuthority": False,
        "graphAdmissionAuthority": False,
        "findingAuthority": False,
        "reportDeliveryAuthority": False,
    }


def _error_summary(exc: BaseException) -> dict[str, object]:
    return {
        "apiVersion": _SUMMARY_API_VERSION,
        "kind": "OperationalSkillBoundWebCapacityConformance",
        "status": "operational-error",
        "errorType": type(exc).__name__,
        "complete": False,
        "offlineTokenizerOnly": True,
        "modelCompletionsPerformed": 0,
        "providerDispatchCount": 0,
        "targetRequestCount": 0,
        "targetRequestsPerformed": False,
        "externalDeliveryPerformed": False,
        "executionAuthority": False,
        "graphAdmissionAuthority": False,
        "findingAuthority": False,
        "reportDeliveryAuthority": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    try:
        result = run_operational_skill_bound_web_capacity(_arguments(argv))
    except (Exception, KeyboardInterrupt) as exc:
        print(json.dumps(_error_summary(exc), sort_keys=True))
        return 2
    print(json.dumps(result.summary, sort_keys=True))
    return 0 if result.succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
