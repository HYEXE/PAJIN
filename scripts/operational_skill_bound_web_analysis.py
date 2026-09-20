"""Run one local-only SKILL-002-bound WEB analysis turn over sealed evidence."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING or __package__:
    from scripts import operational_web_analysis as _legacy
else:  # pragma: no cover - exercised by the standalone entrypoint
    import operational_web_analysis as _legacy

from pajin.benchmark.effectiveness.docker import LocalModelRuntime, verify_images
from pajin.benchmark.effectiveness.suite import ModelPin, RuntimePin
from pajin.benchmark.effectiveness_structured.plan import ComparisonPlan
from pajin.skills.models import SkillRegistryRef
from pajin.web_assessment.analysis_local import (
    LocalWebAnalysisProviderAssembly,
    LocalWebAnalysisProviderCleanup,
    build_local_web_analysis_provider_registration,
    build_local_web_analysis_provider_runtime,
    require_local_web_analysis_request_fits_model_budget,
    require_local_web_analysis_request_fits_runtime_context,
)
from pajin.web_assessment.analysis_skill_invocation import (
    build_skill_bound_web_analysis_chat_request,
)
from pajin.web_assessment.analysis_skill_projection import (
    VerifiedWebAnalysisSkillProjectionRun,
    build_skill_bound_web_analysis_snapshot,
    load_verified_web_analysis_skill_projection,
)
from pajin.web_assessment.analysis_skill_receipts import (
    VerifiedSkillBoundWebAnalysisFailureRun,
    VerifiedSkillBoundWebAnalysisInvocationRun,
)
from pajin.web_assessment.analysis_skill_runtime import (
    SkillBoundWebAnalysisCancelledError,
    SkillBoundWebAnalysisInvocationRuntime,
    SkillBoundWebAnalysisProviderRuntime,
    SkillBoundWebAnalysisRuntimeError,
    bind_skill_bound_web_analysis_provider_runtime,
    load_verified_skill_bound_web_analysis_failure,
    load_verified_skill_bound_web_analysis_invocation,
)
from pajin.web_assessment.analysis_transport import (
    WebAnalysisTransportRuntimePin,
    load_verified_web_analysis_transport_runtime_pin,
)
from pajin.web_assessment.discovery_artifact import VerifiedAuthenticatedDiscoveryRun

_SUMMARY_API_VERSION: Final = "pajin.dev/operational-skill-bound-web-analysis-conformance/v1alpha1"


class OperationalSkillBoundWebAnalysisError(ValueError):
    """Raised when the local successor conformance boundary fails closed."""


@dataclass(frozen=True, slots=True)
class OperationalSkillBoundWebAnalysisResult:
    """Secret-free terminal summary plus its process-success classification."""

    summary: dict[str, object]
    succeeded: bool


@dataclass(frozen=True, slots=True)
class OperationalSkillBoundWebAnalysisInputs:
    """Caller-supplied immutable inputs and separately retained anchors."""

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
    provider_output_root: Path
    analysis_output_root: Path


@dataclass(frozen=True, slots=True)
class VerifiedOperationalSkillBoundWebAnalysisInputs:
    """All authority inputs strictly reloaded before local model startup."""

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
    provider_output_root: Path
    analysis_output_root: Path


@dataclass(frozen=True, slots=True)
class _TerminalEvidence:
    status: str
    semantics: str
    analysis_run_id: str
    analysis_root_digest: str
    provider_run_id: str
    provider_root_digest: str
    provider_execution_context_digest: str
    terminal_state: str
    dispatch_count: int


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
    parser.add_argument("--provider-output-root", required=True, type=Path)
    parser.add_argument("--analysis-output-root", required=True, type=Path)
    return parser


def _arguments(argv: Sequence[str] | None = None) -> OperationalSkillBoundWebAnalysisInputs:
    args = _parser().parse_args(argv)
    return OperationalSkillBoundWebAnalysisInputs(
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
        provider_output_root=args.provider_output_root,
        analysis_output_root=args.analysis_output_root,
    )


def _verify_inputs(
    values: OperationalSkillBoundWebAnalysisInputs,
) -> VerifiedOperationalSkillBoundWebAnalysisInputs:
    """Finish every file, digest, Skill, image, and overlap check before startup."""

    try:
        base = _legacy._verify_inputs(
            _legacy.OperationalWebAnalysisInputs(
                source_run_path=values.source_run_path,
                source_run_id=values.source_run_id,
                source_root_digest=values.source_root_digest,
                comparison_plan_run_path=values.comparison_plan_run_path,
                comparison_plan_run_id=values.comparison_plan_run_id,
                comparison_plan_root_digest=values.comparison_plan_root_digest,
                qwen_model_path=values.qwen_model_path,
                provider_output_root=values.provider_output_root,
                analysis_output_root=values.analysis_output_root,
            )
        )
        _require_outputs_outside_successor_inputs(
            base.provider_output_root,
            base.analysis_output_root,
            skill_run_path=values.skill_run_path,
            transport_pin_path=values.transport_pin_path,
        )
        transport = load_verified_web_analysis_transport_runtime_pin(
            values.transport_pin_path,
            runtime=base.plan.runtime,
            expected_pin_digest=values.expected_transport_pin_digest,
        )
        _verify_transport_images(transport, runtime=base.plan.runtime)
        expected_snapshot = build_skill_bound_web_analysis_snapshot(
            base.source,
            expected_source_run_id=values.source_run_id,
            expected_source_root_digest=values.source_root_digest,
        )
        registry_ref = expected_snapshot.selection_policy.registry
        policy_digest = expected_snapshot.selection_policy.policy_digest
        skill_run = load_verified_web_analysis_skill_projection(
            values.skill_run_path,
            source=base.source,
            expected_run_id=values.skill_run_id,
            expected_root_digest=values.skill_root_digest,
            expected_source_run_id=values.source_run_id,
            expected_source_root_digest=values.source_root_digest,
            expected_registry_ref=registry_ref,
            expected_policy_digest=policy_digest,
        )
        if skill_run.snapshot != expected_snapshot:
            raise ValueError("sealed SKILL-002 Run differs from code-owned projection")
        registration = build_local_web_analysis_provider_registration(
            runtime=base.plan.runtime,
            model=base.model,
        )
        request = build_skill_bound_web_analysis_chat_request(skill_run.snapshot)
        require_local_web_analysis_request_fits_model_budget(
            request,
            registration=registration,
        )
        require_local_web_analysis_request_fits_runtime_context(
            request,
            registration=registration,
            runtime=base.plan.runtime,
        )
        return VerifiedOperationalSkillBoundWebAnalysisInputs(
            source=base.source,
            plan=base.plan,
            comparison_plan_run_id=base.comparison_plan_run_id,
            comparison_plan_root_digest=base.comparison_plan_root_digest,
            skill_run=skill_run,
            expected_registry_ref=registry_ref,
            expected_policy_digest=policy_digest,
            transport_pin=transport,
            expected_transport_pin_digest=values.expected_transport_pin_digest,
            model=base.model,
            model_path=base.model_path,
            provider_output_root=base.provider_output_root,
            analysis_output_root=base.analysis_output_root,
        )
    except OperationalSkillBoundWebAnalysisError:
        raise
    except Exception as exc:
        raise OperationalSkillBoundWebAnalysisError(
            "Skill-bound WEB analysis inputs failed strict verification"
        ) from exc


def _verify_transport_images(
    transport: WebAnalysisTransportRuntimePin,
    *,
    runtime: RuntimePin,
) -> None:
    material = runtime.model_dump(mode="python")
    material["worker_image"] = transport.worker_image
    material["proxy_image"] = transport.proxy_image
    successor_runtime = RuntimePin.model_validate(material)
    verify_images(successor_runtime)


def _require_outputs_outside_successor_inputs(
    provider_root: Path,
    analysis_root: Path,
    *,
    skill_run_path: Path,
    transport_pin_path: Path,
) -> None:
    inputs = tuple(Path(os.path.abspath(value)) for value in (skill_run_path, transport_pin_path))
    for output in (provider_root, analysis_root):
        if any(
            output == value or value in output.parents or output in value.parents
            for value in inputs
        ):
            raise OperationalSkillBoundWebAnalysisError(
                "successor output roots must be outside immutable Skill and Pin inputs"
            )


async def run_operational_skill_bound_web_analysis(
    values: OperationalSkillBoundWebAnalysisInputs,
) -> OperationalSkillBoundWebAnalysisResult:
    """Perform one successor model dispatch and strictly reload its terminal artifacts."""

    verified = _verify_inputs(values)
    model_runtime: LocalModelRuntime | None = None
    assembly: LocalWebAnalysisProviderAssembly | None = None
    cleanup: LocalWebAnalysisProviderCleanup | None = None
    terminal: _TerminalEvidence | None = None
    pending_error: BaseException | None = None
    with TemporaryDirectory(
        prefix="pajin-skill-bound-web-key-",
        dir=verified.provider_output_root.parent,
    ) as private_directory:
        private_root = Path(private_directory)
        private_root.chmod(0o700)
        key_path = private_root / "model-api-key"
        api_key = secrets.token_urlsafe(32)
        _legacy._write_private_key(key_path, api_key)
        model_runtime = LocalModelRuntime(
            runtime=verified.plan.runtime,
            model=verified.model,
            model_path=verified.model_path,
            key_file=key_path,
        )
        try:
            try:
                model_runtime.start()
                reserved_roots = _legacy._reserve_fresh_output_roots(
                    verified.provider_output_root,
                    verified.analysis_output_root,
                )
                _legacy._require_reserved_output_roots(reserved_roots)
                assembly = build_local_web_analysis_provider_runtime(
                    source=verified.source,
                    expected_run_id=values.source_run_id,
                    expected_root_digest=values.source_root_digest,
                    model_runtime=model_runtime,
                    api_key=api_key,
                    provider_store_root=verified.provider_output_root,
                    analysis_output_root=verified.analysis_output_root,
                    transport_pin=verified.transport_pin,
                    expected_transport_pin_digest=(verified.expected_transport_pin_digest),
                )
                provider_runtime = bind_skill_bound_web_analysis_provider_runtime(
                    assembly,
                    transport_pin=verified.transport_pin,
                    expected_transport_pin_digest=verified.expected_transport_pin_digest,
                    expected_external_network=model_runtime.network_name,
                )
                invocation = SkillBoundWebAnalysisInvocationRuntime(
                    provider_runtime=provider_runtime
                )
                terminal = await _invoke_once_and_reload(
                    invocation=invocation,
                    provider_runtime=provider_runtime,
                    assembly=assembly,
                    model_runtime=model_runtime,
                    verified=verified,
                    values=values,
                )
            except BaseException as exc:
                pending_error = exc
        finally:
            try:
                cleanup = _legacy._cleanup_owned_runtime(
                    model_runtime=model_runtime,
                    assembly=assembly,
                )
            except Exception as exc:
                if pending_error is not None:
                    if isinstance(pending_error, SkillBoundWebAnalysisCancelledError):
                        pending_error.__dict__["_operational_cleanup_verified"] = False
                    pending_error.add_note(
                        f"Skill-bound owned cleanup also failed: {type(exc).__name__}"
                    )
                    raise pending_error from exc
                raise

    try:
        if cleanup is None:
            raise OperationalSkillBoundWebAnalysisError(
                "Skill-bound cleanup evidence is unavailable"
            )
        expected_execution_ids = assembly.execution_ids if assembly is not None else ()
        _legacy._require_clean_cleanup(
            cleanup,
            expected_execution_ids=expected_execution_ids,
        )
        if isinstance(pending_error, SkillBoundWebAnalysisCancelledError):
            pending_error.__dict__["_operational_cleanup_verified"] = True
    except Exception as exc:
        if pending_error is not None:
            if isinstance(pending_error, SkillBoundWebAnalysisCancelledError):
                pending_error.__dict__["_operational_cleanup_verified"] = False
            pending_error.add_note(
                f"Skill-bound owned cleanup verification also failed: {type(exc).__name__}"
            )
            raise pending_error from exc
        raise

    if pending_error is not None:
        raise pending_error
    if terminal is None:
        raise OperationalSkillBoundWebAnalysisError(
            "Skill-bound invocation produced no strictly reloaded terminal evidence"
        )
    return OperationalSkillBoundWebAnalysisResult(
        summary=_secret_free_summary(verified=verified, terminal=terminal, cleanup=cleanup),
        succeeded=terminal.status == "skill-proposal-compiled",
    )


async def _invoke_once_and_reload(
    *,
    invocation: SkillBoundWebAnalysisInvocationRuntime,
    provider_runtime: SkillBoundWebAnalysisProviderRuntime,
    assembly: LocalWebAnalysisProviderAssembly,
    model_runtime: LocalModelRuntime,
    verified: VerifiedOperationalSkillBoundWebAnalysisInputs,
    values: OperationalSkillBoundWebAnalysisInputs,
) -> _TerminalEvidence:
    try:
        completion = await invocation.invoke(
            source=verified.source,
            skill_run=verified.skill_run,
            transport_pin=verified.transport_pin,
            expected_source_run_id=values.source_run_id,
            expected_source_root_digest=values.source_root_digest,
            expected_skill_run_id=values.skill_run_id,
            expected_skill_root_digest=values.skill_root_digest,
            expected_registry_ref=verified.expected_registry_ref,
            expected_policy_digest=verified.expected_policy_digest,
            expected_transport_pin_digest=verified.expected_transport_pin_digest,
        )
    except SkillBoundWebAnalysisCancelledError as exc:
        try:
            _reload_failure(
                run_path=exc.publication.run_path,
                run_id=exc.publication.run_id,
                root_digest=exc.publication.root_digest,
                provider_run_path=exc.provider_publication.run_path,
                provider_run_id=exc.provider_publication.run_id,
                provider_root_digest=exc.provider_publication.root_digest,
                provider_runtime=provider_runtime,
                model_runtime=model_runtime,
                verified=verified,
                values=values,
            )
            exc.__dict__["_operational_terminal_reloaded"] = True
        except Exception as verification_error:
            exc.__dict__["_operational_terminal_reloaded"] = False
            raise exc from verification_error
        raise
    except SkillBoundWebAnalysisRuntimeError as exc:
        if exc.publication is None or exc.provider_publication is None:
            raise OperationalSkillBoundWebAnalysisError(
                "Skill-bound invocation failed before a terminal Run was published"
            ) from exc
        failed = _reload_failure(
            run_path=exc.publication.run_path,
            run_id=exc.publication.run_id,
            root_digest=exc.publication.root_digest,
            provider_run_path=exc.provider_publication.run_path,
            provider_run_id=exc.provider_publication.run_id,
            provider_root_digest=exc.provider_publication.root_digest,
            provider_runtime=provider_runtime,
            model_runtime=model_runtime,
            verified=verified,
            values=values,
        )
        return _failed_terminal(failed)

    loaded = load_verified_skill_bound_web_analysis_invocation(
        completion.publication.run_path,
        expected_run_id=completion.publication.run_id,
        expected_root_digest=completion.publication.root_digest,
        source=verified.source,
        skill_run=verified.skill_run,
        transport_pin=verified.transport_pin,
        registration=assembly.provider_runtime.registration,
        provider_run_path=completion.provider_publication.run_path,
        expected_provider_run_id=completion.provider_publication.run_id,
        expected_provider_root_digest=completion.provider_publication.root_digest,
        expected_provider_execution_context=provider_runtime.execution_context,
        expected_source_run_id=values.source_run_id,
        expected_source_root_digest=values.source_root_digest,
        expected_skill_run_id=values.skill_run_id,
        expected_skill_root_digest=values.skill_root_digest,
        expected_registry_ref=verified.expected_registry_ref,
        expected_policy_digest=verified.expected_policy_digest,
        expected_transport_pin_digest=verified.expected_transport_pin_digest,
        expected_external_network=model_runtime.network_name,
    )
    return _successful_terminal(loaded)


def _reload_failure(
    *,
    run_path: Path,
    run_id: str,
    root_digest: str,
    provider_run_path: Path,
    provider_run_id: str,
    provider_root_digest: str,
    provider_runtime: SkillBoundWebAnalysisProviderRuntime,
    model_runtime: LocalModelRuntime,
    verified: VerifiedOperationalSkillBoundWebAnalysisInputs,
    values: OperationalSkillBoundWebAnalysisInputs,
) -> VerifiedSkillBoundWebAnalysisFailureRun:
    return load_verified_skill_bound_web_analysis_failure(
        run_path,
        expected_run_id=run_id,
        expected_root_digest=root_digest,
        source=verified.source,
        skill_run=verified.skill_run,
        transport_pin=verified.transport_pin,
        registration=provider_runtime.base_runtime.registration,
        provider_run_path=provider_run_path,
        expected_provider_run_id=provider_run_id,
        expected_provider_root_digest=provider_root_digest,
        expected_provider_execution_context=provider_runtime.execution_context,
        expected_source_run_id=values.source_run_id,
        expected_source_root_digest=values.source_root_digest,
        expected_skill_run_id=values.skill_run_id,
        expected_skill_root_digest=values.skill_root_digest,
        expected_registry_ref=verified.expected_registry_ref,
        expected_policy_digest=verified.expected_policy_digest,
        expected_transport_pin_digest=verified.expected_transport_pin_digest,
        expected_external_network=model_runtime.network_name,
    )


def _successful_terminal(run: VerifiedSkillBoundWebAnalysisInvocationRun) -> _TerminalEvidence:
    if (
        run.execution_authority
        or run.graph_admission_authority
        or run.finding_authority
        or run.report_delivery_authority
        or run.target_request_count != 0
        or run.dispatch_count != 1
    ):
        raise OperationalSkillBoundWebAnalysisError(
            "strict successor success unexpectedly carries downstream authority"
        )
    return _TerminalEvidence(
        status="skill-proposal-compiled",
        semantics=run.semantics,
        analysis_run_id=run.verification.run_id,
        analysis_root_digest=run.verification.root_digest,
        provider_run_id=run.provider_publication.run_id,
        provider_root_digest=run.provider_publication.root_digest,
        provider_execution_context_digest=run.provider_execution_context.context_digest,
        terminal_state=run.receipt.response_state,
        dispatch_count=run.dispatch_count,
    )


def _failed_terminal(run: VerifiedSkillBoundWebAnalysisFailureRun) -> _TerminalEvidence:
    if (
        run.execution_authority
        or run.automatic_redispatch_authority
        or run.target_request_count != 0
        or run.receipt.graph_admission_authorized
        or run.receipt.finding_authorized
        or run.receipt.report_delivery_authorized
    ):
        raise OperationalSkillBoundWebAnalysisError(
            "strict successor failure unexpectedly carries downstream authority"
        )
    return _TerminalEvidence(
        status="skill-model-attempt-failed",
        semantics=run.semantics,
        analysis_run_id=run.verification.run_id,
        analysis_root_digest=run.verification.root_digest,
        provider_run_id=run.provider_publication.run_id,
        provider_root_digest=run.provider_publication.root_digest,
        provider_execution_context_digest=run.provider_execution_context.context_digest,
        terminal_state=run.receipt.terminal_state,
        dispatch_count=run.dispatch_count,
    )


def _secret_free_summary(
    *,
    verified: VerifiedOperationalSkillBoundWebAnalysisInputs,
    terminal: _TerminalEvidence,
    cleanup: LocalWebAnalysisProviderCleanup,
) -> dict[str, object]:
    return {
        "apiVersion": _SUMMARY_API_VERSION,
        "kind": "OperationalSkillBoundWebAnalysisConformance",
        "status": terminal.status,
        "semantics": terminal.semantics,
        "terminalState": terminal.terminal_state,
        "strictSourceReloaded": True,
        "comparisonPlanVerified": True,
        "comparisonPlanRunId": verified.comparison_plan_run_id,
        "comparisonPlanRootDigest": verified.comparison_plan_root_digest,
        "comparisonPlanCommitment": verified.plan.commitment,
        "skillProjectionVerified": True,
        "skillRunId": verified.skill_run.verification.run_id,
        "skillRootDigest": verified.skill_run.verification.root_digest,
        "skillBoundSnapshotDigest": verified.skill_run.snapshot.snapshot_digest,
        "selectedSkillCount": verified.skill_run.index.selected_skill_count,
        "transportPinVerified": True,
        "transportPinDigest": verified.expected_transport_pin_digest,
        "successorImagesVerified": True,
        "modelVerified": True,
        "model": {
            "name": verified.model.name,
            "repository": verified.model.repository,
            "revision": verified.model.revision,
            "sha256": verified.model.sha256,
            "sizeBytes": verified.model.size_bytes,
        },
        "invocationAttempts": 1,
        "providerDispatchCount": terminal.dispatch_count,
        "analysisRunId": terminal.analysis_run_id,
        "analysisRootDigest": terminal.analysis_root_digest,
        "providerRunId": terminal.provider_run_id,
        "providerRootDigest": terminal.provider_root_digest,
        "providerExecutionContextDigest": terminal.provider_execution_context_digest,
        "strictTerminalReloaded": True,
        "proposalCompiled": terminal.status == "skill-proposal-compiled",
        "ownedExecutionCount": len(cleanup.execution_ids),
        "cleanupObserved": True,
        "targetRequestsPerformed": False,
        "externalDeliveryPerformed": False,
        "automaticRedispatchAuthorized": False,
        "executionAuthority": False,
        "graphAdmissionAuthority": False,
        "findingAuthority": False,
        "reportDeliveryAuthority": False,
    }


def _error_summary(exc: BaseException) -> dict[str, object]:
    return {
        "apiVersion": _SUMMARY_API_VERSION,
        "kind": "OperationalSkillBoundWebAnalysisConformance",
        "status": "operational-error",
        "errorType": type(exc).__name__,
        "complete": False,
        "targetRequestsPerformed": False,
        "externalDeliveryPerformed": False,
        "automaticRedispatchAuthorized": False,
        "executionAuthority": False,
        "graphAdmissionAuthority": False,
        "findingAuthority": False,
        "reportDeliveryAuthority": False,
    }


def _cancelled_summary(exc: SkillBoundWebAnalysisCancelledError) -> dict[str, object]:
    return {
        "apiVersion": _SUMMARY_API_VERSION,
        "kind": "OperationalSkillBoundWebAnalysisConformance",
        "status": "cancelled",
        "errorType": type(exc).__name__,
        "invocationAttempts": 1,
        "analysisRunId": exc.publication.run_id,
        "analysisRootDigest": exc.publication.root_digest,
        "providerRunId": exc.provider_publication.run_id,
        "providerRootDigest": exc.provider_publication.root_digest,
        "strictTerminalReloaded": bool(exc.__dict__.get("_operational_terminal_reloaded", False)),
        "cleanupObserved": bool(exc.__dict__.get("_operational_cleanup_verified", False)),
        "complete": False,
        "targetRequestsPerformed": False,
        "externalDeliveryPerformed": False,
        "automaticRedispatchAuthorized": False,
        "executionAuthority": False,
        "graphAdmissionAuthority": False,
        "findingAuthority": False,
        "reportDeliveryAuthority": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    try:
        result = asyncio.run(run_operational_skill_bound_web_analysis(_arguments(argv)))
    except SkillBoundWebAnalysisCancelledError as exc:
        print(json.dumps(_cancelled_summary(exc), sort_keys=True))
        return 130
    except asyncio.CancelledError as exc:
        print(json.dumps(_error_summary(exc), sort_keys=True))
        return 130
    except (Exception, KeyboardInterrupt) as exc:
        print(json.dumps(_error_summary(exc), sort_keys=True))
        return 2
    print(json.dumps(result.summary, sort_keys=True))
    return 0 if result.succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
