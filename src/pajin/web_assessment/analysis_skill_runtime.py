"""One-shot runtime boundary for the Skill-bound WEB-007 successor."""

from __future__ import annotations

import asyncio
import inspect
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.providers.models import ProviderChatRequest, ProviderChatResult, ProviderRegistration
from pajin.providers.receipts import ProviderBoundChatOutcome
from pajin.runtime.store import (
    RunStore,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
    verify_run_integrity,
)
from pajin.runtime.verified_snapshot import require_same_authority, strict_json
from pajin.web_assessment.analysis_local import LocalWebAnalysisProviderAssembly
from pajin.web_assessment.analysis_runtime import (
    PreparedWebAnalysisProviderLifecycle,
    WebAnalysisProviderExecutionContext,
    WebAnalysisProviderRunPublication,
    WebAnalysisProviderRuntime,
    prepare_web_analysis_provider_lifecycle,
    verified_web_analysis_provider_dispatch_count,
    verify_web_analysis_provider_run_binding,
    verify_web_analysis_provider_run_publication,
)
from pajin.web_assessment.analysis_skill_invocation import (
    SKILL_BOUND_WEB_ANALYSIS_ATTEMPT,
    SKILL_BOUND_WEB_ANALYSIS_RESPONSE_SCHEMA_NAME,
    SKILL_BOUND_WEB_ANALYSIS_ROLE,
    CompiledSkillBoundWebAnalysisProposal,
    PlannedSkillBoundWebAnalysisCall,
    SkillBoundWebAnalysisInvocationPin,
    SkillBoundWebAnalysisProposalDraft,
    SkillBoundWebAnalysisProviderExecutionContext,
    SkillBoundWebAnalysisRequestEnvelope,
    compile_skill_bound_web_analysis_proposal,
    parse_skill_bound_web_analysis_proposal_draft,
    plan_skill_bound_web_analysis_call,
    verify_compiled_skill_bound_web_analysis_proposal,
    verify_planned_skill_bound_web_analysis_call,
)
from pajin.web_assessment.analysis_skill_projection import (
    SkillBoundWebAnalysisSnapshot,
    SkillRegistryRef,
    VerifiedWebAnalysisSkillProjectionRun,
    canonical_skill_contract,
)
from pajin.web_assessment.analysis_skill_receipts import (
    SkillBoundWebAnalysisInvocationCompletion,
    SkillBoundWebAnalysisInvocationFailureReceipt,
    SkillBoundWebAnalysisInvocationPublication,
    SkillBoundWebAnalysisInvocationReceipt,
    SkillBoundWebAnalysisProviderRunPublication,
    VerifiedSkillBoundWebAnalysisFailureRun,
    VerifiedSkillBoundWebAnalysisInvocationRun,
)
from pajin.web_assessment.analysis_transport import (
    WebAnalysisTransportRuntimePin,
    verify_web_analysis_provider_worker_context,
    verify_web_analysis_transport_runtime_pin,
)
from pajin.web_assessment.discovery_artifact import VerifiedAuthenticatedDiscoveryRun

_ANALYSIS_CAMPAIGN_NAME = "web-analysis-skill-bound"
_SNAPSHOT_PATH = "skill-bound-snapshot.json"
_REQUEST_PATH = "skill-bound-request.json"
_SUCCESSOR_CONTEXT_PATH = "skill-bound-provider-execution-context.json"
_BASE_CONTEXT_PATH = "provider-execution-context.json"
_PROVIDER_OUTCOME_PATH = "provider-outcome.json"
_DRAFT_PATH = "skill-bound-draft.json"
_REJECTED_DRAFT_PATH = "skill-bound-rejected-draft.bin"
_PROPOSAL_PATH = "compiled-skill-bound-proposal.json"
_RECEIPT_PATH = "skill-bound-invocation-receipt.json"
_FAILURE_RECEIPT_PATH = "skill-bound-invocation-failure.json"
_ANALYSIS_STARTED_EVENT = "web-analysis.skill-bound.invocation.started"
_ANALYSIS_COMPLETED_EVENT = "web-analysis.skill-bound.invocation.completed"
_ANALYSIS_FAILED_EVENT = "web-analysis.skill-bound.invocation.failed"
_PROVIDER_STARTED_EVENT = "web-analysis.provider-bound.started"
_PROVIDER_FAILED_EVENT = "web-analysis.provider-bound.failed"
_PROVIDER_FINALIZED_EVENT = "web-analysis.provider-bound.finalized"
_MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_MAX_CONTEXT_BYTES = 2 * 1024 * 1024
_MAX_PROVIDER_OUTCOME_BYTES = 2 * 1024 * 1024
_MAX_RAW_DRAFT_BYTES = 256 * 1024
_MAX_PROPOSAL_BYTES = 4 * 1024 * 1024
_MAX_RECEIPT_BYTES = 16 * 1024 * 1024
_RUN_ID_PATTERN = re.compile(r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")

_SUCCESS_ARTIFACT_LIMITS = {
    _SNAPSHOT_PATH: _MAX_SNAPSHOT_BYTES,
    _REQUEST_PATH: _MAX_REQUEST_BYTES,
    _SUCCESSOR_CONTEXT_PATH: _MAX_CONTEXT_BYTES,
    _PROVIDER_OUTCOME_PATH: _MAX_PROVIDER_OUTCOME_BYTES,
    _DRAFT_PATH: _MAX_RAW_DRAFT_BYTES + 1,
    _PROPOSAL_PATH: _MAX_PROPOSAL_BYTES,
    _RECEIPT_PATH: _MAX_RECEIPT_BYTES,
}


class SkillBoundWebAnalysisRuntimeError(RuntimeError):
    """Raised when the successor runtime differs from independently pinned authority."""

    def __init__(
        self,
        message: str,
        *,
        publication: SkillBoundWebAnalysisInvocationPublication | None = None,
        provider_publication: SkillBoundWebAnalysisProviderRunPublication | None = None,
    ) -> None:
        super().__init__(message)
        self.publication = publication
        self.provider_publication = provider_publication


class SkillBoundWebAnalysisCancelledError(asyncio.CancelledError):
    """Cancellation carrying both terminal successor Run publications."""

    def __init__(
        self,
        *,
        publication: SkillBoundWebAnalysisInvocationPublication,
        provider_publication: SkillBoundWebAnalysisProviderRunPublication,
    ) -> None:
        super().__init__("Skill-bound Web analysis Provider invocation was cancelled")
        self.publication = publication
        self.provider_publication = provider_publication


@dataclass(frozen=True, slots=True)
class SkillBoundWebAnalysisProviderRuntime:
    """Reuse one local Provider assembly under a distinct active invocation contract."""

    base_runtime: WebAnalysisProviderRuntime
    execution_context: SkillBoundWebAnalysisProviderExecutionContext
    expected_external_network: str


def bind_skill_bound_web_analysis_provider_runtime(
    assembly: LocalWebAnalysisProviderAssembly,
    *,
    transport_pin: WebAnalysisTransportRuntimePin,
    expected_transport_pin_digest: str,
    expected_external_network: str,
) -> SkillBoundWebAnalysisProviderRuntime:
    """Bind a successor call contract without rebuilding Provider or cleanup authority."""

    try:
        if type(assembly) is not LocalWebAnalysisProviderAssembly:
            raise TypeError("Skill-bound Web analysis requires the exact local Provider assembly")
        base = assembly.provider_runtime
        if type(base) is not WebAnalysisProviderRuntime:
            raise TypeError("Skill-bound Web analysis Provider runtime type differs")
        registration = ProviderRegistration.model_validate(
            base.registration.model_dump(mode="python")
        )
        base_context = canonical_skill_contract(
            base.execution_context,
            WebAnalysisProviderExecutionContext,
        )
        transport = verify_web_analysis_transport_runtime_pin(
            transport_pin,
            runtime=base_context.effect_runtime_pin,
            expected_pin_digest=expected_transport_pin_digest,
        )
        stable = base_context.tool_stable_execution_context
        nested = stable.get("context")
        if set(stable) != {"type", "context"} or type(nested) is not dict:
            raise ValueError("Skill-bound Web analysis Provider Tool context differs")
        verify_web_analysis_provider_worker_context(
            nested.get("providerWorker"),
            transport_pin=transport,
            expected_external_network=expected_external_network,
        )
        if (
            registration.provider_id != base_context.provider_id
            or registration.model != base_context.model
            or base_context.secret_material_embedded is not False
            or base_context.execution_authority is not False
        ):
            raise ValueError("Skill-bound Web analysis base Provider context differs")
        context = SkillBoundWebAnalysisProviderExecutionContext(
            baseProviderExecutionContext=base_context,
            transportPin=transport,
            invocationPin=SkillBoundWebAnalysisInvocationPin(),
            secretMaterialEmbedded=False,
            executionAuthority=False,
        )
        context = canonical_skill_contract(
            context,
            SkillBoundWebAnalysisProviderExecutionContext,
        )
        assembly.claim_skill_bound_invocation()
        return SkillBoundWebAnalysisProviderRuntime(
            base_runtime=base,
            execution_context=context,
            expected_external_network=expected_external_network,
        )
    except SkillBoundWebAnalysisRuntimeError:
        raise
    except Exception as exc:
        raise SkillBoundWebAnalysisRuntimeError(
            "Skill-bound Web analysis Provider runtime binding failed closed"
        ) from exc


class SkillBoundWebAnalysisInvocationRuntime:
    """Dispatch one Skill-bound Provider request and compile only inert advisory output."""

    def __init__(self, *, provider_runtime: SkillBoundWebAnalysisProviderRuntime) -> None:
        try:
            if type(provider_runtime) is not SkillBoundWebAnalysisProviderRuntime:
                raise TypeError("Skill-bound Web analysis Provider runtime type differs")
            lifecycle = prepare_web_analysis_provider_lifecycle(provider_runtime.base_runtime)
            context = canonical_skill_contract(
                provider_runtime.execution_context,
                SkillBoundWebAnalysisProviderExecutionContext,
            )
            if context.base_provider_execution_context != lifecycle.execution_context:
                raise ValueError("Skill-bound context differs from the base Provider lifecycle")
            stable = context.base_provider_execution_context.tool_stable_execution_context
            nested = stable.get("context")
            if set(stable) != {"type", "context"} or type(nested) is not dict:
                raise ValueError("Skill-bound Web analysis Provider Tool context differs")
            verify_web_analysis_provider_worker_context(
                nested.get("providerWorker"),
                transport_pin=context.transport_pin,
                expected_external_network=provider_runtime.expected_external_network,
            )
        except Exception as exc:
            raise SkillBoundWebAnalysisRuntimeError(
                "Skill-bound Web analysis Provider runtime is invalid"
            ) from exc
        self._lifecycle = lifecycle
        self._execution_context = context
        self._expected_external_network = provider_runtime.expected_external_network
        self._invoke_lock = asyncio.Lock()
        self._attempted = False
        self._provider_terminalized = False

    async def invoke(
        self,
        *,
        source: VerifiedAuthenticatedDiscoveryRun,
        skill_run: VerifiedWebAnalysisSkillProjectionRun,
        transport_pin: WebAnalysisTransportRuntimePin,
        expected_source_run_id: str,
        expected_source_root_digest: str,
        expected_skill_run_id: str,
        expected_skill_root_digest: str,
        expected_registry_ref: SkillRegistryRef,
        expected_policy_digest: str,
        expected_transport_pin_digest: str,
    ) -> SkillBoundWebAnalysisInvocationCompletion:
        """Consume at most one Provider dispatch; every post-dispatch failure is terminal."""

        try:
            transport = verify_web_analysis_transport_runtime_pin(
                transport_pin,
                runtime=self._lifecycle.execution_context.effect_runtime_pin,
                expected_pin_digest=expected_transport_pin_digest,
            )
            if transport != self._execution_context.transport_pin:
                raise ValueError("Skill-bound Web analysis active transport differs")
            planned = plan_skill_bound_web_analysis_call(
                registration=self._lifecycle.registration,
                source=source,
                skill_run=skill_run,
                transport_pin=transport,
                expected_source_run_id=expected_source_run_id,
                expected_source_root_digest=expected_source_root_digest,
                expected_skill_run_id=expected_skill_run_id,
                expected_skill_root_digest=expected_skill_root_digest,
                expected_registry_ref=expected_registry_ref,
                expected_policy_digest=expected_policy_digest,
                expected_transport_pin_digest=expected_transport_pin_digest,
            )
            planned = verify_planned_skill_bound_web_analysis_call(
                planned,
                registration=self._lifecycle.registration,
                source=source,
                skill_run=skill_run,
                transport_pin=transport,
                expected_source_run_id=expected_source_run_id,
                expected_source_root_digest=expected_source_root_digest,
                expected_skill_run_id=expected_skill_run_id,
                expected_skill_root_digest=expected_skill_root_digest,
                expected_registry_ref=expected_registry_ref,
                expected_policy_digest=expected_policy_digest,
                expected_transport_pin_digest=expected_transport_pin_digest,
            )
            _require_skill_invocation_pin(
                self._execution_context.invocation_pin,
                chat=planned.chat,
            )
            _require_source_bound_campaign(self._lifecycle, source=source)
            snapshot = canonical_skill_contract(
                skill_run.snapshot,
                SkillBoundWebAnalysisSnapshot,
            )
            if (
                planned.request.skill_bound_snapshot_digest != snapshot.snapshot_digest
                or skill_run.verification.run_id != expected_skill_run_id
                or skill_run.verification.root_digest != expected_skill_root_digest
            ):
                raise ValueError("Skill-bound Web analysis preparation differs")
        except Exception as exc:
            if isinstance(exc, SkillBoundWebAnalysisRuntimeError):
                raise
            raise SkillBoundWebAnalysisRuntimeError(
                "Skill-bound Web analysis invocation planning failed closed"
            ) from exc

        async with self._invoke_lock:
            if self._attempted:
                raise SkillBoundWebAnalysisRuntimeError(
                    "Skill-bound Web analysis runtime already consumed its one invocation attempt"
                )
            self._attempted = True
            analysis_store = _begin_analysis_run(
                output_root=self._lifecycle.analysis_output_root,
                snapshot=snapshot,
                planned=planned,
                execution_context=self._execution_context,
                registration=self._lifecycle.registration,
                provider_run_id=self._lifecycle.store.run_id,
            )
            try:
                _begin_provider_run(
                    lifecycle=self._lifecycle,
                    analysis_run_id=analysis_store.run_id,
                    planned=planned,
                )
                bound_call = await self._lifecycle.port.chat_bound(
                    role=SKILL_BOUND_WEB_ANALYSIS_ROLE,
                    attempt=SKILL_BOUND_WEB_ANALYSIS_ATTEMPT,
                    chat=planned.chat,
                    request_id=planned.request.request_id,
                )
            except (asyncio.CancelledError, Exception) as exc:
                (
                    provider_publication,
                    _base_publication,
                    dispatch_count,
                    finalization_error,
                ) = self._terminalize_provider_run(
                    analysis_run_id=analysis_store.run_id,
                    planned=planned,
                    provider_invocation_failed=True,
                    expected_transport_pin_digest=expected_transport_pin_digest,
                )
                publication = _complete_failed_analysis_run(
                    store=analysis_store,
                    snapshot=snapshot,
                    planned=planned,
                    transport=transport,
                    execution_context=self._execution_context,
                    provider_publication=provider_publication,
                    provider_outcome=None,
                    raw_draft=None,
                    draft_digest=None,
                    terminal_state="provider-invocation-failed-uncertain",
                    dispatch_count=dispatch_count,
                )
                _reload_published_failure(
                    publication=publication,
                    provider_publication=provider_publication,
                    source=source,
                    skill_run=skill_run,
                    transport=transport,
                    registration=self._lifecycle.registration,
                    context=self._execution_context,
                    expected_source_run_id=expected_source_run_id,
                    expected_source_root_digest=expected_source_root_digest,
                    expected_skill_run_id=expected_skill_run_id,
                    expected_skill_root_digest=expected_skill_root_digest,
                    expected_registry_ref=expected_registry_ref,
                    expected_policy_digest=expected_policy_digest,
                    expected_transport_pin_digest=expected_transport_pin_digest,
                    expected_external_network=self._expected_external_network,
                )
                if finalization_error is not None:
                    exc.add_note(
                        "Skill-bound Provider finalizer also failed: "
                        f"{type(finalization_error).__name__}"
                    )
                cause = finalization_error if finalization_error is not None else exc
                if isinstance(exc, asyncio.CancelledError):
                    raise SkillBoundWebAnalysisCancelledError(
                        publication=publication,
                        provider_publication=provider_publication,
                    ) from cause
                raise SkillBoundWebAnalysisRuntimeError(
                    "Skill-bound Web analysis Provider invocation failed without redispatch",
                    publication=publication,
                    provider_publication=provider_publication,
                ) from cause

            (
                provider_publication,
                base_publication,
                dispatch_count,
                finalization_error,
            ) = self._terminalize_provider_run(
                analysis_run_id=analysis_store.run_id,
                planned=planned,
                provider_invocation_failed=False,
                expected_transport_pin_digest=expected_transport_pin_digest,
            )
            if dispatch_count != 1:
                raise SkillBoundWebAnalysisRuntimeError(
                    "Skill-bound Web analysis returned without one sealed model dispatch",
                    provider_publication=provider_publication,
                )
            if finalization_error is not None:
                publication = _complete_failed_analysis_run(
                    store=analysis_store,
                    snapshot=snapshot,
                    planned=planned,
                    transport=transport,
                    execution_context=self._execution_context,
                    provider_publication=provider_publication,
                    provider_outcome=None,
                    raw_draft=None,
                    draft_digest=None,
                    terminal_state="provider-invocation-failed-uncertain",
                    dispatch_count=dispatch_count,
                )
                _reload_published_failure(
                    publication=publication,
                    provider_publication=provider_publication,
                    source=source,
                    skill_run=skill_run,
                    transport=transport,
                    registration=self._lifecycle.registration,
                    context=self._execution_context,
                    expected_source_run_id=expected_source_run_id,
                    expected_source_root_digest=expected_source_root_digest,
                    expected_skill_run_id=expected_skill_run_id,
                    expected_skill_root_digest=expected_skill_root_digest,
                    expected_registry_ref=expected_registry_ref,
                    expected_policy_digest=expected_policy_digest,
                    expected_transport_pin_digest=expected_transport_pin_digest,
                    expected_external_network=self._expected_external_network,
                )
                raise SkillBoundWebAnalysisRuntimeError(
                    "Skill-bound Web analysis Provider finalization failed without redispatch",
                    publication=publication,
                    provider_publication=provider_publication,
                ) from finalization_error

        draft: SkillBoundWebAnalysisProposalDraft | None = None
        raw_draft: bytes | None = None
        try:
            _require_proposal_only_result(bound_call.result)
            assert bound_call.result.content is not None
            raw_draft = bound_call.result.content.encode("utf-8", errors="strict")
            draft = parse_skill_bound_web_analysis_proposal_draft(
                raw_draft,
                snapshot=snapshot,
            )
            proposal = compile_skill_bound_web_analysis_proposal(
                source=source,
                skill_run=skill_run,
                draft=draft,
                transport_pin=transport,
                expected_source_run_id=expected_source_run_id,
                expected_source_root_digest=expected_source_root_digest,
                expected_skill_run_id=expected_skill_run_id,
                expected_skill_root_digest=expected_skill_root_digest,
                expected_registry_ref=expected_registry_ref,
                expected_policy_digest=expected_policy_digest,
                expected_transport_pin_digest=expected_transport_pin_digest,
            )
            proposal = verify_compiled_skill_bound_web_analysis_proposal(
                proposal,
                source=source,
                skill_run=skill_run,
                draft=draft,
                transport_pin=transport,
                expected_source_run_id=expected_source_run_id,
                expected_source_root_digest=expected_source_root_digest,
                expected_skill_run_id=expected_skill_run_id,
                expected_skill_root_digest=expected_skill_root_digest,
                expected_registry_ref=expected_registry_ref,
                expected_policy_digest=expected_policy_digest,
                expected_transport_pin_digest=expected_transport_pin_digest,
            )
            receipt = _build_success_receipt(
                analysis_run_id=analysis_store.run_id,
                snapshot=snapshot,
                planned=planned,
                transport=transport,
                execution_context=self._execution_context,
                provider_publication=provider_publication,
                provider_outcome=bound_call.outcome,
                raw_draft=raw_draft,
                draft=draft,
                proposal=proposal,
            )
            verify_web_analysis_provider_run_binding(
                base_publication,
                analysis_run_id=analysis_store.run_id,
                registration=self._lifecycle.registration,
                execution_context=self._lifecycle.execution_context,
                stable_request_id=planned.request.request_id,
                provider_chat_request_digest=planned.request.provider_chat_request_digest,
                provider_outcome=bound_call.outcome,
                expected_role=SKILL_BOUND_WEB_ANALYSIS_ROLE,
                expected_attempt=SKILL_BOUND_WEB_ANALYSIS_ATTEMPT,
                expected_schema_name=SKILL_BOUND_WEB_ANALYSIS_RESPONSE_SCHEMA_NAME,
                expected_provider_chat_request=planned.chat,
                expected_transport_pin=transport,
                expected_transport_pin_digest=expected_transport_pin_digest,
                expected_external_network=self._expected_external_network,
            )
        except Exception as exc:
            rejected_raw = _rejected_response_bytes(bound_call.result)
            publication = _complete_failed_analysis_run(
                store=analysis_store,
                snapshot=snapshot,
                planned=planned,
                transport=transport,
                execution_context=self._execution_context,
                provider_publication=provider_publication,
                provider_outcome=bound_call.outcome,
                raw_draft=rejected_raw,
                draft_digest=_draft_digest(draft) if draft is not None else None,
                terminal_state="provider-response-rejected",
                dispatch_count=1,
            )
            _reload_published_failure(
                publication=publication,
                provider_publication=provider_publication,
                source=source,
                skill_run=skill_run,
                transport=transport,
                registration=self._lifecycle.registration,
                context=self._execution_context,
                expected_source_run_id=expected_source_run_id,
                expected_source_root_digest=expected_source_root_digest,
                expected_skill_run_id=expected_skill_run_id,
                expected_skill_root_digest=expected_skill_root_digest,
                expected_registry_ref=expected_registry_ref,
                expected_policy_digest=expected_policy_digest,
                expected_transport_pin_digest=expected_transport_pin_digest,
                expected_external_network=self._expected_external_network,
            )
            raise SkillBoundWebAnalysisRuntimeError(
                "Skill-bound Web analysis Provider response failed closed without proposal",
                publication=publication,
                provider_publication=provider_publication,
            ) from exc

        publication = _complete_successful_analysis_run(
            store=analysis_store,
            snapshot=snapshot,
            planned=planned,
            execution_context=self._execution_context,
            provider_publication=provider_publication,
            provider_outcome=bound_call.outcome,
            raw_draft=raw_draft,
            draft=draft,
            proposal=proposal,
            receipt=receipt,
        )
        loaded = _reload_published_success(
            publication=publication,
            provider_publication=provider_publication,
            source=source,
            skill_run=skill_run,
            transport=transport,
            registration=self._lifecycle.registration,
            context=self._execution_context,
            expected_source_run_id=expected_source_run_id,
            expected_source_root_digest=expected_source_root_digest,
            expected_skill_run_id=expected_skill_run_id,
            expected_skill_root_digest=expected_skill_root_digest,
            expected_registry_ref=expected_registry_ref,
            expected_policy_digest=expected_policy_digest,
            expected_transport_pin_digest=expected_transport_pin_digest,
            expected_external_network=self._expected_external_network,
        )
        if (
            loaded.draft != draft
            or loaded.proposal != proposal
            or loaded.receipt != receipt
            or loaded.provider_outcome != bound_call.outcome
        ):
            raise SkillBoundWebAnalysisRuntimeError(
                "Skill-bound Web analysis strict reload differs from produced artifacts",
                publication=publication,
                provider_publication=provider_publication,
            )
        return SkillBoundWebAnalysisInvocationCompletion(
            draft=draft,
            proposal=proposal,
            receipt=receipt,
            publication=publication,
            provider_publication=provider_publication,
        )

    def _terminalize_provider_run(
        self,
        *,
        analysis_run_id: str,
        planned: PlannedSkillBoundWebAnalysisCall,
        provider_invocation_failed: bool,
        expected_transport_pin_digest: str,
    ) -> tuple[
        SkillBoundWebAnalysisProviderRunPublication,
        WebAnalysisProviderRunPublication,
        Literal[0, 1],
        BaseException | None,
    ]:
        if self._provider_terminalized:
            raise SkillBoundWebAnalysisRuntimeError(
                "Skill-bound Web analysis Provider Run was already terminalized"
            )
        failure_audit_error: BaseException | None = None
        if provider_invocation_failed:
            failure_audit_error = _append_provider_failure_event_resilient(
                self._lifecycle.store,
                analysis_run_id=analysis_run_id,
                execution_context=self._lifecycle.execution_context,
                planned=planned,
            )
        finalization_error = failure_audit_error
        try:
            result = self._lifecycle.finalize_provider_run()
            if result is not None:
                if inspect.iscoroutine(result):
                    result.close()
                raise TypeError("Skill-bound Web analysis Provider finalizer must return None")
        except BaseException as exc:
            if finalization_error is not None:
                exc.add_note(
                    f"Provider failure audit also failed: {type(finalization_error).__name__}"
                )
            finalization_error = exc
        self._lifecycle.store.append_event(
            _PROVIDER_FINALIZED_EVENT,
            _provider_finalized_payload(
                self._lifecycle.execution_context,
                finalizer_completed=finalization_error is None,
            ),
        )
        seal = self._lifecycle.store.seal()
        base_publication = WebAnalysisProviderRunPublication(
            run_path=self._lifecycle.store.path,
            run_id=self._lifecycle.store.run_id,
            root_digest=seal.root_digest,
            execution_context=self._lifecycle.execution_context,
        )
        base_publication = verify_web_analysis_provider_run_publication(
            base_publication,
            expected_execution_context=self._lifecycle.execution_context,
            expected_role=SKILL_BOUND_WEB_ANALYSIS_ROLE,
            expected_attempt=SKILL_BOUND_WEB_ANALYSIS_ATTEMPT,
            expected_schema_name=SKILL_BOUND_WEB_ANALYSIS_RESPONSE_SCHEMA_NAME,
            expected_registration=self._lifecycle.registration,
            expected_provider_chat_request=planned.chat,
            expected_transport_pin=self._execution_context.transport_pin,
            expected_transport_pin_digest=expected_transport_pin_digest,
            expected_external_network=self._expected_external_network,
        )
        dispatch_count = verified_web_analysis_provider_dispatch_count(
            base_publication,
            expected_execution_context=self._lifecycle.execution_context,
            expected_role=SKILL_BOUND_WEB_ANALYSIS_ROLE,
            expected_attempt=SKILL_BOUND_WEB_ANALYSIS_ATTEMPT,
            expected_schema_name=SKILL_BOUND_WEB_ANALYSIS_RESPONSE_SCHEMA_NAME,
            expected_registration=self._lifecycle.registration,
            expected_provider_chat_request=planned.chat,
            expected_transport_pin=self._execution_context.transport_pin,
            expected_transport_pin_digest=expected_transport_pin_digest,
            expected_external_network=self._expected_external_network,
        )
        publication = SkillBoundWebAnalysisProviderRunPublication(
            run_path=base_publication.run_path,
            run_id=base_publication.run_id,
            root_digest=base_publication.root_digest,
            execution_context=self._execution_context,
        )
        self._provider_terminalized = True
        return publication, base_publication, dispatch_count, finalization_error


def _begin_analysis_run(
    *,
    output_root: Path,
    snapshot: SkillBoundWebAnalysisSnapshot,
    planned: PlannedSkillBoundWebAnalysisCall,
    execution_context: SkillBoundWebAnalysisProviderExecutionContext,
    registration: ProviderRegistration,
    provider_run_id: str,
) -> RunStore:
    try:
        store = RunStore.create(output_root, _ANALYSIS_CAMPAIGN_NAME)
        store.append_event(
            _ANALYSIS_STARTED_EVENT,
            _analysis_started_payload(
                analysis_run_id=store.run_id,
                snapshot=snapshot,
                planned=planned,
                execution_context=execution_context,
                registration=registration,
                provider_run_id=provider_run_id,
            ),
        )
        store.write_json_create_only(
            _SNAPSHOT_PATH,
            snapshot.model_dump(mode="json", by_alias=True),
        )
        store.write_json_create_only(
            _REQUEST_PATH,
            planned.request.model_dump(mode="json", by_alias=True),
        )
        store.write_json_create_only(
            _SUCCESSOR_CONTEXT_PATH,
            execution_context.model_dump(mode="json", by_alias=True),
        )
        return store
    except Exception as exc:
        raise SkillBoundWebAnalysisRuntimeError(
            "Skill-bound Web analysis Run could not be created before Provider dispatch"
        ) from exc


def _begin_provider_run(
    *,
    lifecycle: PreparedWebAnalysisProviderLifecycle,
    analysis_run_id: str,
    planned: PlannedSkillBoundWebAnalysisCall,
) -> None:
    lifecycle.store.write_json_create_only(
        _BASE_CONTEXT_PATH,
        lifecycle.execution_context.model_dump(mode="json", by_alias=True),
    )
    lifecycle.store.append_event(
        _PROVIDER_STARTED_EVENT,
        _provider_started_payload(
            analysis_run_id=analysis_run_id,
            provider_run_id=lifecycle.store.run_id,
            registration=lifecycle.registration,
            execution_context=lifecycle.execution_context,
            planned=planned,
        ),
    )


def _provider_started_payload(
    *,
    analysis_run_id: str,
    provider_run_id: str,
    registration: ProviderRegistration,
    execution_context: WebAnalysisProviderExecutionContext,
    planned: PlannedSkillBoundWebAnalysisCall,
) -> dict[str, object]:
    return {
        "analysisRunId": analysis_run_id,
        "providerRunId": provider_run_id,
        "providerId": registration.provider_id,
        "providerRuntimeDigest": planned.request.provider_runtime_digest,
        "providerExecutionContextId": execution_context.context_id,
        "providerExecutionContextDigest": execution_context.context_digest,
        "providerChatRequestDigest": planned.request.provider_chat_request_digest,
        "stableRequestId": planned.request.request_id,
        "attempt": SKILL_BOUND_WEB_ANALYSIS_ATTEMPT,
        "analysisAuthorityGranted": False,
    }


def _provider_failed_payload(
    *,
    analysis_run_id: str,
    provider_run_id: str,
    execution_context: WebAnalysisProviderExecutionContext,
    planned: PlannedSkillBoundWebAnalysisCall,
) -> dict[str, object]:
    return {
        "analysisRunId": analysis_run_id,
        "providerRunId": provider_run_id,
        "providerExecutionContextId": execution_context.context_id,
        "providerExecutionContextDigest": execution_context.context_digest,
        "providerChatRequestDigest": planned.request.provider_chat_request_digest,
        "stableRequestId": planned.request.request_id,
        "attempt": SKILL_BOUND_WEB_ANALYSIS_ATTEMPT,
        "failureClass": "provider-local-invocation-error",
        "automaticRedispatchAuthorized": False,
        "analysisAuthorityGranted": False,
    }


def _append_provider_failure_event_resilient(
    store: RunStore,
    *,
    analysis_run_id: str,
    execution_context: WebAnalysisProviderExecutionContext,
    planned: PlannedSkillBoundWebAnalysisCall,
) -> BaseException | None:
    payload = _provider_failed_payload(
        analysis_run_id=analysis_run_id,
        provider_run_id=store.run_id,
        execution_context=execution_context,
        planned=planned,
    )
    first_error: BaseException | None = None
    for _attempt in range(2):
        try:
            store.append_unique_event(
                _PROVIDER_FAILED_EVENT,
                payload,
                unique_by="stableRequestId",
            )
            return None
        except BaseException as exc:
            if first_error is None:
                first_error = exc
            else:
                exc.add_note(
                    "initial Provider failure-audit append also failed: "
                    f"{type(first_error).__name__}"
                )
                return exc
    raise AssertionError("Provider failure-audit retry loop did not terminate")


def _provider_finalized_payload(
    execution_context: WebAnalysisProviderExecutionContext,
    *,
    finalizer_completed: bool,
) -> dict[str, object]:
    if type(finalizer_completed) is not bool:
        raise TypeError("Provider finalizer completion marker must be a boolean")
    return {
        "providerExecutionContextId": execution_context.context_id,
        "providerExecutionContextDigest": execution_context.context_digest,
        "finalizerCompleted": finalizer_completed,
        "analysisAuthorityGranted": False,
    }


def _analysis_started_payload(
    *,
    analysis_run_id: str,
    snapshot: SkillBoundWebAnalysisSnapshot,
    planned: PlannedSkillBoundWebAnalysisCall,
    execution_context: SkillBoundWebAnalysisProviderExecutionContext,
    registration: ProviderRegistration,
    provider_run_id: str,
) -> dict[str, object]:
    bundle = snapshot.projection_bundle
    return {
        "analysisRunId": analysis_run_id,
        "skillProjectionRunId": planned.request.skill_projection_run_id,
        "skillProjectionRootDigest": planned.request.skill_projection_root_digest,
        "skillBoundSnapshotId": snapshot.snapshot_id,
        "skillBoundSnapshotDigest": snapshot.snapshot_digest,
        "projectionBundleDigest": bundle.bundle_digest,
        "instructionProjectionDigest": bundle.instruction_projection.projection_digest,
        "evidenceProjectionDigest": bundle.evidence_projection.projection_digest,
        "transportPinDigest": execution_context.transport_pin.pin_digest,
        "providerId": registration.provider_id,
        "providerRuntimeDigest": planned.request.provider_runtime_digest,
        "providerRunId": provider_run_id,
        "providerExecutionContextId": execution_context.context_id,
        "providerExecutionContextDigest": execution_context.context_digest,
        "requestId": planned.request.request_id,
        "requestDigest": planned.request.request_digest,
        "providerChatRequestDigest": planned.request.provider_chat_request_digest,
        "role": SKILL_BOUND_WEB_ANALYSIS_ROLE,
        "attempt": SKILL_BOUND_WEB_ANALYSIS_ATTEMPT,
        "semantics": "skill-bound-proposal-only-provider-dispatch",
        "modelDispatchPlanned": True,
        "targetRequestAuthorized": False,
        "automaticRedispatchAuthorized": False,
        "executionAuthorized": False,
    }


def _common_receipt_fields(
    *,
    analysis_run_id: str,
    snapshot: SkillBoundWebAnalysisSnapshot,
    planned: PlannedSkillBoundWebAnalysisCall,
    transport: WebAnalysisTransportRuntimePin,
    execution_context: SkillBoundWebAnalysisProviderExecutionContext,
    provider_publication: SkillBoundWebAnalysisProviderRunPublication,
    dispatch_count: Literal[0, 1],
) -> dict[str, object]:
    bundle = snapshot.projection_bundle
    return {
        "analysisRunId": analysis_run_id,
        "requestEnvelope": planned.request,
        "skillProjectionRunId": planned.request.skill_projection_run_id,
        "skillProjectionRootDigest": planned.request.skill_projection_root_digest,
        "skillBoundSnapshotDigest": snapshot.snapshot_digest,
        "projectionBundleDigest": bundle.bundle_digest,
        "instructionProjectionDigest": bundle.instruction_projection.projection_digest,
        "evidenceProjectionDigest": bundle.evidence_projection.projection_digest,
        "registry": snapshot.selection_policy.registry,
        "selectionPolicyDigest": snapshot.selection_policy.policy_digest,
        "transportPin": transport,
        "baseProviderExecutionContext": execution_context.base_provider_execution_context,
        "successorProviderExecutionContext": execution_context,
        "providerRunId": provider_publication.run_id,
        "providerRootDigest": provider_publication.root_digest,
        "providerRunSealCount": 1,
        "dispatchCount": dispatch_count,
        "targetRequestCount": 0,
    }


def _build_success_receipt(
    *,
    analysis_run_id: str,
    snapshot: SkillBoundWebAnalysisSnapshot,
    planned: PlannedSkillBoundWebAnalysisCall,
    transport: WebAnalysisTransportRuntimePin,
    execution_context: SkillBoundWebAnalysisProviderExecutionContext,
    provider_publication: SkillBoundWebAnalysisProviderRunPublication,
    provider_outcome: ProviderBoundChatOutcome,
    raw_draft: bytes,
    draft: SkillBoundWebAnalysisProposalDraft,
    proposal: CompiledSkillBoundWebAnalysisProposal,
) -> SkillBoundWebAnalysisInvocationReceipt:
    return SkillBoundWebAnalysisInvocationReceipt.model_validate(
        {
            **_common_receipt_fields(
                analysis_run_id=analysis_run_id,
                snapshot=snapshot,
                planned=planned,
                transport=transport,
                execution_context=execution_context,
                provider_publication=provider_publication,
                dispatch_count=1,
            ),
            "providerOutcome": provider_outcome,
            "rawDraftSha256": sha256(raw_draft).hexdigest(),
            "rawDraftBytes": len(raw_draft),
            "draftDigest": _draft_digest(draft),
            "compiledProposal": proposal,
        }
    )


def _build_failure_receipt(
    *,
    analysis_run_id: str,
    snapshot: SkillBoundWebAnalysisSnapshot,
    planned: PlannedSkillBoundWebAnalysisCall,
    transport: WebAnalysisTransportRuntimePin,
    execution_context: SkillBoundWebAnalysisProviderExecutionContext,
    provider_publication: SkillBoundWebAnalysisProviderRunPublication,
    provider_outcome: ProviderBoundChatOutcome | None,
    raw_draft: bytes | None,
    draft_digest: str | None,
    terminal_state: Literal[
        "provider-invocation-failed-uncertain",
        "provider-response-rejected",
    ],
    dispatch_count: Literal[0, 1],
) -> SkillBoundWebAnalysisInvocationFailureReceipt:
    return SkillBoundWebAnalysisInvocationFailureReceipt.model_validate(
        {
            **_common_receipt_fields(
                analysis_run_id=analysis_run_id,
                snapshot=snapshot,
                planned=planned,
                transport=transport,
                execution_context=execution_context,
                provider_publication=provider_publication,
                dispatch_count=dispatch_count,
            ),
            "providerOutcome": provider_outcome,
            "terminalState": terminal_state,
            "rawDraftSha256": (sha256(raw_draft).hexdigest() if raw_draft is not None else None),
            "rawDraftBytes": len(raw_draft) if raw_draft is not None else 0,
            "draftDigest": draft_digest,
        }
    )


def _complete_successful_analysis_run(
    *,
    store: RunStore,
    snapshot: SkillBoundWebAnalysisSnapshot,
    planned: PlannedSkillBoundWebAnalysisCall,
    execution_context: SkillBoundWebAnalysisProviderExecutionContext,
    provider_publication: SkillBoundWebAnalysisProviderRunPublication,
    provider_outcome: ProviderBoundChatOutcome,
    raw_draft: bytes,
    draft: SkillBoundWebAnalysisProposalDraft,
    proposal: CompiledSkillBoundWebAnalysisProposal,
    receipt: SkillBoundWebAnalysisInvocationReceipt,
) -> SkillBoundWebAnalysisInvocationPublication:
    if receipt.analysis_run_id != store.run_id:
        raise SkillBoundWebAnalysisRuntimeError(
            "Skill-bound receipt belongs to another analysis Run"
        )
    store.write_json_create_only(
        _PROVIDER_OUTCOME_PATH,
        provider_outcome.model_dump(mode="json", by_alias=True),
    )
    store.write_text_create_only(
        _DRAFT_PATH,
        raw_draft.decode("utf-8", errors="strict"),
    )
    store.write_json_create_only(
        _PROPOSAL_PATH,
        proposal.model_dump(mode="json", by_alias=True),
    )
    store.write_json_create_only(
        _RECEIPT_PATH,
        receipt.model_dump(mode="json", by_alias=True),
    )
    store.append_event(
        _ANALYSIS_COMPLETED_EVENT,
        _analysis_completed_payload(
            provider_outcome=provider_outcome,
            raw_draft=raw_draft,
            draft=draft,
            proposal=proposal,
            receipt=receipt,
            provider_publication=provider_publication,
        ),
    )
    seal = store.seal()
    verification = verify_run_integrity(store.path)
    if (
        verification.run_id != store.run_id
        or verification.root_digest != seal.root_digest
        or verification.seal_count != 1
        or verification.event_count != 2
        or verification.artifact_count != len(_SUCCESS_ARTIFACT_LIMITS)
    ):
        raise SkillBoundWebAnalysisRuntimeError(
            "Skill-bound Web analysis success Run did not seal exactly once"
        )
    return SkillBoundWebAnalysisInvocationPublication(
        run_path=store.path,
        run_id=store.run_id,
        root_digest=seal.root_digest,
    )


def _complete_failed_analysis_run(
    *,
    store: RunStore,
    snapshot: SkillBoundWebAnalysisSnapshot,
    planned: PlannedSkillBoundWebAnalysisCall,
    transport: WebAnalysisTransportRuntimePin,
    execution_context: SkillBoundWebAnalysisProviderExecutionContext,
    provider_publication: SkillBoundWebAnalysisProviderRunPublication,
    provider_outcome: ProviderBoundChatOutcome | None,
    raw_draft: bytes | None,
    draft_digest: str | None,
    terminal_state: Literal[
        "provider-invocation-failed-uncertain",
        "provider-response-rejected",
    ],
    dispatch_count: Literal[0, 1],
) -> SkillBoundWebAnalysisInvocationPublication:
    receipt = _build_failure_receipt(
        analysis_run_id=store.run_id,
        snapshot=snapshot,
        planned=planned,
        transport=transport,
        execution_context=execution_context,
        provider_publication=provider_publication,
        provider_outcome=provider_outcome,
        raw_draft=raw_draft,
        draft_digest=draft_digest,
        terminal_state=terminal_state,
        dispatch_count=dispatch_count,
    )
    if provider_outcome is not None:
        store.write_json_create_only(
            _PROVIDER_OUTCOME_PATH,
            provider_outcome.model_dump(mode="json", by_alias=True),
        )
    if raw_draft is not None:
        store.write_text_create_only(
            _REJECTED_DRAFT_PATH,
            raw_draft.decode("utf-8", errors="strict"),
        )
    store.write_json_create_only(
        _FAILURE_RECEIPT_PATH,
        receipt.model_dump(mode="json", by_alias=True),
    )
    store.append_event(
        _ANALYSIS_FAILED_EVENT,
        _analysis_failed_payload(receipt),
    )
    seal = store.seal()
    verification = verify_run_integrity(store.path)
    expected_artifact_count = 4 + int(provider_outcome is not None) + int(raw_draft is not None)
    if (
        verification.run_id != store.run_id
        or verification.root_digest != seal.root_digest
        or verification.seal_count != 1
        or verification.event_count != 2
        or verification.artifact_count != expected_artifact_count
    ):
        raise SkillBoundWebAnalysisRuntimeError(
            "Skill-bound Web analysis failure Run did not seal exactly once"
        )
    return SkillBoundWebAnalysisInvocationPublication(
        run_path=store.path,
        run_id=store.run_id,
        root_digest=seal.root_digest,
    )


def _analysis_completed_payload(
    *,
    provider_outcome: ProviderBoundChatOutcome,
    raw_draft: bytes,
    draft: SkillBoundWebAnalysisProposalDraft,
    proposal: CompiledSkillBoundWebAnalysisProposal,
    receipt: SkillBoundWebAnalysisInvocationReceipt,
    provider_publication: SkillBoundWebAnalysisProviderRunPublication,
) -> dict[str, object]:
    return {
        "providerOutcomeId": provider_outcome.outcome_id,
        "providerOutcomeDigest": provider_outcome.outcome_digest,
        "providerRunId": provider_publication.run_id,
        "providerRootDigest": provider_publication.root_digest,
        "providerRunSealCount": 1,
        "rawDraftSha256": sha256(raw_draft).hexdigest(),
        "draftDigest": _draft_digest(draft),
        "proposalId": proposal.proposal_id,
        "proposalDigest": proposal.proposal_digest,
        "receiptId": receipt.receipt_id,
        "receiptDigest": receipt.receipt_digest,
        "dispatchCount": 1,
        "targetRequestCount": 0,
        "responseState": "skill-bound-draft-compiled-not-admitted",
        "automaticRedispatchAuthorized": False,
        "executionAuthorized": False,
        "graphAdmissionAuthorized": False,
        "findingAuthorized": False,
        "reportDeliveryAuthorized": False,
    }


def _analysis_failed_payload(
    receipt: SkillBoundWebAnalysisInvocationFailureReceipt,
) -> dict[str, object]:
    return {
        "failureReceiptId": receipt.receipt_id,
        "failureReceiptDigest": receipt.receipt_digest,
        "requestId": receipt.request_envelope.request_id,
        "providerRunId": receipt.provider_run_id,
        "providerRootDigest": receipt.provider_root_digest,
        "providerRunSealCount": 1,
        "terminalState": receipt.terminal_state,
        "dispatchCount": receipt.dispatch_count,
        "targetRequestCount": 0,
        "proposalCompiled": False,
        "automaticRedispatchAuthorized": False,
        "executionAuthorized": False,
    }


def _require_skill_invocation_pin(
    pin: SkillBoundWebAnalysisInvocationPin,
    *,
    chat: ProviderChatRequest,
) -> None:
    current = canonical_skill_contract(pin, SkillBoundWebAnalysisInvocationPin)
    response_format = chat.response_format
    if (
        current.role != SKILL_BOUND_WEB_ANALYSIS_ROLE
        or current.attempt != SKILL_BOUND_WEB_ANALYSIS_ATTEMPT
        or chat.max_completion_tokens != current.max_completion_tokens
        or chat.seed != current.seed
        or chat.temperature != current.temperature
        or chat.top_p != current.top_p
        or chat.tool_choice != current.tool_choice
        or bool(chat.tools) != current.tools_allowed
        or chat.stream != current.streaming_allowed
        or chat.parallel_tool_calls != current.parallel_tool_calls_allowed
        or response_format is None
        or response_format.json_schema.name != current.response_schema_name
    ):
        raise SkillBoundWebAnalysisRuntimeError(
            "Skill-bound Provider request differs from its invocation Pin"
        )


def _require_source_bound_campaign(
    lifecycle: PreparedWebAnalysisProviderLifecycle,
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
) -> None:
    campaign = lifecycle.campaign
    if (
        campaign.spec.authorization.evidence
        != f"sealed-authenticated-discovery:{source.index.index_digest}"
        or campaign.spec.access_profile != "sealed-discovery-analysis"
        or campaign.spec.objectives
        != ["Rank and assess every installed WEB-007 hypothesis without execution"]
        or campaign.spec.outputs
    ):
        raise SkillBoundWebAnalysisRuntimeError(
            "Skill-bound Provider Campaign differs from the sealed discovery source"
        )


def _require_proposal_only_result(result: ProviderChatResult) -> None:
    if (
        result.streamed
        or result.chunks != 1
        or result.refusal is not None
        or result.tool_calls
        or result.content is None
        or result.content == ""
    ):
        raise SkillBoundWebAnalysisRuntimeError(
            "Skill-bound Provider returned refusal, tool calls, or non-content output"
        )


def _rejected_response_bytes(result: ProviderChatResult) -> bytes | None:
    content = result.content
    if content is None or content == "":
        return None
    encoded = content.encode("utf-8", errors="strict")
    return encoded if len(encoded) <= _MAX_RAW_DRAFT_BYTES else None


def _draft_digest(draft: SkillBoundWebAnalysisProposalDraft) -> str:
    canonical = canonical_skill_contract(draft, SkillBoundWebAnalysisProposalDraft)
    return _digest(
        "pajin.web-analysis.skill-bound-proposal-draft/v1",
        canonical.model_dump(mode="json", by_alias=True),
    )


def _provider_content_digest(content: bytes) -> str:
    if type(content) is not bytes:
        raise TypeError("Provider content must be exact bytes")
    return _digest(
        "pajin.provider.content/v1",
        {"text": content.decode("utf-8", errors="strict")},
    )


def _digest(domain: str, value: object) -> str:
    return sha256(
        domain.encode("ascii", errors="strict")
        + b"\x00"
        + canonical_json_bytes(
            value,
            label="Skill-bound Web analysis runtime identity",
            max_bytes=_MAX_RECEIPT_BYTES,
        )
    ).hexdigest()


def _reload_published_success(
    *,
    publication: SkillBoundWebAnalysisInvocationPublication,
    provider_publication: SkillBoundWebAnalysisProviderRunPublication,
    source: VerifiedAuthenticatedDiscoveryRun,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    transport: WebAnalysisTransportRuntimePin,
    registration: ProviderRegistration,
    context: SkillBoundWebAnalysisProviderExecutionContext,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    expected_skill_run_id: str,
    expected_skill_root_digest: str,
    expected_registry_ref: SkillRegistryRef,
    expected_policy_digest: str,
    expected_transport_pin_digest: str,
    expected_external_network: str,
) -> VerifiedSkillBoundWebAnalysisInvocationRun:
    try:
        return load_verified_skill_bound_web_analysis_invocation(
            publication.run_path,
            expected_run_id=publication.run_id,
            expected_root_digest=publication.root_digest,
            source=source,
            skill_run=skill_run,
            transport_pin=transport,
            registration=registration,
            provider_run_path=provider_publication.run_path,
            expected_provider_run_id=provider_publication.run_id,
            expected_provider_root_digest=provider_publication.root_digest,
            expected_provider_execution_context=context,
            expected_source_run_id=expected_source_run_id,
            expected_source_root_digest=expected_source_root_digest,
            expected_skill_run_id=expected_skill_run_id,
            expected_skill_root_digest=expected_skill_root_digest,
            expected_registry_ref=expected_registry_ref,
            expected_policy_digest=expected_policy_digest,
            expected_transport_pin_digest=expected_transport_pin_digest,
            expected_external_network=expected_external_network,
        )
    except Exception as exc:
        raise SkillBoundWebAnalysisRuntimeError(
            "Skill-bound Web analysis success publication failed strict reload",
            publication=publication,
            provider_publication=provider_publication,
        ) from exc


def _reload_published_failure(
    *,
    publication: SkillBoundWebAnalysisInvocationPublication,
    provider_publication: SkillBoundWebAnalysisProviderRunPublication,
    source: VerifiedAuthenticatedDiscoveryRun,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    transport: WebAnalysisTransportRuntimePin,
    registration: ProviderRegistration,
    context: SkillBoundWebAnalysisProviderExecutionContext,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    expected_skill_run_id: str,
    expected_skill_root_digest: str,
    expected_registry_ref: SkillRegistryRef,
    expected_policy_digest: str,
    expected_transport_pin_digest: str,
    expected_external_network: str,
) -> VerifiedSkillBoundWebAnalysisFailureRun:
    try:
        return load_verified_skill_bound_web_analysis_failure(
            publication.run_path,
            expected_run_id=publication.run_id,
            expected_root_digest=publication.root_digest,
            source=source,
            skill_run=skill_run,
            transport_pin=transport,
            registration=registration,
            provider_run_path=provider_publication.run_path,
            expected_provider_run_id=provider_publication.run_id,
            expected_provider_root_digest=provider_publication.root_digest,
            expected_provider_execution_context=context,
            expected_source_run_id=expected_source_run_id,
            expected_source_root_digest=expected_source_root_digest,
            expected_skill_run_id=expected_skill_run_id,
            expected_skill_root_digest=expected_skill_root_digest,
            expected_registry_ref=expected_registry_ref,
            expected_policy_digest=expected_policy_digest,
            expected_transport_pin_digest=expected_transport_pin_digest,
            expected_external_network=expected_external_network,
        )
    except Exception as exc:
        raise SkillBoundWebAnalysisRuntimeError(
            "Skill-bound Web analysis failure publication failed strict reload",
            publication=publication,
            provider_publication=provider_publication,
        ) from exc


def load_verified_skill_bound_web_analysis_invocation(
    run_path: Path,
    *,
    expected_run_id: str,
    expected_root_digest: str,
    source: VerifiedAuthenticatedDiscoveryRun,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    transport_pin: WebAnalysisTransportRuntimePin,
    registration: ProviderRegistration,
    provider_run_path: Path,
    expected_provider_run_id: str,
    expected_provider_root_digest: str,
    expected_provider_execution_context: SkillBoundWebAnalysisProviderExecutionContext,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    expected_skill_run_id: str,
    expected_skill_root_digest: str,
    expected_registry_ref: SkillRegistryRef,
    expected_policy_digest: str,
    expected_transport_pin_digest: str,
    expected_external_network: str,
) -> VerifiedSkillBoundWebAnalysisInvocationRun:
    """Strictly reload one successful successor Run under independent anchors."""

    _require_run_anchors(expected_run_id, expected_root_digest)
    try:
        canonical_registration = ProviderRegistration.model_validate(
            registration.model_dump(mode="python")
        )
        context = canonical_skill_contract(
            expected_provider_execution_context,
            SkillBoundWebAnalysisProviderExecutionContext,
        )
        transport = verify_web_analysis_transport_runtime_pin(
            transport_pin,
            runtime=context.base_provider_execution_context.effect_runtime_pin,
            expected_pin_digest=expected_transport_pin_digest,
        )
        planned = plan_skill_bound_web_analysis_call(
            registration=canonical_registration,
            source=source,
            skill_run=skill_run,
            transport_pin=transport,
            expected_source_run_id=expected_source_run_id,
            expected_source_root_digest=expected_source_root_digest,
            expected_skill_run_id=expected_skill_run_id,
            expected_skill_root_digest=expected_skill_root_digest,
            expected_registry_ref=expected_registry_ref,
            expected_policy_digest=expected_policy_digest,
            expected_transport_pin_digest=expected_transport_pin_digest,
        )
        planned = verify_planned_skill_bound_web_analysis_call(
            planned,
            registration=canonical_registration,
            source=source,
            skill_run=skill_run,
            transport_pin=transport,
            expected_source_run_id=expected_source_run_id,
            expected_source_root_digest=expected_source_root_digest,
            expected_skill_run_id=expected_skill_run_id,
            expected_skill_root_digest=expected_skill_root_digest,
            expected_registry_ref=expected_registry_ref,
            expected_policy_digest=expected_policy_digest,
            expected_transport_pin_digest=expected_transport_pin_digest,
        )
        _require_context_binding(
            context,
            registration=canonical_registration,
            transport=transport,
            planned=planned,
        )
        base_publication, provider_publication, provider_dispatch_count = (
            _load_provider_publications(
                provider_run_path=provider_run_path,
                expected_provider_run_id=expected_provider_run_id,
                expected_provider_root_digest=expected_provider_root_digest,
                context=context,
                registration=canonical_registration,
                planned=planned,
                transport=transport,
                expected_transport_pin_digest=expected_transport_pin_digest,
                expected_external_network=expected_external_network,
            )
        )
        if provider_dispatch_count != 1:
            raise ValueError("successful Skill-bound Provider Run lacks one model dispatch")
        initial = load_verified_run_snapshot(run_path, expected_run_id=expected_run_id)
        _require_analysis_run_shape(
            initial,
            expected_root_digest=expected_root_digest,
            event_types=(_ANALYSIS_STARTED_EVENT, _ANALYSIS_COMPLETED_EVENT),
            expected_paths=set(_SUCCESS_ARTIFACT_LIMITS),
        )
        loaded = load_verified_run_artifacts(
            initial.run_path,
            requests=dict(_SUCCESS_ARTIFACT_LIMITS),
            expected_run_id=expected_run_id,
        )
        require_same_authority(
            initial,
            loaded,
            message="sealed Skill-bound Web analysis changed while artifacts were loaded",
        )
        snapshot = _strict_artifact_model(
            loaded,
            _SNAPSHOT_PATH,
            SkillBoundWebAnalysisSnapshot,
            _MAX_SNAPSHOT_BYTES,
        )
        request = _strict_artifact_model(
            loaded,
            _REQUEST_PATH,
            SkillBoundWebAnalysisRequestEnvelope,
            _MAX_REQUEST_BYTES,
        )
        persisted_context = _strict_artifact_model(
            loaded,
            _SUCCESSOR_CONTEXT_PATH,
            SkillBoundWebAnalysisProviderExecutionContext,
            _MAX_CONTEXT_BYTES,
        )
        outcome = _strict_artifact_model(
            loaded,
            _PROVIDER_OUTCOME_PATH,
            ProviderBoundChatOutcome,
            _MAX_PROVIDER_OUTCOME_BYTES,
        )
        proposal = _strict_artifact_model(
            loaded,
            _PROPOSAL_PATH,
            CompiledSkillBoundWebAnalysisProposal,
            _MAX_PROPOSAL_BYTES,
        )
        receipt = _strict_artifact_model(
            loaded,
            _RECEIPT_PATH,
            SkillBoundWebAnalysisInvocationReceipt,
            _MAX_RECEIPT_BYTES,
        )
        raw_draft = _restore_raw_draft(
            loaded.artifact_bytes(_DRAFT_PATH),
            expected_bytes=receipt.raw_draft_bytes,
            expected_sha256=receipt.raw_draft_sha256,
        )
        draft = parse_skill_bound_web_analysis_proposal_draft(
            raw_draft,
            snapshot=snapshot,
        )
        verified_proposal = verify_compiled_skill_bound_web_analysis_proposal(
            proposal,
            source=source,
            skill_run=skill_run,
            draft=draft,
            transport_pin=transport,
            expected_source_run_id=expected_source_run_id,
            expected_source_root_digest=expected_source_root_digest,
            expected_skill_run_id=expected_skill_run_id,
            expected_skill_root_digest=expected_skill_root_digest,
            expected_registry_ref=expected_registry_ref,
            expected_policy_digest=expected_policy_digest,
            expected_transport_pin_digest=expected_transport_pin_digest,
        )
        expected_receipt = _build_success_receipt(
            analysis_run_id=expected_run_id,
            snapshot=snapshot,
            planned=planned,
            transport=transport,
            execution_context=context,
            provider_publication=provider_publication,
            provider_outcome=outcome,
            raw_draft=raw_draft,
            draft=draft,
            proposal=verified_proposal,
        )
        if (
            snapshot
            != canonical_skill_contract(
                skill_run.snapshot,
                SkillBoundWebAnalysisSnapshot,
            )
            or request != planned.request
            or persisted_context != context
            or receipt != expected_receipt
            or outcome.content_digest != _provider_content_digest(raw_draft)
        ):
            raise ValueError("sealed Skill-bound Web analysis artifact lineage differs")
        verify_web_analysis_provider_run_binding(
            base_publication,
            analysis_run_id=expected_run_id,
            registration=canonical_registration,
            execution_context=context.base_provider_execution_context,
            stable_request_id=request.request_id,
            provider_chat_request_digest=request.provider_chat_request_digest,
            provider_outcome=outcome,
            expected_role=SKILL_BOUND_WEB_ANALYSIS_ROLE,
            expected_attempt=SKILL_BOUND_WEB_ANALYSIS_ATTEMPT,
            expected_schema_name=SKILL_BOUND_WEB_ANALYSIS_RESPONSE_SCHEMA_NAME,
            expected_provider_chat_request=planned.chat,
            expected_transport_pin=transport,
            expected_transport_pin_digest=expected_transport_pin_digest,
            expected_external_network=expected_external_network,
        )
        started, completed = loaded.events
        if started.payload != _analysis_started_payload(
            analysis_run_id=expected_run_id,
            snapshot=snapshot,
            planned=planned,
            execution_context=context,
            registration=canonical_registration,
            provider_run_id=provider_publication.run_id,
        ) or completed.payload != _analysis_completed_payload(
            provider_outcome=outcome,
            raw_draft=raw_draft,
            draft=draft,
            proposal=verified_proposal,
            receipt=expected_receipt,
            provider_publication=provider_publication,
        ):
            raise ValueError("sealed Skill-bound Web analysis audit events differ")
        final = load_verified_run_snapshot(initial.run_path, expected_run_id=expected_run_id)
        require_same_authority(
            initial,
            final,
            message="sealed Skill-bound Web analysis changed during strict reload",
        )
        return VerifiedSkillBoundWebAnalysisInvocationRun(
            run_path=initial.run_path,
            verification=initial.verification.model_copy(deep=True),
            snapshot=snapshot,
            request=request,
            provider_execution_context=context,
            provider_publication=provider_publication,
            provider_outcome=outcome,
            raw_draft=raw_draft,
            draft=draft,
            proposal=verified_proposal,
            receipt=expected_receipt,
        )
    except SkillBoundWebAnalysisRuntimeError:
        raise
    except Exception as exc:
        raise SkillBoundWebAnalysisRuntimeError(
            "sealed Skill-bound Web analysis invocation failed strict verification"
        ) from exc


def load_verified_skill_bound_web_analysis_failure(
    run_path: Path,
    *,
    expected_run_id: str,
    expected_root_digest: str,
    source: VerifiedAuthenticatedDiscoveryRun,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    transport_pin: WebAnalysisTransportRuntimePin,
    registration: ProviderRegistration,
    provider_run_path: Path,
    expected_provider_run_id: str,
    expected_provider_root_digest: str,
    expected_provider_execution_context: SkillBoundWebAnalysisProviderExecutionContext,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    expected_skill_run_id: str,
    expected_skill_root_digest: str,
    expected_registry_ref: SkillRegistryRef,
    expected_policy_digest: str,
    expected_transport_pin_digest: str,
    expected_external_network: str,
) -> VerifiedSkillBoundWebAnalysisFailureRun:
    """Strictly reload one terminal successor failure under independent anchors."""

    _require_run_anchors(expected_run_id, expected_root_digest)
    try:
        canonical_registration = ProviderRegistration.model_validate(
            registration.model_dump(mode="python")
        )
        context = canonical_skill_contract(
            expected_provider_execution_context,
            SkillBoundWebAnalysisProviderExecutionContext,
        )
        transport = verify_web_analysis_transport_runtime_pin(
            transport_pin,
            runtime=context.base_provider_execution_context.effect_runtime_pin,
            expected_pin_digest=expected_transport_pin_digest,
        )
        planned = plan_skill_bound_web_analysis_call(
            registration=canonical_registration,
            source=source,
            skill_run=skill_run,
            transport_pin=transport,
            expected_source_run_id=expected_source_run_id,
            expected_source_root_digest=expected_source_root_digest,
            expected_skill_run_id=expected_skill_run_id,
            expected_skill_root_digest=expected_skill_root_digest,
            expected_registry_ref=expected_registry_ref,
            expected_policy_digest=expected_policy_digest,
            expected_transport_pin_digest=expected_transport_pin_digest,
        )
        planned = verify_planned_skill_bound_web_analysis_call(
            planned,
            registration=canonical_registration,
            source=source,
            skill_run=skill_run,
            transport_pin=transport,
            expected_source_run_id=expected_source_run_id,
            expected_source_root_digest=expected_source_root_digest,
            expected_skill_run_id=expected_skill_run_id,
            expected_skill_root_digest=expected_skill_root_digest,
            expected_registry_ref=expected_registry_ref,
            expected_policy_digest=expected_policy_digest,
            expected_transport_pin_digest=expected_transport_pin_digest,
        )
        _require_context_binding(
            context,
            registration=canonical_registration,
            transport=transport,
            planned=planned,
        )
        base_publication, provider_publication, provider_dispatch_count = (
            _load_provider_publications(
                provider_run_path=provider_run_path,
                expected_provider_run_id=expected_provider_run_id,
                expected_provider_root_digest=expected_provider_root_digest,
                context=context,
                registration=canonical_registration,
                planned=planned,
                transport=transport,
                expected_transport_pin_digest=expected_transport_pin_digest,
                expected_external_network=expected_external_network,
            )
        )
        initial = load_verified_run_snapshot(run_path, expected_run_id=expected_run_id)
        records = _artifact_paths(initial)
        required = {
            _SNAPSHOT_PATH,
            _REQUEST_PATH,
            _SUCCESSOR_CONTEXT_PATH,
            _FAILURE_RECEIPT_PATH,
        }
        allowed = required | {_PROVIDER_OUTCOME_PATH, _REJECTED_DRAFT_PATH}
        if not required <= records or not records <= allowed:
            raise ValueError("sealed Skill-bound failure artifact inventory differs")
        _require_analysis_run_shape(
            initial,
            expected_root_digest=expected_root_digest,
            event_types=(_ANALYSIS_STARTED_EVENT, _ANALYSIS_FAILED_EVENT),
            expected_paths=records,
        )
        limits = {
            _SNAPSHOT_PATH: _MAX_SNAPSHOT_BYTES,
            _REQUEST_PATH: _MAX_REQUEST_BYTES,
            _SUCCESSOR_CONTEXT_PATH: _MAX_CONTEXT_BYTES,
            _FAILURE_RECEIPT_PATH: _MAX_RECEIPT_BYTES,
            _PROVIDER_OUTCOME_PATH: _MAX_PROVIDER_OUTCOME_BYTES,
            _REJECTED_DRAFT_PATH: _MAX_RAW_DRAFT_BYTES + 1,
        }
        loaded = load_verified_run_artifacts(
            initial.run_path,
            requests={path: limits[path] for path in records},
            expected_run_id=expected_run_id,
        )
        require_same_authority(
            initial,
            loaded,
            message="sealed Skill-bound failure changed while artifacts were loaded",
        )
        snapshot = _strict_artifact_model(
            loaded,
            _SNAPSHOT_PATH,
            SkillBoundWebAnalysisSnapshot,
            _MAX_SNAPSHOT_BYTES,
        )
        request = _strict_artifact_model(
            loaded,
            _REQUEST_PATH,
            SkillBoundWebAnalysisRequestEnvelope,
            _MAX_REQUEST_BYTES,
        )
        persisted_context = _strict_artifact_model(
            loaded,
            _SUCCESSOR_CONTEXT_PATH,
            SkillBoundWebAnalysisProviderExecutionContext,
            _MAX_CONTEXT_BYTES,
        )
        receipt = _strict_artifact_model(
            loaded,
            _FAILURE_RECEIPT_PATH,
            SkillBoundWebAnalysisInvocationFailureReceipt,
            _MAX_RECEIPT_BYTES,
        )
        outcome = (
            _strict_artifact_model(
                loaded,
                _PROVIDER_OUTCOME_PATH,
                ProviderBoundChatOutcome,
                _MAX_PROVIDER_OUTCOME_BYTES,
            )
            if _PROVIDER_OUTCOME_PATH in records
            else None
        )
        raw_draft = (
            _restore_raw_draft(
                loaded.artifact_bytes(_REJECTED_DRAFT_PATH),
                expected_bytes=receipt.raw_draft_bytes,
                expected_sha256=receipt.raw_draft_sha256 or "",
            )
            if _REJECTED_DRAFT_PATH in records
            else None
        )
        expected_paths = set(required)
        if receipt.provider_outcome is not None:
            expected_paths.add(_PROVIDER_OUTCOME_PATH)
        if receipt.raw_draft_sha256 is not None:
            expected_paths.add(_REJECTED_DRAFT_PATH)
        expected_receipt = _build_failure_receipt(
            analysis_run_id=expected_run_id,
            snapshot=snapshot,
            planned=planned,
            transport=transport,
            execution_context=context,
            provider_publication=provider_publication,
            provider_outcome=outcome,
            raw_draft=raw_draft,
            draft_digest=receipt.draft_digest,
            terminal_state=receipt.terminal_state,
            dispatch_count=provider_dispatch_count,
        )
        if (
            records != expected_paths
            or snapshot
            != canonical_skill_contract(skill_run.snapshot, SkillBoundWebAnalysisSnapshot)
            or request != planned.request
            or persisted_context != context
            or receipt != expected_receipt
            or receipt.dispatch_count != provider_dispatch_count
            or (
                outcome is not None
                and raw_draft is not None
                and outcome.content_digest != _provider_content_digest(raw_draft)
            )
        ):
            raise ValueError("sealed Skill-bound failure artifact lineage differs")
        if receipt.draft_digest is not None:
            if raw_draft is None:
                raise ValueError("sealed Skill-bound failure draft bytes are absent")
            parsed = parse_skill_bound_web_analysis_proposal_draft(
                raw_draft,
                snapshot=snapshot,
            )
            if _draft_digest(parsed) != receipt.draft_digest:
                raise ValueError("sealed Skill-bound failure draft digest differs")
        verify_web_analysis_provider_run_binding(
            base_publication,
            analysis_run_id=expected_run_id,
            registration=canonical_registration,
            execution_context=context.base_provider_execution_context,
            stable_request_id=request.request_id,
            provider_chat_request_digest=request.provider_chat_request_digest,
            provider_outcome=outcome,
            expected_role=SKILL_BOUND_WEB_ANALYSIS_ROLE,
            expected_attempt=SKILL_BOUND_WEB_ANALYSIS_ATTEMPT,
            expected_schema_name=SKILL_BOUND_WEB_ANALYSIS_RESPONSE_SCHEMA_NAME,
            expected_provider_chat_request=planned.chat,
            expected_transport_pin=transport,
            expected_transport_pin_digest=expected_transport_pin_digest,
            expected_external_network=expected_external_network,
        )
        started, failed = loaded.events
        if started.payload != _analysis_started_payload(
            analysis_run_id=expected_run_id,
            snapshot=snapshot,
            planned=planned,
            execution_context=context,
            registration=canonical_registration,
            provider_run_id=provider_publication.run_id,
        ) or failed.payload != _analysis_failed_payload(expected_receipt):
            raise ValueError("sealed Skill-bound failure audit events differ")
        final = load_verified_run_snapshot(initial.run_path, expected_run_id=expected_run_id)
        require_same_authority(
            initial,
            final,
            message="sealed Skill-bound failure changed during strict reload",
        )
        return VerifiedSkillBoundWebAnalysisFailureRun(
            run_path=initial.run_path,
            verification=initial.verification.model_copy(deep=True),
            snapshot=snapshot,
            request=request,
            provider_execution_context=context,
            provider_publication=provider_publication,
            provider_outcome=outcome,
            raw_draft=raw_draft,
            receipt=expected_receipt,
            dispatch_count=provider_dispatch_count,
        )
    except SkillBoundWebAnalysisRuntimeError:
        raise
    except Exception as exc:
        raise SkillBoundWebAnalysisRuntimeError(
            "sealed failed Skill-bound Web analysis invocation failed strict verification"
        ) from exc


def _require_context_binding(
    context: SkillBoundWebAnalysisProviderExecutionContext,
    *,
    registration: ProviderRegistration,
    transport: WebAnalysisTransportRuntimePin,
    planned: PlannedSkillBoundWebAnalysisCall,
) -> None:
    base = context.base_provider_execution_context
    if (
        context.transport_pin != transport
        or base.provider_id != registration.provider_id
        or base.model != registration.model
        or base.tool_id != f"provider.{registration.provider_id}.chat"
        or context.secret_material_embedded is not False
        or context.execution_authority is not False
    ):
        raise ValueError("Skill-bound Provider execution context differs")
    _require_skill_invocation_pin(context.invocation_pin, chat=planned.chat)


def _load_provider_publications(
    *,
    provider_run_path: Path,
    expected_provider_run_id: str,
    expected_provider_root_digest: str,
    context: SkillBoundWebAnalysisProviderExecutionContext,
    registration: ProviderRegistration,
    planned: PlannedSkillBoundWebAnalysisCall,
    transport: WebAnalysisTransportRuntimePin,
    expected_transport_pin_digest: str,
    expected_external_network: str,
) -> tuple[
    WebAnalysisProviderRunPublication,
    SkillBoundWebAnalysisProviderRunPublication,
    Literal[0, 1],
]:
    base_publication = WebAnalysisProviderRunPublication(
        run_path=provider_run_path,
        run_id=expected_provider_run_id,
        root_digest=expected_provider_root_digest,
        execution_context=context.base_provider_execution_context,
    )
    base_publication = verify_web_analysis_provider_run_publication(
        base_publication,
        expected_execution_context=context.base_provider_execution_context,
        expected_role=SKILL_BOUND_WEB_ANALYSIS_ROLE,
        expected_attempt=SKILL_BOUND_WEB_ANALYSIS_ATTEMPT,
        expected_schema_name=SKILL_BOUND_WEB_ANALYSIS_RESPONSE_SCHEMA_NAME,
        expected_registration=registration,
        expected_provider_chat_request=planned.chat,
        expected_transport_pin=transport,
        expected_transport_pin_digest=expected_transport_pin_digest,
        expected_external_network=expected_external_network,
    )
    dispatch_count = verified_web_analysis_provider_dispatch_count(
        base_publication,
        expected_execution_context=context.base_provider_execution_context,
        expected_role=SKILL_BOUND_WEB_ANALYSIS_ROLE,
        expected_attempt=SKILL_BOUND_WEB_ANALYSIS_ATTEMPT,
        expected_schema_name=SKILL_BOUND_WEB_ANALYSIS_RESPONSE_SCHEMA_NAME,
        expected_registration=registration,
        expected_provider_chat_request=planned.chat,
        expected_transport_pin=transport,
        expected_transport_pin_digest=expected_transport_pin_digest,
        expected_external_network=expected_external_network,
    )
    return (
        base_publication,
        SkillBoundWebAnalysisProviderRunPublication(
            run_path=base_publication.run_path,
            run_id=base_publication.run_id,
            root_digest=base_publication.root_digest,
            execution_context=context,
        ),
        dispatch_count,
    )


def _strict_artifact_model[T: BaseModel](
    snapshot: VerifiedRunSnapshot,
    path: str,
    model: type[T],
    max_bytes: int,
) -> T:
    raw = strict_json(
        snapshot,
        path,
        label=path,
        max_bytes=max_bytes,
        expected_type=dict,
    )
    current = model.model_validate(raw)
    canonical = canonical_skill_contract(current, model)
    if canonical_json_bytes(
        raw,
        label=f"persisted {path}",
        max_bytes=max_bytes,
    ) != canonical_json_bytes(
        canonical.model_dump(mode="json", by_alias=True),
        label=f"canonical {path}",
        max_bytes=max_bytes,
    ):
        raise ValueError(f"{path} differs from its exact canonical wire")
    return canonical


def _artifact_paths(snapshot: VerifiedRunSnapshot) -> set[str]:
    paths = [artifact.path for seal in snapshot.seals for artifact in seal.artifacts]
    if len(paths) != len(set(paths)):
        raise ValueError("sealed Skill-bound Web analysis contains duplicate artifact paths")
    return set(paths)


def _require_analysis_run_shape(
    snapshot: VerifiedRunSnapshot,
    *,
    expected_root_digest: str,
    event_types: tuple[str, str],
    expected_paths: set[str],
) -> None:
    verification = snapshot.verification
    if (
        verification.root_digest != expected_root_digest
        or verification.seal_count != 1
        or len(snapshot.seals) != 1
        or verification.event_count != 2
        or tuple(event.event_type for event in snapshot.events) != event_types
        or verification.artifact_count != len(expected_paths)
        or _artifact_paths(snapshot) != expected_paths
    ):
        raise ValueError("sealed Skill-bound Web analysis Run shape differs")


def _restore_raw_draft(
    persisted: bytes,
    *,
    expected_bytes: int,
    expected_sha256: str,
) -> bytes:
    if len(persisted) == expected_bytes:
        raw = persisted
    elif len(persisted) == expected_bytes + 1 and persisted.endswith(b"\n"):
        raw = persisted[:-1]
    else:
        raise ValueError("sealed Skill-bound raw draft length differs")
    if (
        _SHA256_PATTERN.fullmatch(expected_sha256) is None
        or sha256(raw).hexdigest() != expected_sha256
    ):
        raise ValueError("sealed Skill-bound raw draft digest differs")
    return raw


def _require_run_anchors(expected_run_id: str, expected_root_digest: str) -> None:
    if (
        type(expected_run_id) is not str
        or _RUN_ID_PATTERN.fullmatch(expected_run_id) is None
        or type(expected_root_digest) is not str
        or _SHA256_PATTERN.fullmatch(expected_root_digest) is None
    ):
        raise SkillBoundWebAnalysisRuntimeError("Skill-bound Web analysis Run anchors are invalid")


__all__ = [
    "SkillBoundWebAnalysisCancelledError",
    "SkillBoundWebAnalysisInvocationCompletion",
    "SkillBoundWebAnalysisInvocationFailureReceipt",
    "SkillBoundWebAnalysisInvocationReceipt",
    "SkillBoundWebAnalysisInvocationRuntime",
    "SkillBoundWebAnalysisProviderRuntime",
    "SkillBoundWebAnalysisRuntimeError",
    "VerifiedSkillBoundWebAnalysisFailureRun",
    "VerifiedSkillBoundWebAnalysisInvocationRun",
    "bind_skill_bound_web_analysis_provider_runtime",
    "load_verified_skill_bound_web_analysis_failure",
    "load_verified_skill_bound_web_analysis_invocation",
]
