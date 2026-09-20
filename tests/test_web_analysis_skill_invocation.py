from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import AnyHttpUrl, ValidationError

import pajin.web_assessment.analysis_skill_invocation as invocation_module
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.providers.models import ProviderRegistration
from pajin.tools.ai import ChatRole
from pajin.web_assessment.analysis_proposal import (
    WebAnalysisProposalError,
    parse_web_analysis_proposal_draft,
)
from pajin.web_assessment.analysis_skill_invocation import (
    CompiledSkillBoundWebAnalysisProposal,
    PlannedSkillBoundWebAnalysisCall,
    SkillBoundWebAnalysisInvocationError,
    SkillBoundWebAnalysisProposalDraft,
    SkillBoundWebAnalysisRequestEnvelope,
    build_skill_bound_web_analysis_chat_request,
    compile_skill_bound_web_analysis_proposal,
    parse_skill_bound_web_analysis_proposal_draft,
    plan_skill_bound_web_analysis_call,
    verify_compiled_skill_bound_web_analysis_proposal,
    verify_planned_skill_bound_web_analysis_call,
)
from pajin.web_assessment.analysis_skill_projection import (
    VerifiedWebAnalysisSkillProjectionRun,
    _create_web_analysis_skill_projection_run_with_loader,
)
from pajin.web_assessment.analysis_transport import (
    WebAnalysisTransportRuntimePin,
    web_analysis_transport_runtime_pin,
)
from pajin.web_assessment.discovery_artifact import VerifiedAuthenticatedDiscoveryRun
from tests.test_web_analysis_proposal import (
    _draft_payload,
    _synthetic_loader,
    _verified_source,
)
from tests.test_web_analysis_proposal import (
    compile_web_analysis_proposal as compile_nested_proposal,
)
from tests.test_web_analysis_proposal import (
    verify_compiled_web_analysis_proposal as verify_nested_proposal,
)
from tests.test_web_analysis_transport import _runtime_pin, _transport_pin


@pytest.fixture
def prepared_skill_run(
    tmp_path: Path,
) -> tuple[VerifiedAuthenticatedDiscoveryRun, VerifiedWebAnalysisSkillProjectionRun]:
    source = _verified_source()
    run = _create_web_analysis_skill_projection_run_with_loader(
        source=source,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        output_root=tmp_path,
        source_loader=_synthetic_loader(source),
    )
    return source, run


def _registration(*, model: str = "qwen3-4b") -> ProviderRegistration:
    return ProviderRegistration(
        provider_id="local-analysis",
        endpoint=AnyHttpUrl("http://127.0.0.1:11434/v1/chat/completions"),
        model=model,
        secret_ref="provider/local-analysis/test-key",
        allow_streaming=False,
        allowed_function_tools=set(),
        allow_private_networks=True,
    )


def _patch_strict_skill_loader(
    monkeypatch: pytest.MonkeyPatch,
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    run: VerifiedWebAnalysisSkillProjectionRun,
) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []

    def strict_loader(path: Path, **anchors: object) -> VerifiedWebAnalysisSkillProjectionRun:
        calls.append({"path": path, **anchors})
        assert path == run.run_path
        assert anchors == {
            "source": source,
            "expected_run_id": run.verification.run_id,
            "expected_root_digest": run.verification.root_digest,
            "expected_source_run_id": source.verification.run_id,
            "expected_source_root_digest": source.verification.root_digest,
            "expected_registry_ref": run.index.registry,
            "expected_policy_digest": run.index.selection_policy_digest,
        }
        return run

    monkeypatch.setattr(
        invocation_module,
        "load_verified_web_analysis_skill_projection",
        strict_loader,
    )
    return calls


def _successor_draft_payload(
    run: VerifiedWebAnalysisSkillProjectionRun,
) -> dict[str, object]:
    bundle = run.snapshot.projection_bundle
    return {
        "apiVersion": "pajin.dev/skill-bound-web-analysis-proposal-draft/v1alpha1",
        "kind": "SkillBoundWebAnalysisProposalDraft",
        "instructionProjectionDigest": bundle.instruction_projection.projection_digest,
        "evidenceProjectionDigest": bundle.evidence_projection.projection_digest,
        "proposal": _draft_payload(run.snapshot.source_snapshot),
        "proposalState": "untrusted-skill-bound-model-output-not-authorized",
        "scopeExpansionAuthorized": False,
        "toolRequestCompiled": False,
        "capabilityGranted": False,
        "permitGranted": False,
        "executionAuthorized": False,
        "graphAdmissionAuthorized": False,
        "findingAuthorized": False,
        "reportDeliveryAuthorized": False,
    }


def _successor_draft(
    run: VerifiedWebAnalysisSkillProjectionRun,
) -> SkillBoundWebAnalysisProposalDraft:
    return parse_skill_bound_web_analysis_proposal_draft(
        canonical_json_bytes(
            _successor_draft_payload(run),
            label="test Skill-bound Web analysis draft",
        ),
        snapshot=run.snapshot,
    )


def _plan(
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    run: VerifiedWebAnalysisSkillProjectionRun,
    registration: ProviderRegistration,
    transport: WebAnalysisTransportRuntimePin,
) -> PlannedSkillBoundWebAnalysisCall:
    return plan_skill_bound_web_analysis_call(
        registration=registration,
        source=source,
        skill_run=run,
        transport_pin=transport,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        expected_skill_run_id=run.verification.run_id,
        expected_skill_root_digest=run.verification.root_digest,
        expected_registry_ref=run.index.registry,
        expected_policy_digest=run.index.selection_policy_digest,
        expected_transport_pin_digest=transport.pin_digest,
    )


def test_chat_request_routes_only_code_owned_instructions_and_exact_evidence(
    prepared_skill_run: tuple[
        VerifiedAuthenticatedDiscoveryRun,
        VerifiedWebAnalysisSkillProjectionRun,
    ],
) -> None:
    _source, run = prepared_skill_run
    bundle = run.snapshot.projection_bundle

    chat = build_skill_bound_web_analysis_chat_request(run.snapshot)

    assert [message.role for message in chat.messages] == [
        ChatRole.DEVELOPER,
        ChatRole.USER,
    ]
    assert chat.messages[0].content is not None
    assert chat.messages[1].content is not None
    developer = json.loads(chat.messages[0].content)
    evidence = json.loads(chat.messages[1].content)
    assert set(developer) == {
        "apiVersion",
        "kind",
        "instruction",
        "instructionProjection",
    }
    assert developer["instructionProjection"] == (
        bundle.instruction_projection.model_dump(mode="json", by_alias=True)
    )
    assert "evidenceProjection" not in developer
    assert evidence == bundle.evidence_projection.model_dump(mode="json", by_alias=True)
    assert chat.tools == []
    assert chat.tool_choice == "none"
    assert chat.parallel_tool_calls is False
    assert chat.stream is False
    assert chat.response_format is not None
    assert chat.response_format.json_schema.name == "skill_bound_web_analysis_proposal_draft"
    assert chat.response_format.json_schema.strict is True


def test_request_identity_binds_projection_transport_schema_and_provider_digests(
    prepared_skill_run: tuple[
        VerifiedAuthenticatedDiscoveryRun,
        VerifiedWebAnalysisSkillProjectionRun,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, run = prepared_skill_run
    loader_calls = _patch_strict_skill_loader(
        monkeypatch,
        source=source,
        run=run,
    )
    runtime = _runtime_pin()
    transport = _transport_pin(runtime)

    planned = _plan(
        source=source,
        run=run,
        registration=_registration(),
        transport=transport,
    )

    bundle = run.snapshot.projection_bundle
    request = planned.request
    assert request.instruction_projection_digest == (
        bundle.instruction_projection.projection_digest
    )
    assert request.evidence_projection_digest == bundle.evidence_projection.projection_digest
    assert request.transport_pin_digest == transport.pin_digest
    assert request.provider_chat_request_digest
    assert request.response_schema_digest
    assert request.provider_runtime_digest

    base = request.model_dump(mode="json", by_alias=True)
    for field in (
        "providerRuntimeDigest",
        "instructionProjectionDigest",
        "evidenceProjectionDigest",
        "transportPinDigest",
        "responseSchemaDigest",
        "providerChatRequestDigest",
        "developerMessageDigest",
        "evidenceMessageDigest",
    ):
        raw = dict(base)
        raw["requestId"] = ""
        raw["requestDigest"] = ""
        raw[field] = "f" * 64 if raw[field] != "f" * 64 else "e" * 64
        rebound = SkillBoundWebAnalysisRequestEnvelope.model_validate(raw)
        assert rebound.request_digest != request.request_digest
        assert rebound.request_id != request.request_id

    changed_provider = _plan(
        source=source,
        run=run,
        registration=_registration(model="qwen3-4b-successor"),
        transport=transport,
    )
    assert changed_provider.request.provider_runtime_digest != request.provider_runtime_digest
    assert changed_provider.request.request_digest != request.request_digest
    assert len(loader_calls) == 2


def test_planned_verifier_reloads_all_anchors_and_rejects_foreign_transport_digest(
    prepared_skill_run: tuple[
        VerifiedAuthenticatedDiscoveryRun,
        VerifiedWebAnalysisSkillProjectionRun,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, run = prepared_skill_run
    loader_calls = _patch_strict_skill_loader(
        monkeypatch,
        source=source,
        run=run,
    )
    registration = _registration()
    runtime = _runtime_pin()
    transport = _transport_pin(runtime)
    foreign_transport = web_analysis_transport_runtime_pin(
        runtime,
        worker_image="sha256:" + "5" * 64,
        proxy_image="sha256:" + "6" * 64,
    )
    planned = _plan(
        source=source,
        run=run,
        registration=registration,
        transport=transport,
    )

    verified = verify_planned_skill_bound_web_analysis_call(
        planned,
        registration=registration,
        source=source,
        skill_run=run,
        transport_pin=transport,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        expected_skill_run_id=run.verification.run_id,
        expected_skill_root_digest=run.verification.root_digest,
        expected_registry_ref=run.index.registry,
        expected_policy_digest=run.index.selection_policy_digest,
        expected_transport_pin_digest=transport.pin_digest,
    )
    assert verified == planned
    assert len(loader_calls) == 2

    with pytest.raises(
        SkillBoundWebAnalysisInvocationError,
        match="request planning failed closed",
    ):
        verify_planned_skill_bound_web_analysis_call(
            planned,
            registration=registration,
            source=source,
            skill_run=run,
            transport_pin=transport,
            expected_source_run_id=source.verification.run_id,
            expected_source_root_digest=source.verification.root_digest,
            expected_skill_run_id=run.verification.run_id,
            expected_skill_root_digest=run.verification.root_digest,
            expected_registry_ref=run.index.registry,
            expected_policy_digest=run.index.selection_policy_digest,
            expected_transport_pin_digest=foreign_transport.pin_digest,
        )
    assert len(loader_calls) == 3


def test_successor_and_v1_draft_grammars_mutually_reject_each_other(
    prepared_skill_run: tuple[
        VerifiedAuthenticatedDiscoveryRun,
        VerifiedWebAnalysisSkillProjectionRun,
    ],
) -> None:
    _source, run = prepared_skill_run
    successor_bytes = canonical_json_bytes(
        _successor_draft_payload(run),
        label="successor draft",
    )
    v1_bytes = canonical_json_bytes(
        _draft_payload(run.snapshot.source_snapshot),
        label="v1 draft",
    )

    assert (
        parse_skill_bound_web_analysis_proposal_draft(
            successor_bytes,
            snapshot=run.snapshot,
        ).kind
        == "SkillBoundWebAnalysisProposalDraft"
    )
    with pytest.raises(WebAnalysisProposalError):
        parse_web_analysis_proposal_draft(
            successor_bytes,
            expected_projection=run.snapshot.source_snapshot.model_projection,
        )
    with pytest.raises(SkillBoundWebAnalysisInvocationError):
        parse_skill_bound_web_analysis_proposal_draft(
            v1_bytes,
            snapshot=run.snapshot,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("instructionProjectionDigest", "0" * 64),
        ("evidenceProjectionDigest", "0" * 64),
        ("scopeExpansionAuthorized", True),
        ("toolRequestCompiled", True),
        ("executionAuthorized", True),
        ("futureAuthority", True),
    ),
)
def test_successor_draft_digest_extra_and_authority_drift_fails_closed(
    prepared_skill_run: tuple[
        VerifiedAuthenticatedDiscoveryRun,
        VerifiedWebAnalysisSkillProjectionRun,
    ],
    field: str,
    value: object,
) -> None:
    _source, run = prepared_skill_run
    raw = _successor_draft_payload(run)
    raw[field] = value

    with pytest.raises(SkillBoundWebAnalysisInvocationError):
        parse_skill_bound_web_analysis_proposal_draft(
            canonical_json_bytes(raw, label="mutated successor draft"),
            snapshot=run.snapshot,
        )


def test_request_and_message_role_or_authority_drift_fails_closed(
    prepared_skill_run: tuple[
        VerifiedAuthenticatedDiscoveryRun,
        VerifiedWebAnalysisSkillProjectionRun,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, run = prepared_skill_run
    loader_calls = _patch_strict_skill_loader(
        monkeypatch,
        source=source,
        run=run,
    )
    runtime = _runtime_pin()
    planned = _plan(
        source=source,
        run=run,
        registration=_registration(),
        transport=_transport_pin(runtime),
    )
    raw_request = planned.request.model_dump(mode="json", by_alias=True)

    for field, value in (
        ("role", "web-analysis-proposal"),
        ("splitMessagesRequired", False),
        ("automaticRedispatchAuthorized", True),
        ("targetRequestAuthorized", True),
        ("executionAuthorized", True),
        ("futureAuthority", True),
    ):
        mutated = dict(raw_request)
        mutated[field] = value
        with pytest.raises(ValidationError):
            SkillBoundWebAnalysisRequestEnvelope.model_validate(mutated)

    forged_bundle = run.snapshot.projection_bundle.model_copy(
        update={"instruction_message_role": "user"},
    )
    forged_snapshot = run.snapshot.model_copy(
        update={"projection_bundle": forged_bundle},
    )
    with pytest.raises(SkillBoundWebAnalysisInvocationError):
        build_skill_bound_web_analysis_chat_request(forged_snapshot)
    assert len(loader_calls) == 1


def test_hidden_model_copy_state_fails_closed_at_build_plan_and_verify_boundaries(
    prepared_skill_run: tuple[
        VerifiedAuthenticatedDiscoveryRun,
        VerifiedWebAnalysisSkillProjectionRun,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, run = prepared_skill_run
    loader_calls = _patch_strict_skill_loader(
        monkeypatch,
        source=source,
        run=run,
    )
    registration = _registration()
    transport = _transport_pin(_runtime_pin())

    hidden_snapshot = run.snapshot.model_copy(update={"unmodeled_authority": True})
    with pytest.raises(SkillBoundWebAnalysisInvocationError):
        build_skill_bound_web_analysis_chat_request(hidden_snapshot)

    planned = _plan(
        source=source,
        run=run,
        registration=registration,
        transport=transport,
    )
    hidden_transport = transport.model_copy(update={"unmodeled_authority": True})
    with pytest.raises(SkillBoundWebAnalysisInvocationError):
        _plan(
            source=source,
            run=run,
            registration=registration,
            transport=hidden_transport,
        )

    hidden_request = planned.request.model_copy(update={"unmodeled_authority": True})
    hidden_planned = PlannedSkillBoundWebAnalysisCall(
        chat=planned.chat,
        request=hidden_request,
    )
    with pytest.raises(SkillBoundWebAnalysisInvocationError):
        verify_planned_skill_bound_web_analysis_call(
            hidden_planned,
            registration=registration,
            source=source,
            skill_run=run,
            transport_pin=transport,
            expected_source_run_id=source.verification.run_id,
            expected_source_root_digest=source.verification.root_digest,
            expected_skill_run_id=run.verification.run_id,
            expected_skill_root_digest=run.verification.root_digest,
            expected_registry_ref=run.index.registry,
            expected_policy_digest=run.index.selection_policy_digest,
            expected_transport_pin_digest=transport.pin_digest,
        )
    assert len(loader_calls) == 3


def test_compiler_strictly_reloads_skill_anchors_and_preserves_zero_authority(
    prepared_skill_run: tuple[
        VerifiedAuthenticatedDiscoveryRun,
        VerifiedWebAnalysisSkillProjectionRun,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, run = prepared_skill_run
    runtime = _runtime_pin()
    transport = _transport_pin(runtime)
    draft = _successor_draft(run)
    compile_calls: list[dict[str, object]] = []
    verify_calls: list[dict[str, object]] = []
    loader_calls = _patch_strict_skill_loader(
        monkeypatch,
        source=source,
        run=run,
    )

    def compile_nested(**values: object):
        compile_calls.append(values)
        assert values["expected_run_id"] == source.verification.run_id
        assert values["expected_root_digest"] == source.verification.root_digest
        return compile_nested_proposal(
            source=source,
            snapshot=run.snapshot.source_snapshot,
            draft=draft.proposal,
        )

    def verify_nested(proposal: object, **values: object):
        verify_calls.append({"proposal": proposal, **values})
        assert values["expected_run_id"] == source.verification.run_id
        assert values["expected_root_digest"] == source.verification.root_digest
        return verify_nested_proposal(
            proposal,
            source=source,
            snapshot=run.snapshot.source_snapshot,
            draft=draft.proposal,
        )

    monkeypatch.setattr(invocation_module, "compile_web_analysis_proposal", compile_nested)
    monkeypatch.setattr(invocation_module, "verify_compiled_web_analysis_proposal", verify_nested)

    compiled = compile_skill_bound_web_analysis_proposal(
        source=source,
        skill_run=run,
        draft=draft,
        transport_pin=transport,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        expected_skill_run_id=run.verification.run_id,
        expected_skill_root_digest=run.verification.root_digest,
        expected_registry_ref=run.index.registry,
        expected_policy_digest=run.index.selection_policy_digest,
        expected_transport_pin_digest=transport.pin_digest,
    )

    verified_compiled = verify_compiled_skill_bound_web_analysis_proposal(
        compiled,
        source=source,
        skill_run=run,
        draft=draft,
        transport_pin=transport,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        expected_skill_run_id=run.verification.run_id,
        expected_skill_root_digest=run.verification.root_digest,
        expected_registry_ref=run.index.registry,
        expected_policy_digest=run.index.selection_policy_digest,
        expected_transport_pin_digest=transport.pin_digest,
    )

    assert type(compiled) is CompiledSkillBoundWebAnalysisProposal
    assert verified_compiled == compiled
    assert len(loader_calls) == len(compile_calls) == len(verify_calls) == 2
    assert compiled.skill_projection_run_id == run.verification.run_id
    assert compiled.skill_projection_root_digest == run.verification.root_digest
    assert compiled.skill_bound_snapshot_digest == run.snapshot.snapshot_digest
    assert compiled.registry == run.index.registry
    assert compiled.qualification_digest == run.index.qualification_digest
    assert compiled.selection_policy_digest == run.index.selection_policy_digest
    assert compiled.selection_receipt_digest == run.index.selection_receipt_digest
    assert compiled.projection_bundle_digest == run.index.projection_bundle_digest
    assert compiled.transport_pin_digest == transport.pin_digest
    assert compiled.source_draft_digest == compiled.compiled_proposal.source_draft_digest

    assert compiled.compilation_state == "skill-bound-compiled-proposal-not-authorized"
    for field in (
        "model_output_authoritative",
        "scope_expansion_authorized",
        "tool_request_compiled",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        "graph_admission_authorized",
        "finding_authorized",
        "report_delivery_authorized",
    ):
        assert getattr(compiled, field) is False
    for field in (
        "model_output_authoritative",
        "diagnostic_selection_authoritative",
        "path_assessment_authoritative",
        "scope_expansion_authorized",
        "tool_request_compiled",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        "graph_admission_authorized",
        "finding_authorized",
        "report_delivery_authorized",
    ):
        assert getattr(compiled.compiled_proposal, field) is False

    raw = compiled.model_dump(mode="json", by_alias=True)
    raw["proposalId"] = ""
    raw["proposalDigest"] = ""
    raw["executionAuthorized"] = True
    with pytest.raises(ValidationError):
        CompiledSkillBoundWebAnalysisProposal.model_validate(raw)

    foreign_transport = web_analysis_transport_runtime_pin(
        runtime,
        worker_image="sha256:" + "5" * 64,
        proxy_image="sha256:" + "6" * 64,
    )
    with pytest.raises(
        SkillBoundWebAnalysisInvocationError,
        match="proposal compilation failed closed",
    ):
        verify_compiled_skill_bound_web_analysis_proposal(
            compiled,
            source=source,
            skill_run=run,
            draft=draft,
            transport_pin=transport,
            expected_source_run_id=source.verification.run_id,
            expected_source_root_digest=source.verification.root_digest,
            expected_skill_run_id=run.verification.run_id,
            expected_skill_root_digest=run.verification.root_digest,
            expected_registry_ref=run.index.registry,
            expected_policy_digest=run.index.selection_policy_digest,
            expected_transport_pin_digest=foreign_transport.pin_digest,
        )

    hidden_draft = draft.model_copy(update={"unmodeled_authority": True})
    with pytest.raises(SkillBoundWebAnalysisInvocationError):
        compile_skill_bound_web_analysis_proposal(
            source=source,
            skill_run=run,
            draft=hidden_draft,
            transport_pin=transport,
            expected_source_run_id=source.verification.run_id,
            expected_source_root_digest=source.verification.root_digest,
            expected_skill_run_id=run.verification.run_id,
            expected_skill_root_digest=run.verification.root_digest,
            expected_registry_ref=run.index.registry,
            expected_policy_digest=run.index.selection_policy_digest,
            expected_transport_pin_digest=transport.pin_digest,
        )

    hidden_compiled = compiled.model_copy(update={"unmodeled_authority": True})
    with pytest.raises(SkillBoundWebAnalysisInvocationError):
        verify_compiled_skill_bound_web_analysis_proposal(
            hidden_compiled,
            source=source,
            skill_run=run,
            draft=draft,
            transport_pin=transport,
            expected_source_run_id=source.verification.run_id,
            expected_source_root_digest=source.verification.root_digest,
            expected_skill_run_id=run.verification.run_id,
            expected_skill_root_digest=run.verification.root_digest,
            expected_registry_ref=run.index.registry,
            expected_policy_digest=run.index.selection_policy_digest,
            expected_transport_pin_digest=transport.pin_digest,
        )
    assert len(loader_calls) == len(compile_calls) == len(verify_calls) == 2
