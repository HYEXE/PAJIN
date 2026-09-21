from __future__ import annotations

import ast
import asyncio
import subprocess
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest
from pydantic import ValidationError

import pajin.web_assessment.analysis_skill_live_invocation as invocation_module
from pajin.agentic.durable import AgenticCoordinationStore
from pajin.benchmark.effectiveness.docker import LocalModelRuntime
from pajin.benchmark.effectiveness.suite import PLATFORM_MANIFESTS, RuntimePin, model_pins
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.providers.session import PolicyBoundProviderPort
from pajin.runtime.secrets import SecretBroker
from pajin.runtime.store import RunStore
from pajin.runtime.worker import DockerWorkerBackend
from pajin.skills.catalog import built_in_analysis_skill_registry
from pajin.supervision.invocation_journal import SupervisorInvocationJournal
from pajin.tools.ai import ChatRole
from pajin.web_assessment.analysis_capacity import (
    SubprocessLlamaCppTokenizerBackend,
    _conservative_campaign_prompt_bound,
)
from pajin.web_assessment.analysis_capacity_v2 import (
    _create_web_analysis_capacity_v2_run_with_backend,
    build_web_analysis_capacity_v2_pin,
    load_verified_web_analysis_capacity_v2_run,
)
from pajin.web_assessment.analysis_skill_compact import (
    build_compact_skill_bound_web_analysis_chat_request,
    build_compact_skill_bound_web_analysis_projection,
)
from pajin.web_assessment.analysis_skill_invocation import (
    SkillBoundWebAnalysisRequestEnvelope,
)
from pajin.web_assessment.analysis_skill_live_invocation import (
    PREPARED_COMPACT_ADMISSION_STATUS,
    PlannedPreparedCompactSkillBoundWebAnalysisAdmission,
    PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope,
    PreparedCompactSkillBoundWebAnalysisAdmissionError,
    plan_prepared_compact_skill_bound_web_analysis_admission,
    verify_planned_prepared_compact_skill_bound_web_analysis_admission,
)
from pajin.web_assessment.analysis_skill_live_preparation import (
    create_compact_skill_bound_web_analysis_preparation_run,
)
from pajin.web_assessment.analysis_skill_projection import (
    create_web_analysis_skill_projection_run,
)
from pajin.web_assessment.analysis_skill_runtime import (
    SkillBoundWebAnalysisInvocationRuntime,
)
from pajin.web_assessment.discovery_artifact import (
    load_verified_authenticated_discovery,
)
from tests.test_web_analysis_capacity_v2 import _FakeV2Tokenizer
from tests.test_web_discovery_artifact import _run_fake

_FALSE_FIELD_ALIASES = (
    "toolsAllowed",
    "streamingAllowed",
    "authorizationPresented",
    "authorizationConsumed",
    "preparationClaimed",
    "liveModelMaterializationAttested",
    "modelInvocationAuthorized",
    "providerDispatchAuthorized",
    "targetRequestAuthorized",
    "executionAuthorized",
    "automaticRedispatchAuthorized",
)

_INDEPENDENT_ANCHORS = (
    "expected_source_run_id",
    "expected_source_root_digest",
    "expected_skill_run_id",
    "expected_skill_root_digest",
    "expected_registry_ref",
    "expected_policy_digest",
    "expected_capacity_run_id",
    "expected_capacity_root_digest",
    "expected_capacity_pin_digest",
    "expected_capacity_proof_digest",
    "expected_capacity_model_materialization_attestation_digest",
    "expected_transport_pin_digest",
    "expected_preparation_run_id",
    "expected_preparation_root_digest",
    "expected_preparation_digest",
    "expected_preparation_index_digest",
    "expected_live_request_digest",
)

_RUN_ARTIFACTS = {
    "source": "index.json",
    "skill": "skill-bound-snapshot.json",
    "capacity": "capacity-proof.json",
    "preparation": "compact-live-preparation.json",
}


def _prepared(tmp_path: Path):
    with patch(
        "tests.test_web_discovery_artifact._ORIGIN",
        "http://127.0.0.1:3000",
    ):
        source_artifacts = asyncio.run(_run_fake(tmp_path / "source"))
    source = load_verified_authenticated_discovery(
        source_artifacts.run_path,
        expected_run_id=source_artifacts.index.run_id,
        expected_root_digest=source_artifacts.root_digest,
    )
    skill_run = create_web_analysis_skill_projection_run(
        source=source,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        output_root=tmp_path / "skill",
    )
    projection = build_compact_skill_bound_web_analysis_projection(skill_run.snapshot)
    request = build_compact_skill_bound_web_analysis_chat_request(skill_run.snapshot)
    runtime = RuntimePin(
        platform="linux/arm64",
        platform_manifest=PLATFORM_MANIFESTS["linux/arm64"],
        worker_image="sha256:" + "1" * 64,
        proxy_image="sha256:" + "2" * 64,
    )
    model_pin = model_pins()[0]
    pin = build_web_analysis_capacity_v2_pin(
        skill_run,
        projection,
        request,
        runtime=runtime,
        model_pin=model_pin,
        transport_pin_digest="3" * 64,
        conservative_campaign_prompt_tokens=_conservative_campaign_prompt_bound(
            request,
            model_id=model_pin.name,
        ),
    )
    capacity = _create_web_analysis_capacity_v2_run_with_backend(
        tmp_path / "capacity-v2",
        skill_run=skill_run,
        projection=projection,
        chat_request=request,
        pin=pin,
        tokenizer_backend=_FakeV2Tokenizer(),
    )
    preparation = create_compact_skill_bound_web_analysis_preparation_run(
        tmp_path / "preparation",
        skill_run=skill_run,
        capacity_run=capacity,
        **_capacity_anchors(skill_run, capacity),
    )
    return source, skill_run, capacity, preparation


def _capacity_anchors(skill_run: Any, capacity: Any) -> dict[str, str]:
    return {
        "expected_skill_run_id": skill_run.verification.run_id,
        "expected_skill_root_digest": skill_run.verification.root_digest,
        "expected_capacity_run_id": capacity.run_id,
        "expected_capacity_root_digest": capacity.root_digest,
        "expected_capacity_pin_digest": capacity.pin.pin_digest,
        "expected_capacity_proof_digest": capacity.proof.proof_digest,
        "expected_capacity_model_materialization_attestation_digest": (
            capacity.model_materialization_attestation_digest
        ),
        "expected_transport_pin_digest": capacity.pin.transport_pin_digest,
    }


def _admission_anchors(
    source: Any,
    skill_run: Any,
    capacity: Any,
    preparation: Any,
) -> dict[str, object]:
    return {
        "expected_source_run_id": source.verification.run_id,
        "expected_source_root_digest": source.verification.root_digest,
        **_capacity_anchors(skill_run, capacity),
        "expected_registry_ref": skill_run.index.registry,
        "expected_policy_digest": skill_run.index.selection_policy_digest,
        "expected_preparation_run_id": preparation.run_id,
        "expected_preparation_root_digest": preparation.root_digest,
        "expected_preparation_digest": preparation.preparation.preparation_digest,
        "expected_preparation_index_digest": preparation.index.index_digest,
        "expected_live_request_digest": preparation.live_request.request_digest,
    }


def _plan(
    source: Any,
    skill_run: Any,
    capacity: Any,
    preparation: Any,
    **overrides: object,
):
    anchors = _admission_anchors(source, skill_run, capacity, preparation)
    anchors.update(overrides)
    return plan_prepared_compact_skill_bound_web_analysis_admission(
        source=source,
        skill_run=skill_run,
        capacity_run=capacity,
        preparation_run=preparation,
        **anchors,
    )


def _verify(
    planned: Any,
    source: Any,
    skill_run: Any,
    capacity: Any,
    preparation: Any,
):
    return verify_planned_prepared_compact_skill_bound_web_analysis_admission(
        planned,
        source=source,
        skill_run=skill_run,
        capacity_run=capacity,
        preparation_run=preparation,
        **_admission_anchors(source, skill_run, capacity, preparation),
    )


def _other_digest(value: str) -> str:
    replacement = "0" * 64
    return replacement if value != replacement else "1" * 64


def _other_run_id(value: str) -> str:
    replacement = "run_20990101T000000Z_deadbeef"
    return replacement if value != replacement else "run_20990101T000001Z_deadbeef"


def _tree_snapshot(root: Path) -> tuple[tuple[str, ...], dict[str, bytes]]:
    directories = tuple(
        sorted(str(path.relative_to(root)) for path in root.rglob("*") if path.is_dir())
    )
    files = {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }
    return directories, files


class _AlwaysEqualDuck:
    def __init__(self, wrapped: object) -> None:
        self._wrapped = wrapped

    def __getattr__(self, name: str) -> object:
        return getattr(self._wrapped, name)

    def __eq__(self, _other: object) -> bool:
        return True


def _patch_no_authority_spies(monkeypatch: pytest.MonkeyPatch) -> dict[str, Mock]:
    targets: dict[str, tuple[object, str]] = {
        "run-create": (RunStore, "create"),
        "tokenizer-start": (SubprocessLlamaCppTokenizerBackend, "start"),
        "provider-chat": (PolicyBoundProviderPort, "chat_bound"),
        "secret-materialize": (SecretBroker, "materialize"),
        "skill-runtime": (SkillBoundWebAnalysisInvocationRuntime, "invoke"),
        "worker-runtime": (DockerWorkerBackend, "__init__"),
        "local-model": (LocalModelRuntime, "start"),
        "journal-create": (SupervisorInvocationJournal, "__init__"),
        "journal-claim": (SupervisorInvocationJournal, "claim"),
        "journal-dispatch": (SupervisorInvocationJournal, "begin_dispatch"),
        "cas-create": (AgenticCoordinationStore, "__init__"),
        "cas-claim": (AgenticCoordinationStore, "claim_hypothesis_invocation"),
        "cas-initialize": (AgenticCoordinationStore, "initialize_head"),
        "cas-publish": (AgenticCoordinationStore, "publish_cycle"),
        "subprocess": (subprocess, "run"),
    }
    spies: dict[str, Mock] = {}
    for label, (owner, attribute) in targets.items():
        spy = Mock(side_effect=AssertionError(f"inert admission crossed {label}"))
        monkeypatch.setattr(owner, attribute, spy)
        spies[label] = spy
    return spies


def _assert_no_authority_calls(spies: dict[str, Mock]) -> None:
    for spy in spies.values():
        spy.assert_not_called()


def _canonical_domain_digest(prefix: bytes, domain: str, value: object) -> str:
    encoded_domain = domain.encode("ascii", errors="strict")
    payload = canonical_json_bytes(
        value,
        label="independent prepared-admission test oracle",
        max_bytes=4 * 1024 * 1024,
    )
    return sha256(
        prefix
        + len(encoded_domain).to_bytes(4, "big")
        + encoded_domain
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


def _fault_run_artifact(
    *,
    run_path: Path,
    artifact_name: str,
    fault: str,
    outside_root: Path,
) -> None:
    artifact = run_path / artifact_name
    if fault == "unseal":
        run_path.joinpath("run-integrity.jsonl").unlink()
    elif fault == "extra-artifact":
        run_path.joinpath("unexpected-artifact.json").write_text("{}\n", encoding="utf-8")
    elif fault == "delete":
        artifact.unlink()
    elif fault == "rename":
        artifact.rename(run_path / f"{artifact_name}.renamed")
    elif fault == "symlink":
        substitute = outside_root / f"substituted-{run_path.name}-{artifact_name}"
        artifact.rename(substitute)
        artifact.symlink_to(substitute)
    else:
        artifact.write_bytes(artifact.read_bytes() + b" ")


def test_prepared_admission_exactly_plans_and_verifies_without_dispatch_or_run_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, skill_run, capacity, preparation = _prepared(tmp_path)
    spies = _patch_no_authority_spies(monkeypatch)
    before = _tree_snapshot(tmp_path)

    first = _plan(source, skill_run, capacity, preparation)
    second = _plan(source, skill_run, capacity, preparation)
    verified = _verify(first, source, skill_run, capacity, preparation)

    assert first == second == verified
    assert isinstance(first, PlannedPreparedCompactSkillBoundWebAnalysisAdmission)
    assert first.registration == preparation.live_request.provider_registration
    assert first.chat == preparation.live_request.chat_request
    assert first.admission.status == PREPARED_COMPACT_ADMISSION_STATUS
    assert first.admission.attempt == 1
    assert first.admission.message_roles == ("system", "user")
    assert [message.role for message in first.chat.messages] == [
        ChatRole.SYSTEM,
        ChatRole.USER,
    ]
    assert first.chat.tools == []
    assert first.chat.tool_choice == "none"
    assert first.chat.stream is False
    assert first.chat.parallel_tool_calls is False
    assert all(
        getattr(first.admission, alias) is False
        for alias in (
            "tools_allowed",
            "streaming_allowed",
            "authorization_presented",
            "authorization_consumed",
            "preparation_claimed",
            "live_model_materialization_attested",
            "model_invocation_authorized",
            "provider_dispatch_authorized",
            "target_request_authorized",
            "execution_authorized",
            "automatic_redispatch_authorized",
        )
    )
    assert _tree_snapshot(tmp_path) == before
    _assert_no_authority_calls(spies)


def test_prepared_admission_binds_exact_messages_request_and_all_lineage(
    tmp_path: Path,
) -> None:
    source, skill_run, capacity, preparation = _prepared(tmp_path)
    planned = _plan(source, skill_run, capacity, preparation)
    admission = planned.admission
    projection = build_compact_skill_bound_web_analysis_projection(skill_run.snapshot)
    expected_chat = build_compact_skill_bound_web_analysis_chat_request(skill_run.snapshot)
    strict_capacity = load_verified_web_analysis_capacity_v2_run(
        capacity.run_path,
        skill_run=skill_run,
        expected_run_id=capacity.run_id,
        expected_root_digest=capacity.root_digest,
        expected_pin_digest=capacity.pin.pin_digest,
        expected_transport_pin_digest=capacity.pin.transport_pin_digest,
        expected_proof_digest=capacity.proof.proof_digest,
        expected_model_materialization_attestation_digest=(
            capacity.model_materialization_attestation_digest
        ),
    )

    assert planned.registration == preparation.live_request.provider_registration
    assert planned.chat == expected_chat == preparation.live_request.chat_request
    assert planned.chat.messages[0].content == expected_chat.messages[0].content
    assert planned.chat.messages[1].content == expected_chat.messages[1].content
    assert admission.system_message_digest == projection.system_message_digest
    assert admission.user_message_digest == projection.user_message_digest
    assert admission.compact_projection_digest == projection.projection_digest
    assert admission.provider_registration_digest == (
        preparation.live_request.provider_registration_digest
    )
    assert admission.provider_chat_request_digest == (preparation.live_request.chat_request_digest)
    assert admission.preparation_run_id == preparation.run_id
    assert admission.preparation_run_root_digest == preparation.root_digest
    assert admission.preparation_digest == preparation.preparation.preparation_digest
    assert admission.preparation_index_digest == preparation.index.index_digest
    assert admission.live_request_digest == preparation.live_request.request_digest
    assert admission.source_run_id == source.verification.run_id
    assert admission.source_run_root_digest == source.verification.root_digest
    assert admission.skill_run_id == skill_run.verification.run_id
    assert admission.skill_run_root_digest == skill_run.verification.root_digest
    assert admission.skill_snapshot_digest == skill_run.snapshot.snapshot_digest
    assert admission.registry == skill_run.index.registry
    assert admission.selection_policy_digest == skill_run.index.selection_policy_digest
    assert admission.capacity_run_id == capacity.run_id
    assert admission.capacity_run_root_digest == capacity.root_digest
    assert admission.capacity_pin_digest == capacity.pin.pin_digest
    assert admission.capacity_proof_digest == capacity.proof.proof_digest
    assert admission.model_materialization_attestation_digest == (
        capacity.model_materialization_attestation_digest
    )
    assert admission.transport_pin_digest == capacity.pin.transport_pin_digest
    assert admission.context_tokens == strict_capacity.proof.context_tokens
    assert admission.prompt_tokens == strict_capacity.proof.prompt_tokens
    assert admission.completion_tokens == strict_capacity.proof.completion_tokens
    assert admission.total_tokens == strict_capacity.proof.total_tokens
    assert admission.remaining_tokens == strict_capacity.proof.remaining_tokens
    assert len(admission.response_schema_digest) == 64
    assert (
        PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope.model_validate(
            admission.model_dump(mode="json", by_alias=True)
        )
        == admission
    )


def test_prepared_admission_uses_independent_digest_domains_for_exact_canonical_chat(
    tmp_path: Path,
) -> None:
    source, skill_run, capacity, preparation = _prepared(tmp_path)
    planned = _plan(source, skill_run, capacity, preparation)
    chat_wire = planned.chat.model_dump(mode="json", by_alias=True)
    capacity_digest = _canonical_domain_digest(
        b"PAJIN-WEB-ANALYSIS-CAPACITY\0",
        "chat-request",
        chat_wire,
    )
    preparation_digest = _canonical_domain_digest(
        b"PAJIN-COMPACT-LIVE-PREPARATION\0",
        "provider-chat-request/v1",
        chat_wire,
    )
    response_format = planned.chat.response_format
    assert response_format is not None
    schema = response_format.json_schema.model_dump(mode="json", by_alias=True)["schema"]
    response_schema_digest = _canonical_domain_digest(
        b"PAJIN-PREPARED-COMPACT-WEB-ANALYSIS-ADMISSION\0",
        "response-schema/v1",
        schema,
    )

    assert capacity_digest == capacity.pin.chat_request_digest
    assert preparation_digest == preparation.live_request.chat_request_digest
    assert capacity_digest != preparation_digest
    assert response_schema_digest == planned.admission.response_schema_digest


@pytest.mark.parametrize("anchor_name", _INDEPENDENT_ANCHORS)
def test_prepared_admission_rejects_each_independent_anchor_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    anchor_name: str,
) -> None:
    source, skill_run, capacity, preparation = _prepared(tmp_path)
    _patch_no_authority_spies(monkeypatch)
    anchors = _admission_anchors(source, skill_run, capacity, preparation)
    current = anchors[anchor_name]
    if anchor_name == "expected_registry_ref":
        anchors[anchor_name] = built_in_analysis_skill_registry().reference()
    elif anchor_name.endswith("run_id"):
        anchors[anchor_name] = _other_run_id(str(current))
    else:
        anchors[anchor_name] = _other_digest(str(current))

    with pytest.raises(PreparedCompactSkillBoundWebAnalysisAdmissionError):
        plan_prepared_compact_skill_bound_web_analysis_admission(
            source=source,
            skill_run=skill_run,
            capacity_run=capacity,
            preparation_run=preparation,
            **anchors,
        )


@pytest.mark.parametrize("run_name", tuple(_RUN_ARTIFACTS))
@pytest.mark.parametrize(
    "fault",
    ("unseal", "extra-artifact", "delete", "rename", "symlink", "tamper"),
)
def test_prepared_admission_rejects_each_on_disk_run_fault_without_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    run_name: str,
    fault: str,
) -> None:
    source, skill_run, capacity, preparation = _prepared(tmp_path)
    runs = {
        "source": source.run_path,
        "skill": skill_run.run_path,
        "capacity": capacity.run_path,
        "preparation": preparation.run_path,
    }
    _fault_run_artifact(
        run_path=runs[run_name],
        artifact_name=_RUN_ARTIFACTS[run_name],
        fault=fault,
        outside_root=tmp_path,
    )
    spies = _patch_no_authority_spies(monkeypatch)

    with pytest.raises(PreparedCompactSkillBoundWebAnalysisAdmissionError):
        _plan(source, skill_run, capacity, preparation)

    _assert_no_authority_calls(spies)


@pytest.mark.parametrize("input_name", ("source", "skill", "capacity", "preparation"))
def test_prepared_admission_rejects_always_equal_non_concrete_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    input_name: str,
) -> None:
    source, skill_run, capacity, preparation = _prepared(tmp_path)
    inputs: dict[str, object] = {
        "source": source,
        "skill_run": skill_run,
        "capacity_run": capacity,
        "preparation_run": preparation,
        **_admission_anchors(source, skill_run, capacity, preparation),
    }
    parameter = {
        "source": "source",
        "skill": "skill_run",
        "capacity": "capacity_run",
        "preparation": "preparation_run",
    }[input_name]
    inputs[parameter] = _AlwaysEqualDuck(inputs[parameter])
    spies = _patch_no_authority_spies(monkeypatch)

    with pytest.raises(PreparedCompactSkillBoundWebAnalysisAdmissionError):
        plan_prepared_compact_skill_bound_web_analysis_admission(**inputs)  # type: ignore[arg-type]

    _assert_no_authority_calls(spies)


@pytest.mark.parametrize(
    "drift",
    ("run-id", "root", "live-request", "preparation", "index"),
)
def test_prepared_admission_rejects_supplied_preparation_object_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    source, skill_run, capacity, preparation = _prepared(tmp_path)
    anchors = _admission_anchors(source, skill_run, capacity, preparation)
    if drift == "run-id":
        supplied = replace(preparation, run_id=_other_run_id(preparation.run_id))
    elif drift == "root":
        supplied = replace(preparation, root_digest=_other_digest(preparation.root_digest))
    elif drift == "live-request":
        supplied = replace(
            preparation,
            live_request=preparation.live_request.model_copy(
                update={"request_digest": _other_digest(preparation.live_request.request_digest)}
            ),
        )
    elif drift == "preparation":
        supplied = replace(
            preparation,
            preparation=preparation.preparation.model_copy(
                update={
                    "preparation_digest": _other_digest(preparation.preparation.preparation_digest)
                }
            ),
        )
    else:
        supplied = replace(
            preparation,
            index=preparation.index.model_copy(
                update={"index_digest": _other_digest(preparation.index.index_digest)}
            ),
        )
    _patch_no_authority_spies(monkeypatch)

    with pytest.raises(PreparedCompactSkillBoundWebAnalysisAdmissionError):
        plan_prepared_compact_skill_bound_web_analysis_admission(
            source=source,
            skill_run=skill_run,
            capacity_run=capacity,
            preparation_run=supplied,
            **anchors,
        )


@pytest.mark.parametrize("part", ("registration", "chat", "admission"))
def test_prepared_admission_verifier_rejects_substituted_plan_parts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    part: str,
) -> None:
    source, skill_run, capacity, preparation = _prepared(tmp_path)
    planned = _plan(source, skill_run, capacity, preparation)
    if part == "registration":
        forged = replace(
            planned,
            registration=planned.registration.model_copy(update={"model": "substituted-model"}),
        )
    elif part == "chat":
        messages = list(planned.chat.messages)
        messages[0] = messages[0].model_copy(update={"content": "substituted-system"})
        forged = replace(planned, chat=planned.chat.model_copy(update={"messages": messages}))
    else:
        forged = replace(
            planned,
            admission=planned.admission.model_copy(
                update={
                    "provider_chat_request_digest": _other_digest(
                        planned.admission.provider_chat_request_digest
                    )
                }
            ),
        )
    _patch_no_authority_spies(monkeypatch)

    with pytest.raises(PreparedCompactSkillBoundWebAnalysisAdmissionError):
        _verify(forged, source, skill_run, capacity, preparation)


def test_prepared_admission_requires_each_false_field_and_rejects_coercion(
    tmp_path: Path,
) -> None:
    source, skill_run, capacity, preparation = _prepared(tmp_path)
    payload = _plan(source, skill_run, capacity, preparation).admission.model_dump(
        mode="json",
        by_alias=True,
    )

    for alias in _FALSE_FIELD_ALIASES:
        missing = dict(payload)
        del missing[alias]
        with pytest.raises(ValidationError):
            PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope.model_validate(missing)

        for coerced in (0, "false", None):
            changed = dict(payload)
            changed[alias] = coerced
            with pytest.raises(ValidationError):
                PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope.model_validate(changed)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("attempt", True),
        ("messageRoles", ["user", "system"]),
        ("messageRoles", ["system", "user", "user"]),
    ),
)
def test_prepared_admission_rejects_attempt_or_message_role_drift(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    source, skill_run, capacity, preparation = _prepared(tmp_path)
    payload = _plan(source, skill_run, capacity, preparation).admission.model_dump(
        mode="json",
        by_alias=True,
    )
    payload[field] = value

    with pytest.raises(ValidationError):
        PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope.model_validate(payload)


def test_prepared_admission_and_legacy_request_envelopes_are_mutually_incompatible(
    tmp_path: Path,
) -> None:
    source, skill_run, capacity, preparation = _prepared(tmp_path)
    admission = _plan(source, skill_run, capacity, preparation).admission
    snapshot = skill_run.snapshot
    bundle = snapshot.projection_bundle
    legacy = SkillBoundWebAnalysisRequestEnvelope.model_validate(
        {
            "apiVersion": "pajin.dev/skill-bound-web-analysis-request/v1alpha1",
            "kind": "SkillBoundWebAnalysisRequestEnvelope",
            "requestId": "",
            "requestDigest": "",
            "providerRuntimeDigest": "1" * 64,
            "skillProjectionRunId": skill_run.verification.run_id,
            "skillProjectionRootDigest": skill_run.verification.root_digest,
            "skillBoundSnapshotDigest": snapshot.snapshot_digest,
            "projectionBundleDigest": bundle.bundle_digest,
            "instructionProjectionDigest": bundle.instruction_projection.projection_digest,
            "evidenceProjectionDigest": bundle.evidence_projection.projection_digest,
            "transportPinDigest": capacity.pin.transport_pin_digest,
            "responseSchemaDigest": admission.response_schema_digest,
            "providerChatRequestDigest": admission.provider_chat_request_digest,
            "developerMessageDigest": "2" * 64,
            "evidenceMessageDigest": "3" * 64,
            "role": "skill-bound-web-analysis-proposal",
            "attempt": 1,
            "maxCompletionTokens": 1024,
            "splitMessagesRequired": True,
            "automaticRedispatchAuthorized": False,
            "targetRequestAuthorized": False,
            "executionAuthorized": False,
        }
    )

    with pytest.raises(ValidationError):
        SkillBoundWebAnalysisRequestEnvelope.model_validate(
            admission.model_dump(mode="json", by_alias=True)
        )
    with pytest.raises(ValidationError):
        PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope.model_validate(
            legacy.model_dump(mode="json", by_alias=True)
        )


def test_prepared_admission_module_imports_no_dispatch_or_network_runtime() -> None:
    source_path = Path(invocation_module.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_modules.update(
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )
    forbidden = {
        "httpx",
        "requests",
        "socket",
        "subprocess",
        "urllib.request",
        "pajin.benchmark.effectiveness.docker",
        "pajin.agentic.durable",
        "pajin.providers.session",
        "pajin.runtime.secrets",
        "pajin.runtime.worker",
        "pajin.supervision.invocation_journal",
        "pajin.tools.gateway",
        "pajin.web_assessment.analysis_runtime",
        "pajin.web_assessment.analysis_skill_runtime",
    }

    assert not {
        module
        for module in imported_modules
        if any(module == item or module.startswith(item + ".") for item in forbidden)
    }


def test_prepared_admission_public_surface_is_exact() -> None:
    assert invocation_module.__all__ == [
        "PREPARED_COMPACT_ADMISSION_STATUS",
        "PlannedPreparedCompactSkillBoundWebAnalysisAdmission",
        "PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope",
        "PreparedCompactSkillBoundWebAnalysisAdmissionError",
        "plan_prepared_compact_skill_bound_web_analysis_admission",
        "verify_planned_prepared_compact_skill_bound_web_analysis_admission",
    ]
