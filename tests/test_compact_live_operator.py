from __future__ import annotations

import ast
import asyncio
import inspect
import json
import os
import stat
import tomllib
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import ConfigDict

from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import StrictModel
from pajin.skills.models import SkillRegistryRef
from pajin.web_assessment import compact_live_operator as operator
from pajin.web_assessment.analysis_live_claim_journal import (
    WebAnalysisLiveClaimJournal,
    WebAnalysisLiveClaimTerminalDisposition,
)
from pajin.web_assessment.analysis_proposal import CompiledWebAnalysisProposal
from pajin.web_assessment.analysis_skill_compact_live_runtime import (
    CompactSkillBoundWebAnalysisLiveCompletion,
)
from pajin.web_assessment.analysis_skill_invocation import (
    CompiledSkillBoundWebAnalysisProposal,
)

_DIGEST = "a" * 64
_STORE_ID = "b" * 64


class _OutputModel(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    value: str


def _manifest(root: Path) -> operator.CompactLiveOperatorManifest:
    root = root.resolve()
    return operator.CompactLiveOperatorManifest(
        sourceRunPath=root / "source",
        sourceRunId="run_20260923T000000Z_00000001",
        sourceRunRootDigest="1" * 64,
        skillRunPath=root / "skill",
        skillRunId="run_20260923T000001Z_00000002",
        skillRunRootDigest="2" * 64,
        registry=SkillRegistryRef(
            registryId="pajin.analysis-skills",
            registryVersion="1.0.0",
            registryDigest="3" * 64,
        ),
        selectionPolicyDigest="4" * 64,
        capacityRunPath=root / "capacity",
        capacityRunId="run_20260923T000002Z_00000003",
        capacityRunRootDigest="5" * 64,
        capacityPinDigest="6" * 64,
        capacityProofDigest="7" * 64,
        capacityModelMaterializationAttestationDigest="8" * 64,
        lineageTransportPinPath=root / "lineage-transport.json",
        lineageTransportPinDigest="9" * 64,
        preparationRunPath=root / "preparation",
        preparationRunId="run_20260923T000003Z_00000004",
        preparationRunRootDigest="a" * 64,
        preparationDigest="b" * 64,
        preparationIndexDigest="c" * 64,
        liveRequestDigest="d" * 64,
        admissionPath=root / "admission.json",
        admissionId="prepared-compact-web-analysis:exact",
        admissionDigest="e" * 64,
        compactRuntimePinPath=root / "compact-runtime.json",
        compactRuntimePinDigest="f" * 64,
        compactTransportPinPath=root / "compact-transport.json",
        compactTransportPinDigest="0" * 64,
        modelPath=root / "model.gguf",
    )


def _owner_file(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    if os.name == "posix":
        path.chmod(0o600)


def _owner_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        path.chmod(0o700)


def _compiled_proposal() -> CompiledSkillBoundWebAnalysisProposal:
    nested = CompiledWebAnalysisProposal.model_construct(
        api_version="pajin.dev/compiled-web-analysis-proposal/v1alpha1",
        kind="CompiledWebAnalysisProposal",
        proposal_id="web-analysis-proposal:test",
        proposal_digest="1" * 64,
        model_output_authoritative=False,
        diagnostic_selection_authoritative=False,
        path_assessment_authoritative=False,
        scope_expansion_authorized=False,
        tool_request_compiled=False,
        capability_granted=False,
        permit_granted=False,
        execution_authorized=False,
        graph_admission_authorized=False,
        finding_authorized=False,
        report_delivery_authorized=False,
    )
    return CompiledSkillBoundWebAnalysisProposal.model_construct(
        api_version="pajin.dev/compiled-skill-bound-web-analysis-proposal/v1alpha1",
        kind="CompiledSkillBoundWebAnalysisProposal",
        proposal_id="skill-bound-web-analysis-proposal:test",
        proposal_digest="2" * 64,
        compiled_proposal=nested,
        model_output_authoritative=False,
        scope_expansion_authorized=False,
        tool_request_compiled=False,
        capability_granted=False,
        permit_granted=False,
        execution_authorized=False,
        graph_admission_authorized=False,
        finding_authorized=False,
        report_delivery_authorized=False,
    )


def _successful_completion(
    proposal: CompiledSkillBoundWebAnalysisProposal | None = None,
) -> CompactSkillBoundWebAnalysisLiveCompletion:
    exact_proposal = proposal or _compiled_proposal()
    completion_authorities = {
        "target_request_authority": False,
        "tool_request_authority": False,
        "finding_authority": False,
        "graph_admission_authority": False,
        "report_authority": False,
        "retry_authority": False,
        "automatic_redispatch_authority": False,
    }
    receipt = SimpleNamespace(
        compiled_proposal=exact_proposal,
        pending_claim=SimpleNamespace(dispatch_count=1),
        target_request_authority=False,
        tool_request_authority=False,
        capability_authority=False,
        permit_authority=False,
        finding_authority=False,
        graph_admission_authority=False,
        report_authority=False,
        delivery_authority=False,
        retry_authority=False,
        automatic_redispatch_authority=False,
    )
    terminal_run = SimpleNamespace(
        proposal=exact_proposal,
        receipt=receipt,
        terminal_claim=SimpleNamespace(
            dispatch_count=1,
            terminal_disposition=WebAnalysisLiveClaimTerminalDisposition.SUCCESS,
        ),
        **completion_authorities,
    )
    return CompactSkillBoundWebAnalysisLiveCompletion(
        terminal_run=cast(Any, terminal_run),
        proposal=exact_proposal,
    )


def test_manifest_loader_requires_explicit_strict_anchors(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    manifest = _manifest(root)
    manifest_path = root / "operator-manifest.json"
    manifest_path.write_bytes(
        canonical_json_bytes(
            manifest.model_dump(mode="json", by_alias=True),
            label="test compact live operator manifest",
        )
        + b"\n"
    )

    loaded = operator.load_compact_live_operator_manifest(manifest_path)

    assert loaded == manifest
    assert loaded.admission_digest == "e" * 64
    assert loaded.lineage_transport_pin_digest == "9" * 64
    assert loaded.compact_runtime_pin_digest == "f" * 64
    assert loaded.compact_transport_pin_digest == "0" * 64

    payload = manifest.model_dump(mode="json", by_alias=True)
    payload["unexpected"] = True
    manifest_path.write_bytes(
        canonical_json_bytes(payload, label="invalid compact live manifest") + b"\n"
    )
    with pytest.raises(operator.CompactLiveOperatorError):
        operator.load_compact_live_operator_manifest(manifest_path)


def test_manifest_loader_rejects_noncanonical_or_default_omitting_wire(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    manifest = _manifest(root)
    manifest_path = root / "operator-manifest.json"
    payload = manifest.model_dump(mode="json", by_alias=True)
    exact = canonical_json_bytes(payload, label="test compact live operator manifest")
    missing_default = dict(payload)
    del missing_default["apiVersion"]

    invalid_wires = (
        exact,
        exact + b"\n\n",
        json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n",
        canonical_json_bytes(
            missing_default,
            label="default-omitting compact live operator manifest",
        )
        + b"\n",
    )
    for wire in invalid_wires:
        manifest_path.write_bytes(wire)
        with pytest.raises(operator.CompactLiveOperatorError):
            operator.load_compact_live_operator_manifest(manifest_path)


@pytest.mark.parametrize(
    "entrypoint",
    (
        operator.preflight,
        operator.execute,
        operator.preflight_compact_live,
        operator.execute_compact_live,
    ),
)
def test_live_entrypoints_do_not_accept_caller_supplied_clock(
    entrypoint: Callable[..., object],
) -> None:
    parameters = inspect.signature(entrypoint).parameters

    assert "clock" not in parameters


def test_provision_state_is_owner_only_and_cannot_recreate_store(tmp_path: Path) -> None:
    state_root = tmp_path.resolve() / "state"

    provisioned = operator.provision_state(state_root)

    assert provisioned.state_root == state_root
    assert provisioned.claim_journal_path == state_root / "live-claims.sqlite3"
    assert provisioned.terminal_output_root == state_root / "terminal-output"
    assert len(provisioned.claim_store_id) == 64
    reopened = WebAnalysisLiveClaimJournal(
        provisioned.claim_journal_path,
        expected_store_id=provisioned.claim_store_id,
        allow_create=False,
    )
    assert reopened.store_id == provisioned.claim_store_id
    if os.name == "posix":
        assert stat.S_IMODE(state_root.stat().st_mode) == 0o700
        assert stat.S_IMODE(provisioned.terminal_output_root.stat().st_mode) == 0o700
        assert stat.S_IMODE(provisioned.claim_journal_path.stat().st_mode) == 0o600

    with pytest.raises(operator.CompactLiveOperatorError):
        operator.provision_state(state_root)


def test_prepare_request_writes_one_lf_mode_0600_without_live_side_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path.resolve()
    if os.name == "posix":
        root.chmod(0o700)
    manifest = _manifest(root)
    request = _OutputModel(value="exact-v2-request")
    immutable = SimpleNamespace(
        planned=SimpleNamespace(admission=object()),
        preparation_run=SimpleNamespace(live_request=object()),
        capacity_run=SimpleNamespace(pin=object()),
        lineage_transport_pin=object(),
        compact_runtime_pin=object(),
        compact_transport_pin=object(),
    )
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(operator, "_strict_load_immutable_inputs", lambda value: immutable)

    def build_request(**kwargs: object) -> object:
        calls.append(kwargs)
        return request

    monkeypatch.setattr(
        operator,
        "build_web_analysis_one_call_authorization_request_v2",
        build_request,
    )

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError(f"unexpected live side effect: {args!r} {kwargs!r}")

    monkeypatch.setattr(operator, "WebAnalysisLiveClaimJournal", forbidden)
    monkeypatch.setattr(operator, "SecretBroker", forbidden)
    monkeypatch.setattr(operator, "SubprocessLlamaCppLiveMaterialization", forbidden)
    output = root / "authorization-request.json"

    observed = operator.prepare_authorization_request(manifest, output)

    assert cast(object, observed) is request
    assert len(calls) == 1
    assert output.read_bytes() == b'{"value":"exact-v2-request"}\n'
    if os.name == "posix":
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
    with pytest.raises(operator.CompactLiveOperatorError):
        operator.prepare_authorization_request(manifest, output)


def test_preflight_verifies_owner_only_public_artifacts_without_live_side_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path.resolve()
    if os.name == "posix":
        root.chmod(0o700)
    manifest = _manifest(root)
    source = object()
    skill_run = object()
    capacity_pin = object()
    capacity_run = SimpleNamespace(pin=capacity_pin)
    live_request = object()
    preparation_run = SimpleNamespace(live_request=live_request)
    planned_admission = SimpleNamespace(
        admission_id=manifest.admission_id,
        admission_digest=manifest.admission_digest,
    )
    planned = SimpleNamespace(admission=planned_admission)
    lineage_transport_pin = object()
    compact_runtime_pin = SimpleNamespace(pin_digest="2" * 64)
    compact_transport_pin = SimpleNamespace(pin_digest="3" * 64)
    loader_calls: list[str] = []
    trust_anchor = SimpleNamespace(
        digest=_DIGEST,
        model_dump=lambda **kwargs: {"kind": "anchor"},
    )
    signed = SimpleNamespace(
        digest="4" * 64,
        statement=SimpleNamespace(request=SimpleNamespace(request_digest="5" * 64)),
        model_dump=lambda **kwargs: {"kind": "signed"},
    )
    verification = SimpleNamespace(verification_digest="6" * 64)
    verification_calls: list[dict[str, object]] = []

    def fake_loader(name: str, value: object) -> Callable[..., object]:
        def load(*args: object, **kwargs: object) -> object:
            loader_calls.append(name)
            return value

        return load

    class FakeVerifier:
        def __init__(self, **kwargs: object) -> None:
            assert kwargs == {
                "trust_anchor": trust_anchor,
                "expected_trust_anchor_digest": _DIGEST,
            }

        def verify(self, bundle: object, **kwargs: object) -> object:
            assert bundle is signed
            verification_calls.append(kwargs)
            return verification

    monkeypatch.setattr(
        operator,
        "load_verified_authenticated_discovery",
        fake_loader("source", source),
    )
    monkeypatch.setattr(
        operator,
        "load_verified_web_analysis_skill_projection",
        fake_loader("skill", skill_run),
    )
    monkeypatch.setattr(
        operator,
        "load_verified_web_analysis_capacity_v2_run",
        fake_loader("capacity", capacity_run),
    )
    monkeypatch.setattr(
        operator,
        "load_verified_compact_skill_bound_web_analysis_preparation",
        fake_loader("preparation", preparation_run),
    )
    monkeypatch.setattr(
        operator,
        "_plan_admission",
        fake_loader("plan-admission", planned),
    )
    monkeypatch.setattr(
        operator,
        "_verify_admission",
        fake_loader("verify-admission", planned),
    )
    monkeypatch.setattr(
        operator,
        "_load_exact_admission",
        fake_loader("load-admission", planned_admission),
    )
    monkeypatch.setattr(
        operator,
        "_load_lineage_transport_pin",
        fake_loader("lineage-pin", lineage_transport_pin),
    )
    monkeypatch.setattr(
        operator,
        "load_verified_compact_web_analysis_runtime_pin",
        fake_loader("runtime-pin", compact_runtime_pin),
    )
    monkeypatch.setattr(
        operator,
        "load_verified_compact_web_analysis_transport_pin",
        fake_loader("transport-pin", compact_transport_pin),
    )
    monkeypatch.setattr(
        operator,
        "parse_web_analysis_one_call_authorization_trust_anchor",
        lambda content: trust_anchor,
    )
    monkeypatch.setattr(
        operator,
        "parse_signed_web_analysis_one_call_authorization_v2",
        lambda content: signed,
    )
    monkeypatch.setattr(operator, "WebAnalysisOneCallAuthorizationVerifierV2", FakeVerifier)

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError(f"unexpected live side effect: {args!r} {kwargs!r}")

    monkeypatch.setattr(operator, "WebAnalysisLiveClaimJournal", forbidden)
    monkeypatch.setattr(operator, "SecretBroker", forbidden)
    monkeypatch.setattr(operator, "SubprocessLlamaCppLiveMaterialization", forbidden)

    anchor_path = root / "trust-anchor.json"
    digest_path = root / "trust-anchor.sha256"
    signed_path = root / "signed-authorization.json"
    _owner_file(anchor_path, b'{"kind":"anchor"}\n')
    _owner_file(digest_path, (_DIGEST + "\n").encode())
    _owner_file(signed_path, b'{"kind":"signed"}\n')

    verified = operator.preflight(
        manifest,
        trust_anchor_path=anchor_path,
        trust_anchor_digest_path=digest_path,
        signed_authorization_path=signed_path,
    )

    assert verified.immutable.source is source
    assert verified.immutable.skill_run is skill_run
    assert cast(object, verified.immutable.capacity_run) is capacity_run
    assert cast(object, verified.immutable.preparation_run) is preparation_run
    assert cast(object, verified.immutable.planned) is planned
    assert verified.immutable.lineage_transport_pin is lineage_transport_pin
    assert cast(object, verified.immutable.compact_runtime_pin) is compact_runtime_pin
    assert cast(object, verified.immutable.compact_transport_pin) is compact_transport_pin
    assert cast(object, verified.trust_anchor) is trust_anchor
    assert cast(object, verified.signed_authorization) is signed
    assert cast(object, verified.verified_authorization) is verification
    assert loader_calls == [
        "source",
        "skill",
        "capacity",
        "preparation",
        "plan-admission",
        "verify-admission",
        "load-admission",
        "lineage-pin",
        "runtime-pin",
        "transport-pin",
    ]
    assert len(verification_calls) == 1
    assert verification_calls[0] == {
        "admission": planned_admission,
        "live_request": live_request,
        "capacity_pin": capacity_pin,
        "lineage_transport_pin": lineage_transport_pin,
        "compact_runtime_pin": compact_runtime_pin,
        "compact_transport_pin": compact_transport_pin,
    }
    assert verified.result.provider_dispatch_count == 0
    assert verified.result.target_request_count == 0
    assert verified.result.claim_performed is False


def test_execute_opens_existing_store_registers_random_token_and_invokes_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path.resolve() / "state"
    _owner_directory(root)
    _owner_directory(root / "terminal-output")
    _owner_file(root / "live-claims.sqlite3", b"journal")
    manifest = _manifest(tmp_path.resolve())
    verified = SimpleNamespace(
        immutable=SimpleNamespace(
            preparation_run=SimpleNamespace(
                live_request=SimpleNamespace(
                    provider_registration=SimpleNamespace(secret_ref="local-provider-token")
                )
            )
        )
    )
    monkeypatch.setattr(operator, "preflight", lambda *args, **kwargs: verified)
    journal_calls: list[dict[str, object]] = []

    class FakeJournal:
        store_id = _STORE_ID

        def __init__(self, path: Path, **kwargs: object) -> None:
            assert path == root / "live-claims.sqlite3"
            journal_calls.append(kwargs)

    registered: list[tuple[str, str]] = []

    class FakeBroker:
        def register(self, secret_ref: str, value: str) -> None:
            registered.append((secret_ref, value))

    invoke_count = 0

    class FakeRuntime:
        async def invoke(self) -> _OutputModel:
            nonlocal invoke_count
            invoke_count += 1
            return _OutputModel(value="terminal")

    build_calls: list[dict[str, object]] = []

    def build_runtime(*args: object, **kwargs: object) -> FakeRuntime:
        build_calls.append(kwargs)
        return FakeRuntime()

    monkeypatch.setattr(operator, "WebAnalysisLiveClaimJournal", FakeJournal)
    monkeypatch.setattr(operator, "SecretBroker", FakeBroker)
    monkeypatch.setattr(operator, "_build_live_runtime", build_runtime)

    outcome = asyncio.run(
        operator.execute(
            manifest,
            trust_anchor_path=tmp_path.resolve() / "anchor",
            trust_anchor_digest_path=tmp_path.resolve() / "anchor.sha256",
            signed_authorization_path=tmp_path.resolve() / "signed",
            state_root=root,
            expected_store_id=_STORE_ID,
            docker_executable="docker-test",
        )
    )

    assert outcome == _OutputModel(value="terminal")
    assert journal_calls == [{"expected_store_id": _STORE_ID, "allow_create": False}]
    assert len(registered) == 1
    assert registered[0][0] == "local-provider-token"
    assert registered[0][1]
    assert len(build_calls) == 1
    assert build_calls[0]["docker_executable"] == "docker-test"
    assert invoke_count == 1


def test_execute_requires_expected_store_id_and_rejects_mismatch_before_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path.resolve() / "state"
    _owner_directory(root)
    _owner_directory(root / "terminal-output")
    _owner_file(root / "live-claims.sqlite3", b"journal")
    manifest = _manifest(tmp_path.resolve())
    verified = SimpleNamespace(
        immutable=SimpleNamespace(
            preparation_run=SimpleNamespace(
                live_request=SimpleNamespace(
                    provider_registration=SimpleNamespace(secret_ref="local-provider-token")
                )
            )
        )
    )
    monkeypatch.setattr(operator, "preflight", lambda *args, **kwargs: verified)
    journal_calls: list[dict[str, object]] = []

    class FakeJournal:
        store_id = _STORE_ID

        def __init__(self, path: Path, **kwargs: object) -> None:
            assert path == root / "live-claims.sqlite3"
            journal_calls.append(kwargs)

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError(f"unexpected runtime construction: {args!r} {kwargs!r}")

    monkeypatch.setattr(operator, "WebAnalysisLiveClaimJournal", FakeJournal)
    monkeypatch.setattr(operator, "SecretBroker", forbidden)
    monkeypatch.setattr(operator, "_build_live_runtime", forbidden)

    assert inspect.signature(operator.execute).parameters["expected_store_id"].default is (
        inspect.Parameter.empty
    )
    with pytest.raises(operator.CompactLiveOperatorError):
        asyncio.run(
            operator.execute(
                manifest,
                trust_anchor_path=tmp_path.resolve() / "anchor",
                trust_anchor_digest_path=tmp_path.resolve() / "anchor.sha256",
                signed_authorization_path=tmp_path.resolve() / "signed",
                state_root=root,
                expected_store_id="c" * 64,
            )
        )

    assert journal_calls == [{"expected_store_id": "c" * 64, "allow_create": False}]


def test_execute_does_not_retry_failed_runtime_invoke(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path.resolve() / "state"
    _owner_directory(root)
    _owner_directory(root / "terminal-output")
    _owner_file(root / "live-claims.sqlite3", b"journal")
    manifest = _manifest(tmp_path.resolve())
    verified = SimpleNamespace(
        immutable=SimpleNamespace(
            preparation_run=SimpleNamespace(
                live_request=SimpleNamespace(
                    provider_registration=SimpleNamespace(secret_ref="local-provider-token")
                )
            )
        )
    )
    preflight_count = 0

    def fake_preflight(*args: object, **kwargs: object) -> object:
        nonlocal preflight_count
        preflight_count += 1
        return verified

    class FakeJournal:
        store_id = _STORE_ID

        def __init__(self, path: Path, **kwargs: object) -> None:
            assert path == root / "live-claims.sqlite3"
            assert kwargs == {"expected_store_id": _STORE_ID, "allow_create": False}

    class FakeBroker:
        def register(self, secret_ref: str, value: str) -> None:
            assert secret_ref == "local-provider-token"
            assert value

    invoke_count = 0

    class FailingRuntime:
        async def invoke(self) -> object:
            nonlocal invoke_count
            invoke_count += 1
            raise RuntimeError("injected invoke failure")

    build_count = 0

    def build_runtime(*args: object, **kwargs: object) -> FailingRuntime:
        nonlocal build_count
        build_count += 1
        return FailingRuntime()

    monkeypatch.setattr(operator, "preflight", fake_preflight)
    monkeypatch.setattr(operator, "WebAnalysisLiveClaimJournal", FakeJournal)
    monkeypatch.setattr(operator, "SecretBroker", FakeBroker)
    monkeypatch.setattr(operator, "_build_live_runtime", build_runtime)

    with pytest.raises(operator.CompactLiveOperatorError):
        asyncio.run(
            operator.execute(
                manifest,
                trust_anchor_path=tmp_path.resolve() / "anchor",
                trust_anchor_digest_path=tmp_path.resolve() / "anchor.sha256",
                signed_authorization_path=tmp_path.resolve() / "signed",
                state_root=root,
                expected_store_id=_STORE_ID,
            )
        )

    assert preflight_count == 1
    assert build_count == 1
    assert invoke_count == 1


def test_execute_cli_outputs_only_validated_compiled_proposal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    proposal = _compiled_proposal()
    completion = _successful_completion(proposal)

    async def fake_execute(*args: object, **kwargs: object) -> object:
        return completion

    monkeypatch.setattr(operator, "execute", fake_execute)
    root = tmp_path.resolve()

    result = operator.main(
        [
            "execute",
            "--manifest",
            os.fspath(root / "manifest.json"),
            "--trust-anchor",
            os.fspath(root / "anchor.json"),
            "--trust-anchor-digest",
            os.fspath(root / "anchor.sha256"),
            "--signed-authorization",
            os.fspath(root / "signed.json"),
            "--state-root",
            os.fspath(root / "state"),
            "--expected-store-id",
            _STORE_ID,
        ]
    )

    output = capfd.readouterr()
    expected = canonical_json_bytes(
        proposal.model_dump(mode="json", by_alias=True),
        label="test compact live CLI proposal",
    ).decode("utf-8")
    assert result == 0
    assert output.out == expected + "\n"
    assert "terminal_run" not in output.out
    assert output.err == ""


def test_execute_cli_rejects_invalid_success_shape_without_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    invalid = cast(Any, replace)(_successful_completion(), dispatch_count=0)

    async def fake_execute(*args: object, **kwargs: object) -> object:
        return invalid

    monkeypatch.setattr(operator, "execute", fake_execute)
    root = tmp_path.resolve()

    result = operator.main(
        [
            "execute",
            "--manifest",
            os.fspath(root / "manifest.json"),
            "--trust-anchor",
            os.fspath(root / "anchor.json"),
            "--trust-anchor-digest",
            os.fspath(root / "anchor.sha256"),
            "--signed-authorization",
            os.fspath(root / "signed.json"),
            "--state-root",
            os.fspath(root / "state"),
            "--expected-store-id",
            _STORE_ID,
        ]
    )

    output = capfd.readouterr()
    assert result == 1
    assert output.out == ""
    assert "execution outcome failed success validation" in output.err


def test_success_output_rejects_authority_crosslink_and_disposition_drift() -> None:
    authority_drift = cast(Any, replace)(_successful_completion(), retry_authority=True)
    with pytest.raises(operator.CompactLiveOperatorError):
        operator._successful_proposal_for_output(authority_drift)

    crosslink_drift = _successful_completion()
    crosslink_drift.terminal_run.receipt.compiled_proposal = _compiled_proposal().model_copy(
        update={"proposal_digest": "f" * 64}
    )
    with pytest.raises(operator.CompactLiveOperatorError):
        operator._successful_proposal_for_output(crosslink_drift)

    disposition_drift = _successful_completion()
    disposition_drift.terminal_run.terminal_claim.terminal_disposition = (
        WebAnalysisLiveClaimTerminalDisposition.FAILURE
    )
    with pytest.raises(operator.CompactLiveOperatorError):
        operator._successful_proposal_for_output(disposition_drift)


def test_execute_cli_requires_store_identity() -> None:
    with pytest.raises(SystemExit):
        operator.main(
            [
                "execute",
                "--manifest",
                "/manifest.json",
                "--trust-anchor",
                "/anchor.json",
                "--trust-anchor-digest",
                "/anchor.sha256",
                "--signed-authorization",
                "/signed.json",
                "--state-root",
                "/state",
            ]
        )


def test_operator_has_no_signer_legacy_or_recovery_surface() -> None:
    source_path = Path(operator.__file__).resolve()
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported_modules: set[str] = set()
    imported_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module is not None:
                imported_modules.add(node.module)
            imported_names.update(alias.name for alias in node.names)

    forbidden_modules = {
        "pajin.benchmark.effectiveness.docker",
        "pajin.web_assessment.analysis_runtime",
        "pajin.web_assessment.analysis_skill_runtime",
        "pajin.web_assessment.analysis_skill_compact_live_receipts",
        "pajin.benchmark.effectiveness.runtime",
        "pajin.benchmark.effectiveness.suite",
    }
    assert imported_modules.isdisjoint(forbidden_modules)
    assert not any(name.startswith("offline") or ".offline" in name for name in imported_modules)
    assert not any(name.startswith("tests") or ".tests" in name for name in imported_modules)
    assert {"Ed25519PrivateKey", "LocalModelRuntime"}.isdisjoint(imported_names)
    assert not any(
        isinstance(node, (ast.Name, ast.Attribute))
        and getattr(node, "id", getattr(node, "attr", None)) == "LocalModelRuntime"
        for node in ast.walk(tree)
    )
    parser = operator._parser()
    subparsers = next(
        action for action in parser._actions if action.__class__.__name__ == "_SubParsersAction"
    )
    choices = cast(Any, subparsers).choices
    assert choices is not None
    assert set(choices) == {
        "provision-state",
        "prepare-authorization-request",
        "preflight",
        "execute",
    }


def test_pyproject_packages_the_operator_console_entry() -> None:
    project_root = Path(__file__).resolve().parents[1]
    pyproject = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))

    assert pyproject["project"]["scripts"]["pajin-compact-live"] == (
        "pajin.web_assessment.compact_live_operator:main"
    )
