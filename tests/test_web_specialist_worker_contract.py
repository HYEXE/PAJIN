from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from pajin.runtime.worker import EgressPolicy, NetworkMode, WorkerSecretRequest
from pajin.web_assessment.specialist_worker import (
    SPECIALIST_WORKER_COMMAND,
    SPECIALIST_WORKER_IMAGE,
    SignedSpecialistWorkerOutput,
    SpecialistWorkerContractError,
    SpecialistWorkerInput,
    SpecialistWorkerJobCompiler,
    SpecialistWorkerOutputVerifier,
    SpecialistWorkerStatement,
    SpecialistWorkerVerificationKey,
    compile_specialist_worker_job,
    sign_specialist_worker_statement,
    specialist_worker_public_key_base64url,
    specialist_worker_statement_for_input,
    verify_specialist_worker_job,
)


def _digest(index: int) -> str:
    return f"{index:064x}"


def _reference(reference_id: str, digest: str) -> dict[str, str]:
    return {"id": reference_id, "digest": digest}


def _worker_input_wire() -> dict[str, object]:
    execution_digest = _digest(1)
    binding_digest = _digest(2)
    preparation_digest = _digest(3)
    permit_digest = _digest(9)
    grant_consumption_digest = _digest(10)
    return {
        "apiVersion": "pajin.dev/agentic-web-specialist-worker-input/v1alpha1",
        "kind": "AgenticWebSpecialistWorkerInput",
        "executionRef": _reference(
            f"agentic-specialist-reservation_{execution_digest}",
            execution_digest,
        ),
        "bindingRef": _reference(
            f"agentic-specialist-dispatch-binding_{binding_digest}",
            binding_digest,
        ),
        "preparationRef": _reference(
            f"agentic-specialist-preparation_{preparation_digest}",
            preparation_digest,
        ),
        "profileRef": _reference(
            "pajin.web-specialist.juice-shop.dom-xss-only",
            _digest(4),
        ),
        "executorRef": _reference("pajin.web-specialist.dom-xss", _digest(5)),
        "capabilityRef": _reference(
            "pajin.bug-bounty.web-specialist.dom-xss",
            _digest(6),
        ),
        "toolRef": _reference("web.specialist.dom-xss", _digest(7)),
        "requestRef": _reference(
            f"agentic-specialist-request_{_digest(80)}",
            _digest(8),
        ),
        "permitRef": _reference(f"action-permit_{permit_digest}", permit_digest),
        "grantConsumptionRef": _reference(
            f"agentic-specialist-grant-consumption_{grant_consumption_digest}",
            grant_consumption_digest,
        ),
    }


def _worker_input() -> SpecialistWorkerInput:
    return SpecialistWorkerInput.model_validate(_worker_input_wire())


def _private_key(seed: int = 1) -> bytes:
    return bytes((seed + index) % 256 for index in range(32))


def _verification_key(private_key: bytes | None = None) -> SpecialistWorkerVerificationKey:
    material = private_key if private_key is not None else _private_key()
    return SpecialistWorkerVerificationKey(
        keyId="specialist-worker-key:deployment-1",
        trustDomain="pajin.deployment.test",
        issuer="PAJIN test deployment",
        publicKeyBase64url=specialist_worker_public_key_base64url(material),
    )


def _signed_output(
    worker_input: SpecialistWorkerInput | None = None,
    *,
    private_key: bytes | None = None,
) -> SignedSpecialistWorkerOutput:
    input_value = worker_input if worker_input is not None else _worker_input()
    key = _verification_key(private_key)
    statement = specialist_worker_statement_for_input(
        input_value,
        trust_domain=key.trust_domain,
        issuer=key.issuer,
    )
    return sign_specialist_worker_statement(
        statement,
        key_id=key.key_id,
        private_key=private_key if private_key is not None else _private_key(),
    )


def _all_object_keys(value: object) -> set[str]:
    keys: set[str] = set()
    if type(value) is dict:
        for key, nested in value.items():
            assert type(key) is str
            keys.add(key)
            keys.update(_all_object_keys(nested))
    elif type(value) is list:
        for nested in value:
            keys.update(_all_object_keys(nested))
    return keys


def test_specialist_worker_input_is_exact_secret_free_refs_only() -> None:
    worker_input = _worker_input()
    wire = worker_input.model_dump(mode="json", by_alias=True)

    assert set(wire) == {
        "apiVersion",
        "kind",
        "executionRef",
        "bindingRef",
        "preparationRef",
        "profileRef",
        "executorRef",
        "capabilityRef",
        "toolRef",
        "requestRef",
        "permitRef",
        "grantConsumptionRef",
    }
    for field in set(wire) - {"apiVersion", "kind"}:
        assert set(wire[field]) == {"id", "digest"}
    assert not {
        "route",
        "payload",
        "egressPolicy",
        "transport",
        "catalog",
        "credential",
        "secret",
        "token",
        "origin",
        "target",
    }.intersection(_all_object_keys(wire))


@pytest.mark.parametrize(
    "field",
    ("route", "payload", "egressPolicy", "egress_policy", "transport", "catalog"),
)
def test_specialist_worker_input_rejects_forbidden_executable_fields(field: str) -> None:
    top_level = _worker_input_wire()
    top_level[field] = "/caller-controlled"
    with pytest.raises(ValueError, match="forbidden executable field"):
        SpecialistWorkerInput.model_validate(top_level)

    nested = _worker_input_wire()
    execution_ref = nested["executionRef"]
    assert isinstance(execution_ref, dict)
    execution_ref[field] = "/caller-controlled"
    with pytest.raises(ValueError, match="forbidden executable field"):
        SpecialistWorkerInput.model_validate(nested)


def test_specialist_worker_input_rejects_reference_drift_and_duplicate_keys() -> None:
    wrong_content_address = _worker_input_wire()
    execution_ref = wrong_content_address["executionRef"]
    assert isinstance(execution_ref, dict)
    execution_ref["digest"] = _digest(11)
    with pytest.raises(ValidationError, match="content-addressed reference"):
        SpecialistWorkerInput.model_validate(wrong_content_address)

    duplicate = _worker_input_wire()
    duplicate["toolRef"] = deepcopy(duplicate["profileRef"])
    with pytest.raises(ValidationError, match="code-owned identity family"):
        SpecialistWorkerInput.model_validate(duplicate)

    raw = (
        '{"apiVersion":"pajin.dev/agentic-web-specialist-worker-input/v1alpha1",'
        '"kind":"AgenticWebSpecialistWorkerInput","executionRef":{},'
        '"executionRef":{}}'
    )
    with pytest.raises(ValueError, match="duplicate object key"):
        SpecialistWorkerInput.model_validate_json(raw)


def test_specialist_worker_input_rejects_non_code_owned_or_secret_like_refs() -> None:
    secret_like = _worker_input_wire()
    secret_like["profileRef"] = _reference("password:caller-secret", _digest(4))
    with pytest.raises(ValidationError, match="code-owned identity family"):
        SpecialistWorkerInput.model_validate(secret_like)

    mixed_family = _worker_input_wire()
    mixed_family["toolRef"] = _reference("web.specialist.authorization", _digest(7))
    with pytest.raises(ValidationError, match="code-owned identity family"):
        SpecialistWorkerInput.model_validate(mixed_family)

    foreign_request = _worker_input_wire()
    foreign_request["requestRef"] = _reference("tool_caller-secret", _digest(8))
    with pytest.raises(ValidationError, match="request reference is not code-owned"):
        SpecialistWorkerInput.model_validate(foreign_request)


def test_specialist_worker_compiler_is_deterministic_and_target_io_zero() -> None:
    worker_input = _worker_input()
    compiler = SpecialistWorkerJobCompiler()

    first = compiler.compile_job(worker_input)
    second = compiler.compile_job(worker_input)
    functional = compile_specialist_worker_job(worker_input)

    assert first == second == functional
    assert first.image == SPECIALIST_WORKER_IMAGE
    assert first.command == list(SPECIALIST_WORKER_COMMAND)
    assert first.execution_id == f"specialist-worker:{worker_input.input_digest}"
    assert first.network is NetworkMode.NONE
    assert first.egress_policy is None
    assert first.secret_requests == []
    assert SpecialistWorkerInput.model_validate_json(first.stdin) == worker_input
    assert not {
        "route",
        "payload",
        "egressPolicy",
        "transport",
        "catalog",
    }.intersection(_all_object_keys(worker_input.model_dump(mode="json", by_alias=True)))
    assert compiler.stable_execution_context() == {
        "implementationVersion": "pajin.agentic.web-specialist-worker-compiler/v1",
        "inputApiVersion": "pajin.dev/agentic-web-specialist-worker-input/v1alpha1",
        "image": SPECIALIST_WORKER_IMAGE,
        "command": list(SPECIALIST_WORKER_COMMAND),
        "networkMode": "none",
        "secretRequestsAllowed": False,
        "targetIOAllowed": False,
        "aggregateWebAuthorityReused": False,
    }


def test_specialist_worker_compiler_rejects_hidden_model_copy_fields() -> None:
    hidden = _worker_input().model_copy(update={"route": "/hidden"})
    with pytest.raises(SpecialistWorkerContractError, match="hidden model state"):
        compile_specialist_worker_job(hidden)


def test_specialist_worker_job_requires_exact_recompile_before_handoff() -> None:
    worker_input = _worker_input()
    job = compile_specialist_worker_job(worker_input)

    assert verify_specialist_worker_job(expected_input=worker_input, job=job) == job

    expanded = job.model_copy(
        update={
            "network": NetworkMode.EGRESS_PROXY,
            "egress_policy": EgressPolicy(
                allow=["http://127.0.0.1:3000/*"],
                allow_private_networks=True,
            ),
            "secret_requests": [
                WorkerSecretRequest(secret_ref="caller-secret", binding="credential")
            ],
        }
    )
    with pytest.raises(SpecialistWorkerContractError, match="deterministic compilation"):
        verify_specialist_worker_job(expected_input=worker_input, job=expanded)

    mutable_image = job.model_copy(update={"image": "caller-controlled:latest"})
    with pytest.raises(SpecialistWorkerContractError, match="deterministic compilation"):
        verify_specialist_worker_job(expected_input=worker_input, job=mutable_image)


def test_signed_specialist_worker_output_binds_every_ref_and_false_authority() -> None:
    worker_input = _worker_input()
    key = _verification_key()
    signed = _signed_output(worker_input)
    verifier = SpecialistWorkerOutputVerifier(deployment_verification_key=key)

    verified = verifier.verify_output(
        expected_input=worker_input,
        signed_output=signed,
    )
    assert verified == signed
    statement = verified.statement
    assert statement.input_digest == worker_input.input_digest
    for field in (
        "execution_ref",
        "binding_ref",
        "preparation_ref",
        "profile_ref",
        "executor_ref",
        "capability_ref",
        "tool_ref",
        "request_ref",
        "permit_ref",
        "grant_consumption_ref",
    ):
        assert getattr(statement, field) == getattr(worker_input, field)
    assert statement.network_mode == "none"
    assert statement.target_io_performed is False
    assert statement.backend_invoked is False
    assert statement.secret_material_requested is False
    assert statement.aggregate_source_authority_reused is False
    assert statement.aggregate_validation_authority_reused is False
    assert statement.production_authority_eligible is False
    assert statement.independent_validation is False
    assert statement.finding is False
    assert statement.graph is False
    assert statement.report is False
    assert statement.sarif is False
    assert statement.poc is False
    assert verifier.stable_execution_context()["verificationKeyDigest"] == key.key_digest
    assert verifier.stable_execution_context()["deploymentOwnedVerificationKey"] is True


@pytest.mark.parametrize(
    "field",
    (
        "targetIOPerformed",
        "backendInvoked",
        "secretMaterialRequested",
        "aggregateSourceAuthorityReused",
        "aggregateValidationAuthorityReused",
        "productionAuthorityEligible",
        "independentValidation",
        "finding",
        "graph",
        "report",
        "sarif",
        "poc",
    ),
)
@pytest.mark.parametrize("value", (True, 0, 1, "false"))
def test_specialist_worker_statement_false_markers_are_literal(field: str, value: object) -> None:
    wire = _signed_output().statement.model_dump(mode="json", by_alias=True)
    wire[field] = value
    with pytest.raises(ValidationError, match="literal false"):
        SpecialistWorkerStatement.model_validate(wire)


def test_specialist_worker_verifier_rejects_foreign_key_and_input() -> None:
    worker_input = _worker_input()
    signed_by_foreign_key = _signed_output(worker_input, private_key=_private_key(17))
    verifier = SpecialistWorkerOutputVerifier(
        deployment_verification_key=_verification_key(_private_key())
    )
    with pytest.raises(SpecialistWorkerContractError, match="signature is not trusted"):
        verifier.verify_output(
            expected_input=worker_input,
            signed_output=signed_by_foreign_key,
        )

    changed_wire = _worker_input_wire()
    changed_wire["requestRef"] = _reference(
        f"agentic-specialist-request_{_digest(81)}",
        _digest(12),
    )
    changed_input = SpecialistWorkerInput.model_validate(changed_wire)
    with pytest.raises(SpecialistWorkerContractError, match="deployment authority"):
        verifier.verify_output(
            expected_input=changed_input,
            signed_output=_signed_output(worker_input),
        )


def test_specialist_worker_verifier_rejects_tampered_envelope_and_hidden_state() -> None:
    worker_input = _worker_input()
    verifier = SpecialistWorkerOutputVerifier(deployment_verification_key=_verification_key())
    signed = _signed_output(worker_input)

    signature = signed.signature_base64url
    replacement = "A" if signature[0] != "A" else "B"
    tampered_wire = signed.model_dump(mode="json", by_alias=True)
    tampered_wire["signatureBase64url"] = replacement + signature[1:]
    tampered = SignedSpecialistWorkerOutput.model_validate(tampered_wire)
    with pytest.raises(SpecialistWorkerContractError, match="signature is not trusted"):
        verifier.verify_output(expected_input=worker_input, signed_output=tampered)

    hidden = signed.model_copy(update={"verification_key": "caller-owned"})
    with pytest.raises(SpecialistWorkerContractError, match="hidden model state"):
        verifier.verify_output(expected_input=worker_input, signed_output=hidden)

    caller_key_wire = signed.model_dump(mode="json", by_alias=True)
    caller_key_wire["publicKeyBase64url"] = _verification_key().public_key_base64url
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SignedSpecialistWorkerOutput.model_validate(caller_key_wire)


def test_deployment_ownership_cannot_be_self_labelled_by_key_or_output_wire() -> None:
    wire = _verification_key().model_dump(mode="json", by_alias=True)
    wire["deploymentOwned"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SpecialistWorkerVerificationKey.model_validate(wire)

    signed_wire = _signed_output().model_dump(mode="json", by_alias=True)
    signed_wire["deploymentOwned"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SignedSpecialistWorkerOutput.model_validate(signed_wire)
