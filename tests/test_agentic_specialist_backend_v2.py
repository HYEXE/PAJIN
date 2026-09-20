from __future__ import annotations

import asyncio
import socket
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import cast

import httpx
import pytest

from pajin.agentic.specialist_backend_v2 import (
    CONFORMANCE_COMPLETED_NO_TARGET_IO,
    SignedSpecialistBackendResultV2,
    SpecialistBackendJobTemplateV2,
    SpecialistBackendLaunchEnvelopeV2,
    SpecialistBackendOutputVerifierV2,
    SpecialistBackendResultStatementV2,
    SpecialistBackendV2,
    SpecialistBackendV2ContractError,
    SpecialistBackendVerificationKeyV2,
    SpecialistExecutionInventoryV2,
    StructuredFakeSpecialistBackendV2,
    specialist_backend_launch_envelope_v2,
    specialist_backend_public_key_base64url_v2,
    specialist_execution_inventory_v2,
    structured_fake_specialist_job_template_v2,
)
from pajin.discovery.canonicalization import canonical_json_bytes

PRIVATE_KEY_A = bytes(range(32))
PRIVATE_KEY_B = bytes(range(32, 64))
SHA_A = "a" * 64
SHA_B = "b" * 64


@dataclass(frozen=True, slots=True)
class BackendFixture:
    private_key: bytes
    key: SpecialistBackendVerificationKeyV2
    template: SpecialistBackendJobTemplateV2
    inventory: SpecialistExecutionInventoryV2
    envelope: SpecialistBackendLaunchEnvelopeV2
    backend: StructuredFakeSpecialistBackendV2
    verifier: SpecialistBackendOutputVerifierV2


def _fixture(
    *,
    private_key: bytes = PRIVATE_KEY_A,
    attempt_digest: str = SHA_A,
    dispatch_verification_digest: str = SHA_B,
    deadline: datetime | None = None,
) -> BackendFixture:
    key = SpecialistBackendVerificationKeyV2(
        keyId="key:agentic-specialist-backend-v2",
        trustDomain="trust:agentic-specialist-v2",
        issuer="PAJIN structured fake specialist backend",
        publicKeyBase64url=specialist_backend_public_key_base64url_v2(private_key),
    )
    template = structured_fake_specialist_job_template_v2()
    inventory = specialist_execution_inventory_v2(
        job_template=template,
        verification_key=key,
    )
    envelope = specialist_backend_launch_envelope_v2(
        attempt_digest=attempt_digest,
        dispatch_verification_digest=dispatch_verification_digest,
        job_template=template,
        runtime_inventory=inventory,
        backend_handoff_deadline=deadline or datetime.now(UTC) + timedelta(minutes=5),
    )
    backend = StructuredFakeSpecialistBackendV2(
        signing_private_key=private_key,
        deployment_verification_key=key,
        job_template=template,
        execution_inventory=inventory,
    )
    verifier = SpecialistBackendOutputVerifierV2(
        deployment_verification_key=key,
        job_template=template,
        execution_inventory=inventory,
    )
    return BackendFixture(
        private_key=private_key,
        key=key,
        template=template,
        inventory=inventory,
        envelope=envelope,
        backend=backend,
        verifier=verifier,
    )


def _rehashed_statement_tamper(
    signed: SignedSpecialistBackendResultV2,
    *,
    field: str,
    value: object,
) -> SignedSpecialistBackendResultV2:
    wire = signed.model_dump(mode="json", by_alias=True)
    statement_wire = cast(dict[str, object], wire["statement"])
    statement_wire[field] = value
    statement = SpecialistBackendResultStatementV2.model_validate(statement_wire)
    statement_bytes = canonical_json_bytes(
        statement.model_dump(mode="json", by_alias=True),
        label="tampered specialist backend statement",
    )
    wire["statement"] = statement.model_dump(mode="json", by_alias=True)
    wire["statementSha256"] = sha256(statement_bytes).hexdigest()
    return SignedSpecialistBackendResultV2.model_validate(wire)


def test_inventory_is_content_addressed_and_pins_complete_fake_deployment() -> None:
    fixture = _fixture()
    repeated = specialist_execution_inventory_v2(
        job_template=fixture.template,
        verification_key=fixture.key,
    )

    assert repeated == fixture.inventory
    assert fixture.template.template_id.endswith(fixture.template.template_digest)
    assert fixture.inventory.inventory_id.endswith(fixture.inventory.inventory_digest)
    assert fixture.inventory.job_template_id == fixture.template.template_id
    assert fixture.inventory.job_template_digest == fixture.template.template_digest
    assert fixture.inventory.worker_image_reference == fixture.template.worker_image_reference
    assert fixture.inventory.worker_image_digest == fixture.template.worker_image_digest
    assert fixture.inventory.worker_command_digest == fixture.template.worker_command_digest
    assert fixture.inventory.worker_compiler_id == "pajin.worker-compiler.agentic-specialist"
    assert fixture.inventory.worker_compiler_version == "2.0.0"
    assert len(fixture.inventory.worker_compiler_digest) == 64
    assert len(fixture.inventory.contract_implementation_digest) == 64
    assert fixture.inventory.verification_key_id == fixture.key.key_id
    assert fixture.inventory.verification_key_digest == fixture.key.key_digest
    assert fixture.inventory.network_mode == "none"
    assert fixture.inventory.one_call_backend is True
    assert fixture.inventory.target_io_allowed is False
    assert fixture.inventory.production_authority_eligible is False

    other = _fixture(private_key=PRIVATE_KEY_B)
    assert other.key.key_digest != fixture.key.key_digest
    assert other.inventory.worker_backend_digest != fixture.inventory.worker_backend_digest
    assert other.inventory.worker_verifier_digest != fixture.inventory.worker_verifier_digest
    assert other.inventory.inventory_digest != fixture.inventory.inventory_digest
    assert fixture.backend.stable_execution_context()["contractImplementationDigest"] == (
        fixture.inventory.contract_implementation_digest
    )
    assert fixture.verifier.stable_execution_context()["contractImplementationDigest"] == (
        fixture.inventory.contract_implementation_digest
    )


def test_pre_attempt_template_forbids_attempt_and_dispatch_verification_references() -> None:
    template = structured_fake_specialist_job_template_v2()
    wire = template.model_dump(mode="json", by_alias=True)

    assert "attemptDigest" not in wire
    assert "attemptRef" not in wire
    assert "dispatchVerificationDigest" not in wire
    assert "dispatchVerificationRef" not in wire

    for field in ("attemptDigest", "attemptRef", "dispatchVerificationDigest"):
        tampered = dict(wire)
        tampered[field] = SHA_A
        with pytest.raises(ValueError, match="forbidden runtime reference"):
            SpecialistBackendJobTemplateV2.model_validate(tampered)

    fixture = _fixture()
    hidden = template.model_copy(update={"attempt_ref": {"digest": SHA_A}})
    with pytest.raises(SpecialistBackendV2ContractError, match="hidden model state"):
        specialist_execution_inventory_v2(
            job_template=hidden,
            verification_key=fixture.key,
        )


def test_launch_envelope_binds_only_post_verification_digests_and_pre_attempt_template() -> None:
    fixture = _fixture()
    envelope = fixture.envelope
    wire = envelope.model_dump(mode="json", by_alias=True)

    assert envelope.attempt_digest == SHA_A
    assert envelope.dispatch_verification_digest == SHA_B
    assert envelope.job_template_digest == fixture.template.template_digest
    assert envelope.runtime_inventory_digest == fixture.inventory.inventory_digest
    assert envelope.idempotency_key.startswith("specialist-job:")
    assert envelope.envelope_id.endswith(envelope.envelope_digest)
    assert "attemptRef" not in wire
    assert "dispatchVerificationRef" not in wire

    for field in ("attemptRef", "dispatchVerificationRef"):
        tampered = dict(wire)
        tampered[field] = {"digest": SHA_A}
        with pytest.raises(ValueError, match="forbidden runtime reference"):
            SpecialistBackendLaunchEnvelopeV2.model_validate(tampered)

    other_attempt = specialist_backend_launch_envelope_v2(
        attempt_digest="c" * 64,
        dispatch_verification_digest=envelope.dispatch_verification_digest,
        job_template=fixture.template,
        runtime_inventory=fixture.inventory,
        backend_handoff_deadline=envelope.backend_handoff_deadline,
    )
    assert other_attempt.envelope_digest != envelope.envelope_digest
    assert other_attempt.idempotency_key != envelope.idempotency_key

    other_verification = specialist_backend_launch_envelope_v2(
        attempt_digest=envelope.attempt_digest,
        dispatch_verification_digest="d" * 64,
        job_template=fixture.template,
        runtime_inventory=fixture.inventory,
        backend_handoff_deadline=envelope.backend_handoff_deadline,
    )
    assert other_verification.idempotency_key != envelope.idempotency_key


def test_models_strictly_reload_and_duplicate_or_unknown_fields_fail() -> None:
    fixture = _fixture()
    models = (
        fixture.key,
        fixture.template,
        fixture.inventory,
        fixture.envelope,
    )
    for model in models:
        reloaded = type(model).model_validate_json(model.model_dump_json(by_alias=True))
        assert reloaded == model

    inventory_json = fixture.inventory.model_dump_json(by_alias=True)
    duplicate = '{"gatewayId":"foreign.gateway",' + inventory_json[1:]
    with pytest.raises(ValueError, match="duplicate object key"):
        SpecialistExecutionInventoryV2.model_validate_json(duplicate)

    unknown = fixture.inventory.model_dump(mode="json", by_alias=True)
    unknown["route"] = "https://target.invalid/"
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        SpecialistExecutionInventoryV2.model_validate(unknown)


def test_backend_is_exact_protocol_one_call_and_performs_zero_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def sync_tripwire(*_args: object, **_kwargs: object) -> None:
        calls.append("sync-io")
        raise AssertionError("unexpected sync I/O")

    async def async_tripwire(*_args: object, **_kwargs: object) -> None:
        calls.append("async-io")
        raise AssertionError("unexpected async I/O")

    monkeypatch.setattr(socket, "create_connection", sync_tripwire)
    monkeypatch.setattr(socket, "getaddrinfo", sync_tripwire)
    monkeypatch.setattr(subprocess, "run", sync_tripwire)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", async_tripwire)
    monkeypatch.setattr(httpx.Client, "send", sync_tripwire)
    monkeypatch.setattr(httpx.AsyncClient, "send", async_tripwire)

    fixture = _fixture()
    assert isinstance(fixture.backend, SpecialistBackendV2)

    async def execute() -> SignedSpecialistBackendResultV2:
        first = await fixture.backend.run(fixture.envelope)
        with pytest.raises(SpecialistBackendV2ContractError, match="already consumed"):
            await fixture.backend.run(fixture.envelope)
        return first

    signed = asyncio.run(execute())
    verified = fixture.verifier.verify_output(
        expected_envelope=fixture.envelope,
        signed_result=signed,
    )

    assert verified == signed
    assert fixture.backend.invocation_count == 1
    assert calls == []
    statement = signed.statement
    assert statement.terminal_classification == CONFORMANCE_COMPLETED_NO_TARGET_IO
    assert statement.terminal_classification != "completed-verified"
    assert statement.backend_terminal_proven is True
    assert statement.conformance_succeeded is True
    assert statement.backend_invoked is True
    assert statement.network_mode == "none"
    assert statement.target_io_performed is False
    assert statement.secret_material_requested is False
    assert statement.production_authority_eligible is False
    assert statement.gateway_authority is False
    assert statement.execution_authority is False
    assert statement.independent_validation is False
    assert statement.finding is False
    assert statement.graph is False
    assert statement.report is False
    assert statement.sarif is False
    assert statement.poc is False


def test_concurrent_calls_have_one_winner_and_never_restore_backend_authority() -> None:
    fixture = _fixture()

    async def compete() -> list[object]:
        return await asyncio.gather(
            fixture.backend.run(fixture.envelope),
            fixture.backend.run(fixture.envelope),
            return_exceptions=True,
        )

    results = asyncio.run(compete())
    assert sum(type(item) is SignedSpecialistBackendResultV2 for item in results) == 1
    errors = [item for item in results if isinstance(item, BaseException)]
    assert len(errors) == 1
    assert isinstance(errors[0], SpecialistBackendV2ContractError)
    assert fixture.backend.invocation_count == 1


def test_expired_or_hidden_launch_burns_the_one_call_without_io() -> None:
    expired = _fixture(deadline=datetime.now(UTC) - timedelta(seconds=1))
    with pytest.raises(SpecialistBackendV2ContractError, match="deadline expired"):
        asyncio.run(expired.backend.run(expired.envelope))
    with pytest.raises(SpecialistBackendV2ContractError, match="already consumed"):
        asyncio.run(expired.backend.run(expired.envelope))

    fixture = _fixture()
    hidden = fixture.envelope.model_copy(update={"attempt_ref": {"digest": SHA_A}})
    with pytest.raises(SpecialistBackendV2ContractError, match="hidden model state"):
        asyncio.run(fixture.backend.run(hidden))
    with pytest.raises(SpecialistBackendV2ContractError, match="already consumed"):
        asyncio.run(fixture.backend.run(fixture.envelope))


def test_inventory_private_key_and_verifier_key_substitution_fail_closed() -> None:
    fixture = _fixture()
    other = _fixture(private_key=PRIVATE_KEY_B)

    with pytest.raises(SpecialistBackendV2ContractError, match="signing key differs"):
        StructuredFakeSpecialistBackendV2(
            signing_private_key=PRIVATE_KEY_B,
            deployment_verification_key=fixture.key,
            job_template=fixture.template,
            execution_inventory=fixture.inventory,
        )

    inventory_wire = fixture.inventory.model_dump(mode="json", by_alias=True)
    inventory_wire.update(
        inventoryId="",
        inventoryDigest="",
        workerImageDigest="d" * 64,
    )
    drifted_inventory = SpecialistExecutionInventoryV2.model_validate(inventory_wire)
    with pytest.raises(SpecialistBackendV2ContractError, match="inventory differs"):
        StructuredFakeSpecialistBackendV2(
            signing_private_key=fixture.private_key,
            deployment_verification_key=fixture.key,
            job_template=fixture.template,
            execution_inventory=drifted_inventory,
        )

    signed = asyncio.run(fixture.backend.run(fixture.envelope))
    with pytest.raises(SpecialistBackendV2ContractError, match="deployment authority"):
        other.verifier.verify_output(
            expected_envelope=other.envelope,
            signed_result=signed,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("jobTemplateDigest", "c" * 64),
        ("workerImageDigest", "d" * 64),
        ("workerCompilerDigest", "1" * 64),
        ("contractImplementationDigest", "2" * 64),
        ("launchEnvelopeDigest", "e" * 64),
        ("runtimeInventoryDigest", "f" * 64),
    ),
)
def test_verifier_rejects_rehashed_job_image_inventory_and_envelope_tamper(
    field: str,
    value: str,
) -> None:
    fixture = _fixture()
    signed = asyncio.run(fixture.backend.run(fixture.envelope))
    tampered = _rehashed_statement_tamper(signed, field=field, value=value)

    with pytest.raises(SpecialistBackendV2ContractError, match="deployment authority"):
        fixture.verifier.verify_output(
            expected_envelope=fixture.envelope,
            signed_result=tampered,
        )


def test_verifier_rejects_signature_key_and_expected_envelope_tamper() -> None:
    fixture = _fixture()
    signed = asyncio.run(fixture.backend.run(fixture.envelope))

    signature_wire = signed.model_dump(mode="json", by_alias=True)
    signature = cast(str, signature_wire["signatureBase64url"])
    signature_wire["signatureBase64url"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    signature_tampered = SignedSpecialistBackendResultV2.model_validate(signature_wire)
    with pytest.raises(SpecialistBackendV2ContractError, match="signature is not trusted"):
        fixture.verifier.verify_output(
            expected_envelope=fixture.envelope,
            signed_result=signature_tampered,
        )

    key_wire = signed.model_dump(mode="json", by_alias=True)
    key_wire["keyId"] = "key:substituted"
    key_tampered = SignedSpecialistBackendResultV2.model_validate(key_wire)
    with pytest.raises(SpecialistBackendV2ContractError, match="deployment authority"):
        fixture.verifier.verify_output(
            expected_envelope=fixture.envelope,
            signed_result=key_tampered,
        )

    other_envelope = specialist_backend_launch_envelope_v2(
        attempt_digest="c" * 64,
        dispatch_verification_digest=fixture.envelope.dispatch_verification_digest,
        job_template=fixture.template,
        runtime_inventory=fixture.inventory,
        backend_handoff_deadline=fixture.envelope.backend_handoff_deadline,
    )
    with pytest.raises(SpecialistBackendV2ContractError, match="deployment authority"):
        fixture.verifier.verify_output(
            expected_envelope=other_envelope,
            signed_result=signed,
        )


def test_completed_verified_and_boolean_coercion_are_unrepresentable() -> None:
    fixture = _fixture()
    signed = asyncio.run(fixture.backend.run(fixture.envelope))
    statement_wire = signed.statement.model_dump(mode="json", by_alias=True)
    statement_wire["terminalClassification"] = "completed-verified"
    with pytest.raises(ValueError, match="terminalClassification"):
        SpecialistBackendResultStatementV2.model_validate(statement_wire)

    statement_wire = signed.statement.model_dump(mode="json", by_alias=True)
    statement_wire["backendInvoked"] = 1
    with pytest.raises(ValueError, match="literal true"):
        SpecialistBackendResultStatementV2.model_validate(statement_wire)

    statement_wire = signed.statement.model_dump(mode="json", by_alias=True)
    statement_wire["targetIOPerformed"] = 0
    with pytest.raises(ValueError, match="literal false"):
        SpecialistBackendResultStatementV2.model_validate(statement_wire)
