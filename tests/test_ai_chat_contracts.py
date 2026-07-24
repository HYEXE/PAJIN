import json
from datetime import UTC, datetime
from hashlib import sha256
from urllib.parse import urlsplit, urlunsplit

import pytest
from pydantic import ValidationError

from pajin.domain.models import ToolRequest
from pajin.modes.ai_redteam.catalog import KISA_CATALOG
from pajin.runtime.worker import WorkerResult, WorkerStatus
from pajin.target_attestation import (
    TargetAttestationKeyState,
    TargetAttestationTrustAnchor,
    TargetAttestationVerificationKey,
    TargetExecutionAttestor,
    TargetExecutionTLSBinding,
    TargetExecutionTLSBindingV2,
    TargetExecutionTLSBindingV3,
    canonical_target_json_sha256,
    derive_target_execution_challenge,
    target_public_key_base64url,
)
from pajin.tools.ai import (
    AI_CHAT_PROXY_RECEIPT_VERSION,
    AIChatProbeInput,
    AIChatProbeOutput,
    AIChatProbeTool,
    AIChatRegressionInput,
    AIChatRegressionTool,
    ChatMessage,
    ChatRole,
    ProbeCheck,
    ProbeCheckKind,
    ProbePurpose,
    ProbeTurn,
    evaluate_trusted_regression,
    target_execution_proxy_bindings,
    verify_ai_chat_proxy_receipts,
)
from pajin.tools.base import EGRESS_HTTPS_CONNECT_RECEIPT_VERSION


def _attack_contract() -> tuple[AIChatProbeTool, ToolRequest, dict[str, object]]:
    scenario = next(
        item
        for item in KISA_CATALOG.scenarios
        if item.scenario_id == "kisa.model.system-prompt-disclosure"
    )
    assert scenario.probe is not None
    probe = AIChatProbeInput(
        scenario_id=scenario.scenario_id,
        threat_class="M03",
        session_id="pajin:test:typed-output:1",
        turns=scenario.probe.turns,
        checks=scenario.probe.checks,
    )
    tool = AIChatProbeTool()
    request = ToolRequest(
        request_id="tool_attack_1",
        agent_id="agent:test",
        tool_id=tool.spec.tool_id,
        target="https://ai.example.test/v1/chat",
        method="POST",
        arguments=probe.model_dump(mode="json"),
    )
    raw = _output(
        target=request.target,
        scenario_id=probe.scenario_id,
        threat_class=probe.threat_class,
        session_id=probe.session_id,
        turns=probe.turns,
        checks=probe.checks,
        purpose=ProbePurpose.ATTACK,
    )
    return tool, request, raw


def _output(
    *,
    target: str,
    scenario_id: str,
    threat_class: str,
    session_id: str,
    turns: list[ProbeTurn],
    checks: list[ProbeCheck],
    purpose: ProbePurpose,
) -> dict[str, object]:
    turn_records: list[dict[str, object]] = []
    for index, turn in enumerate(turns):
        markers = [check.value for check in checks if check.turn == index]
        turn_records.append(
            {
                "index": index,
                "name": turn.name,
                "request": {
                    "sessionId": session_id,
                    "messages": [message.model_dump(mode="json") for message in turn.messages],
                    "metadata": {"scenarioId": scenario_id, "turn": index},
                },
                "response": {
                    "sessionId": session_id,
                    "message": {
                        "role": "assistant",
                        "content": " ".join(["observed", *markers]),
                    },
                    "toolCalls": [],
                    "safety": {"blocked": False, "reason": None},
                    "memoryWrites": [],
                    "model": "pajin-contract-test-v1",
                },
                "responseLatencySeconds": 0.01,
            }
        )
    return {
        "target": target,
        "scenarioId": scenario_id,
        "threatClass": threat_class,
        "sessionId": session_id,
        "purpose": purpose.value,
        "vulnerable": purpose is ProbePurpose.ATTACK,
        "observation": "Typed but untrusted Worker observation.",
        "turns": turn_records,
        "checks": [
            {
                "checkId": check.check_id,
                "kind": check.kind.value,
                "turn": check.turn,
                "matched": True,
                "sensitive": check.sensitive,
            }
            for check in checks
        ],
        "sensitiveExposureCount": sum(check.sensitive for check in checks),
        "meanResponseLatencySeconds": 0.01,
        "regressionPassed": True if purpose is ProbePurpose.REGRESSION else None,
        "networkPerformed": True,
    }


def _worker_result(raw: dict[str, object]) -> WorkerResult:
    now = datetime.now(UTC)
    return WorkerResult(
        execution_id="execution_ai_contract_1",
        backend="contract-test",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        stdout=json.dumps(raw),
        started_at=now,
        finished_at=now,
    )


def _regression_contract() -> tuple[
    AIChatRegressionTool,
    ToolRequest,
    dict[str, object],
    WorkerResult,
]:
    regression = AIChatRegressionInput(
        session_id="pajin:test:receipt-validation",
        turns=[
            ProbeTurn(
                name="first",
                messages=[ChatMessage(role=ChatRole.USER, content="Say hello.")],
            ),
            ProbeTurn(
                name="second",
                messages=[ChatMessage(role=ChatRole.USER, content="Say goodbye.")],
            ),
        ],
        checks=[
            ProbeCheck(
                check_id="normal-response",
                kind=ProbeCheckKind.RESPONSE_CONTAINS,
                turn=0,
                value="hello",
            )
        ],
    )
    tool = AIChatRegressionTool()
    request = ToolRequest(
        request_id="tool_regression_receipt_validation",
        agent_id="agent:test",
        tool_id=tool.spec.tool_id,
        target="http://ai.example.test/v1/chat",
        method="POST",
        arguments=regression.model_dump(mode="json"),
    )
    raw = _output(
        target=request.target,
        scenario_id="retest.normal-chat-function",
        threat_class="A00",
        session_id=regression.session_id,
        turns=regression.turns,
        checks=regression.checks,
        purpose=ProbePurpose.REGRESSION,
    )
    worker_result = _worker_result(raw).model_copy(
        update={"backend": "docker", "network_log": _proxy_receipts(request, raw)}
    )
    return tool, request, raw, worker_result


def test_ai_probe_trusted_execution_requires_and_accepts_host_receipts() -> None:
    tool, request, raw = _attack_contract()
    worker_result = _worker_result(raw).model_copy(
        update={
            "backend": "docker",
            "network_log": _proxy_receipts(request, raw),
        }
    )
    result = tool.interpret(request, worker_result)
    assert result.success

    with pytest.raises(ValueError, match="requires complete host-observed"):
        tool.validate_trusted_execution(
            request,
            result,
            worker_result,
            network_log_trusted=False,
        )

    tool.validate_trusted_execution(
        request,
        result,
        worker_result,
        network_log_trusted=True,
    )


def _canonical_digest(value: object) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _proxy_receipts(request: ToolRequest, raw: dict[str, object]) -> str:
    if request.tool_id == AIChatProbeTool.spec.tool_id:
        probe = AIChatProbeInput.model_validate(request.arguments)
        scenario_id = probe.scenario_id
    else:
        probe = AIChatRegressionInput.model_validate(request.arguments)
        scenario_id = "retest.normal-chat-function"
    raw_turns = raw["turns"]
    assert isinstance(raw_turns, list)
    parsed_target = urlsplit(request.target)
    target = urlunsplit(
        (
            parsed_target.scheme,
            parsed_target.netloc,
            parsed_target.path,
            "<redacted>" if parsed_target.query else "",
            "",
        )
    )
    events = [json.dumps({"event": "ready", "port": 8080}, separators=(",", ":"))]
    for index, (turn, raw_turn) in enumerate(zip(probe.turns, raw_turns, strict=True)):
        assert isinstance(raw_turn, dict)
        response = raw_turn["response"]
        request_body = {
            "sessionId": probe.session_id,
            "messages": [message.model_dump(mode="json") for message in turn.messages],
            "metadata": {"scenarioId": scenario_id, "turn": index},
        }
        events.append(
            json.dumps(
                {
                    "event": "allow",
                    "receiptVersion": AI_CHAT_PROXY_RECEIPT_VERSION,
                    "sequence": index + 1,
                    "method": "POST",
                    "target": target,
                    "targetSha256": sha256(request.target.encode("utf-8")).hexdigest(),
                    "address": "203.0.113.10",
                    "status": 200,
                    "requestJsonSha256": _canonical_digest(request_body),
                    "responseBodySha256": _canonical_digest(response),
                    "responseJsonSha256": _canonical_digest(response),
                },
                separators=(",", ":"),
            )
        )
    return "\n".join(events)


def test_ai_chat_probe_output_has_strict_nested_wire_contract() -> None:
    _tool, _request, raw = _attack_contract()

    output = AIChatProbeOutput.model_validate(raw)

    assert output.purpose is ProbePurpose.ATTACK
    assert output.turns[0].request.metadata is not None
    assert output.turns[0].response.message.role is ChatRole.ASSISTANT
    assert output.model_dump(mode="json", by_alias=True) == raw

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AIChatProbeOutput.model_validate({**raw, "command": ["curl", raw["target"]]})


def test_ai_chat_probe_tool_uses_typed_output_and_binds_request_identity() -> None:
    tool, request, raw = _attack_contract()

    result = tool.interpret(request, _worker_result(raw))

    assert result.success is True
    assert result.data == AIChatProbeOutput.model_validate(raw).model_dump(
        mode="json",
        by_alias=True,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("target", "https://different.example/v1/chat"),
        ("scenarioId", "kisa.model.jailbreak-policy-bypass"),
        ("threatClass", "M06"),
        ("sessionId", "pajin:different:session"),
        ("purpose", "regression"),
        ("networkPerformed", False),
    ],
)
def test_ai_chat_probe_tool_rejects_worker_identity_substitution(
    field: str,
    value: object,
) -> None:
    tool, request, raw = _attack_contract()
    raw[field] = value

    result = tool.interpret(request, _worker_result(raw))

    assert result.success is False
    assert result.data == {}
    assert result.error is not None
    assert "invalid AI probe output" in result.error


def test_ai_chat_output_keeps_worker_verdict_typed_but_not_authoritative() -> None:
    _tool, _request, raw = _attack_contract()
    raw["vulnerable"] = False
    checks = raw["checks"]
    assert isinstance(checks, list)
    assert isinstance(checks[0], dict)
    checks[0]["matched"] = False

    output = AIChatProbeOutput.model_validate(raw)

    assert output.vulnerable is False
    assert output.checks[0].matched is False
    assert "PAJIN_SYSTEM_SENTINEL_COBALT" in output.turns[0].response.message.content


def test_ai_chat_regression_tool_requires_regression_specific_output() -> None:
    regression = AIChatRegressionInput(
        session_id="pajin:test:regression:1",
        turns=[
            ProbeTurn(
                name="normal-use",
                messages=[ChatMessage(role=ChatRole.USER, content="Say hello.")],
            )
        ],
        checks=[
            ProbeCheck(
                check_id="normal-response",
                kind=ProbeCheckKind.RESPONSE_CONTAINS,
                turn=0,
                value="hello",
            )
        ],
    )
    tool = AIChatRegressionTool()
    request = ToolRequest(
        request_id="tool_regression_1",
        agent_id="agent:test",
        tool_id=tool.spec.tool_id,
        target="https://ai.example.test/v1/chat",
        method="POST",
        arguments=regression.model_dump(mode="json"),
    )
    raw = _output(
        target=request.target,
        scenario_id="retest.normal-chat-function",
        threat_class="A00",
        session_id=regression.session_id,
        turns=regression.turns,
        checks=regression.checks,
        purpose=ProbePurpose.REGRESSION,
    )
    raw["vulnerable"] = False

    assert tool.interpret(request, _worker_result(raw)).success is True

    raw["regressionPassed"] = None
    rejected = tool.interpret(request, _worker_result(raw))
    assert rejected.success is False
    assert rejected.error is not None
    assert "regressionPassed" in rejected.error


def test_trusted_regression_ignores_forged_worker_verdict_and_check_flags() -> None:
    regression = AIChatRegressionInput(
        session_id="pajin:test:regression:forged",
        turns=[
            ProbeTurn(
                name="normal-use",
                messages=[ChatMessage(role=ChatRole.USER, content="Say hello.")],
            )
        ],
        checks=[
            ProbeCheck(
                check_id="normal-response",
                kind=ProbeCheckKind.RESPONSE_CONTAINS,
                turn=0,
                value="hello",
            )
        ],
    )
    tool = AIChatRegressionTool()
    request = ToolRequest(
        request_id="tool_regression_forged",
        agent_id="agent:test",
        tool_id=tool.spec.tool_id,
        target="https://ai.example.test/v1/chat",
        method="POST",
        arguments=regression.model_dump(mode="json"),
    )
    raw = _output(
        target=request.target,
        scenario_id="retest.normal-chat-function",
        threat_class="A00",
        session_id=regression.session_id,
        turns=regression.turns,
        checks=regression.checks,
        purpose=ProbePurpose.REGRESSION,
    )
    turns = raw["turns"]
    assert isinstance(turns, list)
    assert isinstance(turns[0], dict)
    response = turns[0]["response"]
    assert isinstance(response, dict)
    message = response["message"]
    assert isinstance(message, dict)
    message["content"] = "normal response without the expected marker"
    worker_result = _worker_result(raw)
    worker_result = worker_result.model_copy(
        update={
            "backend": "docker",
            "network_log": _proxy_receipts(request, raw),
        }
    )
    tool_result = tool.interpret(request, worker_result)

    assert tool_result.success is True
    assert tool_result.data["regressionPassed"] is True
    assert tool_result.data["checks"][0]["matched"] is True
    assert (
        evaluate_trusted_regression(
            request,
            tool_result,
            worker_result,
            network_log_trusted=True,
        )
        is False
    )


def test_trusted_regression_is_not_measured_without_host_proxy_provenance() -> None:
    regression = AIChatRegressionInput(
        session_id="pajin:test:regression:untrusted",
        turns=[
            ProbeTurn(
                name="normal-use",
                messages=[ChatMessage(role=ChatRole.USER, content="Say hello.")],
            )
        ],
        checks=[
            ProbeCheck(
                check_id="normal-response",
                kind=ProbeCheckKind.RESPONSE_CONTAINS,
                turn=0,
                value="hello",
            )
        ],
    )
    tool = AIChatRegressionTool()
    request = ToolRequest(
        request_id="tool_regression_untrusted",
        agent_id="agent:test",
        tool_id=tool.spec.tool_id,
        target="http://ai.example.test/v1/chat",
        method="POST",
        arguments=regression.model_dump(mode="json"),
    )
    raw = _output(
        target=request.target,
        scenario_id="retest.normal-chat-function",
        threat_class="A00",
        session_id=regression.session_id,
        turns=regression.turns,
        checks=regression.checks,
        purpose=ProbePurpose.REGRESSION,
    )
    raw["vulnerable"] = False
    worker_result = _worker_result(raw).model_copy(
        update={
            "backend": "docker",
            "network_log": _proxy_receipts(request, raw),
        }
    )
    tool_result = tool.interpret(request, worker_result)

    assert tool_result.success is True
    assert (
        evaluate_trusted_regression(
            request,
            tool_result,
            worker_result,
            network_log_trusted=False,
        )
        is None
    )


def test_trusted_proxy_receipts_require_complete_ordered_non_error_log() -> None:
    _tool, request, raw, worker_result = _regression_contract()
    output = AIChatProbeOutput.model_validate(raw)
    lines = worker_result.network_log.splitlines()
    assert verify_ai_chat_proxy_receipts(
        request,
        worker_result,
        output,
        network_log_trusted=True,
    )

    malformed_logs = {
        "missing its initial ready": "\n".join(lines[1:]),
        "do not cover every": "\n".join(lines[:-1]),
        "duplicate or incomplete": "\n".join([lines[0], lines[1], lines[1]]),
        "denied or failed": "\n".join(
            [lines[0], json.dumps({"event": "error", "error": "upstream failed"})]
        ),
        "duplicate or late ready": "\n".join([lines[0], lines[0], *lines[1:]]),
    }
    for message, network_log in malformed_logs.items():
        malformed = worker_result.model_copy(update={"network_log": network_log})
        with pytest.raises(ValueError, match=message):
            verify_ai_chat_proxy_receipts(
                request,
                malformed,
                output,
                network_log_trusted=True,
            )

    wrong_target_digest = json.loads(lines[1])
    wrong_target_digest["targetSha256"] = "0" * 64
    mismatched = worker_result.model_copy(
        update={"network_log": "\n".join([lines[0], json.dumps(wrong_target_digest), *lines[2:]])}
    )
    with pytest.raises(ValueError, match="differs from its host-observed"):
        verify_ai_chat_proxy_receipts(
            request,
            mismatched,
            output,
            network_log_trusted=True,
        )

    missing_body_digest = json.loads(lines[1])
    missing_body_digest.pop("responseBodySha256")
    malformed = worker_result.model_copy(
        update={"network_log": "\n".join([lines[0], json.dumps(missing_body_digest), *lines[2:]])}
    )
    with pytest.raises(ValueError, match="receipt is invalid"):
        verify_ai_chat_proxy_receipts(
            request,
            malformed,
            output,
            network_log_trusted=True,
        )

    empty = worker_result.model_copy(update={"network_log": ""})
    assert not verify_ai_chat_proxy_receipts(
        request,
        empty,
        output,
        network_log_trusted=True,
    )


def test_trusted_ai_transcript_rechecks_reject_duplicate_worker_json() -> None:
    tool, request, raw, worker_result = _regression_contract()
    output = AIChatProbeOutput.model_validate(raw)
    tool_result = tool.interpret(request, worker_result)
    assert tool_result.success
    encoded = json.dumps(raw, separators=(",", ":"))
    ambiguous = worker_result.model_copy(update={"stdout": '{"turns":[],' + encoded[1:]})

    with pytest.raises(ValueError, match="cannot be bound"):
        verify_ai_chat_proxy_receipts(
            request,
            ambiguous,
            output,
            network_log_trusted=True,
        )
    with pytest.raises(ValueError, match="invalid raw AI regression transcript"):
        evaluate_trusted_regression(
            request,
            tool_result,
            ambiguous,
            network_log_trusted=True,
        )


@pytest.mark.parametrize(
    (
        "tls_peer_leaf_spki_sha256",
        "tls_session_binding_sha256",
        "receipt_tls_session_binding_sha256",
        "expected_binding_type",
        "expected_error",
    ),
    [
        (None, None, None, TargetExecutionTLSBinding, False),
        ("c" * 64, None, None, TargetExecutionTLSBindingV2, False),
        ("c" * 64, "d" * 64, "d" * 64, TargetExecutionTLSBindingV3, False),
        ("c" * 64, "d" * 64, "e" * 64, TargetExecutionTLSBindingV3, True),
    ],
)
def test_target_attested_https_binds_opaque_connect_to_signed_application_exchange(
    tls_peer_leaf_spki_sha256: str | None,
    tls_session_binding_sha256: str | None,
    receipt_tls_session_binding_sha256: str | None,
    expected_binding_type: (
        type[TargetExecutionTLSBinding]
        | type[TargetExecutionTLSBindingV2]
        | type[TargetExecutionTLSBindingV3]
    ),
    expected_error: bool,
) -> None:
    now = datetime(2026, 7, 24, 1, 2, 3, tzinfo=UTC)
    private_key = bytes(range(32))
    anchor = TargetAttestationTrustAnchor(
        trust_domain="pajin.example/targets",
        issuer="PAJIN HTTPS target",
        target_profile="kisa-https-v1",
        keys=[
            TargetAttestationVerificationKey(
                key_id="target-key-https-01",
                public_key_base64url=target_public_key_base64url(private_key),
                state=TargetAttestationKeyState.ACTIVE,
                not_before=now,
            )
        ],
    )
    attestor = TargetExecutionAttestor.from_private_key_bytes(
        active_key_id="target-key-https-01",
        private_key=private_key,
        trust_anchor=anchor,
        clock=lambda: now,
    )
    scenario = next(
        item
        for item in KISA_CATALOG.scenarios
        if item.scenario_id == "kisa.model.system-prompt-disclosure"
    )
    assert scenario.probe is not None
    probe = AIChatProbeInput(
        scenario_id=scenario.scenario_id,
        threat_class="M03",
        session_id="pajin:test:https-target:1",
        turns=scenario.probe.turns[:1],
        checks=[check for check in scenario.probe.checks if check.turn == 0],
    )
    request = ToolRequest(
        request_id=f"tool_replay_{'1' * 32}",
        agent_id="agent:test",
        tool_id=AIChatProbeTool.spec.tool_id,
        target="https://ai.example.test/v1/chat",
        method="POST",
        arguments=probe.model_dump(mode="json"),
    )
    challenge = derive_target_execution_challenge(
        permit_digest="a" * 64,
        replay_request_id=request.request_id,
        batch_id=f"replay-batch_{'2' * 32}",
        item_id=f"replay-item_{'3' * 32}",
        ticket_id=f"replay-ticket_{'4' * 32}",
        fencing_value=1,
        call_ordinal=1,
        target=request.target,
        method=request.method,
        compiled_argument_digest="b" * 64,
        issued_at=now,
        expires_at=now.replace(second=23),
    )
    raw = _output(
        target=request.target,
        scenario_id=probe.scenario_id,
        threat_class=probe.threat_class,
        session_id=probe.session_id,
        turns=probe.turns,
        checks=probe.checks,
        purpose=ProbePurpose.ATTACK,
    )
    raw_turns = raw["turns"]
    assert isinstance(raw_turns, list) and isinstance(raw_turns[0], dict)
    raw_request = raw_turns[0]["request"]
    raw_response = raw_turns[0]["response"]
    assert isinstance(raw_request, dict) and isinstance(raw_response, dict)
    if tls_peer_leaf_spki_sha256 is not None:
        raw_turns[0]["tlsPeerLeafSpkiSha256"] = tls_peer_leaf_spki_sha256
    if tls_session_binding_sha256 is not None:
        raw_turns[0]["tlsSessionBindingSha256"] = tls_session_binding_sha256
    metadata = raw_request["metadata"]
    assert isinstance(metadata, dict)
    metadata["targetChallenge"] = challenge.model_dump(mode="json")
    metadata["targetExchangeOrdinal"] = 1
    statement_fields: dict[str, object] = {
        "challenge_id": challenge.challenge_id,
        "challenge_sha256": challenge.digest,
        "permit_digest": challenge.permit_digest,
        "replay_request_id": challenge.replay_request_id,
        "batch_id": challenge.batch_id,
        "item_id": challenge.item_id,
        "ticket_id": challenge.ticket_id,
        "fencing_value": challenge.fencing_value,
        "call_ordinal": challenge.call_ordinal,
        "exchange_ordinal": 1,
        "target_sha256": challenge.target_sha256,
        "method": challenge.method,
        "request_json_sha256": canonical_target_json_sha256(raw_request),
        "response_payload_sha256": canonical_target_json_sha256(raw_response),
        "status": 200,
    }
    if receipt_tls_session_binding_sha256 is not None:
        statement_fields.update(
            {
                "tls_version": "TLSv1.2",
                "tls_session_binding": "tls-unique-sha256",
                "tls_session_binding_sha256": receipt_tls_session_binding_sha256,
            }
        )
    receipt = attestor.attest(statement_fields)
    raw_response["targetReceipt"] = receipt.model_dump(mode="json")
    output = AIChatProbeOutput.model_validate(raw)
    authority = "ai.example.test:443"
    connect_event = {
        "event": "allow",
        "receiptVersion": EGRESS_HTTPS_CONNECT_RECEIPT_VERSION,
        "sequence": 1,
        "method": "CONNECT",
        "authority": authority,
        "authoritySha256": sha256(authority.encode()).hexdigest(),
        "address": "203.0.113.10",
        "applicationVisibility": "opaque",
        "methodEnforcement": "trusted-worker-only",
        "pathEnforcement": "authority-only",
    }
    worker_result = _worker_result(raw).model_copy(
        update={
            "backend": "docker",
            "network_log": "\n".join(
                [
                    json.dumps({"event": "ready", "port": 8080}),
                    json.dumps(connect_event),
                ]
            ),
        }
    )

    assert not verify_ai_chat_proxy_receipts(
        request,
        worker_result,
        output,
        network_log_trusted=True,
    )
    assert verify_ai_chat_proxy_receipts(
        request,
        worker_result,
        output,
        network_log_trusted=True,
        allow_target_attested_https=True,
    )
    if expected_error:
        with pytest.raises(ValueError, match="Target-signed TLS session binding"):
            target_execution_proxy_bindings(
                request,
                worker_result,
                output,
                expected_challenge=challenge,
                network_log_trusted=True,
            )
        return
    bindings = target_execution_proxy_bindings(
        request,
        worker_result,
        output,
        expected_challenge=challenge,
        network_log_trusted=True,
    )

    assert len(bindings) == 1
    assert type(bindings[0]) is expected_binding_type
    assert bindings[0].connect_authority == authority
    assert bindings[0].target_receipt_sha256 == receipt.digest
    if isinstance(bindings[0], (TargetExecutionTLSBindingV2, TargetExecutionTLSBindingV3)):
        assert bindings[0].tls_peer_leaf_spki_sha256 == tls_peer_leaf_spki_sha256
    if isinstance(bindings[0], TargetExecutionTLSBindingV3):
        assert bindings[0].tls_session_binding_sha256 == tls_session_binding_sha256
