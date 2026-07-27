from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256

import pytest

from pajin.capabilities import (
    EXISTING_KISA_REPLAY_PLAN_API_VERSION,
    CapabilityAuthorityError,
    CapabilityAuthorityRole,
    CapabilityDefinitionError,
    CapabilityMaturity,
    CapabilityOracleDecision,
    CapabilitySideEffectClass,
    ExistingModeCapabilityBundle,
    existing_mode_capability_bundle,
    existing_mode_capability_registrations,
)
from pajin.domain.ctf import CTFScenario
from pajin.domain.models import ToolRequest, ToolResult
from pajin.modes.ai_redteam.catalog import KISA_CATALOG
from pajin.runtime.worker import WorkerResult, WorkerStatus
from pajin.tools.ai import AIChatProbeInput, AIChatProbeTool, ProbePurpose
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import (
    BOOLEAN_SQLI_SCENARIO,
    BooleanSQLiProbeInput,
    BooleanSQLiProbeTool,
)
from pajin.tools.ctf import (
    CTFCryptoXORInput,
    CTFCryptoXORTool,
    CTFWebBackupProbeTool,
    crypto_artifact_target,
)
from pajin.tools.http import HTTPGetTool
from pajin.tools.mock import MockAgentProbe


def _tools() -> tuple[ToolRegistry, AIChatProbeTool]:
    registry = ToolRegistry()
    ai_tool = AIChatProbeTool()
    for tool in (
        MockAgentProbe(),
        ai_tool,
        BooleanSQLiProbeTool(),
        CTFWebBackupProbeTool(),
        CTFCryptoXORTool(),
    ):
        registry.register(tool)
    return registry, ai_tool


def _bundle() -> ExistingModeCapabilityBundle:
    tools, _ai_tool = _tools()
    return existing_mode_capability_bundle(tools)


def _manifest(bundle: ExistingModeCapabilityBundle, capability_id: str):
    return next(
        manifest
        for manifest in bundle.capabilities()
        if manifest.capability.capability_id == capability_id
    )


def _authority(
    bundle: ExistingModeCapabilityBundle,
    capability_id: str,
    role: CapabilityAuthorityRole,
):
    manifest = _manifest(bundle, capability_id)
    return bundle.authorities.authority(manifest.reference(), role)


def _result(
    request: ToolRequest,
    data: dict[str, object],
    *,
    success: bool = True,
) -> ToolResult:
    now = datetime(2026, 7, 27, 1, tzinfo=UTC)
    return ToolResult(
        request_id=request.request_id,
        tool_id=request.tool_id,
        success=success,
        started_at=now,
        finished_at=now,
        data=data,
        error=None if success else "bounded failure",
    )


def _kisa_request(
    scenario_id: str = "kisa.model.system-prompt-disclosure",
) -> ToolRequest:
    scenario = next(item for item in KISA_CATALOG.scenarios if item.scenario_id == scenario_id)
    assert scenario.probe is not None
    probe = AIChatProbeInput(
        scenario_id=scenario.scenario_id,
        threat_class=next(iter(scenario.threat_classes)),
        session_id=f"pajin:test:{scenario.scenario_id.rsplit('.', 1)[-1]}",
        turns=scenario.probe.turns,
        checks=scenario.probe.checks,
    )
    return ToolRequest(
        request_id=f"request_{scenario.scenario_id.rsplit('.', 1)[-1]}",
        agent_id="agent:test",
        tool_id=scenario.tool_id,
        target="https://ai.example.test/v1/chat",
        method=scenario.method,
        arguments=probe.model_dump(mode="json"),
    )


def _kisa_output(request: ToolRequest) -> dict[str, object]:
    probe = AIChatProbeInput.model_validate(request.arguments)
    turn_records: list[dict[str, object]] = []
    for index, turn in enumerate(probe.turns):
        markers = [check.value for check in probe.checks if check.turn == index]
        turn_records.append(
            {
                "index": index,
                "name": turn.name,
                "request": {
                    "sessionId": probe.session_id,
                    "messages": [message.model_dump(mode="json") for message in turn.messages],
                    "metadata": {
                        "scenarioId": probe.scenario_id,
                        "turn": index,
                    },
                },
                "response": {
                    "sessionId": probe.session_id,
                    "message": {
                        "role": "assistant",
                        "content": " ".join(["observed", *markers]),
                    },
                    "toolCalls": [],
                    "safety": {"blocked": False, "reason": None},
                    "memoryWrites": [],
                },
                "responseLatencySeconds": 0.01,
            }
        )
    return {
        "target": request.target,
        "scenarioId": probe.scenario_id,
        "threatClass": probe.threat_class,
        "sessionId": probe.session_id,
        "purpose": ProbePurpose.ATTACK.value,
        # These Worker-authored fields are deliberately false. The Oracle recomputes support.
        "vulnerable": False,
        "observation": "untrusted Worker observation",
        "turns": turn_records,
        "checks": [
            {
                "checkId": check.check_id,
                "kind": check.kind.value,
                "turn": check.turn,
                "matched": False,
                "sensitive": check.sensitive,
            }
            for check in probe.checks
        ],
        "sensitiveExposureCount": sum(check.sensitive for check in probe.checks),
        "meanResponseLatencySeconds": 0.01,
        "regressionPassed": None,
        "networkPerformed": True,
    }


def _boolean_sqli_output(target: str) -> dict[str, object]:
    digest = sha256(b"{}").hexdigest()
    observations = [
        {
            "name": "baseline",
            "status": 200,
            "recordCount": 1,
            "synthetic": True,
            "bodySha256": digest,
            "responseBodyBase64": "e30=",
        },
        {
            "name": "negative-control",
            "status": 200,
            "recordCount": 0,
            "synthetic": True,
            "bodySha256": digest,
            "responseBodyBase64": "e30=",
        },
        {
            "name": "boolean-probe",
            "status": 200,
            "recordCount": 3,
            "synthetic": True,
            "bodySha256": digest,
            "responseBodyBase64": "e30=",
        },
    ]
    return {
        "target": target,
        "scenarioId": BOOLEAN_SQLI_SCENARIO,
        "vulnerable": False,
        "checks": {
            "baselineSingleRecord": False,
            "negativeControlEmpty": False,
            "booleanProbeExpanded": False,
            "syntheticLabOnly": False,
        },
        "observations": observations,
        "networkPerformed": True,
    }


def test_existing_mode_bundle_registers_only_seven_explicit_experimental_capabilities() -> None:
    bundle = _bundle()

    definitions = bundle.definitions.definitions()
    assert len(definitions) == 7
    assert len(bundle.capabilities()) == 7
    assert {definition.capability_id for definition in definitions} == {
        "pajin.ai.kisa.indirect-tool-hijacking",
        "pajin.ai.kisa.system-prompt-disclosure",
        "pajin.ai.kisa.jailbreak-policy-bypass",
        "pajin.ai.kisa.memory-poisoning-persistence",
        "pajin.bug-bounty.boolean-sqli-lab",
        "pajin.ctf.web-exposed-backup-config",
        "pajin.ctf.crypto-single-byte-xor",
    }
    assert all(definition.maturity is CapabilityMaturity.EXPERIMENTAL for definition in definitions)
    assert all(len(manifest.authorities) == 7 for manifest in bundle.capabilities())

    registrations = existing_mode_capability_registrations()
    assert registrations == existing_mode_capability_registrations()
    assert len({item.parameter_schema_digest for item in registrations}) == 7


def test_existing_mode_bundle_does_not_discover_unregistered_extra_tools() -> None:
    tools, _ai_tool = _tools()
    tools.register(HTTPGetTool())

    bundle = existing_mode_capability_bundle(tools)

    assert len(bundle.capabilities()) == 7
    assert "http.get" not in {
        definition.tool.tool_id for definition in bundle.definitions.definitions()
    }


def test_existing_mode_bundle_fails_closed_for_missing_or_changed_tools() -> None:
    tools = ToolRegistry()
    tools.register(MockAgentProbe())

    with pytest.raises(CapabilityDefinitionError, match="unavailable"):
        existing_mode_capability_bundle(tools)

    tools, ai_tool = _tools()
    bundle = existing_mode_capability_bundle(tools)
    ai_tool.spec = ai_tool.spec.model_copy(
        update={"description": "mutated after Capability registration"}
    )

    with pytest.raises(CapabilityAuthorityError, match="identity changed"):
        bundle.capabilities()


def test_kisa_materializer_compiler_and_executor_preserve_exact_catalog_contract() -> None:
    bundle = _bundle()
    capability_id = "pajin.ai.kisa.system-prompt-disclosure"
    request = _kisa_request()
    materializer = _authority(
        bundle,
        capability_id,
        CapabilityAuthorityRole.MATERIALIZER,
    )

    arguments = materializer.materialize(request.arguments)
    compiler = _authority(
        bundle,
        capability_id,
        CapabilityAuthorityRole.ACTION_COMPILER,
    )
    compiled = compiler.compile(request, arguments)
    executor = _authority(
        bundle,
        capability_id,
        CapabilityAuthorityRole.EXECUTOR_ADAPTER,
    )
    job = executor.prepare(compiled)

    assert compiled.arguments == arguments
    assert job.command == ["ai-chat-probe"]

    wrong = dict(request.arguments)
    wrong["scenario_id"] = "kisa.model.jailbreak-policy-bypass"
    with pytest.raises(CapabilityAuthorityError, match="exact catalog probe"):
        materializer.materialize(wrong)


def test_kisa_oracle_recomputes_support_and_replay_is_explicitly_non_executable() -> None:
    bundle = _bundle()
    capability_id = "pajin.ai.kisa.system-prompt-disclosure"
    request = _kisa_request()
    result = _result(request, _kisa_output(request))
    oracle = _authority(
        bundle,
        capability_id,
        CapabilityAuthorityRole.SUCCESS_ORACLE,
    )
    replay = _authority(
        bundle,
        capability_id,
        CapabilityAuthorityRole.REPLAY_STRATEGY,
    )

    assert oracle.evaluate(request, result) is CapabilityOracleDecision.SUCCEEDED
    plan = replay.plan_replay(request, result)
    assert plan is not None
    assert plan["apiVersion"] == EXISTING_KISA_REPLAY_PLAN_API_VERSION
    assert plan["executable"] is False
    assert plan["newAuthorizationRequired"] is True
    assert plan["scenarioId"] == "kisa.model.system-prompt-disclosure"
    assert isinstance(plan["confirmationContract"], dict)
    assert isinstance(plan["negativeRetestContract"], dict)


def test_non_replayable_kisa_mock_capability_never_emits_replay_plan() -> None:
    bundle = _bundle()
    capability_id = "pajin.ai.kisa.indirect-tool-hijacking"
    request = ToolRequest(
        request_id="request_mock_agent",
        agent_id="agent:test",
        tool_id="mock.agent-probe",
        target="mock://agent",
        method="POST",
        arguments={"simulation": {"unauthorizedToolCall": True}},
    )
    result = _result(
        request,
        {
            "target": request.target,
            "vulnerable": True,
            "observation": (
                "target accepted an untrusted instruction and invoked a protected tool"
            ),
            "networkPerformed": False,
        },
    )
    oracle = _authority(
        bundle,
        capability_id,
        CapabilityAuthorityRole.SUCCESS_ORACLE,
    )
    replay = _authority(
        bundle,
        capability_id,
        CapabilityAuthorityRole.REPLAY_STRATEGY,
    )

    assert oracle.evaluate(request, result) is CapabilityOracleDecision.SUCCEEDED
    assert replay.plan_replay(request, result) is None


def test_bug_bounty_oracle_ignores_worker_verdict_and_recomputes_observations() -> None:
    bundle = _bundle()
    capability_id = "pajin.bug-bounty.boolean-sqli-lab"
    request = ToolRequest(
        request_id="request_boolean_sqli",
        agent_id="agent:test",
        tool_id="bug-bounty.boolean-sqli-probe",
        target="http://lab.example/v1/users/lookup",
        method="GET",
        arguments=BooleanSQLiProbeInput().model_dump(mode="json"),
    )
    result = _result(request, _boolean_sqli_output(request.target))
    oracle = _authority(
        bundle,
        capability_id,
        CapabilityAuthorityRole.SUCCESS_ORACLE,
    )

    assert oracle.evaluate(request, result) is CapabilityOracleDecision.SUCCEEDED

    forged = result.model_copy(deep=True)
    forged.data["observations"][2]["recordCount"] = 1
    assert oracle.evaluate(request, forged) is CapabilityOracleDecision.FAILED


def test_ctf_crypto_oracle_recomputes_candidate_and_adapter_normalizes_worker_output() -> None:
    plaintext = b"PAJIN{capability_adapter}"
    key = 73
    ciphertext = bytes(value ^ key for value in plaintext)
    ciphertext_hex = ciphertext.hex()
    artifact_sha256 = sha256(ciphertext).hexdigest()
    target = crypto_artifact_target("crypto-adapter", artifact_sha256)
    request = ToolRequest(
        request_id="request_ctf_crypto",
        agent_id="agent:test",
        tool_id="ctf.crypto-single-byte-xor",
        target=target,
        method="POST",
        arguments=CTFCryptoXORInput(
            challengeId="crypto-adapter",
            scenarioId=CTFScenario.CRYPTO_SINGLE_BYTE_XOR,
            artifactSha256=artifact_sha256,
            ciphertextHex=ciphertext_hex,
        ).model_dump(mode="json", by_alias=True),
    )
    output = {
        "target": target,
        "challengeId": "crypto-adapter",
        "scenarioId": CTFScenario.CRYPTO_SINGLE_BYTE_XOR.value,
        "artifactSha256": artifact_sha256,
        "solved": True,
        "candidateFlag": plaintext.decode("ascii"),
        "key": key,
        "attemptedKeys": 256,
        "synthetic": True,
        "networkPerformed": False,
    }
    now = datetime(2026, 7, 27, 2, tzinfo=UTC)
    worker_result = WorkerResult(
        execution_id="execution_ctf_capability",
        backend="contract-test",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        stdout=json.dumps(output),
        started_at=now,
        finished_at=now,
    )
    bundle = _bundle()
    capability_id = "pajin.ctf.crypto-single-byte-xor"
    normalizer = _authority(
        bundle,
        capability_id,
        CapabilityAuthorityRole.RESULT_NORMALIZER,
    )
    normalized = normalizer.normalize(request, worker_result)
    oracle = _authority(
        bundle,
        capability_id,
        CapabilityAuthorityRole.SUCCESS_ORACLE,
    )

    assert normalized.success
    assert oracle.evaluate(request, normalized) is CapabilityOracleDecision.SUCCEEDED

    forged = normalized.model_copy(deep=True)
    forged.data["key"] = key + 1
    assert oracle.evaluate(request, forged) is CapabilityOracleDecision.INCONCLUSIVE


def test_existing_capability_cleanup_is_explicitly_empty_and_side_effects_are_bounded() -> None:
    bundle = _bundle()
    capability_id = "pajin.ctf.crypto-single-byte-xor"
    request = ToolRequest(
        request_id="request_cleanup",
        agent_id="agent:test",
        tool_id="ctf.crypto-single-byte-xor",
        target="http://artifact.invalid/example/" + "0" * 64,
        method="POST",
        arguments={},
    )
    result = _result(request, {}, success=False)
    cleanup = _authority(
        bundle,
        capability_id,
        CapabilityAuthorityRole.CLEANUP_HANDLER,
    )

    assert cleanup.plan_cleanup(request, result) is None
    definitions = bundle.definitions.definitions()
    assert {definition.side_effect_class for definition in definitions} <= {
        CapabilitySideEffectClass.NONE,
        CapabilitySideEffectClass.READ_ONLY,
    }
    assert all(not definition.cleanup_required for definition in definitions)
