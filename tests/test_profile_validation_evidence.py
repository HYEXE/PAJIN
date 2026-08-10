from __future__ import annotations

import json
import os
import subprocess
import sys
from copy import deepcopy
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.discovery import ValidationDepth
from pajin.domain.manifest import load_manifest
from pajin.domain.models import CampaignManifest
from pajin.modes.ai_redteam import (
    KISACandidateProducer,
    KISAPlannerRuntime,
    KISAReplayCoordinator,
    KISAValidatorRuntime,
)
from pajin.modes.ai_redteam.models import EvaluationThresholds
from pajin.modes.ai_redteam.validation_controls import (
    KISAValidationControlBatchOutcome,
    KISAValidationControlCoordinator,
)
from pajin.policy.engine import PolicyEngine
from pajin.runtime.control import BudgetController
from pajin.runtime.worker import (
    DockerWorkerBackend,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.ai import AI_CHAT_PROXY_RECEIPT_VERSION, AIChatProbeTool
from pajin.tools.base import ToolRegistry, audit_http_target, http_target_sha256
from pajin.tools.gateway import RequestRateLimitLedger
from pajin.workflow.multi_agent import MultiAgentCampaignRunner
from pajin.workflow.profile_evidence import (
    PROFILE_VALIDATION_EVIDENCE_API_VERSION,
    ProfileValidationEvidenceAssessment,
    ProfileValidationEvidenceError,
    evaluate_kisa_profile_validation_evidence,
    verify_kisa_profile_validation_evidence,
)


class _KISAControlContrastWorker:
    async def run(self, job: WorkerJob) -> WorkerResult:
        started_at = datetime.now(UTC)
        payload = json.loads(job.stdin)
        probe = payload["probe"]
        turns: list[dict[str, object]] = []
        for index, turn in enumerate(probe["turns"]):
            prompt = turn["messages"][0]["content"]
            content = (
                "vulnerable response PAJIN_SYSTEM_SENTINEL_COBALT"
                if "internal system instructions" in prompt
                else "READY"
            )
            turns.append(
                {
                    "index": index,
                    "name": turn["name"],
                    "request": {
                        "sessionId": probe["session_id"],
                        "messages": turn["messages"],
                        "metadata": {
                            "scenarioId": probe["scenario_id"],
                            "turn": index,
                        },
                    },
                    "response": {
                        "sessionId": probe["session_id"],
                        "message": {"role": "assistant", "content": content},
                        "toolCalls": [],
                        "safety": {"blocked": False, "reason": None},
                        "memoryWrites": [],
                        "model": "pajin-val004a-fixture-v1",
                    },
                    "responseLatencySeconds": 0.01,
                }
            )
        output = {
            "target": payload["target"],
            "scenarioId": probe["scenario_id"],
            "threatClass": probe["threat_class"],
            "sessionId": probe["session_id"],
            "purpose": "attack",
            "vulnerable": False,
            "observation": "worker-authored verdict is not trusted",
            "turns": turns,
            "checks": [
                {
                    "checkId": check["check_id"],
                    "kind": check["kind"],
                    "turn": check["turn"],
                    "matched": False,
                    "sensitive": check["sensitive"],
                }
                for check in probe["checks"]
            ],
            "sensitiveExposureCount": 0,
            "meanResponseLatencySeconds": 0.01,
            "networkPerformed": True,
        }
        return WorkerResult(
            execution_id=job.execution_id,
            backend="control-contrast-fixture",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(output, separators=(",", ":")),
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )


def _canonical_digest(value: object) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _proxy_receipt_log(job: WorkerJob, worker_result: WorkerResult) -> str:
    payload = json.loads(job.stdin)
    output = json.loads(worker_result.stdout)
    probe = payload["probe"]
    events = [json.dumps({"event": "ready", "port": 8080}, separators=(",", ":"))]
    for index, (turn, observed) in enumerate(zip(probe["turns"], output["turns"], strict=True)):
        request_body = {
            "sessionId": probe["session_id"],
            "messages": turn["messages"],
            "metadata": {"scenarioId": probe["scenario_id"], "turn": index},
        }
        response = observed["response"]
        events.append(
            json.dumps(
                {
                    "event": "allow",
                    "receiptVersion": AI_CHAT_PROXY_RECEIPT_VERSION,
                    "sequence": index + 1,
                    "method": "POST",
                    "target": audit_http_target(payload["target"]),
                    "targetSha256": http_target_sha256(payload["target"]),
                    "address": "172.17.0.1",
                    "status": 200,
                    "requestJsonSha256": _canonical_digest(request_body),
                    "responseBodySha256": _canonical_digest(response),
                    "responseJsonSha256": _canonical_digest(response),
                },
                separators=(",", ":"),
            )
        )
    return "\n".join(events)


def _trusted_backend(worker: _KISAControlContrastWorker) -> DockerWorkerBackend:
    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})

    async def run(
        job: WorkerJob,
        *,
        secrets: object = None,
    ) -> WorkerResult:
        del secrets
        result = await worker.run(job)
        return result.model_copy(
            update={"backend": "docker", "network_log": _proxy_receipt_log(job, result)}
        )

    backend.run = run  # type: ignore[method-assign]
    return backend


def _campaign() -> CampaignManifest:
    campaign = load_manifest(Path("examples/kisa-ai-chat-lab.yaml"))
    return campaign.model_copy(
        update={
            "spec": campaign.spec.model_copy(
                update={
                    "objectives": ["detect system prompt disclosure"],
                    "threat_classes": ["M03"],
                    "budgets": campaign.spec.budgets.model_copy(update={"max_tool_calls": 20}),
                }
            )
        }
    )


def _tools() -> ToolRegistry:
    tools = ToolRegistry()
    tools.register(AIChatProbeTool())
    return tools


@pytest.mark.asyncio
async def test_val004a_evaluates_exact_kisa_replay_and_control_evidence(
    tmp_path: Path,
) -> None:
    campaign = _campaign()
    tools = _tools()
    backend = _trusted_backend(_KISAControlContrastWorker())
    budget = BudgetController(campaign.spec.budgets)
    rate_limits = RequestRateLimitLedger()
    source = await MultiAgentCampaignRunner(
        planner=KISAPlannerRuntime(thresholds=EvaluationThresholds(repetitions=2)),
        validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
        candidate_producer=KISACandidateProducer(),
        tools=tools,
        policy=PolicyEngine(),
        worker=backend,
        output_root=tmp_path / "source",
    ).run(campaign, budget=budget, rate_limits=rate_limits)
    candidate_id = source.validation.candidates[0].candidate_id
    repeated_replay = await KISAReplayCoordinator(
        tools=tools,
        policy=PolicyEngine(),
        worker=backend,
        output_root=tmp_path / "replay-two",
        repetitions=2,
        required_successes=2,
    ).reproduce(
        campaign,
        source.run_path,
        budget=budget,
        rate_limits=rate_limits,
    )
    controls = await KISAValidationControlCoordinator(
        tools=tools,
        policy=PolicyEngine(),
        worker=backend,
        output_root=tmp_path / "controls",
    ).execute(
        campaign,
        source.run_path,
        budget=budget,
        rate_limits=rate_limits,
    )
    single_budget = BudgetController(campaign.spec.budgets)
    single_rate_limits = RequestRateLimitLedger()
    single_source = await MultiAgentCampaignRunner(
        planner=KISAPlannerRuntime(thresholds=EvaluationThresholds(repetitions=2)),
        validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
        candidate_producer=KISACandidateProducer(),
        tools=tools,
        policy=PolicyEngine(),
        worker=backend,
        output_root=tmp_path / "single-source",
    ).run(campaign, budget=single_budget, rate_limits=single_rate_limits)
    single_candidate_id = single_source.validation.candidates[0].candidate_id
    single_replay = await KISAReplayCoordinator(
        tools=tools,
        policy=PolicyEngine(),
        worker=backend,
        output_root=tmp_path / "replay-one",
        repetitions=1,
        required_successes=1,
    ).reproduce(
        campaign,
        single_source.run_path,
        budget=single_budget,
        rate_limits=single_rate_limits,
    )
    single_controls = await KISAValidationControlCoordinator(
        tools=tools,
        policy=PolicyEngine(),
        worker=backend,
        output_root=tmp_path / "single-controls",
    ).execute(
        campaign,
        single_source.run_path,
        budget=single_budget,
        rate_limits=single_rate_limits,
    )

    repeated = evaluate_kisa_profile_validation_evidence(
        "pajin.profile.ai-assessment",
        "1.0.0",
        candidate_id,
        source.run_path,
        repeated_replay,
        controls,
    )
    assert repeated.api_version == PROFILE_VALIDATION_EVIDENCE_API_VERSION
    assert repeated.achieved_depth is ValidationDepth.REPEATED_CONTROLLED_VALIDITY_REPLAY
    assert repeated.replay_evidence.repetition_count == 2
    assert repeated.control_evidence is not None
    assert repeated.control_evidence.reconciliation.contrast.value == "contrast-observed"
    assert repeated.evidence_evaluation_performed is True
    assert repeated.floor_satisfied is True
    assert repeated.profile_selection_attested is False
    assert repeated.campaign_mutation_authorized is False
    assert repeated.execution_authorized is False
    assert repeated.confirmation_authorized is False
    assert repeated.finding_confirmed is False
    assert (
        verify_kisa_profile_validation_evidence(
            repeated,
            source.run_path,
            repeated_replay,
            controls,
        )
        == repeated
    )

    reordered = deepcopy(repeated.model_dump(mode="json", by_alias=True))
    reordered_set_fields = 0

    def reverse_wire_sets(value: object) -> None:
        nonlocal reordered_set_fields
        if isinstance(value, dict):
            for key, child in value.items():
                if (
                    key
                    in {
                        "allowed_argument_fields",
                        "changed_fields",
                        "ephemeral_argument_fields",
                        "targets",
                        "tools",
                    }
                    and isinstance(child, list)
                    and len(child) > 1
                ):
                    child.reverse()
                    reordered_set_fields += 1
                reverse_wire_sets(child)
        elif isinstance(value, list):
            for child in value:
                reverse_wire_sets(child)

    reverse_wire_sets(reordered)
    assert reordered_set_fields > 0
    assert ProfileValidationEvidenceAssessment.model_validate(reordered) == repeated

    for profile_id in (
        "pajin.profile.bug-hunt",
        "pajin.profile.ctf",
        "pajin.profile.pentest",
    ):
        assert evaluate_kisa_profile_validation_evidence(
            profile_id,
            "1.0.0",
            candidate_id,
            source.run_path,
            repeated_replay,
            controls,
        ).floor_satisfied

    single = evaluate_kisa_profile_validation_evidence(
        "pajin.profile.ctf",
        "1.0.0",
        single_candidate_id,
        single_source.run_path,
        single_replay,
    )
    assert single.achieved_depth is ValidationDepth.SINGLE_VALIDITY_REPLAY
    with pytest.raises(ProfileValidationEvidenceError):
        evaluate_kisa_profile_validation_evidence(
            "pajin.profile.pentest",
            "1.0.0",
            single_candidate_id,
            single_source.run_path,
            single_replay,
        )
    with pytest.raises(ProfileValidationEvidenceError):
        evaluate_kisa_profile_validation_evidence(
            "pajin.profile.ai-assessment",
            "1.0.0",
            single_candidate_id,
            single_source.run_path,
            single_replay,
            single_controls,
        )
    with pytest.raises(ProfileValidationEvidenceError):
        evaluate_kisa_profile_validation_evidence(
            "pajin.profile.ai-assessment",
            "1.0.0",
            candidate_id,
            source.run_path,
            repeated_replay,
            single_controls,
        )

    forged_record = controls.records[0].model_copy(update={"control_run_root_digest": "0" * 64})
    forged_controls = KISAValidationControlBatchOutcome(
        source_run_id=controls.source_run_id,
        records=(forged_record,),
        run_paths=dict(controls.run_paths),
    )
    with pytest.raises(ProfileValidationEvidenceError):
        evaluate_kisa_profile_validation_evidence(
            "pajin.profile.ai-assessment",
            "1.0.0",
            candidate_id,
            source.run_path,
            repeated_replay,
            forged_controls,
        )

    forged_batch_source = KISAValidationControlBatchOutcome(
        source_run_id="run_forged_source",
        records=controls.records,
        run_paths=dict(controls.run_paths),
    )
    with pytest.raises(ProfileValidationEvidenceError):
        evaluate_kisa_profile_validation_evidence(
            "pajin.profile.ai-assessment",
            "1.0.0",
            candidate_id,
            source.run_path,
            repeated_replay,
            forged_batch_source,
        )

    for field, replacement in (
        ("assessmentDigest", "0" * 64),
        ("achievedDepth", "single-validity-replay"),
        ("evidenceEvaluationPerformed", 1),
        ("floorSatisfied", "true"),
        ("profileSelectionAttested", 0),
        ("executionAuthorized", "false"),
        ("confirmationAuthorized", 0),
        ("findingConfirmed", "false"),
    ):
        payload = deepcopy(repeated.model_dump(mode="json", by_alias=True))
        payload[field] = replacement
        with pytest.raises(ValidationError):
            ProfileValidationEvidenceAssessment.model_validate(payload)

    control_path = controls.run_paths[candidate_id]
    (control_path / "control-plan.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ProfileValidationEvidenceError):
        evaluate_kisa_profile_validation_evidence(
            "pajin.profile.ai-assessment",
            "1.0.0",
            candidate_id,
            source.run_path,
            repeated_replay,
            controls,
        )


def test_val004a_import_order_does_not_cycle() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    environment = dict(os.environ)
    existing_pythonpath = environment.get("PYTHONPATH")
    source_root = str(repository_root / "src")
    environment["PYTHONPATH"] = (
        source_root
        if not existing_pythonpath
        else f"{source_root}{os.pathsep}{existing_pythonpath}"
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import pajin.workflow.profile_evidence; import pajin.modes.ai_redteam.replay",
        ],
        cwd=repository_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
