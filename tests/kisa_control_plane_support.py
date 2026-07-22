"""Reusable builders for sealed KISA Control Plane source fixtures."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import urlsplit, urlunsplit

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.control_plane.models import ArtifactRef
from pajin.domain.manifest import load_manifest
from pajin.domain.models import CampaignManifest
from pajin.domain.validation import (
    ConfirmationBasis,
    FindingDisposition,
    ValidationReasonCode,
)
from pajin.modes.ai_redteam.candidates import KISACandidateProducer
from pajin.modes.ai_redteam.models import EvaluationThresholds
from pajin.modes.ai_redteam.replay import KISAReplayBatchOutcome, KISAReplayCoordinator
from pajin.modes.ai_redteam.retest import KISARetestService
from pajin.modes.ai_redteam.runtime import (
    KISAPlannerRuntime,
    KISARetestPlannerRuntime,
    KISAValidatorRuntime,
)
from pajin.modes.ai_redteam.service import KISAModePack
from pajin.policy.engine import PolicyEngine
from pajin.runtime.control import BudgetController
from pajin.runtime.secrets import SecretMaterial
from pajin.runtime.store import verify_run_integrity
from pajin.runtime.worker import DockerWorkerBackend, WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.ai import (
    AI_CHAT_PROXY_RECEIPT_VERSION,
    AIChatProbeTool,
    AIChatRegressionTool,
)
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import RequestRateLimitLedger
from pajin.workflow import confirmation as confirmation_module
from pajin.workflow.confirmation import apply_confirmed_gate
from pajin.workflow.multi_agent import MultiAgentCampaignRunner, MultiAgentRunOutcome

_THREAT_CLASSES = ("M03", "M06", "A04")


@dataclass(frozen=True, slots=True)
class KISAControlPlaneSource:
    path: Path
    artifact_ref: ArtifactRef
    campaign: CampaignManifest
    compilation_time: datetime


@dataclass(frozen=True, slots=True)
class KISAControlPlaneRetestSources:
    baseline: KISAControlPlaneSource
    retest: KISAControlPlaneSource


class SupportingKISAWorker:
    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        del secrets
        started_at = datetime.now(UTC)
        payload = json.loads(job.stdin)
        probe = payload["probe"]
        turns: list[dict[str, object]] = []
        for index, turn in enumerate(probe["turns"]):
            markers = [
                check["value"]
                for check in probe["checks"]
                if check["turn"] == index and check["kind"] == "response-contains"
            ]
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
                        "message": {
                            "role": "assistant",
                            "content": " ".join(["supportive response", *markers]),
                        },
                        "toolCalls": [],
                        "safety": {"blocked": False, "reason": None},
                        "memoryWrites": [],
                        "model": "pajin-control-plane-fixture-v1",
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
            "observation": "Worker verdict is not authoritative.",
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
            backend="kisa-control-plane-fixture",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(output, separators=(",", ":")),
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )


class HardenedKISAWorker(SupportingKISAWorker):
    """Return an oracle-verifiable M03 refusal and successful normal regression."""

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        del secrets
        started_at = datetime.now(UTC)
        payload = json.loads(job.stdin)
        probe = payload["probe"]
        purpose = probe.get("purpose", "attack")
        turns: list[dict[str, object]] = []
        for index, turn in enumerate(probe["turns"]):
            if purpose == "regression":
                markers = [
                    check["value"]
                    for check in probe["checks"]
                    if check["turn"] == index and check["kind"] == "response-contains"
                ]
                content = " ".join(["safe normal response", *markers])
                blocked = False
                reason = None
            else:
                content = "I cannot reveal internal instructions."
                blocked = True
                reason = "system-prompt-protection"
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
                        "safety": {"blocked": blocked, "reason": reason},
                        "memoryWrites": [],
                        "model": "pajin-control-plane-hardened-fixture-v1",
                    },
                    "responseLatencySeconds": 0.01,
                }
            )
        output = {
            "target": payload["target"],
            "scenarioId": probe["scenario_id"],
            "threatClass": probe["threat_class"],
            "sessionId": probe["session_id"],
            "purpose": purpose,
            "vulnerable": False,
            "observation": "Worker verdict is not authoritative.",
            "turns": turns,
            "checks": [
                {
                    "checkId": check["check_id"],
                    "kind": check["kind"],
                    "turn": check["turn"],
                    "matched": purpose == "regression",
                    "sensitive": check["sensitive"],
                }
                for check in probe["checks"]
            ],
            "sensitiveExposureCount": 0,
            "meanResponseLatencySeconds": 0.01,
            "regressionPassed": True if purpose == "regression" else None,
            "networkPerformed": True,
        }
        return WorkerResult(
            execution_id=job.execution_id,
            backend="kisa-control-plane-hardened-fixture",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(output, separators=(",", ":")),
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )


def _canonical_json_digest(value: object) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _trusted_supporting_backend(worker: SupportingKISAWorker) -> DockerWorkerBackend:
    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})

    async def run(
        job: WorkerJob,
        *,
        secrets: object = None,
    ) -> WorkerResult:
        del secrets
        result = await worker.run(job)
        payload = json.loads(job.stdin)
        output = json.loads(result.stdout)
        probe = payload["probe"]
        parsed_target = urlsplit(payload["target"])
        audit_target = urlunsplit(
            (
                parsed_target.scheme,
                parsed_target.netloc,
                parsed_target.path,
                "<redacted>" if parsed_target.query else "",
                "",
            )
        )
        events = [json.dumps({"event": "ready", "port": 8080}, separators=(",", ":"))]
        for index, (turn, observed) in enumerate(zip(probe["turns"], output["turns"], strict=True)):
            request_body = {
                "sessionId": probe["session_id"],
                "messages": turn["messages"],
                "metadata": {"scenarioId": probe["scenario_id"], "turn": index},
            }
            events.append(
                json.dumps(
                    {
                        "event": "allow",
                        "receiptVersion": AI_CHAT_PROXY_RECEIPT_VERSION,
                        "sequence": index + 1,
                        "method": "POST",
                        "target": audit_target,
                        "targetSha256": sha256(payload["target"].encode("utf-8")).hexdigest(),
                        "address": "172.17.0.1",
                        "status": 200,
                        "requestJsonSha256": _canonical_json_digest(request_body),
                        "responseBodySha256": _canonical_json_digest(observed["response"]),
                        "responseJsonSha256": _canonical_json_digest(observed["response"]),
                    },
                    separators=(",", ":"),
                )
            )
        return result.model_copy(
            update={
                "backend": "docker",
                "network_log": "\n".join(events),
            }
        )

    backend.run = run  # type: ignore[method-assign]
    return backend


@contextmanager
def externally_attested_confirmation_fixture() -> Iterator[None]:
    """Build a historical trusted baseline without reopening the production Worker-only Gate.

    Retest tests still need a pre-existing Confirmed baseline.  Production code has no external
    execution-attestation verifier yet, so this narrowly scoped fixture substitutes that missing
    authority only while constructing the baseline.  It must never be used to test current Local,
    CLI, or Control Plane confirmation behavior.
    """

    original_build = confirmation_module._build_confirmation_projection

    def externally_attested_disposition(
        *_args: object,
        **_kwargs: object,
    ) -> confirmation_module._ReplayDisposition:
        return confirmation_module._ReplayDisposition(
            disposition=FindingDisposition.CONFIRMED,
            reason=ValidationReasonCode.INDEPENDENT_REPRODUCTION_CONFIRMED,
            confirmation_basis=ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY,
            summary="A test-only external authority attested the target execution.",
        )

    def externally_attested_projection(
        **kwargs: Any,
    ) -> confirmation_module._ConfirmationProjection:
        projection = original_build(**kwargs)
        return replace(
            projection,
            index=projection.index.model_copy(
                update={"confirmation_semantics": "verified-independent-replay"}
            ),
            finding_set=projection.finding_set.model_copy(
                update={"confirmation_semantics": "verified-independent-replay"}
            ),
            report=projection.report.replace(
                "verified-replay-evidence", "verified-independent-replay"
            ),
        )

    with (
        patch.object(
            confirmation_module,
            "_successful_replay_disposition",
            side_effect=externally_attested_disposition,
        ),
        patch.object(
            confirmation_module,
            "_build_confirmation_projection",
            side_effect=externally_attested_projection,
        ),
    ):
        yield


def build_kisa_control_plane_source(
    output_root: Path,
    *,
    scenario_count: int = 1,
    producer_run_id: str | None = None,
    created_by: str = "trusted-source-admission",
) -> KISAControlPlaneSource:
    """Create a sealed completed Run with one to three exact eligible KISA Candidates."""

    if not 1 <= scenario_count <= len(_THREAT_CLASSES):
        raise ValueError("scenario_count must be between one and three")
    campaign = load_manifest(Path("examples/kisa-ai-chat-lab.yaml"))
    campaign = campaign.model_copy(
        update={
            "spec": campaign.spec.model_copy(
                update={"threat_classes": list(_THREAT_CLASSES[:scenario_count])}
            )
        }
    )
    tools = ToolRegistry()
    tools.register(AIChatProbeTool())
    budget = BudgetController(campaign.spec.budgets)
    rate_limits = RequestRateLimitLedger()
    runner = MultiAgentCampaignRunner(
        planner=KISAPlannerRuntime(thresholds=EvaluationThresholds(repetitions=2)),
        validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
        candidate_producer=KISACandidateProducer(),
        tools=tools,
        policy=PolicyEngine(),
        worker=_trusted_supporting_backend(SupportingKISAWorker()),
        output_root=output_root,
    )
    outcome = asyncio.run(runner.run(campaign, budget=budget, rate_limits=rate_limits))
    verification = verify_run_integrity(outcome.run_path)
    content_digest, byte_length = _tree_identity(outcome.run_path)
    identity = sha256(f"{verification.run_id}:{verification.root_digest}".encode()).hexdigest()
    return KISAControlPlaneSource(
        path=outcome.run_path,
        artifact_ref=ArtifactRef(
            artifact_id=f"artifact_{identity[:32]}",
            repository_version=1,
            media_type="application/vnd.pajin.run+directory",
            schema_kind="pajin.run.sealed.v1",
            byte_length=byte_length,
            content_digest=content_digest,
            producer_run_id=producer_run_id or f"run_{identity[32:64]}",
            run_id=verification.run_id,
            integrity_root_digest=verification.root_digest,
            created_by=created_by,
        ),
        campaign=campaign,
        compilation_time=datetime.now(UTC),
    )


def build_kisa_control_plane_retest_sources(
    output_root: Path,
    *,
    baseline_producer_run_id: str,
    retest_producer_run_id: str,
    created_by: str = "trusted-source-admission",
) -> KISAControlPlaneRetestSources:
    """Create a confirmed baseline and a sealed parent Retest with normal regression."""

    campaign = load_manifest(Path("examples/kisa-ai-chat-lab.yaml"))
    campaign = campaign.model_copy(
        update={
            "spec": campaign.spec.model_copy(update={"threat_classes": ["M03"]})
        }
    )
    thresholds = EvaluationThresholds(repetitions=2)
    baseline_tools = ToolRegistry()
    baseline_tools.register(AIChatProbeTool())
    baseline_tools.register(AIChatRegressionTool())
    baseline_budget = BudgetController(campaign.spec.budgets)
    baseline_rates = RequestRateLimitLedger()
    baseline_backend = _trusted_supporting_backend(SupportingKISAWorker())
    baseline_runner = MultiAgentCampaignRunner(
        planner=KISAPlannerRuntime(thresholds=thresholds),
        validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
        candidate_producer=KISACandidateProducer(),
        tools=baseline_tools,
        policy=PolicyEngine(),
        worker=baseline_backend,
        output_root=output_root / "baseline",
    )
    replay = KISAReplayCoordinator(
        tools=baseline_tools,
        policy=PolicyEngine(),
        worker=baseline_backend,
        output_root=output_root / "baseline-replay",
        repetitions=2,
        required_successes=2,
    )

    async def execute_baseline() -> tuple[MultiAgentRunOutcome, KISAReplayBatchOutcome]:
        outcome = await baseline_runner.run(
            campaign,
            budget=baseline_budget,
            rate_limits=baseline_rates,
        )
        replay_batch = await replay.reproduce(
            campaign,
            outcome.run_path,
            budget=baseline_budget,
            rate_limits=baseline_rates,
        )
        return outcome, replay_batch

    baseline_outcome, replay_batch = asyncio.run(execute_baseline())
    with externally_attested_confirmation_fixture():
        confirmation = apply_confirmed_gate(
            source_run_path=baseline_outcome.run_path,
            replay_run_paths=[
                result.run_path for result in replay_batch.verified_results.values()
            ],
            tickets=replay_batch.tickets,
        )
    baseline_outcome = baseline_outcome.model_copy(
        update={
            "validation": confirmation.validation,
            "findings": confirmation.product_confirmed_findings,
        }
    )
    KISAModePack(thresholds=thresholds).evaluate(
        campaign,
        baseline_outcome,
        replay_batch,
    )
    KISARetestService().create_remediation_plan(baseline_outcome.run_path)

    retest_tools = ToolRegistry()
    retest_tools.register(AIChatProbeTool())
    retest_tools.register(AIChatRegressionTool())
    retest_budget = BudgetController(campaign.spec.budgets)
    retest_rates = RequestRateLimitLedger()
    retest_outcome = asyncio.run(
        MultiAgentCampaignRunner(
            planner=KISARetestPlannerRuntime(thresholds=thresholds),
            validator=KISAValidatorRuntime(DeterministicAgentRuntime()),
            candidate_producer=KISACandidateProducer(),
            tools=retest_tools,
            policy=PolicyEngine(),
            worker=_trusted_supporting_backend(HardenedKISAWorker()),
            output_root=output_root / "parent-retest",
        ).run(
            campaign,
            budget=retest_budget,
            rate_limits=retest_rates,
        )
    )
    return KISAControlPlaneRetestSources(
        baseline=_control_plane_source(
            baseline_outcome.run_path,
            campaign=campaign,
            producer_run_id=baseline_producer_run_id,
            created_by=created_by,
        ),
        retest=_control_plane_source(
            retest_outcome.run_path,
            campaign=campaign,
            producer_run_id=retest_producer_run_id,
            created_by=created_by,
        ),
    )


def _control_plane_source(
    path: Path,
    *,
    campaign: CampaignManifest,
    producer_run_id: str,
    created_by: str,
) -> KISAControlPlaneSource:
    verification = verify_run_integrity(path)
    content_digest, byte_length = _tree_identity(path)
    identity = sha256(f"{verification.run_id}:{verification.root_digest}".encode()).hexdigest()
    return KISAControlPlaneSource(
        path=path,
        artifact_ref=ArtifactRef(
            artifact_id=f"artifact_{identity[:32]}",
            repository_version=1,
            media_type="application/vnd.pajin.run+directory",
            schema_kind="pajin.run.sealed.v1",
            byte_length=byte_length,
            content_digest=content_digest,
            producer_run_id=producer_run_id,
            run_id=verification.run_id,
            integrity_root_digest=verification.root_digest,
            created_by=created_by,
        ),
        campaign=campaign,
        compilation_time=datetime.now(UTC),
    )


def _tree_identity(root: Path) -> tuple[str, int]:
    entries: list[dict[str, object]] = []
    byte_length = 0
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        content = path.read_bytes()
        byte_length += len(content)
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size": len(content),
                "sha256": sha256(content).hexdigest(),
            }
        )
    encoded = json.dumps(
        entries,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(encoded).hexdigest(), byte_length
