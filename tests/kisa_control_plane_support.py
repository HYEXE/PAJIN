"""Reusable builders for sealed KISA Control Plane source fixtures."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.control_plane.models import ArtifactRef
from pajin.domain.manifest import load_manifest
from pajin.domain.models import CampaignManifest
from pajin.modes.ai_redteam.candidates import KISACandidateProducer
from pajin.modes.ai_redteam.models import EvaluationThresholds
from pajin.modes.ai_redteam.runtime import KISAPlannerRuntime, KISAValidatorRuntime
from pajin.policy.engine import PolicyEngine
from pajin.runtime.control import BudgetController
from pajin.runtime.secrets import SecretMaterial
from pajin.runtime.store import verify_run_integrity
from pajin.runtime.worker import WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.ai import AIChatProbeTool
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import RequestRateLimitLedger
from pajin.workflow.multi_agent import MultiAgentCampaignRunner

_THREAT_CLASSES = ("M03", "M06", "A04")


@dataclass(frozen=True, slots=True)
class KISAControlPlaneSource:
    path: Path
    artifact_ref: ArtifactRef
    campaign: CampaignManifest


class _SupportingKISAWorker:
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
        worker=_SupportingKISAWorker(),
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
