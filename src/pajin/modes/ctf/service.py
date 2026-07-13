"""Compile local CTF challenges and emit evidence-bound solve artifacts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from hmac import compare_digest
from pathlib import Path

import yaml

from pajin.domain.models import (
    AutonomyLevel,
    CampaignManifest,
    CampaignMetadata,
    CampaignMode,
    CampaignSpec,
    RulesOfEngagement,
    Scope,
    Target,
    ToolRiskTier,
)
from pajin.domain.orchestration import RunStatus
from pajin.modes.ctf.models import (
    CTFCategory,
    CTFChallengeManifest,
    CTFRunResult,
    CTFSolveStatus,
)
from pajin.runtime.store import RunStore, verify_run_integrity
from pajin.tools.ctf import CTF_WEB_BACKUP_TOOL_ID, CTFWebBackupProbeOutput
from pajin.workflow.multi_agent import MultiAgentRunOutcome


@dataclass(frozen=True)
class CTFCampaignArtifact:
    path: Path
    campaign: CampaignManifest


@dataclass(frozen=True)
class CTFRunArtifacts:
    result: CTFRunResult
    result_path: Path
    writeup_path: Path


def load_ctf_challenge(path: Path) -> CTFChallengeManifest:
    with path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise ValueError("CTF challenge manifest must contain a YAML mapping")
    return CTFChallengeManifest.model_validate(raw)


class CTFChallengeService:
    """Compile a typed local challenge into the generic policy-governed Campaign contract."""

    def compile_campaign(
        self,
        challenge: CTFChallengeManifest,
        *,
        evaluated_at: datetime | None = None,
    ) -> CampaignManifest:
        now = evaluated_at or datetime.now(UTC)
        if not challenge.spec.authorization.is_active(now):
            raise ValueError("CTF challenge authorization is not active")

        entry_point = challenge.spec.scope.entry_point
        scenario = challenge.spec.scenario
        return CampaignManifest(
            apiVersion="pajin.dev/v1alpha1",
            kind="Campaign",
            metadata=CampaignMetadata(
                name=challenge.metadata.name,
                description=(
                    challenge.metadata.description
                    or f"Local-only CTF Web challenge: {challenge.metadata.display_name}."
                ),
            ),
            spec=CampaignSpec(
                mode=CampaignMode.CTF,
                autonomy=AutonomyLevel.LAB_AUTONOMOUS,
                authorization=challenge.spec.authorization.model_copy(
                    update={
                        "evidence": (
                            f"{challenge.spec.authorization.evidence}; "
                            f"ctf-challenge:{challenge.metadata.name}; "
                            f"flag-sha256:{challenge.spec.flag.sha256}"
                        )
                    }
                ),
                targets=[
                    Target(
                        type="ctf-web",
                        id=challenge.metadata.name,
                        endpoint=entry_point,
                        simulation={
                            "category": CTFCategory.WEB,
                            "challengeId": challenge.metadata.name,
                            "scenarioId": scenario,
                            "flagSha256": challenge.spec.flag.sha256,
                            "synthetic": True,
                        },
                    )
                ],
                scope=Scope(allow=[entry_point], deny=[]),
                accessProfile="blackbox",
                objectives=challenge.spec.objectives,
                rulesOfEngagement=RulesOfEngagement(
                    maxToolRiskTier=ToolRiskTier.T1,
                    allowedMethods={"GET"},
                    allowedToolCategories={"ctf", "discovery", "http", "web"},
                    prohibit={
                        "arbitrary-path-discovery",
                        "external-target",
                        "scoreboard-submission",
                    },
                    stopOn={"out-of-scope-attempt", "non-synthetic-response"},
                    allowPrivateNetworks=True,
                    maxRequestsPerMinute=5,
                ),
                budgets=challenge.spec.budgets,
                outputs=["ctf-result", "ctf-writeup", "evidence-bundle"],
            ),
        )

    def write_campaign(
        self,
        challenge: CTFChallengeManifest,
        output_path: Path,
        *,
        evaluated_at: datetime | None = None,
    ) -> CTFCampaignArtifact:
        campaign = self.compile_campaign(challenge, evaluated_at=evaluated_at)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            yaml.safe_dump(
                campaign.model_dump(mode="json", by_alias=True),
                allow_unicode=True,
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        return CTFCampaignArtifact(path=output_path, campaign=campaign)


class CTFModePack:
    """Verify a completed run and append CTF result and write-up artifacts."""

    def finalize(
        self,
        challenge: CTFChallengeManifest,
        outcome: MultiAgentRunOutcome,
    ) -> CTFRunArtifacts:
        if outcome.status is not RunStatus.COMPLETED or outcome.plan is None:
            raise ValueError("CTF finalization requires a completed typed run")
        verify_run_integrity(outcome.run_path)
        self._validate_run_campaign(challenge, outcome)

        probe_results = [
            result for result in outcome.tool_results if result.tool_id == CTF_WEB_BACKUP_TOOL_ID
        ]
        if len(probe_results) != 1:
            raise ValueError("CTF Web MVP requires exactly one Specialist probe result")
        tool_result = probe_results[0]
        output: CTFWebBackupProbeOutput | None = None
        if tool_result.success:
            try:
                output = CTFWebBackupProbeOutput.model_validate(tool_result.data)
            except ValueError as exc:
                raise ValueError("CTF Specialist result is not a valid typed observation") from exc

        candidate = output.candidate_flag if output is not None else None
        candidate_digest = sha256(candidate.encode("utf-8")).hexdigest() if candidate else None
        expected_digest = challenge.spec.flag.sha256
        digest_matches = candidate_digest is not None and compare_digest(
            candidate_digest, expected_digest
        )
        validated = any(
            finding.validated
            and finding.threat_class == "CTF-WEB"
            and finding.target == challenge.spec.scope.entry_point
            and set(finding.evidence) <= set(tool_result.evidence)
            for finding in outcome.findings
        )
        if digest_matches and not validated:
            raise ValueError("digest-matched CTF candidate lacks an independent validated finding")

        if digest_matches and validated:
            status = CTFSolveStatus.SOLVED
        elif candidate is not None:
            status = CTFSolveStatus.INVALID_FLAG
        else:
            status = CTFSolveStatus.UNSOLVED

        result = CTFRunResult(
            run_id=outcome.run_id,
            challenge_id=challenge.metadata.name,
            category=challenge.spec.category,
            scenario=challenge.spec.scenario,
            status=status,
            candidate_flag=candidate,
            candidate_sha256=candidate_digest,
            expected_sha256=expected_digest,
            evidence=list(dict.fromkeys(tool_result.evidence)),
        )
        store = RunStore(outcome.run_id, outcome.run_path)
        result_relative = store.write_json("ctf-result.json", result.model_dump(mode="json"))
        writeup_relative = store.write_text(
            "ctf-writeup.md",
            self._render_writeup(challenge, result),
        )
        store.append_event(
            "mode-pack.ctf.completed",
            {
                "challengeId": challenge.metadata.name,
                "status": status.value,
                "result": result_relative,
                "writeup": writeup_relative,
                "externalSubmission": False,
            },
        )
        store.seal()
        return CTFRunArtifacts(
            result=result,
            result_path=outcome.run_path / result_relative,
            writeup_path=outcome.run_path / writeup_relative,
        )

    @staticmethod
    def _validate_run_campaign(
        challenge: CTFChallengeManifest,
        outcome: MultiAgentRunOutcome,
    ) -> None:
        campaign_path = outcome.run_path / "campaign.json"
        try:
            raw = json.loads(campaign_path.read_text(encoding="utf-8"))
            campaign = CampaignManifest.model_validate(raw)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("sealed CTF run campaign is invalid") from exc
        expected = CTFChallengeService().compile_campaign(
            challenge,
            evaluated_at=challenge.spec.authorization.approved_at,
        )
        if campaign != expected:
            raise ValueError("sealed Run campaign does not match the CTF challenge")

    @staticmethod
    def _render_writeup(
        challenge: CTFChallengeManifest,
        result: CTFRunResult,
    ) -> str:
        lines = [
            f"# CTF Write-up: {challenge.metadata.display_name}",
            "",
            f"- Challenge ID: `{challenge.metadata.name}`",
            f"- Category: `{challenge.spec.category.value}`",
            f"- Scenario: `{challenge.spec.scenario.value}`",
            f"- Solve status: `{result.status.value}`",
            f"- Run ID: `{result.run_id}`",
            "- External scoreboard submission: `not performed`",
            "",
            "## Agent route",
            "",
            "1. The Triage Planner classified the typed challenge as Web.",
            "2. A Web Specialist used the one-call Capability for the fixed backup path.",
            "3. The independent Validator hashed the candidate and compared only digests.",
            "4. The Reporter produced this evidence-bound write-up.",
            "",
            "## Observation",
            "",
        ]
        if result.status is CTFSolveStatus.SOLVED:
            lines.extend(
                [
                    "The synthetic backup configuration artifact exposed a candidate flag.",
                    "",
                    f"- Verified flag: `{result.candidate_flag}`",
                    f"- Candidate SHA-256: `{result.candidate_sha256}`",
                ]
            )
        elif result.status is CTFSolveStatus.INVALID_FLAG:
            lines.extend(
                [
                    (
                        "The Specialist found a syntactically valid candidate, but its digest "
                        "did not match."
                    ),
                    "",
                    f"- Candidate SHA-256: `{result.candidate_sha256}`",
                ]
            )
        else:
            lines.append("The fixed backup path did not expose a candidate flag.")
        lines.extend(
            [
                "",
                "## Evidence",
                "",
                *[f"- `{item}`" for item in result.evidence],
                "",
                "## Defensive lesson",
                "",
                (
                    "Exclude backup artifacts from deployment output and deny known backup "
                    "suffixes at build time."
                ),
            ]
        )
        return "\n".join(lines) + "\n"
