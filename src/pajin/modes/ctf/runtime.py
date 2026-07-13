"""Deterministic triage Planner and independent flag Validator for CTF Web Mode."""

from __future__ import annotations

from hashlib import sha256
from hmac import compare_digest

from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    CampaignMode,
    Finding,
    FindingSeverity,
    PlannedStep,
    ToolRequest,
    ToolResult,
)
from pajin.modes.ctf.models import CTFCategory, CTFScenario
from pajin.tools.ctf import (
    CTF_WEB_BACKUP_TOOL_ID,
    CTFWebBackupProbeInput,
    CTFWebBackupProbeOutput,
)


def _target_metadata(
    campaign: CampaignManifest,
    target_id: str,
) -> tuple[str, CTFScenario, str]:
    target = next((item for item in campaign.spec.targets if item.id == target_id), None)
    if target is None or target.type != "ctf-web":
        raise ValueError("CTF Web target metadata is missing")
    challenge_id = target.simulation.get("challengeId")
    scenario_id = target.simulation.get("scenarioId")
    flag_sha256 = target.simulation.get("flagSha256")
    if not all(isinstance(value, str) for value in (challenge_id, scenario_id, flag_sha256)):
        raise ValueError("CTF Web target metadata is incomplete")
    assert isinstance(challenge_id, str)
    assert isinstance(scenario_id, str)
    assert isinstance(flag_sha256, str)
    if scenario_id != CTFScenario.WEB_EXPOSED_BACKUP_CONFIG:
        raise ValueError("CTF Web target uses an unsupported scenario")
    if len(flag_sha256) != 64 or any(char not in "0123456789abcdef" for char in flag_sha256):
        raise ValueError("CTF Web target flag digest is invalid")
    return challenge_id, CTFScenario.WEB_EXPOSED_BACKUP_CONFIG, flag_sha256


class CTFTriagePlannerRuntime:
    """Route a typed Web challenge to the one fixed, bounded Web Specialist Tool."""

    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        if campaign.spec.mode is not CampaignMode.CTF:
            raise ValueError("CTF Triage Planner requires mode: ctf")

        steps: list[PlannedStep] = []
        for target in campaign.spec.targets:
            if target.type != "ctf-web":
                continue
            challenge_id, scenario_id, _ = _target_metadata(campaign, target.id)
            probe = CTFWebBackupProbeInput(
                challengeId=challenge_id,
                scenarioId=CTFScenario.WEB_EXPOSED_BACKUP_CONFIG,
            )
            steps.append(
                PlannedStep(
                    title=f"Inspect the fixed synthetic backup artifact for {target.id}",
                    rationale=(
                        "Triage classified the challenge as Web and selected the bounded "
                        "exposed-backup Specialist for the declared local lab entry point."
                    ),
                    request=ToolRequest(
                        agent_id="agent:ctf-triage-untrusted",
                        tool_id=CTF_WEB_BACKUP_TOOL_ID,
                        target=target.endpoint,
                        method="GET",
                        arguments=probe.model_dump(mode="json", by_alias=True),
                    ),
                    scenario_id=scenario_id,
                    threat_classes={"CTF-WEB"},
                    attack_surface=CTFCategory.WEB,
                    persona="ctf-web-specialist",
                )
            )
        if not steps:
            raise ValueError("no supported local CTF Web target is present")
        return AgentPlan(
            summary=(
                "Triage the typed Web challenge, run one fixed local backup probe, and pass any "
                "candidate flag to an independent digest Validator."
            ),
            steps=steps,
        )


class CTFFlagValidatorRuntime:
    """Hash candidate flags independently without disclosing the expected plaintext."""

    async def validate(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> list[Finding]:
        if campaign.spec.mode is not CampaignMode.CTF:
            raise ValueError("CTF Flag Validator requires mode: ctf")

        targets = {target.endpoint: target for target in campaign.spec.targets}
        steps = {
            step.request.request_id: step
            for step in plan.steps
            if step.request.tool_id == CTF_WEB_BACKUP_TOOL_ID
            and step.scenario_id == CTFScenario.WEB_EXPOSED_BACKUP_CONFIG
        }
        findings: list[Finding] = []
        for result in results:
            step = steps.get(result.request_id)
            if step is None or not result.success or result.tool_id != CTF_WEB_BACKUP_TOOL_ID:
                continue
            target = targets.get(step.request.target)
            if target is None:
                continue
            challenge_id, _, expected_digest = _target_metadata(campaign, target.id)
            try:
                output = CTFWebBackupProbeOutput.model_validate(result.data)
            except ValueError:
                continue
            candidate = output.candidate_flag
            if (
                output.target != target.endpoint
                or output.challenge_id != challenge_id
                or not output.network_performed
                or not output.discovered
                or candidate is None
                or not result.evidence
            ):
                continue
            observed_digest = sha256(candidate.encode("utf-8")).hexdigest()
            if not compare_digest(observed_digest, expected_digest):
                continue
            findings.append(
                Finding(
                    title=f"Verified CTF flag for {challenge_id}",
                    severity=FindingSeverity.SAFE,
                    threat_class="CTF-WEB",
                    target=target.endpoint,
                    summary=(
                        "The independent Validator hashed the Specialist candidate and matched "
                        "the challenge digest without receiving the expected flag plaintext."
                    ),
                    impact="The synthetic local CTF Web challenge is solved.",
                    affected_component="synthetic backup configuration artifact",
                    root_cause=(
                        "The vulnerable lab profile exposes a backup configuration artifact "
                        "containing the synthetic flag."
                    ),
                    reproduction=[
                        (
                            "Run the fixed Web backup Specialist against the declared local "
                            "entry point."
                        ),
                        (
                            "Hash the returned candidate with SHA-256 and compare it to the "
                            "manifest digest."
                        ),
                    ],
                    evidence=list(dict.fromkeys(result.evidence)),
                    remediation=[
                        "Remove backup artifacts from the deployed web root.",
                        "Deny deployment of files with backup suffixes and retest the same path.",
                    ],
                    confidence=1.0,
                    validated=True,
                )
            )
        return findings
