"""Deterministic category routing and independent flag validation for CTF Mode."""

from __future__ import annotations

from dataclasses import dataclass
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
from pajin.modes.ctf.models import CTFCategory, CTFInlineArtifact, CTFScenario
from pajin.tools.ctf import (
    CTF_CRYPTO_XOR_TOOL_ID,
    CTF_WEB_BACKUP_TOOL_ID,
    CTFCryptoXORInput,
    CTFCryptoXOROutput,
    CTFWebBackupProbeInput,
    CTFWebBackupProbeOutput,
)


@dataclass(frozen=True)
class _CTFTargetMetadata:
    challenge_id: str
    category: CTFCategory
    scenario: CTFScenario
    flag_sha256: str
    artifact_sha256: str | None = None
    ciphertext_hex: str | None = None

    @property
    def tool_id(self) -> str:
        if self.category is CTFCategory.WEB:
            return CTF_WEB_BACKUP_TOOL_ID
        return CTF_CRYPTO_XOR_TOOL_ID

    @property
    def threat_class(self) -> str:
        return f"CTF-{self.category.value.upper()}"


def _target_metadata(campaign: CampaignManifest, target_id: str) -> _CTFTargetMetadata:
    target = next((item for item in campaign.spec.targets if item.id == target_id), None)
    if target is None:
        raise ValueError("CTF target metadata is missing")
    raw_category = target.simulation.get("category")
    raw_scenario = target.simulation.get("scenarioId")
    challenge_id = target.simulation.get("challengeId")
    flag_sha256 = target.simulation.get("flagSha256")
    if not all(
        isinstance(value, str) for value in (raw_category, raw_scenario, challenge_id, flag_sha256)
    ):
        raise ValueError("CTF target metadata is incomplete")
    assert isinstance(raw_category, str)
    assert isinstance(raw_scenario, str)
    assert isinstance(challenge_id, str)
    assert isinstance(flag_sha256, str)
    try:
        category = CTFCategory(raw_category)
        scenario = CTFScenario(raw_scenario)
    except ValueError as exc:
        raise ValueError("CTF target category or scenario is unsupported") from exc
    if len(flag_sha256) != 64 or any(char not in "0123456789abcdef" for char in flag_sha256):
        raise ValueError("CTF target flag digest is invalid")

    if category is CTFCategory.WEB:
        if target.type != "ctf-web" or scenario is not CTFScenario.WEB_EXPOSED_BACKUP_CONFIG:
            raise ValueError("CTF Web target metadata is inconsistent")
        return _CTFTargetMetadata(challenge_id, category, scenario, flag_sha256)

    artifact_sha256 = target.simulation.get("artifactSha256")
    ciphertext_hex = target.simulation.get("ciphertextHex")
    if (
        target.type != "ctf-crypto"
        or scenario is not CTFScenario.CRYPTO_SINGLE_BYTE_XOR
        or not isinstance(artifact_sha256, str)
        or not isinstance(ciphertext_hex, str)
    ):
        raise ValueError("CTF Crypto target metadata is inconsistent")
    CTFInlineArtifact(data=ciphertext_hex, sha256=artifact_sha256)
    return _CTFTargetMetadata(
        challenge_id,
        category,
        scenario,
        flag_sha256,
        artifact_sha256,
        ciphertext_hex,
    )


class CTFTriagePlannerRuntime:
    """Route each supported typed category to its one bounded Specialist Tool."""

    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        if campaign.spec.mode is not CampaignMode.CTF:
            raise ValueError("CTF Triage Planner requires mode: ctf")

        steps: list[PlannedStep] = []
        for target in campaign.spec.targets:
            metadata = _target_metadata(campaign, target.id)
            if metadata.category is CTFCategory.WEB:
                web_probe = CTFWebBackupProbeInput(
                    challengeId=metadata.challenge_id,
                    scenarioId=CTFScenario.WEB_EXPOSED_BACKUP_CONFIG,
                )
                title = f"Inspect the fixed synthetic backup artifact for {target.id}"
                rationale = (
                    "Triage classified the challenge as Web and selected the bounded "
                    "exposed-backup Specialist for the declared local lab entry point."
                )
                method = "GET"
                arguments = web_probe.model_dump(mode="json", by_alias=True)
                persona = "ctf-web-specialist"
            else:
                assert metadata.artifact_sha256 is not None
                assert metadata.ciphertext_hex is not None
                crypto_probe = CTFCryptoXORInput(
                    challengeId=metadata.challenge_id,
                    scenarioId=CTFScenario.CRYPTO_SINGLE_BYTE_XOR,
                    artifactSha256=metadata.artifact_sha256,
                    ciphertextHex=metadata.ciphertext_hex,
                )
                title = f"Analyze the bounded XOR artifact for {target.id}"
                rationale = (
                    "Triage classified the challenge as Crypto and selected the offline "
                    "single-byte XOR Specialist for the content-addressed artifact."
                )
                method = "POST"
                arguments = crypto_probe.model_dump(mode="json", by_alias=True)
                persona = "ctf-crypto-specialist"
            steps.append(
                PlannedStep(
                    title=title,
                    rationale=rationale,
                    request=ToolRequest(
                        agent_id="agent:ctf-triage-untrusted",
                        tool_id=metadata.tool_id,
                        target=target.endpoint,
                        method=method,
                        arguments=arguments,
                    ),
                    scenario_id=metadata.scenario,
                    threat_classes={metadata.threat_class},
                    attack_surface=metadata.category,
                    persona=persona,
                )
            )
        if not steps:
            raise ValueError("no supported local CTF target is present")
        categories = ", ".join(
            sorted(
                {
                    _target_metadata(campaign, target.id).category.value
                    for target in campaign.spec.targets
                }
            )
        )
        return AgentPlan(
            summary=(
                f"Triage the typed {categories} challenge, run one bounded Specialist, and pass "
                "any candidate flag to an independent digest Validator."
            ),
            steps=steps,
        )


class CTFFlagValidatorRuntime:
    """Hash category-specific candidate flags without expected plaintext disclosure."""

    async def validate(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> list[Finding]:
        if campaign.spec.mode is not CampaignMode.CTF:
            raise ValueError("CTF Flag Validator requires mode: ctf")

        targets = {target.endpoint: target for target in campaign.spec.targets}
        steps = {step.request.request_id: step for step in plan.steps}
        findings: list[Finding] = []
        for result in results:
            step = steps.get(result.request_id)
            if step is None or not result.success:
                continue
            target = targets.get(step.request.target)
            if target is None:
                continue
            metadata = _target_metadata(campaign, target.id)
            if result.tool_id != metadata.tool_id or step.request.tool_id != metadata.tool_id:
                continue
            candidate = self._candidate(result, target.endpoint, metadata)
            if candidate is None or not result.evidence:
                continue
            observed_digest = sha256(candidate.encode("utf-8")).hexdigest()
            if not compare_digest(observed_digest, metadata.flag_sha256):
                continue
            findings.append(self._finding(target.endpoint, metadata, result.evidence))
        return findings

    @staticmethod
    def _candidate(
        result: ToolResult,
        target: str,
        metadata: _CTFTargetMetadata,
    ) -> str | None:
        try:
            if metadata.category is CTFCategory.WEB:
                web_output = CTFWebBackupProbeOutput.model_validate(result.data)
                if (
                    web_output.target != target
                    or web_output.challenge_id != metadata.challenge_id
                    or web_output.scenario_id is not metadata.scenario
                    or not web_output.network_performed
                    or not web_output.discovered
                ):
                    return None
                return web_output.candidate_flag

            crypto_output = CTFCryptoXOROutput.model_validate(result.data)
            if (
                crypto_output.target != target
                or crypto_output.challenge_id != metadata.challenge_id
                or crypto_output.scenario_id is not metadata.scenario
                or crypto_output.artifact_sha256 != metadata.artifact_sha256
                or crypto_output.network_performed
                or not crypto_output.solved
            ):
                return None
            return crypto_output.candidate_flag
        except ValueError:
            return None

    @staticmethod
    def _finding(
        target: str,
        metadata: _CTFTargetMetadata,
        evidence: list[str],
    ) -> Finding:
        if metadata.category is CTFCategory.WEB:
            affected_component = "synthetic backup configuration artifact"
            root_cause = (
                "The vulnerable lab profile exposes a backup configuration artifact containing "
                "the synthetic flag."
            )
            reproduction = [
                "Run the fixed Web backup Specialist against the declared local entry point.",
                "Hash the candidate with SHA-256 and compare it to the manifest digest.",
            ]
            lessons = [
                "Remove backup artifacts from the deployed web root.",
                "Deny deployment of backup suffixes and retest the same path.",
            ]
        else:
            affected_component = "content-addressed synthetic XOR artifact"
            root_cause = (
                "The synthetic ciphertext uses one repeated byte across a finite 256-key space."
            )
            reproduction = [
                "Verify the inline artifact SHA-256 before analysis.",
                (
                    "Evaluate all 256 single-byte XOR keys offline and retain one PAJIN flag "
                    "candidate."
                ),
                "Hash the candidate with SHA-256 and compare it to the manifest digest.",
            ]
            lessons = [
                "Use this bounded solver only for synthetic training artifacts.",
                "Keep real cryptographic material and external files outside this Mode Pack.",
            ]
        return Finding(
            title=f"Verified CTF flag for {metadata.challenge_id}",
            severity=FindingSeverity.SAFE,
            threat_class=metadata.threat_class,
            target=target,
            summary=(
                "The independent Validator hashed the Specialist candidate and matched the "
                "challenge digest without receiving the expected flag plaintext."
            ),
            impact=f"The synthetic local CTF {metadata.category.value} challenge is solved.",
            affected_component=affected_component,
            root_cause=root_cause,
            reproduction=reproduction,
            evidence=list(dict.fromkeys(evidence)),
            remediation=lessons,
            confidence=1.0,
            validated=True,
        )
