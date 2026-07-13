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
from pajin.tools.ctf import (
    CTF_CRYPTO_XOR_TOOL_ID,
    CTF_WEB_BACKUP_TOOL_ID,
    CTFCryptoXOROutput,
    CTFWebBackupProbeOutput,
    crypto_artifact_target,
)
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


@dataclass(frozen=True)
class _CompiledProfile:
    target: Target
    rules: RulesOfEngagement
    access_profile: str


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

        profile = self._profile(challenge)
        return CampaignManifest(
            apiVersion="pajin.dev/v1alpha1",
            kind="Campaign",
            metadata=CampaignMetadata(
                name=challenge.metadata.name,
                description=(
                    challenge.metadata.description
                    or (
                        f"Local-only CTF {challenge.spec.category.value} challenge: "
                        f"{challenge.metadata.display_name}."
                    )
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
                targets=[profile.target],
                scope=Scope(allow=[profile.target.endpoint], deny=[]),
                accessProfile=profile.access_profile,
                objectives=challenge.spec.objectives,
                rulesOfEngagement=profile.rules,
                budgets=challenge.spec.budgets,
                outputs=["ctf-result", "ctf-writeup", "evidence-bundle"],
            ),
        )

    @staticmethod
    def _profile(challenge: CTFChallengeManifest) -> _CompiledProfile:
        common_prohibitions = {"external-target", "scoreboard-submission"}
        if challenge.spec.category is CTFCategory.WEB:
            assert challenge.spec.scope is not None
            target = Target(
                type="ctf-web",
                id=challenge.metadata.name,
                endpoint=challenge.spec.scope.entry_point,
                simulation={
                    "category": CTFCategory.WEB,
                    "challengeId": challenge.metadata.name,
                    "scenarioId": challenge.spec.scenario,
                    "flagSha256": challenge.spec.flag.sha256,
                    "synthetic": True,
                },
            )
            rules = RulesOfEngagement(
                maxToolRiskTier=ToolRiskTier.T1,
                allowedMethods={"GET"},
                allowedToolCategories={"ctf", "discovery", "http", "web"},
                prohibit=common_prohibitions | {"arbitrary-path-discovery"},
                stopOn={"out-of-scope-attempt", "non-synthetic-response"},
                allowPrivateNetworks=True,
                maxRequestsPerMinute=5,
            )
            return _CompiledProfile(target, rules, "blackbox")

        assert challenge.spec.artifact is not None
        artifact = challenge.spec.artifact
        endpoint = crypto_artifact_target(challenge.metadata.name, artifact.sha256)
        target = Target(
            type="ctf-crypto",
            id=challenge.metadata.name,
            endpoint=endpoint,
            simulation={
                "category": CTFCategory.CRYPTO,
                "challengeId": challenge.metadata.name,
                "scenarioId": challenge.spec.scenario,
                "flagSha256": challenge.spec.flag.sha256,
                "artifactSha256": artifact.sha256,
                "ciphertextHex": artifact.data,
                "synthetic": True,
            },
        )
        rules = RulesOfEngagement(
            maxToolRiskTier=ToolRiskTier.T0,
            allowedMethods={"POST"},
            allowedToolCategories={"crypto", "ctf", "offline-analysis"},
            prohibit=common_prohibitions
            | {"external-process", "network-access", "unbounded-bruteforce"},
            stopOn={"artifact-integrity-failure", "out-of-scope-attempt"},
            allowPrivateNetworks=False,
        )
        return _CompiledProfile(target, rules, "inline-artifact")

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
    """Verify a completed run and append category-aware CTF result artifacts."""

    def finalize(
        self,
        challenge: CTFChallengeManifest,
        outcome: MultiAgentRunOutcome,
    ) -> CTFRunArtifacts:
        if outcome.status is not RunStatus.COMPLETED or outcome.plan is None:
            raise ValueError("CTF finalization requires a completed typed run")
        verify_run_integrity(outcome.run_path)
        campaign = self._validate_run_campaign(challenge, outcome)
        target = campaign.spec.targets[0]
        tool_id = (
            CTF_WEB_BACKUP_TOOL_ID
            if challenge.spec.category is CTFCategory.WEB
            else CTF_CRYPTO_XOR_TOOL_ID
        )
        probe_results = [result for result in outcome.tool_results if result.tool_id == tool_id]
        if len(outcome.tool_results) != 1 or len(probe_results) != 1:
            raise ValueError("CTF MVP requires exactly one category Specialist result")
        tool_result = probe_results[0]
        candidate = self._candidate(challenge, target.endpoint, tool_result.data)
        candidate_digest = sha256(candidate.encode("utf-8")).hexdigest() if candidate else None
        expected_digest = challenge.spec.flag.sha256
        digest_matches = candidate_digest is not None and compare_digest(
            candidate_digest, expected_digest
        )
        threat_class = f"CTF-{challenge.spec.category.value.upper()}"
        validated = any(
            finding.validated
            and finding.threat_class == threat_class
            and finding.target == target.endpoint
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
                "category": challenge.spec.category.value,
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
    def _candidate(
        challenge: CTFChallengeManifest,
        target: str,
        data: dict[str, object],
    ) -> str | None:
        try:
            if challenge.spec.category is CTFCategory.WEB:
                web_output = CTFWebBackupProbeOutput.model_validate(data)
                if (
                    web_output.target != target
                    or web_output.challenge_id != challenge.metadata.name
                    or not web_output.discovered
                    or not web_output.network_performed
                ):
                    return None
                return web_output.candidate_flag

            crypto_output = CTFCryptoXOROutput.model_validate(data)
            assert challenge.spec.artifact is not None
            if (
                crypto_output.target != target
                or crypto_output.challenge_id != challenge.metadata.name
                or crypto_output.artifact_sha256 != challenge.spec.artifact.sha256
                or not crypto_output.solved
                or crypto_output.network_performed
            ):
                return None
            return crypto_output.candidate_flag
        except ValueError:
            return None

    @staticmethod
    def _validate_run_campaign(
        challenge: CTFChallengeManifest,
        outcome: MultiAgentRunOutcome,
    ) -> CampaignManifest:
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
        return campaign

    @staticmethod
    def _render_writeup(
        challenge: CTFChallengeManifest,
        result: CTFRunResult,
    ) -> str:
        category = challenge.spec.category
        if category is CTFCategory.WEB:
            specialist_step = (
                "A Web Specialist used the one-call Capability for the fixed backup path."
            )
            solved_observation = (
                "The synthetic backup configuration artifact exposed a candidate flag."
            )
            unsolved_observation = "The fixed backup path did not expose a candidate flag."
            lesson = (
                "Exclude backup artifacts from deployment output and deny known backup suffixes "
                "at build time."
            )
        else:
            specialist_step = (
                "A Crypto Specialist verified the artifact digest and evaluated 256 XOR keys "
                "without network access."
            )
            solved_observation = (
                "The bounded offline XOR analysis produced one format-constrained candidate flag."
            )
            unsolved_observation = "The bounded 256-key analysis produced no candidate flag."
            lesson = (
                "Keep offline CTF inputs content-addressed and explicitly bound computation, "
                "artifact size, and candidate grammar."
            )
        lines = [
            f"# CTF Write-up: {challenge.metadata.display_name}",
            "",
            f"- Challenge ID: `{challenge.metadata.name}`",
            f"- Category: `{category.value}`",
            f"- Scenario: `{challenge.spec.scenario.value}`",
            f"- Solve status: `{result.status.value}`",
            f"- Run ID: `{result.run_id}`",
            "- External scoreboard submission: `not performed`",
            "",
            "## Agent route",
            "",
            f"1. The Triage Planner classified the typed challenge as {category.value}.",
            f"2. {specialist_step}",
            "3. The independent Validator hashed the candidate and compared only digests.",
            "4. The Reporter produced this evidence-bound write-up.",
            "",
            "## Observation",
            "",
        ]
        if result.status is CTFSolveStatus.SOLVED:
            lines.extend(
                [
                    solved_observation,
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
            lines.append(unsolved_observation)
        lines.extend(
            [
                "",
                "## Evidence",
                "",
                *[f"- `{item}`" for item in result.evidence],
                "",
                "## Defensive lesson",
                "",
                lesson,
            ]
        )
        return "\n".join(lines) + "\n"
