"""Compile local CTF challenges and emit evidence-bound solve artifacts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from hmac import compare_digest
from pathlib import Path
from re import fullmatch

import yaml

from pajin.domain.models import (
    Authorization,
    AutonomyLevel,
    Budgets,
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
from pajin.domain.yaml_loader import load_yaml_mapping
from pajin.modes.ctf.evidence import load_authoritative_ctf_execution
from pajin.modes.ctf.models import (
    CTFCategory,
    CTFChallengeManifest,
    CTFRunResult,
    CTFSolveStatus,
    CTFSuiteResult,
    CTFSuiteSummary,
)
from pajin.reporting import escape_markdown_text, markdown_code_span
from pajin.runtime.safe_files import atomic_write_text_no_follow
from pajin.runtime.store import RunStore
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
class CTFSuiteArtifacts:
    result: CTFSuiteResult
    result_path: Path
    writeup_path: Path


@dataclass(frozen=True)
class _CompiledProfile:
    target: Target
    rules: RulesOfEngagement
    access_profile: str


def load_ctf_challenge(path: Path) -> CTFChallengeManifest:
    raw = load_yaml_mapping(path, label="CTF challenge manifest")
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

    def compile_suite(
        self,
        suite_name: str,
        challenges: list[CTFChallengeManifest],
        *,
        evaluated_at: datetime | None = None,
    ) -> CampaignManifest:
        """Compile one Web and one Crypto challenge into a shared bounded Campaign."""

        ordered = self._ordered_suite(suite_name, challenges)
        now = evaluated_at or datetime.now(UTC)
        authorization = self._suite_authorization(suite_name, ordered)
        if not authorization.is_active(now):
            raise ValueError("CTF Suite authorization intersection is not active")

        profiles = [self._profile(challenge) for challenge in ordered]
        rate_limits = [
            profile.rules.max_requests_per_minute
            for profile in profiles
            if profile.rules.max_requests_per_minute is not None
        ]
        rules = RulesOfEngagement(
            maxToolRiskTier=max(profile.rules.max_tool_risk_tier for profile in profiles),
            allowedMethods=set().union(*(profile.rules.allowed_methods for profile in profiles)),
            allowedToolCategories=set().union(
                *(profile.rules.allowed_tool_categories for profile in profiles)
            ),
            prohibit=set().union(*(profile.rules.prohibit for profile in profiles)),
            stopOn=set().union(*(profile.rules.stop_on for profile in profiles)),
            allowPrivateNetworks=any(profile.rules.allow_private_networks for profile in profiles),
            maxRequestsPerMinute=max(rate_limits) if rate_limits else None,
        )
        budgets = Budgets(
            durationSeconds=sum(challenge.spec.budgets.duration_seconds for challenge in ordered),
            maxCostUsd=0,
            maxAgents=len(ordered) + 4,
            maxSpawnDepth=1,
            maxToolCalls=len(ordered),
            maxModelCalls=0,
            maxModelTokens=0,
        )
        objectives = [
            f"[{challenge.metadata.name}] {objective}"
            for challenge in ordered
            for objective in challenge.spec.objectives
        ]
        return CampaignManifest(
            apiVersion="pajin.dev/v1alpha1",
            kind="Campaign",
            metadata=CampaignMetadata(
                name=suite_name,
                description=(
                    "Local-only CTF Suite with one bounded Web challenge and one bounded "
                    "Crypto challenge."
                ),
            ),
            spec=CampaignSpec(
                mode=CampaignMode.CTF,
                autonomy=AutonomyLevel.LAB_AUTONOMOUS,
                authorization=authorization,
                targets=[profile.target for profile in profiles],
                scope=Scope(
                    allow=[profile.target.endpoint for profile in profiles],
                    deny=[],
                ),
                accessProfile="mixed",
                objectives=objectives,
                rulesOfEngagement=rules,
                budgets=budgets,
                outputs=["ctf-suite-result", "ctf-suite-writeup", "evidence-bundle"],
            ),
        )

    @staticmethod
    def _ordered_suite(
        suite_name: str,
        challenges: list[CTFChallengeManifest],
    ) -> list[CTFChallengeManifest]:
        if fullmatch(r"[a-z0-9][a-z0-9-]{2,63}", suite_name) is None:
            raise ValueError("CTF Suite name must be a lowercase DNS-style identifier")
        if len(challenges) != 2:
            raise ValueError("CTF Suite MVP requires exactly two challenges")
        if len({challenge.metadata.name for challenge in challenges}) != 2:
            raise ValueError("CTF Suite challenge IDs must be unique")
        by_category = {challenge.spec.category: challenge for challenge in challenges}
        if set(by_category) != {CTFCategory.WEB, CTFCategory.CRYPTO}:
            raise ValueError("CTF Suite MVP requires exactly one Web and one Crypto challenge")
        return [by_category[CTFCategory.WEB], by_category[CTFCategory.CRYPTO]]

    @staticmethod
    def _suite_authorization(
        suite_name: str,
        challenges: list[CTFChallengeManifest],
    ) -> Authorization:
        approvers = {challenge.spec.authorization.approved_by for challenge in challenges}
        if len(approvers) != 1:
            raise ValueError("CTF Suite challenges must have the same approving authority")
        approved_at = max(challenge.spec.authorization.approved_at for challenge in challenges)
        expires_at = min(challenge.spec.authorization.expires_at for challenge in challenges)
        if approved_at >= expires_at:
            raise ValueError("CTF Suite challenge authorizations do not overlap")
        members = [
            {
                "challengeId": challenge.metadata.name,
                "category": challenge.spec.category.value,
                "authorization": challenge.spec.authorization.model_dump(
                    mode="json", by_alias=True
                ),
                "flagSha256": challenge.spec.flag.sha256,
            }
            for challenge in challenges
        ]
        member_digest = sha256(
            json.dumps(members, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return Authorization(
            approvedBy=next(iter(approvers)),
            approvedAt=approved_at,
            expiresAt=expires_at,
            evidence=f"ctf-suite:{suite_name}; members-sha256:{member_digest}",
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
        atomic_write_text_no_follow(
            output_path,
            yaml.safe_dump(
                campaign.model_dump(mode="json", by_alias=True),
                allow_unicode=True,
                sort_keys=False,
            ),
            label="CTF Campaign artifact",
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
        execution = load_authoritative_ctf_execution(outcome)
        campaign = self._validate_run_campaign(challenge, execution.campaign)
        target = campaign.spec.targets[0]
        tool_id = (
            CTF_WEB_BACKUP_TOOL_ID
            if challenge.spec.category is CTFCategory.WEB
            else CTF_CRYPTO_XOR_TOOL_ID
        )
        if len(execution.plan.steps) != 1 or len(execution.tool_results) != 1:
            raise ValueError("CTF MVP requires exactly one category Specialist result")
        step = execution.plan.steps[0]
        tool_result = execution.tool_results[0]
        if (
            step.request.target != target.endpoint
            or step.request.tool_id != tool_id
            or tool_result.request_id != step.request.request_id
            or tool_result.tool_id != tool_id
        ):
            raise ValueError("sealed CTF result does not match its Specialist request")
        if not tool_result.success:
            raise ValueError("CTF finalization requires a successful Specialist result")
        candidate = self._candidate(challenge, target.endpoint, tool_result.data)
        candidate_digest = sha256(candidate.encode("utf-8")).hexdigest() if candidate else None
        expected_digest = challenge.spec.flag.sha256
        digest_matches = candidate_digest is not None and compare_digest(
            candidate_digest, expected_digest
        )
        # CTF flag verification is a deterministic Mode solve state, not a security
        # Finding confirmation. ADR 0027 therefore keeps this digest gate independent
        # from the common Candidate/ReplayOutcome confirmation projection.
        if digest_matches:
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
        campaign: CampaignManifest,
    ) -> CampaignManifest:
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
            f"# CTF Write-up: {escape_markdown_text(challenge.metadata.display_name)}",
            "",
            f"- Challenge ID: {markdown_code_span(challenge.metadata.name)}",
            f"- Category: {markdown_code_span(category.value)}",
            f"- Scenario: {markdown_code_span(challenge.spec.scenario.value)}",
            f"- Solve status: {markdown_code_span(result.status.value)}",
            f"- Run ID: {markdown_code_span(result.run_id)}",
            "- External scoreboard submission: `not performed`",
            "",
            "## Agent route",
            "",
            f"1. The Triage Planner classified the typed challenge as {category.value}.",
            f"2. {specialist_step}",
            "3. The Mode-owned solve verifier hashed the candidate and compared only digests.",
            "4. The Reporter produced this evidence-bound write-up.",
            "",
            "## Observation",
            "",
        ]
        if result.status is CTFSolveStatus.SOLVED:
            if result.candidate_flag is None or result.candidate_sha256 is None:
                raise ValueError("solved CTF write-up requires verified flag material")
            lines.extend(
                [
                    solved_observation,
                    "",
                    f"- Verified flag: {markdown_code_span(result.candidate_flag)}",
                    "- Candidate SHA-256: " + markdown_code_span(result.candidate_sha256),
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
                    "- Candidate SHA-256: " + markdown_code_span(result.candidate_sha256 or ""),
                ]
            )
        else:
            lines.append(unsolved_observation)
        lines.extend(
            [
                "",
                "## Evidence",
                "",
                *[f"- {markdown_code_span(item)}" for item in result.evidence],
                "",
                "## Defensive lesson",
                "",
                lesson,
            ]
        )
        return "\n".join(lines) + "\n"


class CTFSuiteModePack:
    """Verify and seal aggregate results for one bounded Web/Crypto Suite run."""

    def finalize(
        self,
        suite_name: str,
        challenges: list[CTFChallengeManifest],
        outcome: MultiAgentRunOutcome,
    ) -> CTFSuiteArtifacts:
        if outcome.status is not RunStatus.COMPLETED or outcome.plan is None:
            raise ValueError("CTF Suite finalization requires a completed typed run")
        execution = load_authoritative_ctf_execution(outcome)
        ordered = CTFChallengeService._ordered_suite(suite_name, challenges)
        campaign = self._validate_run_campaign(suite_name, ordered, execution.campaign)
        if len(execution.plan.steps) != 2 or len(execution.tool_results) != 2:
            raise ValueError("CTF Suite MVP requires exactly two Specialist results")

        items: list[CTFRunResult] = []
        for challenge in ordered:
            target = next(
                (
                    candidate
                    for candidate in campaign.spec.targets
                    if candidate.id == challenge.metadata.name
                ),
                None,
            )
            if target is None:
                raise ValueError("CTF Suite target is missing from the sealed Campaign")
            tool_id = (
                CTF_WEB_BACKUP_TOOL_ID
                if challenge.spec.category is CTFCategory.WEB
                else CTF_CRYPTO_XOR_TOOL_ID
            )
            steps = [
                step
                for step in execution.plan.steps
                if step.request.target == target.endpoint and step.request.tool_id == tool_id
            ]
            if len(steps) != 1:
                raise ValueError("CTF Suite plan does not uniquely bind each Specialist")
            tool_results = [
                result
                for result in execution.tool_results
                if result.request_id == steps[0].request.request_id and result.tool_id == tool_id
            ]
            if len(tool_results) != 1:
                raise ValueError("CTF Suite result does not match its Specialist request")
            tool_result = tool_results[0]
            if not tool_result.success:
                raise ValueError("CTF Suite finalization requires successful Specialist results")
            candidate = CTFModePack._candidate(challenge, target.endpoint, tool_result.data)
            candidate_digest = sha256(candidate.encode("utf-8")).hexdigest() if candidate else None
            expected_digest = challenge.spec.flag.sha256
            digest_matches = candidate_digest is not None and compare_digest(
                candidate_digest, expected_digest
            )
            if digest_matches:
                status = CTFSolveStatus.SOLVED
            elif candidate is not None:
                status = CTFSolveStatus.INVALID_FLAG
            else:
                status = CTFSolveStatus.UNSOLVED
            items.append(
                CTFRunResult(
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
            )
        summary = CTFSuiteSummary(
            solved=sum(item.status is CTFSolveStatus.SOLVED for item in items),
            unsolved=sum(item.status is CTFSolveStatus.UNSOLVED for item in items),
            invalidFlag=sum(item.status is CTFSolveStatus.INVALID_FLAG for item in items),
        )
        result = CTFSuiteResult(
            run_id=outcome.run_id,
            suite_name=suite_name,
            items=items,
            summary=summary,
        )
        store = RunStore(outcome.run_id, outcome.run_path)
        result_relative = store.write_json(
            "ctf-suite-result.json",
            result.model_dump(mode="json", by_alias=True),
        )
        writeup_relative = store.write_text(
            "ctf-suite-writeup.md",
            self._render_writeup(result),
        )
        store.append_event(
            "mode-pack.ctf-suite.completed",
            {
                "suiteName": suite_name,
                "solved": summary.solved,
                "unsolved": summary.unsolved,
                "invalidFlag": summary.invalid_flag,
                "result": result_relative,
                "writeup": writeup_relative,
                "externalSubmission": False,
            },
        )
        store.seal()
        return CTFSuiteArtifacts(
            result=result,
            result_path=outcome.run_path / result_relative,
            writeup_path=outcome.run_path / writeup_relative,
        )

    @staticmethod
    def _validate_run_campaign(
        suite_name: str,
        challenges: list[CTFChallengeManifest],
        campaign: CampaignManifest,
    ) -> CampaignManifest:
        evaluated_at = max(challenge.spec.authorization.approved_at for challenge in challenges)
        expected = CTFChallengeService().compile_suite(
            suite_name,
            challenges,
            evaluated_at=evaluated_at,
        )
        if campaign != expected:
            raise ValueError("sealed Run campaign does not match the CTF Suite")
        return campaign

    @staticmethod
    def _render_writeup(result: CTFSuiteResult) -> str:
        lines = [
            f"# CTF Suite Write-up: {escape_markdown_text(result.suite_name)}",
            "",
            f"- Run ID: {markdown_code_span(result.run_id)}",
            f"- Solved: `{result.summary.solved}`",
            f"- Unsolved: `{result.summary.unsolved}`",
            f"- Invalid flag: `{result.summary.invalid_flag}`",
            "- External scoreboard submission: `not performed`",
            "",
            "## Challenge results",
            "",
        ]
        for item in result.items:
            lines.extend(
                [
                    f"### {escape_markdown_text(item.challenge_id)}",
                    "",
                    f"- Category: `{item.category.value}`",
                    f"- Scenario: `{item.scenario.value}`",
                    f"- Status: `{item.status.value}`",
                ]
            )
            if item.status is CTFSolveStatus.SOLVED:
                if item.candidate_flag is None or item.candidate_sha256 is None:
                    raise ValueError("solved CTF Suite write-up requires verified flag material")
                lines.append(f"- Verified flag: {markdown_code_span(item.candidate_flag)}")
            elif item.candidate_sha256 is not None:
                lines.append(f"- Candidate SHA-256: {markdown_code_span(item.candidate_sha256)}")
            lines.extend(["", "Evidence:", ""])
            lines.extend(f"- {markdown_code_span(evidence)}" for evidence in item.evidence)
            lines.append("")
        lines.extend(
            [
                "## Execution boundary",
                "",
                (
                    "The Triage Planner created one target-bound Specialist per category. "
                    "Each candidate was independently digest-validated, and no external "
                    "scoreboard submission was performed."
                ),
            ]
        )
        return "\n".join(lines) + "\n"
