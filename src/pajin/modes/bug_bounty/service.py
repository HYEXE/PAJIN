"""Deterministic Bug Bounty scope review and Campaign compilation."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from hmac import compare_digest
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

from pajin.domain.models import (
    Authorization,
    CampaignManifest,
    CampaignMetadata,
    CampaignMode,
    CampaignSpec,
    RulesOfEngagement,
    Scope,
    Target,
)
from pajin.modes.bug_bounty.models import (
    DEFAULT_PROHIBITED_TECHNIQUES,
    DEFAULT_STOP_CONDITIONS,
    BugBountyProbeProfile,
    BugBountyProgramManifest,
    BugBountyScopeApproval,
    BugBountyScopeReview,
)


class BugBountyReviewArtifacts(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    directory: Path
    normalized_program_path: Path
    review_json_path: Path
    review_markdown_path: Path
    review: BugBountyScopeReview


class BugBountyCampaignArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    path: Path
    campaign: CampaignManifest


def load_bug_bounty_program(path: Path) -> BugBountyProgramManifest:
    with path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise ValueError("bug bounty program manifest must contain a YAML mapping")
    return BugBountyProgramManifest.model_validate(raw)


class BugBountyScopeService:
    """Create an operator-reviewable policy snapshot, then compile the approved digest."""

    def review(
        self,
        program: BugBountyProgramManifest,
        *,
        generated_at: datetime | None = None,
    ) -> BugBountyScopeReview:
        canonical = self._canonical_program(program)
        source_text = program.spec.policy.raw_text.encode("utf-8")
        allow = sorted(asset.pattern for asset in program.spec.scope.in_scope)
        deny = sorted(asset.pattern for asset in program.spec.scope.out_of_scope)
        entry_points = sorted(
            entry_point
            for asset in program.spec.scope.in_scope
            for entry_point in asset.entry_points
        )
        warnings: list[str] = []
        if not deny:
            warnings.append(
                "No explicit out-of-scope rule is defined; operator review is required."
            )
        wildcard_assets = [pattern for pattern in allow if "*." in pattern]
        if wildcard_assets:
            warnings.append(
                f"{len(wildcard_assets)} wildcard scope rule(s) require ownership verification."
            )
        empty_assets = [
            asset.asset_id for asset in program.spec.scope.in_scope if not asset.entry_points
        ]
        if empty_assets:
            warnings.append(
                "In-scope assets without executable entry points are review-only: "
                + ", ".join(sorted(empty_assets))
            )
        state_changing = program.spec.rules.state_changing_methods
        if state_changing:
            warnings.append(
                "State-changing methods require minimum-impact test design: "
                + ", ".join(sorted(state_changing))
            )

        data = program.spec.data_handling
        reporting = program.spec.reporting
        manual_controls = [
            "Use only program-approved test accounts and synthetic data.",
            (
                "Delete or re-authorize evidence after "
                f"{data.max_evidence_retention_days} days; automatic retention is not yet enabled."
            ),
            f"Apply the {reporting.severity_standard} severity standard during final triage.",
        ]
        if reporting.duplicate_check_required:
            manual_controls.append("Complete duplicate review before submitting a report.")

        return BugBountyScopeReview(
            program_name=program.metadata.name,
            generated_at=generated_at or datetime.now(UTC),
            source_sha256=sha256(source_text).hexdigest(),
            scope_digest=sha256(canonical).hexdigest(),
            allow=allow,
            deny=deny,
            entry_points=entry_points,
            allowed_methods=program.spec.rules.allowed_methods,
            allowed_tool_categories=program.spec.rules.allowed_tool_categories,
            prohibited_techniques=(
                program.spec.rules.prohibited_techniques | DEFAULT_PROHIBITED_TECHNIQUES
            ),
            stop_on=program.spec.rules.stop_on | DEFAULT_STOP_CONDITIONS,
            max_requests_per_minute=program.spec.rules.max_requests_per_minute,
            testing_windows=program.spec.rules.testing_windows,
            warnings=warnings,
            manual_controls=manual_controls,
        )

    def write_review(
        self,
        program: BugBountyProgramManifest,
        output_root: Path,
        *,
        generated_at: datetime | None = None,
    ) -> BugBountyReviewArtifacts:
        review = self.review(program, generated_at=generated_at)
        directory = output_root / program.metadata.name / review.scope_digest[:12]
        directory.mkdir(parents=True, exist_ok=True)
        normalized_program_path = directory / "program.normalized.json"
        review_json_path = directory / "scope-review.json"
        review_markdown_path = directory / "scope-review.md"
        normalized_program_path.write_text(
            json.dumps(
                self._stable_json_value(program.model_dump(mode="json", by_alias=True)),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        review_json_path.write_text(
            json.dumps(
                self._stable_json_value(review.model_dump(mode="json")),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        review_markdown_path.write_text(self.render_review(program, review), encoding="utf-8")
        return BugBountyReviewArtifacts(
            directory=directory,
            normalized_program_path=normalized_program_path,
            review_json_path=review_json_path,
            review_markdown_path=review_markdown_path,
            review=review,
        )

    def compile_campaign(
        self,
        program: BugBountyProgramManifest,
        approval: BugBountyScopeApproval,
    ) -> CampaignManifest:
        review = self.review(program)
        if not compare_digest(review.scope_digest, approval.scope_digest):
            raise ValueError("scope approval digest does not match the current program policy")
        approved_at = self._aware(approval.approved_at)
        retrieved_at = self._aware(program.spec.policy.retrieved_at)
        if approved_at < retrieved_at:
            raise ValueError("scope approval predates the retrieved program policy")

        targets: list[Target] = []
        for asset in program.spec.scope.in_scope:
            for index, entry_point in enumerate(asset.entry_points, start=1):
                suffix = "" if len(asset.entry_points) == 1 else f"-{index}"
                targets.append(
                    Target(
                        type=(
                            "bug-bounty-api"
                            if asset.probe_profile is BugBountyProbeProfile.BOOLEAN_SQLI_LAB
                            else "http"
                        ),
                        id=f"{asset.asset_id}{suffix}",
                        endpoint=entry_point,
                    )
                )

        rules = program.spec.rules
        campaign = CampaignManifest(
            apiVersion="pajin.dev/v1alpha1",
            kind="Campaign",
            metadata=CampaignMetadata(
                name=program.metadata.name,
                description=(
                    f"Digest-approved Bug Bounty campaign for {program.metadata.display_name}."
                ),
            ),
            spec=CampaignSpec(
                mode=CampaignMode.BUG_BOUNTY,
                authorization=Authorization(
                    approvedBy=approval.approved_by,
                    approvedAt=approval.approved_at,
                    expiresAt=approval.expires_at,
                    evidence=f"{approval.evidence}; scope-sha256:{review.scope_digest}",
                ),
                targets=targets,
                scope=Scope(allow=review.allow, deny=review.deny),
                accessProfile="blackbox",
                objectives=program.spec.objectives,
                rulesOfEngagement=RulesOfEngagement(
                    maxToolRiskTier=rules.max_tool_risk_tier,
                    allowedMethods=review.allowed_methods,
                    allowedToolCategories=review.allowed_tool_categories,
                    prohibit=review.prohibited_techniques,
                    stopOn=review.stop_on,
                    allowPrivateNetworks=rules.allow_private_networks,
                    maxRequestsPerMinute=review.max_requests_per_minute,
                    testingWindows=review.testing_windows,
                ),
                budgets=program.spec.budgets,
                outputs=[
                    "markdown-report",
                    "json-findings",
                ],
            ),
        )
        return campaign

    def write_campaign(
        self,
        program: BugBountyProgramManifest,
        approval: BugBountyScopeApproval,
        output_path: Path,
    ) -> BugBountyCampaignArtifact:
        campaign = self.compile_campaign(program, approval)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            yaml.safe_dump(
                self._stable_json_value(campaign.model_dump(mode="json", by_alias=True)),
                allow_unicode=True,
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        return BugBountyCampaignArtifact(path=output_path, campaign=campaign)

    @staticmethod
    def render_review(
        program: BugBountyProgramManifest,
        review: BugBountyScopeReview,
    ) -> str:
        lines = [
            f"# Bug Bounty Scope Review: {program.metadata.display_name}",
            "",
            f"- Program: `{program.metadata.name}`",
            f"- Platform: `{program.metadata.platform}`",
            f"- Policy source: `{program.spec.policy.uri}`",
            f"- Source SHA-256: `{review.source_sha256}`",
            f"- Approval scope digest: `{review.scope_digest}`",
            "- Approval required: `true`",
            "",
            "## Executable scope",
            "",
            "### Allow",
            "",
        ]
        lines.extend(f"- `{item}`" for item in review.allow)
        lines.extend(["", "### Deny", ""])
        lines.extend(f"- `{item}`" for item in review.deny)
        if not review.deny:
            lines.append("- None declared")
        lines.extend(["", "### Concrete entry points", ""])
        lines.extend(f"- `{item}`" for item in review.entry_points)
        lines.extend(
            [
                "",
                "## Enforced execution policy",
                "",
                "- Allowed methods: " + ", ".join(sorted(review.allowed_methods)),
                "- Allowed tool categories: " + ", ".join(sorted(review.allowed_tool_categories)),
                "- Prohibited techniques: " + ", ".join(sorted(review.prohibited_techniques)),
                f"- Maximum requests per minute: {review.max_requests_per_minute}",
                f"- Testing windows: {len(review.testing_windows)}",
                "",
                "## Warnings",
                "",
            ]
        )
        lines.extend(f"- {item}" for item in review.warnings)
        if not review.warnings:
            lines.append("- None")
        lines.extend(["", "## Manual controls", ""])
        lines.extend(f"- {item}" for item in review.manual_controls)
        lines.extend(
            [
                "",
                "## Approval procedure",
                "",
                "Compile a Campaign only after comparing this review with the program policy. ",
                "Pass the exact approval scope digest to `pajin bug-bounty-compile`; any policy ",
                "change produces a different digest and invalidates the approval.",
                "",
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def _canonical_program(program: BugBountyProgramManifest) -> bytes:
        return json.dumps(
            BugBountyScopeService._stable_json_value(
                program.model_dump(mode="json", by_alias=True)
            ),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @staticmethod
    def _stable_json_value(value: object) -> object:
        if isinstance(value, dict):
            return {
                str(key): BugBountyScopeService._stable_json_value(item)
                for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            }
        if isinstance(value, list):
            normalized = [BugBountyScopeService._stable_json_value(item) for item in value]
            if all(
                item is None or isinstance(item, str | int | float | bool) for item in normalized
            ):
                return sorted(
                    normalized,
                    key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True),
                )
            return normalized
        return value

    @staticmethod
    def _aware(value: datetime) -> datetime:
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
