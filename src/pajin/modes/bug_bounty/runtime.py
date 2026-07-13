"""Deterministic Planner and independent Validator for the Bug Bounty lab profile."""

from __future__ import annotations

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
from pajin.tools.bug_bounty import (
    BOOLEAN_SQLI_SCENARIO,
    BooleanSQLiObservation,
    BooleanSQLiProbeInput,
    BooleanSQLiProbeOutput,
)

BOOLEAN_SQLI_TOOL_ID = "bug-bounty.boolean-sqli-probe"


class BugBountyPlannerRuntime:
    """Create only the fixed, policy-compiled probe steps supported by the local lab."""

    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        if campaign.spec.mode is not CampaignMode.BUG_BOUNTY:
            raise ValueError("Bug Bounty Planner requires mode: bug-bounty")

        steps: list[PlannedStep] = []
        for target in campaign.spec.targets:
            if target.type != "bug-bounty-api":
                continue
            probe = BooleanSQLiProbeInput()
            steps.append(
                PlannedStep(
                    title=f"Fixed boolean SQLi comparison for {target.id}",
                    rationale=(
                        "Compare one baseline, one negative control, and one boolean predicate "
                        "against the explicitly approved synthetic lab endpoint."
                    ),
                    request=ToolRequest(
                        agent_id="agent:bug-bounty-planner-untrusted",
                        tool_id=BOOLEAN_SQLI_TOOL_ID,
                        target=target.endpoint,
                        method="GET",
                        arguments=probe.model_dump(mode="json", by_alias=True),
                    ),
                    scenario_id=BOOLEAN_SQLI_SCENARIO,
                    threat_classes={"CWE-89"},
                    attack_surface="api",
                    persona="bug-bounty-researcher",
                )
            )
        if not steps:
            raise ValueError("no executable fixed Bug Bounty lab target is present")
        return AgentPlan(
            summary=(
                "Execute the fixed three-request boolean SQLi comparison on each approved "
                "synthetic Bug Bounty lab target."
            ),
            steps=steps,
        )


class BugBountyValidatorRuntime:
    """Recompute a SQLi signal from observations without trusting Worker conclusions."""

    async def validate(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> list[Finding]:
        if campaign.spec.mode is not CampaignMode.BUG_BOUNTY:
            raise ValueError("Bug Bounty Validator requires mode: bug-bounty")

        steps = {
            step.request.request_id: step
            for step in plan.steps
            if step.request.tool_id == BOOLEAN_SQLI_TOOL_ID
            and step.scenario_id == BOOLEAN_SQLI_SCENARIO
        }
        findings: list[Finding] = []
        for result in results:
            step = steps.get(result.request_id)
            if step is None or not result.success or result.tool_id != BOOLEAN_SQLI_TOOL_ID:
                continue
            try:
                output = BooleanSQLiProbeOutput.model_validate(result.data)
            except ValueError:
                continue
            if (
                output.target != step.request.target
                or output.scenario_id != step.scenario_id
                or not output.network_performed
                or not result.evidence
                or not self._observations_confirm_sqli(output.observations)
            ):
                continue
            findings.append(
                Finding(
                    title="Boolean-based SQL injection in synthetic user lookup",
                    severity=FindingSeverity.HIGH,
                    threat_class="CWE-89",
                    target=step.request.target,
                    summary=(
                        "A fixed boolean predicate changed the synthetic lookup result from one "
                        "record to multiple records while the negative control returned none."
                    ),
                    impact=(
                        "An attacker able to control the lookup identifier can alter the query "
                        "predicate and expand the returned synthetic record set."
                    ),
                    affected_component="synthetic user lookup query",
                    root_cause=(
                        "The lookup identifier is concatenated into a query predicate instead of "
                        "being bound as a parameter."
                    ),
                    reproduction=[
                        "Send the fixed numeric baseline to the approved lookup endpoint and "
                        "observe one synthetic record.",
                        "Send the fixed false predicate control and observe zero records.",
                        "Send the fixed true predicate probe and observe multiple synthetic "
                        "records.",
                    ],
                    evidence=list(dict.fromkeys(result.evidence)),
                    remediation=[
                        "Use parameterized queries for the lookup identifier.",
                        "Validate that the identifier is a decimal integer before database access.",
                        "Retest the same baseline and controls after applying the fix.",
                    ],
                    confidence=1.0,
                    validated=True,
                )
            )
        return findings

    @staticmethod
    def _observations_confirm_sqli(observations: list[BooleanSQLiObservation]) -> bool:
        by_name = {observation.name: observation for observation in observations}
        baseline = by_name["baseline"]
        negative = by_name["negative-control"]
        probe = by_name["boolean-probe"]
        return (
            baseline.status == 200
            and baseline.record_count == 1
            and negative.status in {200, 400}
            and negative.record_count == 0
            and probe.status == 200
            and probe.record_count > baseline.record_count
            and all(observation.synthetic for observation in observations)
        )
