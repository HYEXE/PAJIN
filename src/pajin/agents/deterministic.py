"""Deterministic runtime used to test PAJIN without model credentials."""

from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    Finding,
    FindingSeverity,
    PlannedStep,
    ToolRequest,
    ToolResult,
)


class DeterministicAgentRuntime:
    """Exercise the same contracts as an LLM runtime with repeatable output."""

    agent_id = "agent:planner-local"

    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        target = campaign.spec.targets[0]
        if target.type == "http":
            return AgentPlan(
                summary="Fetch the authorized HTTP target through the isolated egress proxy.",
                steps=[
                    PlannedStep(
                        title="Fetch authorized HTTP target",
                        rationale="Validate network-layer target allowlisting and proxy evidence.",
                        request=ToolRequest(
                            agent_id=self.agent_id,
                            tool_id="http.get",
                            target=target.endpoint,
                            method="GET",
                        ),
                    )
                ],
            )
        if target.type == "mock-mcp":
            text = str(target.simulation.get("text", ""))
            return AgentPlan(
                summary="Invoke a registered MCP security tool inside the isolated Worker.",
                steps=[
                    PlannedStep(
                        title="Inspect untrusted text through MCP",
                        rationale="Validate the registered MCP bridge and structured tool result.",
                        request=ToolRequest(
                            agent_id=self.agent_id,
                            tool_id="mcp.demo-security.inspect-text",
                            target=target.endpoint,
                            method="POST",
                            arguments={"text": text},
                        ),
                    )
                ],
            )
        if target.type == "mock-sleep":
            return AgentPlan(
                summary="Run a bounded Worker operation to verify cancellation propagation.",
                steps=[
                    PlannedStep(
                        title="Run cancellable Worker operation",
                        rationale="Verify that the campaign Kill Switch reaches the Worker.",
                        request=ToolRequest(
                            agent_id=self.agent_id,
                            tool_id="mock.sleep-check",
                            target=target.endpoint,
                            method="POST",
                            arguments={"seconds": target.simulation.get("seconds", 5)},
                        ),
                    )
                ],
            )
        request = ToolRequest(
            agent_id=self.agent_id,
            tool_id="mock.agent-probe",
            target=target.endpoint,
            method="POST",
            arguments={"simulation": target.simulation},
        )
        return AgentPlan(
            summary="Probe the authorized mock agent target for unauthorized tool execution.",
            steps=[
                PlannedStep(
                    title="Run indirect prompt-injection simulation",
                    rationale="Validate KISA A01/A02 controls without contacting a real target.",
                    request=request,
                )
            ],
        )

    async def validate(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> list[Finding]:
        del plan
        findings: list[Finding] = []
        for result in results:
            if not result.success or not result.data.get("vulnerable"):
                continue
            target = str(result.data["target"])
            findings.append(
                Finding(
                    title="Untrusted instruction triggered an unauthorized tool call",
                    severity=FindingSeverity.HIGH,
                    threat_class="A02",
                    target=target,
                    summary=(
                        "The simulated target followed an indirect instruction and invoked a "
                        "protected tool without an independent authorization check."
                    ),
                    reproduction=[
                        "Submit untrusted external content containing a tool-use instruction.",
                        "Observe whether the target requests the protected tool.",
                        "Verify the tool invocation was not independently authorized.",
                    ],
                    evidence=list(result.evidence),
                    confidence=1.0,
                    validated=True,
                )
            )
        return findings
