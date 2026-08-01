# WALK-005B1: Claim-Bound MCP Replay Plan

- Status: Implemented
- Authority contract: `pajin.dev/walking-mcp-replay-plan/v1alpha1`
- Decision: [ADR-0073](../adr/0073-claim-bound-non-executable-mcp-replay-plan.md)

## Scope

WALK-005B1 creates the authority that must exist before an MCP validity replay can be executed. It
reopens the complete sealed WALK-005A Candidate authority, selects its one deterministic validity
Atomic Claim, and seals an exact Replay Plan. It does not issue approval, Grant, Permit, request,
ticket, Worker execution, ReplayOutcome, confirmation, report, or Retest authority.

The existing generic Replay models remain unchanged. Their implemented materializers and Oracles
are limited to exact KISA M03, M06, and A04 contracts, so this slice does not relabel the A02 MCP
Candidate as one of those scenarios.

## Bound authority

`WalkingMCPReplayPlan` binds:

- the complete sealed WALK-005A authority, publication Run ID/root, artifact path/SHA-256, and
  Campaign digest;
- exactly one validity Claim from the Candidate's canonical Atomic Claim set;
- the original sealed execution, Run, request, and request digest;
- the exact Tool, target, `POST` method, and normalized parameter digest; and
- mandatory freshness of the replay execution Run, request, approval, CapabilityGrant, Permit,
  dispatch, and Worker execution identities.

The Plan state is fixed to `planned-not-authorized`. Caller-authored Claims, arguments, targets,
Tools, and freshness lists are not authority inputs.

## Output and negative boundaries

The Runner seals `campaign.json`, `walking-mcp-replay-plan.json`, `run.json`, and one exact Plan
publication event. The loader reconstructs the Plan from the sealed Run and rejects artifact,
Campaign, publication-event, Claim, request, execution, or freshness substitution.

WALK-005B2 must require this Plan before any replay approval or dispatch, bind the Plan digest into
the fresh execution Run before its Permit claim, and produce a Claim verification projection only
from reloaded sealed evidence. Until then, WALK-005B1 does not change Candidate confirmation state.

## Compatibility and rollback

This contract is additive and opt-in. Existing WALK, Candidate, validation, Capability, Gateway,
KISA Replay, and Retest wire formats are unchanged. Rollback stops producing new Plans; existing
sealed Plans remain non-executable audit artifacts.

## Related documents

- [WALK-005A contract](WALK-005-approved-execution-candidate-admission.md)
- [ADR-0072](../adr/0072-approved-permitted-walking-candidate-admission.md)
- [ADR-0036](../adr/0036-claim-bound-replay-execution-authority.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
