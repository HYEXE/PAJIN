# ADR-0071: Evidence-Bound Walking Observation Replan

- Status: Accepted
- Date: 2026-08-01

## Context

ORCH-002 already provides deterministic two- or three-wave Observation Graph replanning for the
general Hypothesis Wave path. WALK-003 is deliberately separate: it seals a correlated MCP
authorization Hypothesis as `registered-not-authorized` and creates no runtime request or result.

The Phase 4 walking chain needs an explicit bridge from that sealed state into a Graph and a changed
follow-up Plan. Reusing ORCH-002's result classifier would require inventing a Tool result that does
not exist, while treating the WALK-003 artifact itself as approval would collapse discovery,
admission, and execution authority.

## Decision

1. Add an independent additive `pajin.dev/walking-observation-replan/v1alpha1` authority rather
   than changing A5, ORCH-001/002, or WALK-003 wire shapes.
2. Re-verify the complete sealed WALK-003 Run, artifact, publication event, single Hypothesis, and
   nested WALK-002 lineage before admission.
3. Admit only a content-addressed `sealed-hypothesis-state` candidate that exactly matches the
   verified `registered-not-authorized` source.
4. Use a code-registered rule to classify the Observation and select only
   `request-independent-approval` with `proposed-not-authorized` state.
5. Bind the complete Campaign, both Surface Snapshots, immutable Capability reference, Tool
   binding inherited through WALK-003, approval control, rule, evidence, Observation, state path,
   Plan, and typed Graph edges into one content-addressed authority.
6. Use expected-state comparison and a bounded unique state path to reject stale state, repeated
   state, and cycles. Accept history only from the baseline or a fully re-verified sealed prior
   WALK-004 authority; never trust caller-authored digest history. Give the semantic Plan state a
   digest independent of its previous-state pointer so replaying the same Plan is not disguised as
   novelty.
7. Seal the complete authority and exact publication event in a separate Run, and provide a loader
   that reconstructs both before returning authority.
8. Create no Capability activation, approval receipt, Permit, request, argument, or dispatch.

## Consequences

- One admitted WALK-003 Observation now changes the chain from its baseline state to an explicit
  approval-request Plan without granting execution authority.
- Forged evidence, cross-Run/Hypothesis substitution, stale state, repeated/cyclic state, and
  Campaign/Snapshot/Capability expansion fail closed.
- The Graph records `supports`, `enables`, and `depends-on` relations. `contradicts` remains a typed
  vocabulary value for later admitted negative evidence; mismatched candidates are rejected in
  this slice.
- The authority duplicates some sealed dependency material intentionally so offline audit can
  reconstruct the complete decision without trusting mutable registries.
- Actual approval admission and MCP execution remain WALK-005 or a later separately versioned
  boundary.

## Compatibility and rollback

The change is additive and opt-in. Existing A4/A5, ORCH-001/002, WALK-001/002/003, Campaign,
Hypothesis, Recon, and Replanning readers remain unchanged. Rollback removes WALK-004 composition
while retaining sealed, non-executable artifacts for audit.

## Related documents

- [WALK-004 contract](../orchestration/WALK-004-observation-graph-replan.md)
- [WALK-003 contract](../orchestration/WALK-003-mcp-tool-authorization-hypothesis.md)
- [ADR-0066: Deterministic Two- or Three-Wave Orchestration](0066-deterministic-two-three-wave-orchestration.md)
- [ADR-0069: Snapshot-Bound MCP Tool Authorization Hypothesis](0069-snapshot-bound-mcp-tool-authorization-hypothesis.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
