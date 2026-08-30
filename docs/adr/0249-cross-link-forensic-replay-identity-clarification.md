# ADR-0249: Cross-link Forensic Replay Identity Clarification

- Status: Accepted
- Date: 2026-08-28
- Owners: PAJIN architecture and security boundary maintainers
- Scope: FORENSICS-001D decision-history linkage
- Supersedes: [ADR-0248](0248-clarify-forensic-replay-semantic-and-execution-identity.md)
- Clarifies: [ADR-0247](0247-bind-independent-forensic-parser-comparison-and-seeded-evidence-without-source-or-measurement-authority.md)

## Context

ADR-0248 records the active clarification of FORENSICS-001D semantic and execution identity, but
its references to ADR-0247 are plain text rather than a direct Markdown link. Accepted ADRs are
immutable decision history in this repository, so the missing cross-link cannot be added by
rewriting ADR-0248.

## Decision

Supersede ADR-0248 for active decision lookup and adopt its semantic and execution-identity
clarification unchanged. This successor directly links both ADR-0248 and the ADR-0247 decision it
clarifies. ADR-0247 and ADR-0248 remain preserved as historical decision records.

No code, wire, authority, replay-mode, comparison, fixture, metric, or trusted-loader behavior
changes through this administrative successor.

## Consequences

- the accepted decision chain is explicit and traversable without rewriting history; and
- the FORENSICS-001D contract can cite ADR-0247 and this active successor while ADR-0249 retains
  the direct link to ADR-0248.
