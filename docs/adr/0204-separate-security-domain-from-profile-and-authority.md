# ADR-0204: Separate Security Domain from Profile and Authority

## Status

Accepted

## Context

PAJIN is expanding its target architecture from initial Pentest and AI/Web product slices to Web,
Network, System, Application, Mobile, Cloud, AI, Cryptography, and Digital Forensics. The existing
Campaign Profile catalog already distinguishes `pentest`, `bug-hunt`, `ctf`, and `ai-assessment`
operating semantics. The current `CapabilityDefinition.domain` field predates this expansion and
contains legacy namespace values such as `ai-redteam`, `bug-bounty`, `ctf`, and `pentest`.

Reusing that field as a new authority-bearing domain selector would mix product semantics,
classification, and execution authority. Rewriting it would also change existing Capability
digests and signed releases.

## Decision

Security Domain is an orthogonal, non-authoritative classification with the code-owned values
`web`, `network`, `system`, `application`, `mobile`, `cloud`, `ai`, `cryptography`, and
`forensics`.

Campaign Profiles continue to own operating semantics, ROE expectations, reporting semantics,
validation floors, and authority ceilings. A Profile may contain exact Capabilities from more than
one domain. A domain value cannot select a Profile, activate a Capability release, issue a Grant or
Permit, select a Tool or Worker, widen Scope, or satisfy approval.

Existing `CapabilityDefinition.domain` values remain unchanged legacy namespaces. DOMAIN-003 will
define an additive content-addressed classification projection bound to an exact
`CapabilityDefinitionRef` and reviewed surface-type mappings. The projection is inventory metadata
only and must carry explicit false authority markers.

MCP remains a Tool transport and Surface type where applicable, not a special authority system.
Tool categories, plugin metadata, and discovered interfaces are also non-authoritative.

## Consequences

- Existing Capability identities and REDTEAM/PENTEST contracts remain compatible.
- The same `pentest` Profile can later admit exact Web, System, Mobile, or Cloud Capabilities.
- `ai-assessment + ai` and `ctf + cryptography` remain valid combinations without creating more
  Profiles.
- Domain-aware inventory and UI projections require an additive registry rather than inference
  from free-form metadata.
- Runtime support for the nine domains remains planned until code-backed Capabilities and Worker
  boundaries are implemented.

## Rejected alternatives

### Create one Campaign Profile per domain

Rejected because a Profile defines operating semantics, while a domain classifies security
subject matter. Coupling them prevents cross-domain Campaigns and duplicates policy machinery.

### Reinterpret `CapabilityDefinition.domain`

Rejected because current values mix legacy Mode and product namespaces, and changing them alters
definition digests and signed release identity.

### Infer authority from Tool or MCP metadata

Rejected because Tool discovery describes an interface, not an authorized semantic action.

## Compatibility and rollback

No existing wire or digest changes. Rollback ignores the additive classification projection. It
does not delete or reinterpret existing Capability, Profile, Graph, Permit, Tool, or evidence
records.

## Related documents

- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ARCH-001](../rfc/0001-pajin-architecture-v2.md)
- [CAP-001](../capability/CAP-001-versioned-capability-definition.md)
- [PROF-001](../orchestration/PROF-001-campaign-profile-authority.md)
