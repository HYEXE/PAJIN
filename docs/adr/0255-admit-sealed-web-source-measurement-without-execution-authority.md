# ADR-0255: Admit Sealed Web Source Measurement Without Execution Authority

- Status: Accepted
- Date: 2026-08-29

## Context

WEB-002B produces a fully sealed, registry-governed ZAP source-measurement authority. It proves
that one exact WEB-002A case completed its source Target lifecycle, strict SARIF normalization,
and cleanup. It deliberately carries no Campaign CapabilityGrant or ActionPermit and explicitly
denies Graph write, Finding, controlled-validation, and further execution authority.

Canonical Graph Observation proposals previously required a CapabilityGrant or ActionPermit
lineage. Treating the WEB-002A Capability release, scanner registry activation, or WEB-002B
measurement authority as one of those execution grants would invent authority that the source
does not possess. Refusing all import, however, would prevent authenticated historical knowledge
from entering the Graph even through its existing single writer.

## Decision

Add the `sealed-source-authority` Graph authority kind as an additive, knowledge-only lineage
path. A proposal using this path must carry an exact `sourceAuthorityId` and
`sourceAuthorityDigest`, and it must carry none of the CapabilityGrant, ActionPermit, or
Capability identity tuple. The corresponding Graph Action records that an already completed
sealed source is being projected; it does not authorize or execute another target action.

WEB-002C is the first producer using this path. Its gate:

1. reopens the WEB-002B outer Run seal and all source-measurement predecessors;
2. independently reloads the strict scanner normalization and requires the second outer Run
   snapshot's canonical authority bytes and exact three event payloads to equal the reopened
   authority;
3. derives only whether the exact registered Web Surface was present, without consulting
   `knownFindingMatched` or private Ground Truth;
4. requires that exact Surface to exist in the caller-bound current Graph Snapshot;
5. registers the exact sealed-source lineage together with the canonical Proposal digest and the
   exact Event Log predecessor head with the trusted lineage verifier; and
6. submits one neutral Observation and, only when the Surface signal is present, one confidence
   `0.5` open Hypothesis through the existing Graph Admission Authority and compare-and-set head.

The Observation has exactly one Evidence node referencing the sealed outer WEB-002B authority
artifact by relative path and SHA-256. Raw SARIF, normalized Finding material, private Ground
Truth, Target or provider runtime identity, and controlled-validation state do not enter the
candidate or Graph event.

The new optional source-authority fields are omitted when absent. Existing Capability- and
Permit-backed Graph wires and content identities therefore remain unchanged.

Sealed-source trust is content-specific and CAS-specific. A registered lineage cannot authorize a
different Observation/Hypothesis payload, and the exact Proposal cannot use generic `submit`
without its registered predecessor head. The authority kind is also non-transferable through the
current DOMAIN-005 cross-domain producer. Future chaining requires a new lineage, source-event
Evidence, and an explicit transfer contract.

## Compatibility and rollback

Existing Capability- and Permit-backed node, Proposal, and event serialization and digests are
byte-for-byte unchanged because absent source fields are omitted. A new
`sealed-source-authority` Action or admission event is nevertheless a forward extension of the
experimental `v1alpha1` wire: an older strict reader does not know the new authority enum or source
fields and cannot read a Graph Store after such an event is appended.

Deploy readers and writers that understand this ADR before enabling WEB-002C. Do not perform an
in-place reader downgrade after the first sealed-source event. Rollback requires either leaving
the upgraded reader installed or restoring a verified pre-event Graph Store backup; deleting,
rewriting, or selectively skipping canonical events is not a rollback mechanism.

## Consequences

- A sealed historical source can support neutral Graph knowledge without being misrepresented as
  a fresh execution grant.
- Sealed-source lineage and Capability/Permit lineage are mutually exclusive and fail closed when
  mixed, incomplete, foreign, stale, or unregistered.
- Registered sealed-source lineage cannot be reused for different Proposal content, another Graph
  head, generic non-CAS submission, or cross-domain authority transfer.
- WEB-002C cannot activate a Capability, issue or consume a Permit, select a Worker, access the
  network, run ZAP, evaluate the WEB-002A validation floor, or project a Finding.
- A bounded Hypothesis remains an open proposition requiring separately authorized independent
  controlled validation in WEB-002D.
- Future producers may use this authority kind only by defining their own exact source verifier,
  producer registration, evidence contract, and negative-authority boundary.

## Rejected alternatives

### Reuse the WEB-002A Capability release as a CapabilityGrant

Rejected because a signed release describes distributable Capability code; it is not a current
Campaign grant and does not authorize the completed WEB-002B execution or a Graph write.

### Reuse scanner registry activation as a CapabilityGrant

Rejected because registry activation authorizes measurement trust material, not Campaign Scope,
Graph mutation, or controlled validation.

### Embed the complete WEB-002B authority or raw SARIF in Graph Evidence

Rejected because it would copy runtime and scanner detail into canonical knowledge, increase
leakage and identity coupling, and blur Evidence reference with Evidence content custody.

### Emit a Finding directly from a normalized scanner match

Rejected because a source scanner result is neither independent validation nor satisfaction of
the WEB-002A Profile floor.
