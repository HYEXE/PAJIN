# DOMAIN-001: Security Domain Taxonomy

- Status: Implemented
- Contract versions:
  - `pajin.dev/security-domain-classification/v1alpha1`
  - `pajin.dev/security-domain-taxonomy/v1alpha1`
- Decision: [ADR-0204](../adr/0204-separate-security-domain-from-profile-and-authority.md)

## Scope

DOMAIN-001 registers one code-owned taxonomy that classifies security subject matter without
selecting operating semantics or granting authority. The taxonomy contains exactly these values in
canonical order:

| Classification ID | Domain | Display name |
| --- | --- | --- |
| `pajin.security-domain.web` | `web` | Web |
| `pajin.security-domain.network` | `network` | Network |
| `pajin.security-domain.system` | `system` | System |
| `pajin.security-domain.application` | `application` | Application |
| `pajin.security-domain.mobile` | `mobile` | Mobile |
| `pajin.security-domain.cloud` | `cloud` | Cloud |
| `pajin.security-domain.ai` | `ai` | AI |
| `pajin.security-domain.cryptography` | `cryptography` | Cryptography |
| `pajin.security-domain.forensics` | `forensics` | Digital Forensics |

This registry implements classification only. It does not claim an executable vertical slice for
any of the nine domains.

## Identity and exact resolution

Each `RegisteredSecurityDomain` has version `1.0.0` and a digest over its complete identity,
classification markers, and authority markers. `SecurityDomainTaxonomy` has version `1.0.0` and a
digest over the exact ordered nine-record set and taxonomy markers.

`resolve_registered_security_domain(reference)` accepts only an exact classification ID, version,
digest, and Domain tuple already present in the code-owned taxonomy. It returns classification
metadata only. Unknown values, aliases, `latest`, changed digests, reordered membership, and
standalone substitutions fail closed.

## Profile orthogonality

Security Domain and Campaign Profile remain separate dimensions. DOMAIN-001 contains no Profile
ID or Profile mapping. A later Campaign may combine, for example, `pentest + web`,
`pentest + system`, `ai-assessment + ai`, or `ctf + cryptography`, but this taxonomy does not select
or authorize those combinations.

The legacy `CapabilityDefinition.domain` field remains unchanged. Existing values such as
`ai-redteam`, `bug-bounty`, `ctf`, and `pentest` are signed compatibility namespaces, not inputs to
this registry. DOMAIN-001 exposes no inference or migration adapter between those strings and the
new taxonomy. [DOMAIN-003](../capability/DOMAIN-003-domain-aware-capability-inventory-projection.md)
defines a separate exact content-addressed projection for the explicitly reviewed current
Capability inventory.

## Non-authority boundary

Every classification fixes `classificationOnly=true` and `profileOrthogonal=true`. It fixes all of
the following to false:

- Campaign Profile selection;
- Capability registration and activation;
- Scope expansion and approval satisfaction;
- Permit issuance;
- Tool and Worker selection;
- network, filesystem, and credential use;
- Graph admission;
- Finding confirmation; and
- execution.

The taxonomy additionally fixes Profile mapping availability, legacy Capability Domain
reinterpretation, runtime-support assertion, and execution authority to false. Values must be
actual JSON booleans; integer and string coercions are rejected.

## Negative cases

Validation and resolution reject:

- an unknown Domain, classification version, or alias;
- changed classification ID, display name, digest, or taxonomy digest;
- missing, extra, duplicated, substituted, or reordered taxonomy membership;
- any authority or runtime-support marker set true;
- integer or string substitution for fixed boolean markers;
- injected Profile, Capability, Tool, Worker, Scope, Permit, or similar mapping fields; and
- an exact reference whose ID, version, digest, and Domain do not all match one registered record.

## Compatibility, migration, and rollback

DOMAIN-001 is additive. It changes no Campaign Profile, `CampaignMode`, `CapabilityDefinition`,
Tool, Graph schema, Permit, Gateway, Worker job, Evidence, Replay, Finding, benchmark, or REDTEAM /
PENTEST identity. Existing Capability digests remain stable.

Rollback removes the taxonomy module and public exports. Serialized classification records remain
self-describing but non-executable. No existing record requires migration, and no legacy
`CapabilityDefinition.domain` value is rewritten.

## Follow-up boundary

- DOMAIN-002 reuses the Canonical Graph while adding common multi-domain Surface, Hypothesis, and
  Observation semantics.
- DOMAIN-003 binds exact CAP-001/CAP-002 identities to reviewed classifications without inferring
  the mapping from legacy namespaces or Tool metadata.
- DOMAIN-004 defines deployment-owned Worker trust-boundary registration. Domain labels cannot
  select a Worker.
