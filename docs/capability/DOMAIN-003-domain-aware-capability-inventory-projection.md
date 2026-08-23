# DOMAIN-003: Domain-aware Capability Inventory Projection

- Status: Implemented, inventory projection only
- Contract versions:
  - `pajin.dev/capability-domain-classification/v1alpha1`
  - `pajin.dev/capability-domain-inventory-projection/v1alpha1`
- Decision: [ADR-0204](../adr/0204-separate-security-domain-from-profile-and-authority.md)

## Scope

DOMAIN-003 projects the exact current CAP-001 and CAP-002 code-backed inventory into reviewed
DOMAIN-001 classifications. It is inventory metadata only. It does not select a Campaign Profile,
resolve a signed Capability release, bind a current activation, expand Scope, satisfy approval,
issue a Permit, select a Tool or Worker, admit Graph knowledge, confirm a Finding, or authorize
execution.

The projection accepts only the existing registered Mode bundle with its registered MCP Capability
and the Pentest Recon bundle. Both source registries are re-resolved before projection. A missing,
extra, substituted, or digest-drifted CAP-001 definition, complete CAP-002 seven-role authority set,
or reviewed surface set fails closed.

## Exact reviewed inventory

The current projection contains exactly nine records in canonical Capability ID and version order:

| Security Domain | Exact Capability ID | Version | Reviewed legacy surface set |
| --- | --- | --- | --- |
| `ai` | `pajin.ai.kisa.indirect-tool-hijacking` | `1.0.0` | `mock-agent` |
| `ai` | `pajin.ai.kisa.jailbreak-policy-bypass` | `1.0.0` | `ai-chat-api`, `rag-chat-api` |
| `ai` | `pajin.ai.kisa.memory-poisoning-persistence` | `1.1.0` | `ai-chat-api`, `rag-chat-api` |
| `ai` | `pajin.ai.kisa.system-prompt-disclosure` | `1.0.0` | `ai-chat-api`, `rag-chat-api` |
| `ai` | `pajin.ai.mcp.instruction-hijacking-inspection` | `1.0.0` | `mock-mcp` |
| `web` | `pajin.bug-bounty.boolean-sqli-lab` | `1.0.0` | `bug-bounty-api` |
| `cryptography` | `pajin.ctf.crypto-single-byte-xor` | `1.0.0` | `ctf-crypto` |
| `web` | `pajin.ctf.web-exposed-backup-config` | `1.0.0` | `ctf-web` |
| `web` | `pajin.pentest.http-get-recon` | `1.0.0` | `http-endpoint` |

Only Web, AI, and Cryptography have classified records in this projection. This does not claim
general executable support for those domains. The other six DOMAIN-001 values remain valid
classifications but have no current projected Capability.

The reviewed surface values above are the unchanged CAP-001 `supportedSurfaceTypes` identities.
They are not DOMAIN-002 locator implementations, Graph producers, Tool selectors, or authority
inputs.

## Identity and exact resolution

Each `RegisteredCapabilityDomainClassification` binds all of the following in one content digest:

- the exact CAP-001 `CapabilityDefinitionRef`;
- its exact CAP-002 `CodeBackedCapabilityRef`, including the complete seven-role authority-set
  identity and digest;
- the exact DOMAIN-001 classification reference;
- the explicitly reviewed, ordered legacy surface set; and
- fixed projection and non-authority markers.

`CapabilityDomainInventoryProjection` binds the exact ordered nine-record set, DOMAIN-001 taxonomy
identity and digest, exact classified Capability and Domain counts, and aggregate non-authority
markers. `resolve_registered_capability_domain_classification` re-verifies both source registries
and accepts only an exact content-addressed classification reference.

Aliases, `latest`, partial identity, reorder, injected membership, a CAP-001 or CAP-002 substitution,
a changed surface set, a different DOMAIN-001 classification, or a digest substitution fail
closed.

## No inference and no authority

The mapping basis is `explicit-code-reviewed-capability-and-surface-set`. The implementation does
not reinterpret legacy `CapabilityDefinition.domain`, Tool metadata, MCP discovery, or DOMAIN-002
Surface and locator identifiers. In particular, the legacy `ctf` namespace maps to both Web and
Cryptography in the reviewed inventory, so it cannot be used as a Security Domain selector.

Every classification fixes these facts to true:

- the record is projection-only;
- the mapping was explicit and reviewed;
- the complete CAP-002 code authority set was verified; and
- a signed release and current activation are still required for execution.

It fixes release and activation binding, Profile mapping, Capability activation, Scope expansion,
approval satisfaction, Permit issuance, Tool and Worker selection, Graph admission, Finding
confirmation, runtime-support assertion, and execution authorization to false. The aggregate
projection likewise binds neither a release inventory nor an activation inventory. Fixed markers
require real JSON booleans, and fixed counts require real JSON integers.

## Compatibility, migration, and rollback

DOMAIN-003 is additive. It changes no CAP-001 definition, CAP-002 authority set, CAP-004 signed
release, CAP-005 activation, Campaign Profile, Tool registration, Graph schema, Permit, Gateway,
Worker job, Evidence, Replay, Finding, REDTEAM, or PENTEST identity. Existing Capability digests and
legacy `CapabilityDefinition.domain` values remain unchanged. No stored record requires migration.

Rollback removes the projection module, exports, tests, and this contract. Existing Capability,
release, activation, Graph, and execution records remain valid because the projection owns none of
their authority.

## Verified rejection contract

Positive and adversarial tests cover:

- exact CAP-001, CAP-002, DOMAIN-001, surface-set, order, and count binding;
- explicit Web, AI, and Cryptography mapping for all nine records;
- the same legacy `ctf` namespace mapping to two different Security Domains;
- source registry and content-addressed classification resolution;
- missing MCP inventory, CAP-001 digest drift, CAP-002 authority substitution, Domain relabeling,
  reordered membership, changed counts, and changed projection identity;
- authority escalation and boolean or integer coercion; and
- injected release, activation, Profile, Tool, Worker, Scope, Permit, or execution mappings.

## Follow-up boundary

- DOMAIN-004 may register deployment-owned Worker trust-boundary profiles against exact signed
  Capability releases. This projection cannot select such a profile.
- DOMAIN-005 may register cross-domain Graph producers and admission while every discovered Surface
  remains registered-not-authorized.
- A future Capability inventory change requires an explicit review and versioned projection update;
  it must not be absorbed through namespace or metadata inference.

The Pentest Recon CAP-002 stable context canonicalizes unordered Tool category and evidence-type
sets before digesting. This preserves the reviewed `7bcc380f...410af8` authority-set identity
across Python hash seeds instead of accepting multiple identities for the same code.
