# DOMAIN-002: Common Multi-domain Graph Semantics

- Status: Implemented, semantics only
- Contract versions:
  - `pajin.dev/security-domain-graph-type-set/v1alpha1`
  - `pajin.dev/multi-domain-graph-semantics/v1alpha1`
- Decisions: [ADR-0204](../adr/0204-separate-security-domain-from-profile-and-authority.md),
  [ADR-0205](../adr/0205-admit-cross-domain-knowledge-without-scope-expansion.md)

## Scope

DOMAIN-002 binds the exact DOMAIN-001 taxonomy to additive, non-executable Surface, locator,
Hypothesis, and Observation semantic identifiers. It preserves the existing Canonical Graph v1
schema, relation directions, admission authority, and node identities. It does not implement a
domain locator, Graph producer, admission path, Capability, Tool, Worker, Scope, Permit, Replay,
benchmark, or executable vertical slice.

The registry is code-owned and content-addressed. It contains exactly one type-set for each of the
nine registered Security Domains in canonical DOMAIN-001 order.

## Reused Canonical Graph

The registry binds the existing API versions and the same six node kinds:

```text
Surface
Hypothesis
Action
Observation
Evidence
CampaignFact
```

It also fixes the existing eight relation directions:

```text
Surface motivates Hypothesis
Hypothesis tested-by Action
Action produces Observation
Observation supported-by Evidence
Observation supports Hypothesis
Observation contradicts Hypothesis
Observation discovers Surface
Observation enables Hypothesis
```

`pajin.graph.admission.GraphAdmissionAuthority` remains the only Canonical Graph writer. The
registry fixes `graphWriterCount=1` and `domainLedgerCount=0`; it neither creates a domain-specific
ledger nor authorizes admission through the existing writer.

## Registered semantic type-sets

The locator schema values below are reserved semantic identifiers. Their presence is not an
implementation claim: every type-set fixes `locatorSchemaImplementationAvailable=false` and
`graphProducerRegistered=false`.

| Domain | Surface type | Locator schema | Hypothesis type | Observation type |
| --- | --- | --- | --- | --- |
| `web` | `web.http-operation` | `pajin.locator.web.http-operation.v1` | `web.security-property` | `web.protocol-observation` |
| `network` | `network.host-service` | `pajin.locator.network.host-service.v1` | `network.exposure` | `network.protocol-observation` |
| `system` | `system.host-resource` | `pajin.locator.system.host-resource.v1` | `system.security-configuration` | `system.host-observation` |
| `application` | `application.artifact-runtime` | `pajin.locator.application.artifact-runtime.v1` | `application.vulnerability` | `application.analysis-observation` |
| `mobile` | `mobile.application-runtime` | `pajin.locator.mobile.application-runtime.v1` | `mobile.security-property` | `mobile.analysis-observation` |
| `cloud` | `cloud.account-resource` | `pajin.locator.cloud.account-resource.v1` | `cloud.policy-exposure` | `cloud.api-observation` |
| `ai` | `ai.model-rag-agent-tool` | `pajin.locator.ai.model-rag-agent-tool.v1` | `ai.security-property` | `ai.behavior-observation` |
| `cryptography` | `cryptography.protocol-key-artifact` | `pajin.locator.cryptography.protocol-key-artifact.v1` | `cryptography.misuse-weakness` | `cryptography.analysis-observation` |
| `forensics` | `forensics.immutable-artifact` | `pajin.locator.forensics.immutable-artifact.v1` | `forensics.forensic-proposition` | `forensics.analysis-observation` |

These identifiers classify the intended meaning of future typed records. The existing generic
`GraphSurface`, `GraphHypothesis`, and `GraphObservation` contracts do not gain a Domain field, so
their canonical IDs and serialized records remain unchanged.

## Identity and exact resolution

Each `RegisteredSecurityDomainGraphTypeSet` binds its exact DOMAIN-001 classification reference,
type-set ID, version, four semantic identifiers, implementation markers, authority markers, and
content digest. `MultiDomainGraphSemanticsRegistry` binds the exact ordered type-sets, DOMAIN-001
taxonomy digest, Graph API versions, node and relation vocabulary, writer identity, and registry
digest.

`resolve_registered_security_domain_graph_type_set(reference)` accepts only an exact registered
type-set ID, version, digest, and DOMAIN-001 classification reference. Unknown values, `latest`,
reordered records, domain relabeling, changed relation endpoints, and digest substitution fail
closed.

## Non-authority boundary

Every type-set fixes `semanticsOnly=true` and all of these values to false:

- locator implementation availability;
- registered Graph producer;
- Graph admission authority;
- runtime-support assertion; and
- execution authority.

The aggregate registry additionally fixes the following to false:

- Canonical Graph schema change and domain-specific ledger creation;
- Graph admission and Scope expansion;
- Capability activation and Permit issuance;
- source authority transfer; and
- runtime-support assertion and execution.

A future discovered Surface starts `registered-not-authorized`. This contract records that state
but does not admit any Surface. Discovery remains knowledge only and cannot modify Campaign Scope,
activation, approval, budgets, egress, credentials, Worker selection, or a Permit.

Fixed markers require actual JSON booleans. Integer or string coercion is rejected. The registry
also rejects injected Profile, Capability, Tool, Worker, Scope, Permit, or similar mapping fields.

## Compatibility, migration, and rollback

DOMAIN-002 is additive. It changes no Graph v1 node, edge, Proposal, admission event, Event Log,
Projection, Snapshot, legacy discovery artifact, Campaign Profile, Capability Definition, Permit,
Gateway, Worker, Evidence, Replay, Finding, REDTEAM, or PENTEST identity. Existing Graph node and
Capability digests remain stable; no stored record requires migration.

Rollback removes this registry, its exports, tests, and contract. Existing Canonical Graph data
remains valid because no Graph schema or writer changed.

## Verified rejection contract

Positive and adversarial tests cover:

- exact DOMAIN-001, Graph API, six-node, eight-relation, and single-writer binding;
- exact nine-domain membership and content-addressed reference resolution;
- construction of every registered relation through the existing `GraphEdge` validator;
- changed API versions, relation order or endpoints, type-set order or semantics, writer, ledger,
  or discovered-Surface state;
- Domain, classification, digest, and identity substitution;
- authority escalation and boolean or integer coercion;
- injected execution mappings; and
- unchanged existing Graph Surface identity and absence of Domain fields in Graph nodes.

## Follow-up boundary

- DOMAIN-003 projects exact registered CAP-001/CAP-002 references into reviewed Domain
  classifications without inferring activation, Tool, Permit, or Worker authority.
- DOMAIN-004 registers deployment-owned Worker trust boundaries behind the existing authority path.
- DOMAIN-005 may implement code-registered cross-domain Graph producers and admission while keeping
  every discovered Surface registered-not-authorized.
- Domain vertical slices must implement and review the reserved locator schemas before asserting
  locator availability or runtime support.
