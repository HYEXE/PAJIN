# ADR-0232: Type Application Artifact and Runtime Knowledge without Analysis Authority

## Status

Accepted

## Context

DOMAIN-002 reserves `application.artifact-runtime` and
`pajin.locator.application.artifact-runtime.v1` as Application semantic identifiers, but it does
not implement the locator schema. PAJIN has Artifact custody, sandbox, Worker, and sealed-evidence
patterns from other vertical slices. Those patterns govern storage or execution boundaries and are
not a neutral Application identity model.

APP-001A must represent binaries, configurations, declared runtimes, and libraries before an
artifact repository has resolved bytes or a static-analysis Capability has been authorized.
Filesystem paths, process identifiers, running-state metadata, package aliases such as `latest`,
and a Worker sandbox are mutable or operational coordinates. Treating any of them as the Surface
would import storage, execution, or authority semantics into the representation layer.

## Decision

Add a content-addressed Application artifact/runtime locator registry with four code-owned
classes:

- `application-binary`: one lowercase SHA-256 artifact digest;
- `application-configuration`: one exact binary parent, sanitized namespace and identifier, and
  lowercase SHA-256 artifact digest;
- `application-runtime`: one exact binary parent, normalized runtime family and exact normalized
  version, and lowercase SHA-256 artifact digest; and
- `application-library`: one exact binary or declared-runtime parent, normalized library
  namespace, identifier, and exact version, and lowercase SHA-256 artifact digest.

Embed complete parents as discriminated locators so parent substitution changes content identity.
Require exact versions with a numeric dotted base and reject floating aliases, ranges, wildcards,
path, URL, query, fragment, surrounding whitespace, control characters, and unknown fields.
Artifact digests are caller-supplied identity coordinates; APP-001A does not resolve or read bytes,
verify a digest against content, identify a binary format, parse configuration semantics, attest a
runtime environment, or resolve a dependency graph.

Add an inert `ApplicationArtifactRuntimeSurface` that binds one locator to the exact Application
Domain and DOMAIN-002 type-set and starts as `registered-not-authorized`. Do not add these locators
to the established evidence-bound discovery `SurfaceLocator` union. Do not change `AttackSurface`,
Artifact readers, Scope, Graph, Capability, sandbox, Worker, or execution wires.

The registry and typed Surface explicitly deny artifact resolution or read, static or dynamic
analysis, credential access, Scope expansion, Capability activation, approval satisfaction,
Permit issuance, sandbox or Worker selection, network access, debugger attach, artifact mutation,
Graph admission, Finding authority, runtime-support assertion, and execution authority.

## Consequences

- APP-001B can bind an exact Application identity to a separately reviewed read-only static
  analysis Capability and sandbox boundary without deriving authority from locator metadata.
- A binary digest identifies supplied content-addressed knowledge but proves neither custody nor
  file format. Later evidence must prove both when required.
- A declared runtime is an artifact coordinate, not a live process, installed interpreter, or
  supported execution environment.
- Configuration and library coordinates preserve exact binary/runtime lineage without storing raw
  configuration values, repository URLs, local paths, credentials, or package-manager state.
- Floating version selection and dependency resolution remain outside v1. A later producer may
  seal a resolved dependency graph as Evidence under a separately reviewed contract.

## Rejected alternatives

### Use a local path as artifact identity

Rejected because paths are mutable deployment aliases, may disclose operator data, and do not
bind content. A later trusted artifact resolver may map an authorized reference to bytes, but the
typed Surface remains digest-based.

### Treat a running process as the runtime Surface

Rejected because PID, environment, and process state are live System-domain or execution
evidence. APP-001A represents only a declared runtime artifact below an exact binary parent.

### Resolve package aliases or dependency ranges in the locator

Rejected because `latest`, wildcards, and ranges depend on repository state and time. Exact
versions and artifact digests keep identity deterministic without network or repository access.

### Reuse sandbox or Worker identity as an Application Surface

Rejected because isolation and deployment identity constrain authorized execution; they do not
identify the application artifact and cannot grant static-analysis authority.

### Extend the established discovery locator union immediately

Rejected because APP-001A has no sealed Application Observation/Evidence admission contract. An
additive typed wrapper preserves existing readers and artifact identities.

## Compatibility and rollback

APP-001A is additive and requires no migration. Existing discovery locators, `AttackSurface`,
Artifact readers, canonical digests, Scope, Graph, Capability, Worker, and runtime behavior remain
unchanged. Rollback removes the new module, exports, tests, contract, ADR, and consumers. New
locator classes, parent relationships, version rules, identity fields, or digest algorithms
require an explicit versioned change rather than silent registry expansion.

## Related documents

- [APP-001A contract](../discovery/APP-001A-binary-configuration-runtime-library-surface-model.md)
- [DOMAIN-002](../graph/DOMAIN-002-common-multi-domain-graph-semantics.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0002](0002-tool-gateway-and-worker-isolation.md)
- [ADR-0204](0204-separate-security-domain-from-profile-and-authority.md)
- [ADR-0205](0205-admit-cross-domain-knowledge-without-scope-expansion.md)
