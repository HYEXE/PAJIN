# ADR-0233: Bind Application Static Analysis without Artifact-access Authority

## Status

Accepted

## Context

APP-001A supplies exact, secret-free binary, configuration, declared-runtime, and library Surface
identity. Its artifact SHA-256 values are caller-supplied coordinates: it intentionally proves no
custody, bytes, file format, parser compatibility, runtime support, dependency graph, Scope, or
analysis authority.

PAJIN has a complete CAP-002 lifecycle and a DOMAIN-004 Application profile requiring an offline
sandbox, read-only artifact filesystem boundary, no credential boundary, disabled-by-default
network, exact analyzer/artifact identity, and artifact-byte/runtime budgets. The profile is a
minimum contract, not a selected or attested runtime. The repository also has sealed Run artifact
repositories, but their `ArtifactRef` identifies immutable Run directories with a dedicated media
type; it is not a generic arbitrary-application custody protocol.

APP-001B must make the next authority connection without fabricating a file reader, generic
artifact service, parser executable, container image, sandbox deployment, or successful analysis.
It must also keep dynamic target execution, debugger attach, and network access outside APP-001.

## Decision

Add the experimental T2 read-only Capability
`pajin.application.read-only-static-analysis@1.0.0` and Tool identity
`application.read-only-static-analysis@1.0.0`. Register all seven CAP-002 authority roles and
require an externally signed current Range release. Bind the complete code-backed Capability,
complete APP-001A locator registry, a local Application Domain classification, the fixed output
schema, and the exact DOMAIN-004 minimum Application Worker profile. Do not change the global
DOMAIN-003 inventory.

Define one structure-only operation and logical parser per exact Surface class: binary metadata,
configuration structure, runtime metadata, and library metadata. Treat parser selection as a
request contract, not proof that an executable or compatible file format exists.

Require a content-addressed custody configuration that binds the complete exact Surface, its
artifact digest, a bounded custody-authority ID, opaque object ID, opaque authorization ID,
authorization-document digest, and declared byte count. Allow no path, URL, raw bytes, secret, or
credential. The authorization reference is explicitly supplied deployment input; preparation
does not verify its issuer, signature, freshness, object existence, digest, or byte count.

Require a content-addressed sandbox configuration that binds one exact operation/parser,
parser-executable digest, sandbox-image digest, explicit non-root run-as identity, fixed read-only
no-exec artifact mount, fixed bounded JSON output schema and transport, and artifact/output/runtime/
memory/process ceilings. Require network disabled, read-only root filesystem, no new privileges,
no host filesystem, no credentials, no ambient environment inheritance, and no symlink traversal.
Treat every setting as a requirement that a later runtime must attest, not as live conformance.

Project each exact typed Surface to a non-routable HTTPS Scope token under
`application-scope.pajin.invalid` and require that exact token in the current Campaign allow set.
Reject wildcard-only authorization, any matching deny rule, or absence of GET. Preserve but do not
interpret the private-network flag as authority because all APP-001B execution-related network
limits remain zero.

Allow preparation to create a secret-free request and `PreparedCapabilityAction`, but do not
resolve or read bytes, verify custody authorization, materialize a mount, select or attest a
sandbox, reserve a budget, materialize a Worker job, invoke a parser, normalize a result, or grant
approval, Permit, Gateway, Worker, network, dynamic-execution, debugger, mutation, Observation,
Evidence, Graph, Finding, or execution authority. The executor and result-normalizer roles fail
closed and the Oracle remains inconclusive.

## Consequences

- Surface identity, custody configuration, authorization verification, sandbox requirements,
  live runtime attestation, artifact-read authority, and result admission remain separate
  reviewable boundaries.
- Serialized custody and sandbox bindings are deterministic and substitution-resistant but prove
  no external object or runtime state.
- The fixed parser mapping prevents caller-selected parser confusion while making no format or
  compatibility claim.
- Resource ceilings and zero network/dynamic/debugger/write budgets are bound before any future
  execution authority can be considered.
- APP-001C can admit neutral Application knowledge only from a separately authorized, sealed,
  exact-artifact sandbox result.

## Rejected alternatives

### Reuse the sealed Run `ArtifactRef`

Rejected because that reference identifies an admitted Run-directory artifact with an existing
media type and repository contract. Rebranding it as an arbitrary application binary would create
false storage and reader semantics. APP-001B instead defines a storage-neutral, secret-free
custody configuration and leaves byte resolution to a future deployment boundary.

### Accept a local path or download URL

Rejected because paths and URLs are mutable, may disclose operator data, and may silently import
host-filesystem, network, or credential authority. The binding accepts only opaque identifiers and
content digests.

### Infer the parser from a filename, format label, or artifact bytes

Rejected because APP-001A stores no verified filename or format and APP-001B performs no byte
read. Parser selection is an exact class-owned contract and still requires later runtime
compatibility checks.

### Mark the sandbox requirements as runtime attestation

Rejected because image and executable digests, run-as names, mount settings, and resource maxima
are configuration. They do not prove the actual namespace, UID/SID, filesystem flags, seccomp or
capability set, network isolation, loaded executable, or applied cgroup ceilings.

### Implement a placeholder parser or successful Oracle

Rejected because the repository has no admitted generic Artifact resolver, live sandbox runtime,
parser implementation, bounded output custody, or sealed Application result contract in this
slice. Placeholder success would be fictitious runtime support.

### Include dynamic execution, debugger, or network access

Rejected because those actions have different side effects and threat boundaries. They require
separate reviewed Capabilities and cannot be inferred from a read-only static-analysis request.

## Compatibility and rollback

APP-001B is additive. Existing APP-001A, sealed Run Artifact, Campaign Scope, Capability, Tool,
Worker, Graph, and runtime wires retain their versions. No artifact service, parser process,
sandbox deployment, credential store, network route, or data migration is introduced. Rollback
removes the additive module, tests, contract, ADR, and consumers; existing Application Surfaces
remain valid under their original contract.

## Related documents

- [APP-001B contract](../capability/APP-001B-read-only-static-analysis-capability.md)
- [APP-001A contract](../discovery/APP-001A-binary-configuration-runtime-library-surface-model.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0002](0002-tool-gateway-and-worker-isolation.md)
- [ADR-0206](0206-bind-domain-workers-to-existing-authority-path.md)
- [ADR-0232](0232-type-application-artifact-runtime-without-analysis-authority.md)
