# ADR-0234: Admit Application Analysis Knowledge without Artifact Authority

## Status

Accepted

## Context

APP-001B produces a current signed preparation for one exact read-only static-analysis request. It
binds an inert APP-001A Surface, Campaign Scope, complete CAP-002 release, opaque artifact custody
and authorization coordinates, exact class-owned parser, parser executable and sandbox image
digests, a declared non-root offline sandbox, and bounded resource ceilings. It deliberately has
no custody client, file reader, parser implementation, sandbox runtime, Worker materializer,
result, or Graph-admission authority.

PAJIN needs to admit knowledge from an analysis that a deployment separately approved and
completed without pretending that APP-001B executed it. Accepting an unsigned digest, trusting the
preparation as runtime evidence, interpreting an unbounded parser body, or copying artifact data
into Graph prose would break the authority, provenance, privacy, and single-writer boundaries.

## Decision

Add an APP-001C source-verification and Graph-admission boundary. Do not add a repository-owned
artifact resolver, parser, sandbox runtime, or Worker. Require a deployment-owned external runtime
to provide:

1. an Ed25519-signed `ApplicationStaticAnalysisExecutionBundle`; and
2. a detached `ApplicationStaticAnalysisResultReceipt` containing only exact identities, bounded
   result metadata, a body digest, and an optional fixed review signal.

Configure the trust anchor when constructing the admission gate; source inputs cannot provide or
override it. Bind the anchor to the exact APP-001B sandbox, code-backed Capability, signed release,
trust domain, issuer, and a uniquely sorted Ed25519 keyring with exactly one active key. Treat it as
verification-only, not current activation, Campaign, approval, Permit, artifact access, sandbox,
Graph, or execution authority.

Require the signed statement to bind the current Campaign and Run, rebuilt APP-001B preparation
and analysis request, consumed ActionPermit, durable approval-consumption receipt, recomputable
Gateway outcome, content-addressed sandbox-runtime receipt, execution window, and detached result
receipt. The runtime receipt must match the exact custody binding, artifact digest and byte count,
sandbox binding, operation, parser, executable and image digests, deployment, and run-as identity.
It records deployment assertions for authorization, digest, non-root, network-disabled,
read-only/no-exec mount, no-new-privileges, and resource-limit conformance while embedding no raw
artifact or identity metadata.

Rebuild the preparation from current activation, Campaign, Surface, custody and sandbox bindings.
Join it to exactly one consumed Permit and exactly one durable approval receipt in the existing
SQLite authority store. Recompute Gateway policy from the current Campaign, Grant, request, and
Tool spec. Verify all signature, key-lifecycle, authority, request, timing, budget, detached-file,
and content identities before registering Graph lineage. The repository verifies the configured
deployment assertion; it does not independently inspect a live sandbox or custody service.

Construct one Observation proposal containing one succeeded Action, one target-derived
`application.analysis-observation`, two restricted Evidence nodes, one `produces` edge, and two
`supported-by` edges. Fixed prose states only that a sealed, read-only analysis produced a
digest-bound neutral receipt. Raw parser output, artifact bytes/path, format conclusions,
configuration values, runtime-support conclusions, dependency conclusions, and vulnerability
claims remain outside the Graph.

Permit an optional open Hypothesis only for four code-owned class/operation review signals:
binary security metadata, configuration structure, runtime metadata, or library metadata review.
Each produces a separate confidence `0.5`, agent-derived `application.vulnerability` Hypothesis
whose expected observable is reproduction by independently authorized re-analysis of the same
artifact digest. The Hypothesis never names or confirms a vulnerability. No signal produces no
Hypothesis and no negative conclusion.

Submit the Observation and, when present, the immediately following Hypothesis through the
existing `GraphAdmissionAuthority` using compare-and-set heads. Exact retries return prior events
without reopening custody or invoking a Tool, Gateway, sandbox, Worker, or network operation.

## Consequences

- APP-001C proves only that the configured deployment issuer signed one bounded completed
  execution and named digest-only evidence that matches current authority.
- Repository code does not become a live sandbox, custody-authorization, image, parser, format,
  runtime, dependency, or vulnerability Oracle.
- Raw result bodies and artifact bytes remain under external custody.
- Optional review signals motivate an open Hypothesis but never establish a vulnerability,
  exploitability, impact, or Finding.
- Surface, Scope, Capability, approval, Permit, artifact access, custody authorization, sandbox
  invocation, Worker selection, network, dynamic execution, debugger, mutation, Replay, Finding,
  and further execution authority remain false.
- APP-001D owns deterministic re-analysis, Controls, seeded Ground Truth, disposable fixtures, and
  measurement.

## Rejected alternatives

### Treat APP-001B preparation as execution evidence

Rejected because preparation explicitly performs no authorization verification, artifact read,
mount, sandbox attestation, parser invocation, or result sealing.

### Accept a result digest without a deployment signature and consumed Permit

Rejected because a digest alone proves neither who produced it nor whether current Scope, approval,
Permit, Gateway policy, exact artifact, and sandbox constraints governed the action.

### Interpret or embed the parser body during admission

Rejected because parser output is target-controlled and may be large, sensitive, malformed, or
semantically wrong. Digest-only external custody preserves lineage without making admission a
format, dependency, vulnerability, or sensitive-data interpreter.

### Treat a review signal as a Finding

Rejected because the deployment receipt is not an independent Replay, Control, Ground Truth, or
impact Oracle. A signal can only motivate bounded re-analysis.

### Add an Application-specific Graph writer

Rejected because the existing writer already enforces producer registration, trusted lineage,
stale-head checks, append-only events, and exact retry semantics.

## Compatibility and rollback

APP-001C is additive. Existing APP-001A/B, sealed Run artifact, Campaign Scope, Capability, Tool,
approval, ActionPermit, Graph, Replay, Finding, and benchmark wires retain their versions. Rollback
removes the specialized workflow, tests, contract, and this ADR. Existing external evidence and
already admitted immutable Graph events require no migration.

## Related documents

- [APP-001C contract](../graph/APP-001C-sealed-application-static-analysis-knowledge-admission.md)
- [APP-001B](../capability/APP-001B-read-only-static-analysis-capability.md)
- [APP-001A](../discovery/APP-001A-binary-configuration-runtime-library-surface-model.md)
- [DOMAIN-002](../graph/DOMAIN-002-common-multi-domain-graph-semantics.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0233](0233-bind-application-static-analysis-without-artifact-access-authority.md)
