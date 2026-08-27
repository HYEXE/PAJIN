# ADR-0238: Admit Mobile Package-analysis Knowledge without Package or Device Authority

## Status

Accepted

## Context

MOBILE-001B produces one current signed preparation for an exact read-only static package-analysis
request. It binds both a selected MOBILE-001A Surface and its root APK or IPA package Surface,
current exact Scope for both identities, opaque deployment custody and authorization coordinates,
a lineage-derived parser, parser-executable and sandbox-image digests, explicit non-root
network/DNS-disabled read-only sandbox requirements, and package/archive resource ceilings. It
deliberately stops before package resolution, authorization verification, byte access, parser or
sandbox execution, Domain Worker profile binding, Worker-job materialization, device access,
result production, or Graph admission.

PAJIN needs to admit neutral knowledge from a static package analysis that an external deployment
separately approved and completed without pretending that MOBILE-001B executed it. Trusting the
preparation as runtime proof, accepting an unsigned result digest, ignoring APK/IPA parent lineage
or archive-bomb constraints, treating the device-bound DOMAIN-004 profile as satisfied, or copying
parser output into Graph prose would violate current authority, provenance, privacy, and
single-writer boundaries.

## Decision

Add a MOBILE-001C source-verification and Graph-admission boundary. Do not add a repository-owned
package resolver, archive or manifest parser, static sandbox runtime, Domain Worker profile,
Worker job, emulator/device path, installer, instrumentation client, network path, credential
client, or raw result interpreter. Require the deployment-owned external static runtime to
provide:

1. an Ed25519-signed `MobilePackageAnalysisExecutionBundle`; and
2. a detached `MobilePackageAnalysisResultReceipt` containing only exact identities, bounded
   result metadata, a result-body digest, and an optional fixed review signal.

Configure the trust anchor when constructing the admission gate. Source inputs cannot provide or
override it. Bind the anchor to the exact MOBILE-001B sandbox, code-backed Capability, signed
release, trust domain, issuer, and a uniquely sorted Ed25519 keyring with exactly one active key.
Treat it as verification-only and external-static-sandbox-only, not current activation, Campaign,
approval, Permit, package access, sandbox invocation, Graph, or execution authority.

Preserve the deliberate MOBILE-001B worker boundary. The trust anchor, signed statement, receipts,
candidate, and admission must keep Domain Worker profile binding deferred, profile binding false,
device-bound runtime profile application false, and Worker-job materialization unavailable. A
valid external signature proves statement origin and integrity only; it does not establish
DOMAIN-004 profile conformance, Worker mTLS identity, device identity, or runtime support.

Require the signed statement and sandbox receipt to bind the current Campaign and Run, rebuilt
MOBILE-001B preparation and exact request, consumed ActionPermit, durable approval-consumption
receipt, recomputable Gateway outcome, exact selected and root package Surfaces, root package
digest and bytes, custody authority/object/binding/authorization identities and digest,
operation, platform, lineage-derived parser, executable and
image digests, deployment, non-root identity, execution window, and detached result receipt.

Require the runtime receipt to echo every package, output, runtime, memory, process, and archive
ceiling and to record bounded observed archive entry, byte, path, nesting, and compression-ratio
values. Require deployment assertions for disabled network and DNS, read-only root, read-only
no-exec package mount, no-new-privileges, exact executable/image identity, archive ceiling
application, and traversal/symlink/duplicate-name rejection. Treat these as signed historical
assertions, not an independent repository inspection or fresh package-read authority.

Rebuild the MOBILE-001B preparation from current activation, release, Campaign, selected Surface,
root package lineage, custody, sandbox, request, and agent identity. This rebuild must recheck exact
allow Scope for both selected and root package Surface tokens, deny precedence, and GET. Join it to
exactly one consumed Permit and one durable approval receipt in the existing SQLite authority
store. Recompute Gateway policy from the current Campaign, Grant, exact request, and Tool spec.
Verify signature, key lifecycle, authority, request, timing, zero-live-channel budgets, archive
limits and observations, detached file, receipt, and content-addressed identities before
registering Graph lineage.

Construct one Observation proposal containing one succeeded Action, one target-derived
`mobile.analysis-observation`, two restricted Evidence nodes, one `produces` edge, and two
`supported-by` edges. Fixed prose states only that a sealed read-only package-analysis execution
produced a digest-bound neutral Mobile result receipt. Raw package or parser output, manifest and
signing data, identifiers, paths, device state, credentials, and security conclusions remain
outside the Graph.

Permit an optional open `mobile.security-property` Hypothesis only for eight code-owned exact
Surface/operation review signals: APK package structure, IPA package structure, application
declaration, runtime declaration, storage declaration, deep-link declaration, TLS-policy
declaration, or authentication-flow declaration. Each creates a separate agent-derived confidence
`0.5` Hypothesis whose expected observable is reproduction by separately authorized static
re-analysis of the same selected Surface and root package digest. It never confirms a weakness,
runtime behavior, vulnerability, exploitability, impact, or Finding. No signal produces no
Hypothesis and no negative conclusion.

Submit the Observation and, when present, immediately following Hypothesis through the existing
`GraphAdmissionAuthority` with compare-and-set heads. Exact retries return prior events without
opening package custody or invoking a Tool, Gateway, sandbox, Worker, device, network, storage,
TLS, authentication, or credential service.

## Consequences

- MOBILE-001C proves only that the configured deployment issuer signed one bounded, completed
  device-free static execution and named digest-only evidence matching current authority.
- Repository code does not become a custody authorization, package format, archive parser,
  manifest, signing, sandbox, profile, Worker, device, runtime, or security-property Oracle.
- Raw result bodies and package bytes remain under external custody.
- Optional review signals motivate open re-analysis only; they establish no package truth,
  vulnerability, security property, or Finding.
- Scope, Capability, approval, Permit, package access, custody authorization, sandbox invocation,
  Worker/profile/job binding, DNS/network, emulator/device access, installation, launch,
  instrumentation, storage/TLS/authentication/credential use, mutation, Replay, Finding, and
  further execution authority remain false.
- MOBILE-001D owns deterministic package re-analysis, Controls, seeded Ground Truth, disposable
  static-sandbox fixtures, and measurement.

## Rejected alternatives

### Treat MOBILE-001B preparation as execution evidence

Rejected because preparation performs no custody verification, package read, archive-limit
application, parser or sandbox invocation, runtime attestation, result sealing, or Graph admission.

### Bind the current device-oriented DOMAIN-004 Mobile profile

Rejected because the static slice has no emulator or device identity and no Mobile Worker job.
Claiming profile conformance would fabricate a runtime and weaken the exact profile boundary.

### Accept only a package or result digest

Rejected because a digest alone proves neither the producer nor whether current selected/root
Scope, approval, Permit, Gateway policy, custody, parser/image identity, sandbox constraints, and
archive limits governed the action.

### Interpret or embed parser output during admission

Rejected because package output is target-controlled and may be large, malformed, sensitive, or
semantically wrong. Digest-only external custody preserves lineage without making Graph admission
a package-format, manifest, signing, runtime, storage, link, TLS, authentication, or vulnerability
interpreter.

### Treat a review signal as a Finding

Rejected because the signed deployment receipt is not an independent Replay, Control, Ground
Truth, impact Oracle, or device observation. A fixed signal can only motivate bounded independent
re-analysis.

### Add a Mobile-specific Graph writer

Rejected because the existing writer already enforces producer registration, trusted lineage,
stale-head checks, append-only events, and exact retry semantics.

## Compatibility and rollback

MOBILE-001C is additive and explicitly imported. Existing MOBILE-001A/B, APP-001A, Campaign,
Scope, Capability, ToolRequest, approval, ActionPermit, DOMAIN-004, Worker, Graph, Replay, Finding,
and benchmark wires retain their versions. Rollback removes the workflow, tests, contract, and
this ADR. Existing external evidence and admitted immutable Graph events require no migration.

## Related documents

- [MOBILE-001C contract](../graph/MOBILE-001C-sealed-mobile-package-analysis-knowledge-admission.md)
- [MOBILE-001B](../capability/MOBILE-001B-read-only-package-analysis-capability.md)
- [MOBILE-001A](../discovery/MOBILE-001A-apk-ipa-app-runtime-storage-deeplink-tls-auth-surface-model.md)
- [DOMAIN-002](../graph/DOMAIN-002-common-multi-domain-graph-semantics.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ARCH-001](../rfc/0001-pajin-architecture-v2.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0237](0237-bind-mobile-package-analysis-without-package-or-device-access-authority.md)
