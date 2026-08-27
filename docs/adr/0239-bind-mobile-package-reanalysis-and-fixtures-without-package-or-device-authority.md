# ADR-0239: Bind Mobile Package Re-analysis and Fixtures without Package or Device Authority

- Status: Accepted
- Date: 2026-08-27
- Owners: PAJIN architecture and security boundary maintainers
- Scope: MOBILE-001D

## Context

MOBILE-001C can reverify one already completed, approved, device-free static package analysis and
admit only neutral Graph knowledge. Package bytes and the result body remain outside the
repository. The Graph contains no parser output, manifest or signing data, platform-runtime claim,
storage or link value, TLS or authentication conclusion, confirmed security property,
vulnerability, or Finding.

MOBILE-001D must compare that stored source with a separately authorized execution and register
future seeded Mobile benchmark requirements. Equal output digests alone do not prove the same
selected and root package Surfaces, APK/IPA platform lineage, custody object, parser, sandbox image,
Scope, resource ceilings, or observed archive set. Different output digests do not prove a package
or security change. Graph knowledge and an open MOBILE-001C Hypothesis also cannot dispatch a
parser, authorize another package read, apply the device-bound Mobile Worker profile, or select an
emulator or device.

The Mobile fixture space has fourteen valid selected Surface/platform/root-package lineages: APK on
Android, IPA on iOS, and each of application, runtime, storage, deep link, TLS policy, and
authentication flow on both platforms. Registering only one child platform would claim complete
Mobile coverage while leaving the other package lineage unspecified.

## Decision

Add a MOBILE-001D package re-analysis gate that:

1. reopens the exact stored MOBILE-001C source admission and independently reloads both sealed
   executions through the current MOBILE-001C verifier and one deployment-configured trust anchor;
2. requires the exact selected and root package Surfaces, full parent lineage, platform, immutable
   package SHA-256 and byte count, operation, custody and sandbox bindings, logical parser, parser
   executable, sandbox image, output schema, Campaign Scope and both exact allow rules, release,
   normalized request semantics, and all resource and archive ceilings to match;
3. requires all six signed observed archive values and archive-entry rejection requirements to
   match, so a different parse observation is incomparable rather than a security-result change;
4. rejects reuse of any Run, source-root, request, envelope, proposal, Decision, Permit, dispatch,
   approval, approval-consumption, execution, sandbox-runtime receipt, statement, attestation, or
   result-receipt identity coordinate;
5. requires the re-analysis statement's signed start to be strictly later than the source
   statement's signed finish;
6. rejects an equal result-body digest paired with a different signed result byte count, while
   allowing different digests to have equal or different byte counts;
7. binds the exact DOMAIN-006 Mobile `deterministic-package-reanalysis` strategy;
8. emits only `package-analysis-result-match`, `package-analysis-result-changed`, or
   `package-analysis-result-unresolved`, plus exact digest, byte-count, and signal equality
   booleans; and
9. performs no Graph write, package read, parser call, sandbox invocation, profile binding, Worker
   or device selection, network or credential operation, mutation, or Replay scheduling.

An exact body-digest, byte-count, and review-signal match is `match`. A differing bounded review
signal, or a result-digest difference when at least one bounded signal exists, is `changed`. If both
executions have no bounded signal and their opaque result digests differ, the comparison is
`unresolved`. Result byte-count equality is retained as provenance but does not independently
become package or security truth.

Trusted wire reload requires the deployment-configured trust anchor, both original MOBILE-001C
evidence roots and source inputs, and both exact Graph stores. It re-runs the current MOBILE-001C
verifier, confirms exact source-event storage, rebuilds the expected MOBILE-001D projection, and
compares the complete canonical model. Bare Pydantic parsing is structural only. The public
projection therefore records `deploymentContextReverificationRequired=true` and
`selfAuthenticatingProjection=false`.

Register a content-addressed 28-case fixture profile: one class-bound known-positive review signal
and one no-signal negative Control for every valid selected Surface/platform/root-package lineage.
Every case requires an externally seeded immutable APK or IPA, a disposable network/DNS-disabled
non-root static sandbox, a read-only no-exec exact-digest package mount, the MOBILE-001B archive
ceilings and entry-safety rejections, and complete execution, runtime, result, and cleanup evidence.
The profile materializes, provisions, executes, cleans up, and measures nothing.

Keep the DOMAIN-006 `mobile.manifest-component-coverage` metric required but unmeasured. Preserve
the MOBILE-001B/C device boundary: the current DOMAIN-004 Mobile profile remains deferred and
unbound, profile conformance remains false, and no Mobile Worker job, emulator, device, bridge,
installer, launcher, or instrumentation runtime is materialized.

## Consequences

- Package equality is exact signed selected/root/platform/custody provenance, not an inference from
  equal output.
- Parser executable, sandbox image, output schema, Scope, budget, archive ceiling, or archive
  observation drift fails closed rather than becoming a misleading changed result.
- Equal result digests cannot carry contradictory signed byte counts.
- A disjoint but older or concurrent execution cannot be relabeled as deterministic re-analysis.
- A result-digest difference without either bounded signal remains unresolved.
- The 28-case fixture registry covers both package platforms for all valid Surface lineages without
  claiming that any package, sandbox, cleanup, or Ground Truth result exists.
- Known-positive fixtures expect a bounded class-owned review signal, not a vulnerability Finding.
- The validation and fixture profile create no package, parser, sandbox, profile, Worker, device,
  Finding, Replay, measurement, or future execution authority.

## Alternatives considered

### Compare MOBILE-001C Graph nodes only

Rejected because the Graph deliberately omits exact custody, sandbox, package lineage, archive
observations, and detached result provenance needed to prove deterministic semantics and separate
execution authority.

### Compare only the package and result digests

Rejected because those digests do not bind selected/root Scope, parent lineage, platform, parser
executable, sandbox image, resource and archive ceilings, observed archive values, or deployment
trust. Equal result digests with different signed byte counts are also internally inconsistent.

### Register sixteen class-only fixtures

Rejected because the six child Surface classes are valid below both APK/Android and IPA/iOS roots.
Sixteen positive/negative class-only cases cannot express all fourteen valid platform lineages;
28 exact lineage cases are required.

### Bind the current DOMAIN-004 Mobile Worker profile

Rejected because that profile is device-bound while MOBILE-001D compares static package-analysis
evidence. Substituting an Application profile or placeholder device identity would fabricate
profile conformance and Worker or device authority.

### Treat every digest or byte-count difference as a security change

Rejected because MOBILE-001D cannot inspect raw output or distinguish serialization differences,
parser behavior, manifest semantics, runtime behavior, or a security regression. Byte-count
equality is provenance only and never selects a conclusion by itself.

### Materialize and execute seeded packages in MOBILE-001D

Rejected because the repository has no governed Mobile package provider, archive or manifest
parser runtime, static-sandbox scheduler, Mobile Target Factory, or device-free Worker profile for
this slice. Registration must precede execution and measurement.

## Security and authority impact

MOBILE-001D consumes only prior signed, approved, and stored provenance. Package digests, parser and
image identities, archive observations, admitted Observations, open Hypotheses, comparisons, and
fixture Ground Truth requirements are knowledge. They do not grant Scope, Capability activation,
approval, Permit issuance, package or credential access, custody authority, sandbox or Worker
selection, Domain Worker profile binding, emulator or device access, install, launch,
instrumentation, debugger or dynamic execution, network, DNS, storage, TLS, authentication,
credential use, mutation, Replay, Finding, benchmark measurement, or execution authority.

The fixture registry contains no raw package, manifest, signing data, parser output, secret,
credential, private key, filesystem path, full URI, storage value, device identity, or live runtime
state. Its private Ground Truth is a closed expected-outcome vocabulary, not observed package or
device data.

## Compatibility and rollback

MOBILE-001D is additive. MOBILE-001A through MOBILE-001C wire identities do not change. Existing
committed Web, AI, Network, Cloud, Campaign, Graph, Capability, Replay, Finding, and benchmark
readers require no migration.

Rollback removes the MOBILE-001D module, tests, contract, and this ADR. No Graph event, external
package, sandbox, fixture, device state, or cleanup operation is created by MOBILE-001D.

## Verification

Positive and adversarial tests cover all fourteen platform/root lineages, match, changed, and
unresolved comparison, stored source binding, complete separate authority, authority reuse, exact
selected/root/platform/package and archive semantics, non-causal execution, result digest/byte
consistency, marker coercion, Graph immutability, exact 28-case fixture registration, Ground Truth
and signal substitution, device/profile/Worker false authority, and structural and contextful wire
reload.

## Related contracts

- [MOBILE-001C](../graph/MOBILE-001C-sealed-mobile-package-analysis-knowledge-admission.md)
- [MOBILE-001D](../benchmark/MOBILE-001D-package-reanalysis-seeded-mobile-fixtures.md)
- [ADR-0238](0238-admit-mobile-package-analysis-knowledge-without-package-or-device-authority.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [DOMAIN-006](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
