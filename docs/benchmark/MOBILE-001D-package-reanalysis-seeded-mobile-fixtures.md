# MOBILE-001D: Deterministic Package Re-analysis and Seeded Mobile Fixtures

- Status: Implemented
- Version: `v1alpha1`
- Domain: Mobile
- Decision: [ADR-0239](../adr/0239-bind-mobile-package-reanalysis-and-fixtures-without-package-or-device-authority.md)
- Predecessors:
  [MOBILE-001A](../discovery/MOBILE-001A-apk-ipa-app-runtime-storage-deeplink-tls-auth-surface-model.md),
  [MOBILE-001B](../capability/MOBILE-001B-read-only-package-analysis-capability.md), and
  [MOBILE-001C](../graph/MOBILE-001C-sealed-mobile-package-analysis-knowledge-admission.md)

## Purpose

MOBILE-001D reopens one stored MOBILE-001C admission and one separately authorized sealed static
package-analysis execution for the same immutable APK or IPA lineage. It returns only a neutral
result-body digest, byte-count, and bounded review-signal comparison. It also registers future
seeded Mobile Ground Truth requirements without materializing a package, provisioning or invoking
a sandbox, cleaning up a fixture, accessing a device, or recording a benchmark measurement.

The implementation is a verification and projection boundary. It is not a package resolver,
archive or manifest parser, sandbox or Worker runtime, Replay scheduler, Target Factory, benchmark
Harness, device or emulator controller, vulnerability Oracle, or Finding validator.

## Re-analysis inputs

The gate receives:

1. exact MOBILE-001C source inputs;
2. the corresponding stored `MobilePackageAnalysisKnowledgeAdmission`;
3. exact separately authorized re-analysis inputs;
4. source and re-analysis SQLite Graph authority stores; and
5. the deployment-configured Mobile package-analysis execution trust anchor.

Both executions are reopened through
`load_verified_mobile_package_analysis_observation_source`. This rechecks current activation and
Campaign Scope for both the selected and root package Surfaces, exact MOBILE-001B preparation and
approved job, exactly one consumed ActionPermit and durable approval receipt, the Ed25519 execution
signature, recomputed Gateway policy result, exact custody and immutable package digest, platform,
lineage-derived parser, parser executable and sandbox image, non-root network/DNS-disabled
read-only/no-exec runtime assertions, bounded archive configuration and observations, detached
result receipt, timing, and all declared resource and live-channel budgets.

Only the source must already be admitted. Its Observation and optional Hypothesis events must
exist exactly in the supplied source Graph store. The re-analysis remains sealed evidence and is
not automatically admitted to the Graph.

## Exact deterministic package semantics

Source and re-analysis must have the same:

- deployment trust anchor, code-backed Capability, signed release, and activation-set digest;
- exact selected MOBILE-001A Surface, root APK or IPA package Surface, complete parent lineage,
  platform, operation, and immutable package SHA-256 and byte count;
- custody authority, object, binding, authorization identity, and authorization digest;
- static-sandbox binding, lineage-derived logical parser, parser executable SHA-256, sandbox image
  SHA-256, non-root identity, package mount, and output schema;
- package, output, runtime, memory, process, archive-entry, total and single uncompressed-size,
  archive-path, nesting, and compression-ratio ceilings;
- traversal, symlink, and duplicate-name rejection requirements;
- all six signed archive observations: entry count, total and largest uncompressed bytes, maximum
  archive-path bytes, nesting depth, and maximum compression ratio;
- Campaign Scope and the matched exact allow rules for both selected and root package Surfaces; and
- normalized parameters and request fields other than the intentionally fresh request ID.

A different selected or root Surface, platform, package digest, parent coordinate, operation,
custody binding, parser, image, output schema, Scope, release, budget, archive ceiling, or observed
archive value is not a changed result. It is an incomparable execution and fails closed.

The result receipt retains the exact signed `resultBytes` for each opaque result body. Equal
`resultBodySha256` values must have equal `resultBytes`; an equal digest with a different declared
byte count is inconsistent sealed provenance and fails closed. Different result digests may have
equal or different byte counts. Byte-count equality is recorded but is not package or security
truth and does not independently select a comparison state.

## Separate authority and causal order

The following coordinates must all differ:

- Run and source-root digest;
- request and request digest;
- MissionEnvelope, proposal, Graph Decision, ActionPermit, and dispatch;
- approval envelope and approval-consumption receipt;
- execution ID, signed statement digest, and sandbox-runtime receipt;
- attestation artifact digest; and
- result-receipt ID, receipt digest, and artifact digest.

The re-analysis statement's signed `startedAt` must be strictly later than the source statement's
signed `finishedAt`. Distinct identifiers alone cannot relabel an older or concurrent execution as
deterministic package re-analysis.

The result-body digest and review signal are comparison values and therefore may match. Custody and
sandbox bindings and the exact archive observations must remain equal. Stable runtime identity,
confinement digest, and relative evidence filenames may also remain equal, but they are
per-execution provenance or storage coordinates rather than deterministic-input equality
requirements. The contract establishes separate action and evidence authority, not a different
physical host, Worker, parser implementation, or live sandbox.

## Neutral comparison

`MobilePackageAnalysisReanalysisComparison` has three values:

- `package-analysis-result-match`: result-body digest, result byte count, and bounded review signal
  are all equal;
- `package-analysis-result-changed`: a bounded review signal differs or a signaled result digest
  differs; and
- `package-analysis-result-unresolved`: both executions lack a bounded review signal while their
  opaque result-body digests differ.

The projection records exact digest, byte-count, and signal equality booleans. Every accepted
comparison satisfies the exact DOMAIN-006 Mobile `deterministic-package-reanalysis` strategy
because the gate has already required one identical immutable package lineage, analyzer boundary,
archive configuration, and archive observation set.

`changed` does not confirm a package-format, manifest, signing, application, runtime, storage,
deep-link, TLS, authentication, security-property, or vulnerability change. `unresolved` is not a
negative conclusion. MOBILE-001D never opens or interprets either result body.

## Seeded Mobile fixture profile

`MobilePackageAnalysisBenchmarkFixtureProfile` is content addressed and pins the DOMAIN-006 Mobile
plan, all eight MOBILE-001A Surface classes, both platforms, and all fourteen valid selected
Surface/platform/root-package lineages. Each lineage has one known-positive expected review signal
and one no-signal negative Control, producing exactly 28 sorted private Ground Truth requirements:

| Selected Surface | Platform and root package | Known-positive expected outcome | Negative-Control expected outcome |
| --- | --- | --- | --- |
| APK | Android / APK | APK package-structure review signal | no review signal |
| IPA | iOS / IPA | IPA package-structure review signal | no review signal |
| application | Android / APK and iOS / IPA | application-declaration review signal | no review signal |
| runtime | Android / APK and iOS / IPA | runtime-declaration review signal | no review signal |
| storage | Android / APK and iOS / IPA | storage-declaration review signal | no review signal |
| deep link | Android / APK and iOS / IPA | deep-link-declaration review signal | no review signal |
| TLS policy | Android / APK and iOS / IPA | TLS-policy-declaration review signal | no review signal |
| authentication flow | Android / APK and iOS / IPA | authentication-flow-declaration review signal | no review signal |

Each case requires an externally seeded immutable APK or IPA and one disposable,
network/DNS-disabled, non-root static sandbox with a read-only no-exec exact-digest package mount,
the MOBILE-001B archive ceilings and archive-entry safety rejections, and four evidence roles:

- execution attestation;
- non-root offline runtime receipt;
- result receipt; and
- cleanup receipt.

The registry embeds no package bytes, manifest, signing data, parser output, secret, credential,
path, URI, storage value, device identity, or runtime value. It requires zero package writes,
network and DNS requests, dynamic target executions, debugger or instrumentation attaches,
emulator or device sessions, install or launch operations, storage/TLS/authentication invocations,
and credential uses.
Host-filesystem reads outside the exact package mount are also fixed at zero.

The fixture profile records positive and negative Controls, complete valid lineage coverage,
deterministic package re-analysis, archive safety, isolation, cleanup, and evidence-completeness
requirements only. The DOMAIN-006 `mobile.manifest-component-coverage` metric remains required but
unmeasured. The profile has no selected Target profile or Target Factory authority, no materialized
fixture, no provisioned sandbox, no observed cleanup, no bound re-analysis evidence, and no numeric
metric or Profile-floor evidence.

`privateGroundTruthRequirementsRegistered=true` means only that the exact 28 requirements are code
registered. `privateGroundTruthVerified=false` remains explicit until a later boundary supplies and
verifies materialized package, execution, cleanup, and measurement evidence. Provider and fixture
execution authorization also remain false.

## Device, profile, and Worker boundary

MOBILE-001D preserves the deliberate static-analysis boundary established by MOBILE-001B/C. The
current DOMAIN-004 Mobile minimum profile remains device-bound and is not applied to either sealed
static execution or the fixture registry. Profile binding remains deferred, profile conformance is
not established, and no Mobile Worker job, emulator, device, bridge, installer, launcher, or
instrumentation runtime is selected or materialized.

An exact package and platform lineage identifies comparison semantics only. It does not prove that
an APK or IPA is valid, signed, installable, launchable, compatible with a device, or behaviorally
equivalent at runtime.

## Non-authority boundary

Re-analysis validation and fixture registration keep the following false:

- package format, manifest component, signing identity, application, runtime, storage, deep-link,
  TLS, authentication, security-property, vulnerability, or Hypothesis confirmation;
- Ground Truth or negative-Control observation;
- manifest-component coverage, evidence completeness, benchmark measurement, detection quality,
  or Profile validation floor;
- Finding authority;
- Scope expansion, Capability activation, approval, or Permit issuance;
- package access, custody-authorization authority, sandbox invocation, or Worker selection;
- Domain Worker profile binding, conformance, or Worker-job materialization;
- emulator or device access, installation, launch, instrumentation, debugger, or dynamic execution;
- network, DNS, storage, TLS, authentication, or credential use;
- host-filesystem access outside the exact read-only package mount;
- package mutation; and
- Replay scheduling and execution authority.

The implementation imports no socket, HTTP or DNS client, subprocess, shell, package repository,
archive or manifest parser, container or VM controller, emulator or device bridge, installer,
instrumentation framework, debugger, or artifact storage API.

## Audit and storage

The returned validation and fixture profile are deterministic content-addressed projections.
MOBILE-001D writes no Graph node, edge, event, snapshot, approval, Permit, artifact, benchmark
result, sandbox journal, device record, or cleanup receipt.

Bare `MobilePackageAnalysisReanalysisValidation.model_validate` is structural,
content-addressed parsing only and is not a trusted verification entry point. Trusted wire reload
must use `load_verified_mobile_package_analysis_reanalysis_validation` with the
deployment-configured trust anchor, both original MOBILE-001C evidence roots and inputs, and both
exact Graph stores. The loader reopens both MOBILE-001C sources with the current verifier, confirms
the stored source admission, rebuilds the expected projection, and requires exact canonical model
equality. An embedded trust anchor, attestation digest, Graph event, or recomputed public projection
ID cannot replace that context. The wire projection makes this explicit with
`deploymentContextReverificationRequired=true` and `selfAuthenticatingProjection=false`.

## Failure handling

The gate and contextful wire loader fail closed for invalid or substituted trust anchors,
signatures, source admissions, Campaign Scope, preparations, selected or root package Surfaces,
platform or package lineage, package/custody/sandbox/parser/image identities, archive ceilings or
observations, output schemas, budgets, result receipts, reused authority coordinates, non-causal
execution, inconsistent result digest and byte-count claims, comparison fields, fixture cases,
Domain plans, boolean or integer coercion, or any mismatch between a serialized projection and the
current evidence and Graph context.

## Compatibility and rollback

MOBILE-001D is additive and does not change MOBILE-001A~C public wire identities. Existing
committed Web, AI, Network, Cloud, Campaign, Graph, Capability, Replay, Finding, and benchmark
contracts also remain unchanged.

Rollback removes the MOBILE-001D workflow module, tests, this contract, and ADR-0239. MOBILE-001D
creates no Graph event, external package, sandbox, fixture, device state, or cleanup operation that
requires migration or cleanup.

## Verification

Tests cover all fourteen valid platform/root lineages, match, changed, and unresolved comparison
states, stored source admission, complete separate-authority coordinates, aggregate authority
reuse, non-causal execution, selected/root/platform/parser/package and archive-observation drift,
result digest/byte-count consistency, comparison and authority-marker drift, Graph event-count
preservation, exact 28-case fixture coverage, positive/negative signal binding, device/profile/
Worker false authority, evidence requirements, coercion, digest drift, structural wire round trip,
and contextful wire reload. Adversarial reload cases substitute Graph, evidence, and deployment
trust context and must fail closed.
