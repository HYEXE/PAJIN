# MOBILE-001C: Sealed Mobile Package-analysis Knowledge Admission

- Status: Implemented, neutral Observation and optional bounded open Hypothesis
- API versions:
  - `pajin.dev/mobile-package-analysis-execution-trust-anchor/v1alpha1`
  - `pajin.dev/mobile-package-analysis-result-receipt/v1alpha1`
  - `pajin.dev/mobile-package-analysis-execution-statement/v1alpha1`
  - `pajin.dev/mobile-package-analysis-execution-bundle/v1alpha1`
  - `pajin.dev/mobile-package-analysis-knowledge-admission-policy/v1alpha1`
  - `pajin.dev/mobile-package-analysis-knowledge-candidate/v1alpha1`
  - `pajin.dev/mobile-package-analysis-knowledge-admission/v1alpha1`
- Authority: `src/pajin/workflow/mobile_package_analysis_admission.py`
- Decision: [ADR-0238](../adr/0238-admit-mobile-package-analysis-knowledge-without-package-or-device-authority.md)

## Purpose

MOBILE-001C admits one neutral `mobile.analysis-observation` only after independently rechecking
one separately authorized, deployment-produced, signed MOBILE-001B static package-analysis
execution. One fixed class-owned review signal may additionally admit one bounded open
`mobile.security-property` Hypothesis. The workflow adds no repository package resolver, archive
reader, manifest parser, image registry, sandbox runtime, Domain Worker profile, Worker job,
emulator, device bridge, installer, launcher, instrumentation path, network client, storage
reader, TLS client, authentication client, credential accessor, result-body interpreter, or
Finding producer.

MOBILE-001A Surfaces remain `registered-not-authorized`, and MOBILE-001B remains preparation-only.
The approval, Permit, custody, sandbox, signature, and detached receipt records are provenance for
one already completed action. They authorize no subsequent package read, sandbox invocation,
Worker or device selection, Replay, or execution.

## Deployment-owned source and trust

`MobilePackageAnalysisObservationSourceInputs` supplies a bounded evidence root, signed-bundle
reference, expected Run, current Mobile activation, current Campaign, exact MOBILE-001B
preparation, and approved `CapabilityGraphCampaignJobInput`. The admission gate receives its
trust anchor separately through deployment configuration; source evidence cannot select or
replace the anchor.

`MobilePackageAnalysisExecutionTrustAnchor` binds the exact MOBILE-001B sandbox configuration,
code-backed Capability, signed release, trust domain, issuer, and an ordered Ed25519 keyring with
exactly one active key. The anchor is verification-only and explicitly describes an external
device-free static sandbox. Current activation, Campaign, approval, Permit, package access,
sandbox invocation, Graph admission, and execution authority remain false.

The current DOMAIN-004 Mobile minimum profile is device-bound. MOBILE-001C therefore preserves
`domainWorkerProfileBindingDeferred=true`, `domainWorkerProfileBound=false`,
`deviceBoundRuntimeProfileApplied=false`, and unavailable Worker-job materialization throughout
the trust anchor, execution statement, receipts, candidate, and admission. A deployment signature
does not prove DOMAIN-004 profile conformance, Worker mTLS identity, or device runtime support.

## Signed external static execution

The signed statement binds:

- trust domain, issuer, exact sandbox binding and deployment;
- recomputable Gateway `PolicyDecision` and a sanitized outcome digest;
- execution, Campaign ID/digest, Run, MOBILE-001B preparation, and exact analysis request;
- request and normalized-parameter identities;
- one consumed ActionPermit and one durable approval-consumption receipt;
- one content-addressed `MobilePackageSandboxRuntimeReceipt`;
- detached result-receipt path, file SHA-256, receipt identity, and content digest; and
- execution start, runtime-attestation, finish, and statement-issue times.

The statement records exactly one request and one package read. Network and DNS requests,
emulator and device sessions, package installations, application launches, instrumentation,
dynamic target executions, debugger attaches, storage reads, TLS connections, authentication
invocations, package writes, host-filesystem reads, and credential reads are all zero. It cannot
authorize a new package read, sandbox invocation, Worker or profile binding, device access,
network use, mutation, Replay, Graph admission, Finding confirmation, or execution.

## Selected Surface, root package, and sandbox receipt

The runtime receipt binds both the exact selected MOBILE-001A Surface and its reconstructed root
APK or IPA package Surface. It also binds:

- root package SHA-256 and byte count;
- custody authority, object, binding, authorization identities and digest, operation, platform,
  and lineage-derived parser;
- parser-executable and sandbox-image digests, deployment, and explicit non-root identity;
- fixed `/pajin/input/package` mount and `bounded-json-stdout` result transport;
- package, output, runtime, memory, and process ceilings;
- archive entry, total and single-entry uncompressed byte, path byte, nesting depth, and
  compression-ratio ceilings;
- observed archive entry, byte, path, nesting, and compression-ratio maxima;
- runtime-identity and confinement digests; and
- assertions that custody authorization, package digest, parser/image identity, disabled network
  and DNS, read-only root, read-only no-exec package mount, no-new-privileges, resource ceilings,
  archive ceilings, and traversal/symlink/duplicate-name rejection were checked.

Every observed archive value must remain within the exact MOBILE-001B ceiling. These fields are
signed assertions from the configured deployment, not an independent inspection by repository
code. The receipt embeds no package bytes or runtime identity metadata and grants no profile,
Worker, device, network, mutation, or execution authority.

## Neutral result receipt

`MobilePackageAnalysisResultReceipt` is a strict detached JSON artifact. It binds the execution,
request, preparation, selected Surface, root package Surface, operation, platform,
lineage-derived parser, root package digest, fixed output schema, result-body SHA-256, bounded byte
count, JSON media type,
optional fixed review signal, and receipt time. The signed statement covers its content-addressed
identity and actual file SHA-256.

The receipt never embeds raw result, package, manifest, signing, security-configuration, device,
credential, or path data. It cannot assert package format, manifest truth, signing identity,
application declaration truth, runtime declaration truth or support, storage values, deep-link
reachability, TLS enforcement, authentication safety, vulnerability, security-property,
Hypothesis, Finding, Worker/profile conformance, or execution authority. The raw result body stays
in external custody and is not opened during admission.

## Current authority revalidation

Before Graph lineage registration, the loader:

1. rebuilds the exact MOBILE-001B preparation using the current signed activation, release,
   Campaign, selected Surface, root package lineage, operation, custody binding, sandbox binding,
   request, and agent identity;
2. thereby rechecks exact current allow Scope for both the selected Surface token and root package
   token, deny precedence, and GET Rules of Engagement;
3. rechecks the Graph Decision, ActionProposal, Capability Grant, approved job, request, target,
   normalized parameters, preparation digest, and activation-set identity;
4. resolves exactly one matching consumed ActionPermit and exactly one durable
   approval-consumption receipt from the existing SQLite authority store;
5. recomputes the Gateway decision from the current Campaign, Grant, request, and network-disabled
   Mobile Tool spec;
6. verifies the deployment-configured trust anchor, key lifecycle, Ed25519 signature, sandbox
   receipt, result receipt, and sanitized Gateway outcome; and
7. checks selected/root lineage, custody, package digest and bytes, operation/parser, executable,
   image, non-root identity, archive limits and observations, causal timing, zero live-channel
   budgets, result size, detached paths, file digests, receipt identities, and source-root digest.

The loader never invokes the Tool, resolves package custody, opens package or result-body bytes,
launches a sandbox, creates a Worker job, binds a Domain Worker profile, selects a device, or
accesses a network or credential service.

## Observation and Evidence

The Observation proposal contains exactly:

- one succeeded `Action` bound to the consumed ActionPermit;
- one target-derived `mobile.analysis-observation` with fixed neutral prose;
- two restricted `Evidence` nodes for the signed execution bundle and detached result receipt;
- one `produces` edge; and
- two `supported-by` edges.

Its value digest binds the preparation, selected and root package references, package digest,
operation, parser, output schema, request, approval receipt, trust anchor, signed statement,
Gateway outcome, sandbox receipt, configured and observed archive limits, runtime and confinement
digests, result receipt, result-body digest, bounded byte count, optional review signal, deferred
profile markers, and source-root digest.

Graph prose contains no package or parser output, manifest or signing data, application ID,
storage value, deep-link target, TLS or authentication detail, device coordinate, package path,
filename, vulnerability statement, or negative conclusion.

## Bounded open Hypothesis

Only the following exact class/operation signals are allowed:

| Signal | Exact source |
| --- | --- |
| `apk-package-structure-review` | APK plus `apk-package-structure-read` |
| `ipa-package-structure-review` | IPA plus `ipa-package-structure-read` |
| `application-declaration-review` | application plus `application-declaration-read` |
| `runtime-declaration-review` | runtime plus `runtime-declaration-read` |
| `storage-declaration-review` | storage plus `storage-declaration-read` |
| `deep-link-declaration-review` | deep link plus `deep-link-declaration-read` |
| `tls-policy-declaration-review` | TLS policy plus `tls-policy-declaration-read` |
| `authentication-flow-declaration-review` | authentication plus `authentication-flow-declaration-read` |

Each signal may create one agent-derived confidence `0.5` open `mobile.security-property`
Hypothesis and one `enables` edge from the neutral Observation. Fixed prose requires separately
authorized static re-analysis of the same exact selected Surface and root package digest to
reproduce the same signal. It does not name or confirm a weakness, runtime behavior, exploit,
impact, or Finding. No signal creates no Hypothesis and no negative conclusion.

## Existing writer and exact retry

The gate requires a current non-empty Graph Snapshot and the exact existing
`GraphAdmissionAuthority`, SQLite event log, and trusted-lineage registry. Observation admission
uses compare-and-set against the bound current head. An optional Hypothesis must immediately
follow the admitted Observation; intervening Graph activity fails closed.

Both proposals are content-addressed. Exact retry returns prior events and performs no package,
Tool, Gateway, sandbox, Worker, device, network, storage, TLS, authentication, or credential
operation. MOBILE-001C creates no Mobile-specific Graph store or writer.

## Explicit non-authority

Candidate and admission artifacts fix all of the following to false: raw package, manifest,
parser output, signing, security-configuration, device-state, credential, and path embedding;
package/manifest/application/signing/runtime/storage/deep-link/TLS/authentication truth;
vulnerability and Hypothesis confirmation; mutation; Scope expansion; Capability activation;
approval; Permit issuance; package and custody access; sandbox invocation; Worker/profile/job
binding; DNS and network access; emulator/device access; installation; launch; instrumentation;
dynamic execution; debugger attach; storage/TLS/authentication invocation; credential use; Replay;
Finding confirmation; and execution authority.

Successful admission remains `registered-not-authorized`. Signed execution provenance and neutral
knowledge cannot be converted into another package read or action.

## Fail-closed behavior

Admission rejects absent, changed, oversized, multiply linked, non-JSON, duplicate-key, or
path-invalid evidence; signature, issuer, key lifecycle, trust-anchor, Campaign, activation,
selected or root Scope, preparation, Decision, Proposal, Grant, approval, Permit, request, target,
normalized parameter, custody, package digest or size, selected/root lineage, operation, parser,
executable, image, deployment, run-as identity, archive ceiling or observed value, timing, budget,
output schema, receipt, or digest substitution; APK/IPA and Android/iOS parser confusion; missing
or ambiguous Permit/approval records; class-crossing review signals; stale Graph heads; Graph
authority substitution; proposal/event drift; extra model instance state; true authority markers;
and boolean or integer coercion.

## Compatibility and rollback

MOBILE-001C is additive and explicitly imported. MOBILE-001A/B, APP-001A, Campaign, Scope,
Capability, ToolRequest, approval, ActionPermit, DOMAIN-004, Worker, Graph, Replay, Finding, and
benchmark wires retain their versions. Rollback removes the workflow, tests, this contract, and
ADR-0238. Already admitted immutable Graph events and deployment-owned evidence require no
migration.

## Verification requirements

Focused verification must cover all eight Surface/operation/review-signal bindings on APK and IPA
lineages, signal-free neutral admission, exact retry, selected/root Scope drift, signature and
detached-receipt tampering, missing or substituted Permit and approval identity, recomputed Gateway
policy, result overflow, parser/image/run-as/archive substitution, deferred profile and Worker
markers, stale Graph heads, producer registration, raw/truth/authority escalation, integer and
boolean coercion, forged model-instance state, and cross-class review-signal rejection.

MOBILE-001D remains responsible for separately authorized deterministic re-analysis, seeded
package Ground Truth, disposable static-sandbox fixtures, Controls, metrics, and validation floors.
Emulator or physical-device analysis requires a separate exact Capability, device identity,
Scope, Worker profile, deployment, cleanup, and fresh authority contract.
