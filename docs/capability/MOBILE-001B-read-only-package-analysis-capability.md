# MOBILE-001B: Read-only Mobile Package-analysis Capability

- Status: Implemented, signed preparation and request adaptation only
- Capability: `pajin.mobile.read-only-package-analysis@1.0.0`
- Tool: `mobile.read-only-package-analysis@1.0.0`
- Binding API: `pajin.dev/mobile-package-analysis-binding/v1alpha1`
- Preparation API: `pajin.dev/mobile-package-analysis-preparation/v1alpha1`
- Custody API: `pajin.dev/mobile-package-custody-binding/v1alpha1`
- Sandbox API: `pajin.dev/mobile-package-analysis-sandbox-binding/v1alpha1`
- Request API: `pajin.dev/mobile-package-analysis-request/v1alpha1`
- Output schema: `pajin.mobile.package-analysis-result.v1`
- Authority: `src/pajin/capabilities/mobile_package_analysis.py`
- Decision: [ADR-0237](../adr/0237-bind-mobile-package-analysis-without-package-or-device-access-authority.md)

## Purpose

MOBILE-001B binds one exact MOBILE-001A typed Surface and its exact APK or IPA root package to a
complete signed read-only CAP-002 Capability, the current Campaign Scope, an externally supplied
immutable package-custody and authorization reference, one lineage-derived logical parser,
explicit package and archive ceilings, and a configuration-only offline sandbox requirement. It
stops at `PreparedCapabilityAction`.

The bounded adapter creates only a secret-free request description. It does not resolve, read,
mount, unpack, or parse package bytes; verify package format, manifest, application, signing, or
custody claims; select or attest a sandbox; bind or select a Domain Worker profile; materialize a
Worker job; select an emulator or device; install or launch an application; instrument a process;
read storage; access DNS or a network; make a TLS connection; invoke authentication; use a
credential; normalize a result; or produce an Observation, Evidence, Graph admission, Hypothesis,
or Finding.

## Capability, operation, and parser binding

The Capability is experimental, T2, `READ_ONLY`, network-disabled, approval-required, and costs
one request unit. Its complete CAP-002 set binds materializer, action compiler, executor adapter,
result normalizer, success Oracle, Replay strategy, and cleanup handler roles. Worker
materialization and result interpretation fail closed, Replay and cleanup return no plan, and the
Oracle returns `INCONCLUSIVE` because MOBILE-001B creates no runtime result.

Activation accepts only an externally signed current Range release resolved through the existing
Capability lifecycle registry. The static binding pins the complete eight-member MOBILE-001A
locator registry, the complete code-backed CAP-002 identity, a local Mobile classification, the
fixed output schema, and the complete operation and parser sets. The established global DOMAIN-003
and DOMAIN-004 registries are unchanged.

Each Surface class has exactly one structure-only operation:

| Surface class | Operation |
| --- | --- |
| `apk` | `apk-package-structure-read` |
| `ipa` | `ipa-package-structure-read` |
| `application` | `application-declaration-read` |
| `runtime` | `runtime-declaration-read` |
| `storage` | `storage-declaration-read` |
| `deeplink` | `deep-link-declaration-read` |
| `tls` | `tls-policy-declaration-read` |
| `auth` | `authentication-flow-declaration-read` |

The logical parser is not caller-selected from the child Surface class. It is derived from the
complete root-package lineage: every APK descendant binds `android-apk-structure-parser`, and
every IPA descendant binds `ios-ipa-structure-parser`. A child, package class, operation, or parser
cannot be substituted while retaining the same binding. Parser names identify request contracts
only; they do not assert that an executable, compatible package format, manifest grammar, signing
verifier, or vulnerability detector has been implemented or invoked.

## Selected Surface and root-package boundary

Every custody, sandbox, request, and preparation value carries both the complete selected Surface
and the reconstructed root APK or IPA Surface. The package digest is obtained only from that exact
root package's embedded APP-001A application-binary lineage. For an application or declaration
child, changing any package, platform, binary, application, or parent coordinate changes the
binding. For an APK or IPA Surface, the selected Surface and root package are the same value.

This lineage is an identity constraint, not a package read or a Graph edge. It does not prove that
the referenced bytes exist, match the supplied digest, have APK or IPA format, contain the child
declaration, or are installable.

## Authorized custody reference boundary

`MobilePackageCustodyBinding` is an explicitly supplied, content-addressed configuration value.
It binds:

- the complete exact selected Surface and root package Surface;
- the root package's caller-supplied lowercase artifact SHA-256;
- one bounded deployment custody-authority identifier and opaque object identifier;
- one opaque authorization identifier and lowercase SHA-256 authorization-document digest; and
- the declared artifact-byte count, bounded from 1 through 536,870,912 bytes.

The opaque object identifier cannot be a filesystem path or URL. The binding contains no package
bytes, manifest, filename, mutable path, repository URL, token, password, credential reference,
signing material, device identity, or private key. Its authorization reference is deployment
input: preparation binds it but does not verify the issuer, signature, freshness, object
existence, content digest, byte count, package format, manifest, application ID, or signing
identity. Those checks remain mandatory at later authorized custody and result-admission
boundaries.

The serialized binding records authorization and custody verification, artifact resolution and
byte verification, artifact-read authority, mount materialization, and execution authority as
false. It does not replace the sealed Run `ArtifactRef`, whose media type and repository semantics
describe a different artifact class.

The public custody reference recomputes the originating binding digest from every variable claim
it carries, including both Surface references, all opaque custody and authorization coordinates,
the package digest, and the byte ceiling. A claim cannot be changed while retaining the same
binding identity. Recomputing a different digest creates a different unverified configuration; it
does not grant custody, approval, Permit, or execution authority.

## Configuration-only sandbox and archive boundary

`MobilePackageAnalysisSandboxBinding` is content-addressed configuration, not a selected or
attested runtime. It binds one deployment ID, the selected Surface and root package, the exact
operation and lineage-derived parser, exact parser-executable and sandbox-image SHA-256 digests,
an explicit non-root run-as identity, the fixed read-only no-exec
`/pajin/input/package` mount target, `bounded-json-stdout`, the fixed output schema, and package,
output, runtime, memory, and process ceilings.

Package archives additionally bind maximum entry count, total uncompressed bytes, single-entry
uncompressed bytes, archive-path bytes, nesting depth, and compression ratio. Path traversal,
symlinks, and duplicate archive names must be rejected. The configured values must stay within
the code-owned maxima and the single-entry ceiling cannot exceed the total-uncompressed ceiling.
These are future runtime requirements; MOBILE-001B neither opens an archive nor proves that any
limit was applied.

The configuration requires DNS and network disabled, a read-only root filesystem, a read-only
no-exec package mount, no-new-privileges, a non-root runtime, and exact executable/image digests.
Host-filesystem access, credential injection, ambient environment inheritance, symlink traversal,
emulator or device use, installation, launch, instrumentation, dynamic execution, storage read,
TLS invocation, and authentication invocation are forbidden.

The existing DOMAIN-004 minimum Mobile profile is device-bound and requires an emulator or device
identity. Applying it to this device-free static slice would fabricate runtime support. Therefore
the binding explicitly records `domainWorkerProfileBound=false`,
`domainWorkerProfileBindingDeferred=true`, and `deviceBoundRuntimeProfileApplied=false`.
Configuration-only sandbox requirements are not a substitute profile, and Worker-job
materialization remains unavailable until a separately reviewed static Mobile Worker profile and
deployment boundary exist.

The public sandbox reference likewise recomputes the originating binding digest from its selected
and root Surface references, operation/parser, deployment and non-root identity, executable/image
digests, output schema, and every package, runtime, process, and archive ceiling. Cross-platform
lineage, parser, image, deployment, or ceiling substitution therefore cannot retain the same
sandbox identity.

## Request and budget boundary

`BoundedMobilePackageAnalyzerAdapter.prepare_request` requires exact agreement among the selected
Surface, root package, custody, sandbox, operation, parser, artifact digest, and resource ceilings.
It creates one `MobilePackageAnalysisRequest` with both non-routable Scope targets, `GET`, the
fixed output schema, and complete secret-free references.

The request budget binds one request, the declared package bytes, and the sandbox's output,
runtime, memory, and process ceilings. Network and DNS requests, package installations,
application launches, emulator and device sessions, instrumentation sessions, dynamic target
executions, debugger attaches, storage reads, TLS connections, authentication invocations,
package writes, host-filesystem reads, and credential reads are all fixed to zero. The budget is
attenuation-only and unreserved.

No raw package or manifest content, mutable path, routable package URL, signing or credential
material, device identity, package resolution/read/mount, sandbox invocation, Worker job,
network access, or device/runtime authority can be embedded in the request. Unknown fields and
boolean or integer coercion fail closed.

## Campaign Scope and preparation

Preparation requires exact non-routable tokens under
`https://mobile-scope.pajin.invalid/surfaces/<surface-id>` for both the selected Surface and its
root package in the current Campaign allow rules. A child Surface therefore cannot inherit Scope
merely from its package, and package Scope cannot be inferred from child Scope. For a root APK or
IPA request the two exact identities coincide. Wildcard coverage is insufficient, any matching
deny rule rejects preparation, and `GET` must be present in Rules of Engagement. The Campaign
private-network flag is preserved but cannot enable DNS or network access.

`prepare_mobile_package_analysis` revalidates the current signed activation, registered binding,
current Campaign projection, both exact Scope rules, selected/root lineage, custody identity,
operation and parser selection, sandbox configuration, and request ceilings. It creates a
content-addressed `MobilePackageAnalysisPreparation` whose normalized parameters contain only the
secret-free request description and whose state is `prepared-not-authorized`.

The preparation stops at `PreparedCapabilityAction`. It records custody and authorization
verification, package resolution/byte/format/manifest/signing verification and read, sandbox
availability/attestation/selection, mount materialization, budget reservation, Domain Worker
profile binding, Worker-job materialization, network or DNS activity, emulator/device selection,
installation, launch, instrumentation, dynamic execution, storage read, TLS or authentication
invocation, credential read, package mutation, Observation production, Evidence sealing, Graph
admission, Hypothesis or Finding production, approval satisfaction, Permit issuance, Gateway
dispatch, Worker selection, and execution as false.

Actual analysis still requires current Policy and Approval, one-use ActionPermit, Gateway policy
re-entry, deployment-owned authorization verification, immutable byte resolution and digest
verification, exact image/executable admission, a reviewed static Mobile Worker profile, live
non-root sandbox attestation, safe read-only archive handling, bounded output custody, and a sealed
result-admission contract. None is supplied by MOBILE-001B.

## Fail-closed behavior

Definitions, references, activation, Mobile classification, static binding, custody, sandbox,
Campaign projection, request, and preparation are exact or content-addressed values. Resolution
and preparation reject selected/root Surface substitution, APK/IPA ancestry or artifact-digest
drift, operation or parser substitution, image or executable substitution, privileged run-as
identities, package or archive ceiling overflow and integer coercion, inconsistent archive
ceilings, missing exact selected or package Scope, matching deny rules, absent GET, stale release,
target or method drift, path/URL/secret/device/runtime-admission field injection, authority-marker
escalation, unknown instance state, and boolean coercion.

## Observation, Replay, and benchmark boundary

A prepared request proves neither that package custody exists nor that analysis occurred.
MOBILE-001C must separately verify one sealed, authorized, exact-package sandbox result before
admitting neutral package, application, runtime, storage, deep-link, TLS, or authentication
Observation and Evidence or a bounded Hypothesis. MOBILE-001D owns deterministic re-analysis,
seeded package Ground Truth, disposable sandbox fixtures, metrics, and validation floors.
MOBILE-001B creates none of them.

Emulator or physical-device analysis, installation, launch, instrumentation, storage access,
network access, TLS connections, authentication invocation, and credential use remain outside
MOBILE-001B. Any later feature requiring them needs separate exact Capability, Scope, profile,
deployment, cleanup, and fresh authority contracts.

## Compatibility and rollback

The implementation is additive. Existing MOBILE-001A, APP-001A, sealed Run Artifact repositories,
discovery, Scope, Capability, Tool, DOMAIN-003/004, Worker, Graph, and runtime schemas remain
unchanged. No package reader, archive parser, manifest parser, sandbox deployment, emulator,
device bridge, credential store, network route, or data migration is added. Rollback removes the
additive module, tests, contract, ADR, and consumers; existing typed Mobile Surfaces retain their
original validity.

## Verification

`tests/test_mobile_package_analysis.py` covers all seven CAP-002 roles, current signed release
activation, complete eight-Surface binding without a Domain Worker profile, all eight operation
mappings, APK/IPA lineage-derived parser selection, selected/root custody and Scope binding,
opaque authorization, configuration-only non-root network-disabled sandbox requirements, archive
bomb ceilings and rejection markers, zero live-device/network/mutation budgets, preparation's
non-authority markers, runtime fail-closed behavior, inconclusive Oracle, package/platform/parser/
operation/sandbox substitution, stale release, target/method/digest drift, path/URL/secret/device/
runtime-admission injection, authority escalation, forged model-instance rejection, and boolean/
integer coercion.
