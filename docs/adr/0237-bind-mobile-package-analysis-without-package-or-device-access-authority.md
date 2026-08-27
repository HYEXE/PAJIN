# ADR-0237: Bind Mobile Package Analysis without Package- or Device-access Authority

## Status

Accepted

## Context

MOBILE-001A supplies exact, secret-free APK, IPA, application, runtime, storage, deep-link, TLS,
and authentication Surface identity. Its package SHA-256 is a caller-supplied coordinate inherited
from APP-001A: it intentionally proves no custody, bytes, APK/IPA format, manifest, application or
signing identity, parser compatibility, Scope, analysis, emulator, device, or execution authority.

PAJIN has a complete CAP-002 lifecycle and a DOMAIN-004 Mobile minimum profile. That profile is
device-bound and requires exact application, artifact, and emulator-or-device identity. It is
appropriate as a minimum for future device-backed Mobile execution, but not for a device-free
static package-analysis preparation. Binding it here would falsely assert that an emulator or
device identity and runtime are part of this slice. The DOMAIN-004 Application profile is also not
usable because binding a Mobile Capability to another Domain's profile would violate exact Domain
classification.

The repository has sealed Run artifact repositories, but their `ArtifactRef` identifies immutable
Run directories with a dedicated media type rather than arbitrary APK or IPA custody. It also has
no admitted generic package resolver, archive parser, manifest parser, Mobile static sandbox
deployment, bounded result custody, or sealed Mobile result contract.

MOBILE-001B must make the next authority connection without fabricating any of those facilities.
It must bind each child to its exact root package, prevent APK/IPA parser confusion, address hostile
archive structure before future byte access, and keep device, emulator, network, credential,
storage, TLS, authentication, installation, launch, and instrumentation authority outside this
slice.

## Decision

Add the experimental T2 read-only Capability
`pajin.mobile.read-only-package-analysis@1.0.0` and Tool identity
`mobile.read-only-package-analysis@1.0.0`. Register all seven CAP-002 authority roles and require
an externally signed current Range release. Bind the complete code-backed Capability, complete
eight-member MOBILE-001A locator registry, a local Mobile classification, and the fixed
`pajin.mobile.package-analysis-result.v1` output schema. Do not change the global DOMAIN-003 or
DOMAIN-004 inventories.

Define one structure-only operation for each exact Surface class: APK package structure, IPA
package structure, application declaration, runtime declaration, storage declaration, deep-link
declaration, TLS-policy declaration, and authentication-flow declaration. Derive the logical
parser only from the exact root package lineage: APK descendants use the Android APK structure
parser contract and IPA descendants use the iOS IPA structure parser contract. Treat both parser
names as request identity, not proof that an executable, compatible format, or successful parse
exists.

Require every custody, sandbox, request, and preparation value to bind both the exact selected
Surface and its reconstructed root APK or IPA Surface. Derive the artifact digest only through the
complete root package's embedded APP-001A binary lineage. Require exact current Campaign allow
rules for both non-routable Surface tokens and reject wildcard-only coverage, a matching deny
rule, or absence of GET.

Require a content-addressed custody configuration that binds the selected/root lineage, package
digest, bounded custody-authority ID, opaque object ID, opaque authorization ID,
authorization-document digest, and declared byte count. Allow no path, URL, raw package or
manifest bytes, signing material, secret, credential, or device identity. Treat the authorization
reference as deployment input; preparation does not verify its issuer, signature, freshness,
object existence, bytes, digest, package format, manifest, application ID, or signing identity.

Require a content-addressed, configuration-only sandbox boundary that binds one exact
operation/parser, parser-executable digest, sandbox-image digest, explicit non-root run-as
identity, fixed read-only no-exec package mount, fixed bounded JSON output contract, and package,
output, runtime, memory, and process ceilings. Also bind archive entry count, total and
single-entry uncompressed sizes, path length, nesting depth, and compression-ratio ceilings, with
path traversal, symlinks, and duplicate names rejected. Require DNS and network disabled,
read-only root filesystem, no new privileges, no host filesystem, no credentials, no ambient
environment inheritance, and no symlink traversal. Treat every setting as a requirement for a
future runtime, not live attestation.

Do not bind the existing device-bound Mobile DOMAIN-004 profile and do not substitute another
Domain's profile. Record `domainWorkerProfileBound=false`,
`domainWorkerProfileBindingDeferred=true`, and `deviceBoundRuntimeProfileApplied=false` in the
binding boundary. Keep Worker-job materialization unavailable until a separately reviewed static
Mobile profile and deployment binding can satisfy exact Domain and runtime requirements.

Bind an attenuation-only budget with one preparation request and exact package/output/runtime/
memory/process ceilings. Fix DNS/network requests, installation, launch, emulator/device,
instrumentation, dynamic execution, debugger, storage, TLS, authentication, package write,
host-filesystem read, and credential channels to zero.

Allow preparation to create a secret-free request and `PreparedCapabilityAction`, but do not
resolve, verify, read, mount, unpack, or parse package bytes; select or attest a sandbox; reserve a
budget; bind or select a Worker profile; materialize a Worker job; select a device or emulator;
install, launch, instrument, or dynamically execute an application; access storage, DNS, network,
TLS, authentication, or credentials; normalize a result; mutate a package; or grant approval,
Permit, Gateway, Worker, Observation, Evidence, Graph, Hypothesis, Finding, Scope-expansion, or
execution authority. The executor and result-normalizer roles fail closed and the Oracle remains
inconclusive.

## Consequences

- Selected Surface identity, root package identity, custody configuration, authorization
  verification, static sandbox requirements, future Worker-profile conformance, byte access, and
  result admission remain separate reviewable boundaries.
- Exact selected and root Scope prevents a child declaration from inheriting package authority or
  a package from inheriting child authority.
- APK/IPA lineage-derived parser selection prevents caller-selected cross-platform parser
  confusion while making no format or compatibility claim.
- Archive ceilings are bound before any future byte access, but configuration does not claim that
  an archive was opened or that hostile input was safely handled.
- Deferring profile binding accurately preserves the device-free static boundary instead of
  weakening or misrepresenting the existing DOMAIN-004 Mobile profile.
- MOBILE-001C can admit neutral Mobile knowledge only from a separately authorized, sealed,
  exact-package sandbox result.

## Rejected alternatives

### Bind the existing DOMAIN-004 Mobile profile

Rejected because that minimum profile is intentionally device-bound and requires an exact
emulator or device identity. MOBILE-001B provides neither identity nor device runtime and fixes all
device sessions to zero. Claiming the profile is bound would fabricate conformance.

### Reuse the DOMAIN-004 Application profile

Rejected because it belongs to another exact Security Domain. Similar offline-sandbox properties
do not authorize cross-Domain profile substitution. A future static Mobile profile must be
reviewed and registered under Mobile semantics.

### Reuse the sealed Run `ArtifactRef`

Rejected because that reference identifies an admitted Run-directory artifact with an existing
media type and repository contract. Rebranding it as arbitrary APK/IPA custody would create false
storage and reader semantics. MOBILE-001B uses a storage-neutral opaque custody configuration and
leaves byte resolution to a future deployment boundary.

### Accept a local package path or download URL

Rejected because paths and URLs are mutable, may disclose operator data, and silently import
host-filesystem, network, or credential authority. Only opaque identifiers and content digests are
accepted.

### Select a parser from the requested child class or a filename

Rejected because child class and filename do not establish package platform, and MOBILE-001B
reads no bytes. The complete root APK/IPA lineage owns parser selection and still requires later
runtime compatibility checks.

### Treat sandbox and archive settings as runtime attestation

Rejected because digests, run-as identity, mount flags, and resource maxima are configuration.
They do not prove the actual namespace, UID/SID, filesystem flags, archive-reader behavior,
network isolation, loaded executable, or applied resource controls.

### Implement a placeholder parser or successful Oracle

Rejected because the repository has no admitted package resolver, live static Mobile sandbox,
parser implementation, bounded output custody, or sealed result contract. Placeholder success
would be fictitious runtime support.

### Include device, dynamic, storage, TLS, authentication, or network analysis

Rejected because those actions have distinct side effects, identities, cleanup needs, and threat
boundaries. They require separate reviewed Capabilities, exact Scope, deployment bindings, and
fresh authority and cannot be inferred from static package metadata.

## Compatibility and rollback

MOBILE-001B is additive. Existing MOBILE-001A, APP-001A, sealed Run Artifact, Campaign Scope,
Capability, Tool, DOMAIN-003/004, Worker, Graph, and runtime wires retain their versions. No
package service, archive/parser process, sandbox deployment, emulator, device bridge, credential
store, network route, or data migration is introduced. Rollback removes the additive module,
tests, contract, ADR, and consumers; existing Mobile Surfaces remain valid under their original
contract.

## Related documents

- [MOBILE-001B contract](../capability/MOBILE-001B-read-only-package-analysis-capability.md)
- [MOBILE-001A contract](../discovery/MOBILE-001A-apk-ipa-app-runtime-storage-deeplink-tls-auth-surface-model.md)
- [APP-001A contract](../discovery/APP-001A-binary-configuration-runtime-library-surface-model.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0002](0002-tool-gateway-and-worker-isolation.md)
- [ADR-0204](0204-separate-security-domain-from-profile-and-authority.md)
- [ADR-0206](0206-bind-domain-workers-to-existing-authority-path.md)
- [ADR-0236](0236-type-mobile-application-runtime-without-package-or-device-authority.md)
