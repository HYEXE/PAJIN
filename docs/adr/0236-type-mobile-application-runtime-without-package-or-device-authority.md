# ADR-0236: Type Mobile Application and Runtime Knowledge without Package or Device Authority

## Status

Accepted

## Context

DOMAIN-002 reserves `mobile.application-runtime` and
`pajin.locator.mobile.application-runtime.v1` as Mobile semantic identifiers, but it does not
implement their locator schema. APP-001A now provides exact content coordinates for application
binaries, while PAJIN's Artifact, sandbox, Worker, and evidence contracts govern later custody and
execution boundaries. None is by itself a Mobile identity model.

MOBILE-001A must represent APK and IPA packages, application identities, declared runtimes,
logical storage, deep-link declarations, TLS policies, and authentication flows before any package
has been resolved or parsed and before a package-analysis Capability has been authorized. Local or
archive paths, raw manifests, signing data, storage values, full deep-link URLs, TLS key material,
authentication secrets, emulator/device identity, and runtime process state are private, mutable,
operational, or evidence-owned data. Treating them as Surface identity would import package access,
network, credential, device, or execution semantics into the representation layer.

Nested Pydantic model instances also require an explicit trust boundary. A model created through
unchecked instance-copy updates can otherwise reach a parent or typed wrapper without repeating
field validation. Content-addressing a value after such a bypass would make malformed identity
deterministic rather than trustworthy.

## Decision

Add a content-addressed Mobile application/runtime locator registry with eight code-owned classes:

- `mobile-apk-package`: one exact APP-001A binary parent declared as an Android package;
- `mobile-ipa-package`: one exact APP-001A binary parent declared as an iOS package;
- `mobile-application`: one platform-valid canonical application ID below an exact package;
- `mobile-runtime`: one exact application parent, platform family, bounded declaration kind, and
  exact numeric or dotted runtime version;
- `mobile-storage`: one exact application parent, bounded logical storage kind and ID, and
  sanitized declaration digest;
- `mobile-deeplink`: one exact application parent, bounded link kind, canonical scheme, optional
  strict IDNA2008/UTS #46 host and optional exact port that requires a host, stable route ID, and
  sanitized declaration digest;
- `mobile-tls-policy`: one exact application parent, bounded policy kind and ID, and sanitized
  declaration digest; and
- `mobile-authentication`: one exact application parent, bounded flow kind and ID, and sanitized
  declaration digest.

Embed complete parents as discriminated locators. APK and IPA reuse the exact APP-001A binary
coordinate instead of duplicating a bare digest, but this nested identity creates no Graph edge or
authority transfer. Application children embed the complete application, so package, platform,
binary, and application substitution all change content identity.

Reject non-canonical application IDs, floating or ranged runtime versions, mutable aliases, path,
full URL, user information, query, fragment, wildcard, percent-encoding, surrounding whitespace,
control characters, raw values, and unknown fields. Android App Link, iOS Universal Link, Android
network-security configuration, and iOS App Transport Security declarations must match the parent
package platform. Store a route ID and declaration digest rather than a raw deep-link path or
template. Store no certificate, key, pin, endpoint, redirect URI, token, secret, credential
reference, signing data, device identity, or runtime state.

At every public parent/child builder and typed-Surface boundary, serialize nested model instances
to alias JSON and validate them again through the exact model or discriminated union. Reject forged
or malformed preconstructed instances before calculating content identity.

Add an inert `MobileApplicationRuntimeSurface` that binds one locator to the exact Mobile Domain,
DOMAIN-002 type-set, and complete registry and starts as `registered-not-authorized`. Do not add
Mobile locators to the established evidence-bound discovery `SurfaceLocator` union. Do not change
`SurfaceObservation`, `AttackSurface`, Artifact, Scope, Graph, Capability, Worker, or runtime wires.

The registry and typed Surface explicitly deny package resolution or read, static or dynamic
analysis, sandbox/emulator/device/Tool/Worker selection, device access, instrumentation, storage
read, TLS validation, authentication invocation, network or credential access, Scope expansion,
Capability activation, approval satisfaction, Permit issuance, Graph admission, package mutation,
Finding authority, runtime-support assertion, and execution authority.

## Consequences

- MOBILE-001B can bind one exact package/application/declaration identity to a separately reviewed
  read-only package-analysis Capability without deriving authority from Mobile metadata.
- An APK or IPA locator is a caller declaration below an exact binary coordinate. It proves neither
  custody nor package format, manifest content, application identity, signing identity, or
  installability.
- A runtime locator is a package declaration, not a running Android/iOS environment or supported
  emulator/device claim.
- Storage, deep-link, TLS, and authentication locators retain stable declaration coordinates but
  no raw path, stored value, route path, endpoint, key, pin, secret, or credential material.
- Emulator or physical-device analysis remains a separate future authority boundary with exact
  deployment-owned device identity, access, instrumentation, cleanup, and fresh Permit evidence.
- Revalidation makes public constructors fail closed for malformed nested instances even when the
  instance originated outside ordinary Pydantic parsing.

## Rejected alternatives

### Repeat a bare package digest independently of APP-001A

Rejected because it would create two visually identical string coordinates without an explicit
typed lineage. Reusing the exact APP-001A binary parent preserves one content-coordinate model
without asserting a cross-domain Graph relationship or analysis authority.

### Use a local APK/IPA path or archive entry as identity

Rejected because paths are mutable deployment aliases, may disclose operator data, and do not
bind content. A later authorized Artifact resolver may bind custody and bytes to the typed Surface.

### Include manifest, signing certificate, provisioning profile, or team identity

Rejected because MOBILE-001A has not parsed or verified the package and signing identity remains an
unresolved product decision and later sealed-Evidence concern. Raw signing material is never a
locator field.

### Store a complete deep-link URL or route template

Rejected because user information, paths, queries, fragments, encodings, and wildcard templates
can carry private values or accidentally resemble network Scope. Version 1 stores structured
canonical scheme plus an optional host and host-dependent port, a stable route ID, and a sanitized
declaration digest.

### Put certificate pins, OAuth endpoints, or credential references in TLS/auth locators

Rejected because values and references can be sensitive and could be misread as connection or
credential-use authority. Later analysis may retain raw input externally and seal digest-bound
Evidence under a separately reviewed contract.

### Treat emulator or device identity as a package Surface

Rejected because device identity and access are deployment-owned Worker constraints for authorized
runtime analysis. MOBILE-001A is static typed knowledge and makes no device selection or access
claim.

### Trust already constructed Pydantic instances

Rejected because unchecked instance copying can bypass normal field validation. Public Mobile
boundaries must establish their own canonical validation before deriving identity.

## Compatibility and rollback

MOBILE-001A is additive and requires no migration. Existing discovery locators, `AttackSurface`,
DOMAIN-002 semantics, APP-001A identities, Artifact readers, canonical digests, Scope, Graph,
Capability, Worker, and runtime behavior remain unchanged. Rollback removes the new module,
exports, tests, contract, ADR, and consumers. New locator classes, parent relations, platform
grammars, declaration fields, or digest algorithms require an explicit versioned change rather
than silent registry expansion.

## Related documents

- [MOBILE-001A contract](../discovery/MOBILE-001A-apk-ipa-app-runtime-storage-deeplink-tls-auth-surface-model.md)
- [APP-001A contract](../discovery/APP-001A-binary-configuration-runtime-library-surface-model.md)
- [DOMAIN-002](../graph/DOMAIN-002-common-multi-domain-graph-semantics.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0002](0002-tool-gateway-and-worker-isolation.md)
- [ADR-0204](0204-separate-security-domain-from-profile-and-authority.md)
- [ADR-0205](0205-admit-cross-domain-knowledge-without-scope-expansion.md)
