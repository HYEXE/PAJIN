# MOBILE-001A: APK, IPA, Application, Runtime, Storage, Deep-link, TLS, and Authentication Surface Model

- Status: Implemented, typed registry only
- API versions:
  - `pajin.dev/mobile-application-runtime-locator/v1alpha1`
  - `pajin.dev/mobile-application-runtime-locator-registry/v1alpha1`
  - `pajin.dev/mobile-application-runtime-surface/v1alpha1`
- Authority: `src/pajin/discovery/mobile_surfaces.py`
- Decision: [ADR-0236](../adr/0236-type-mobile-application-runtime-without-package-or-device-authority.md)

## Purpose

MOBILE-001A implements the locator schema reserved by DOMAIN-002 for
`mobile.application-runtime`. It binds the exact DOMAIN-001 Mobile classification and DOMAIN-002
Mobile type-set to eight code-owned, secret-free locator classes. It also provides a
content-addressed typed Surface whose initial state is `registered-not-authorized`.

This contract represents caller-supplied identity and sanitized declaration coordinates only. It
does not resolve or read a package, verify a digest against bytes, verify APK or IPA format, parse
a manifest, verify an application or signing identity, analyze a package, select or start a
sandbox or emulator, identify or access a device, install an application, instrument a process,
read storage, route a deep link, make a TLS connection, invoke authentication, use credentials,
access a network, admit Graph knowledge, or authorize execution.

## Locator classes and lineage

| Class | Locator kind | Exact fields | Required parent | Meaning |
| --- | --- | --- | --- | --- |
| `apk` | `mobile-apk-package` | exact APP-001A binary coordinate | Application binary | One caller-declared Android package coordinate; APK format remains unverified |
| `ipa` | `mobile-ipa-package` | exact APP-001A binary coordinate | Application binary | One caller-declared iOS package coordinate; IPA format remains unverified |
| `application` | `mobile-application` | platform-valid exact application ID | APK or IPA | One declared application identity below exact package content; manifest and signing identity remain unverified |
| `runtime` | `mobile-runtime` | platform family, minimum/target declaration kind, exact numeric or dotted version | application | One declared runtime requirement, not a live device runtime |
| `storage` | `mobile-storage` | bounded storage kind, stable logical ID, sanitized declaration SHA-256 | application | One logical store with no device path or stored value |
| `deeplink` | `mobile-deeplink` | bounded link kind, canonical scheme, optional canonical host and port, stable route ID, sanitized declaration SHA-256 | application | One link declaration without a full URI, path, query, fragment, or user information |
| `tls` | `mobile-tls-policy` | bounded policy kind, stable policy ID, sanitized declaration SHA-256 | application | One TLS-policy declaration without endpoint, certificate, key, or pin values |
| `auth` | `mobile-authentication` | bounded authentication kind, stable flow ID, sanitized declaration SHA-256 | application | One authentication-flow declaration without endpoint, secret, token, or credential reference |

APK and IPA locators embed the complete APP-001A `ApplicationBinarySurfaceLocator` rather than
repeating a bare digest. This establishes explicit content-coordinate lineage while granting no
cross-domain Graph relation or authority. Application locators embed the complete package, and
runtime, storage, deep-link, TLS, and authentication locators embed the complete application.
Changing the binary digest, package class, application ID, or any child declaration therefore
changes typed Surface identity.

## Canonical and private coordinates

Package content identity is one lowercase SHA-256 inherited from APP-001A. Android application IDs
use at least two ASCII dot-separated segments that begin with a letter and otherwise contain
alphanumeric characters or underscores. Allowed uppercase characters are preserved because the
declared application ID remains the exact caller coordinate. iOS application IDs use at least two
ASCII dot-separated alphanumeric or hyphenated segments and are case-folded to lowercase because
the platform treats bundle IDs as case-insensitive.

Runtime versions accept one exact numeric Android API level such as `34` or an exact numeric iOS
version such as `17.5`. Components use canonical decimal spelling with no leading zeroes except the
single value `0`. Alphabetic components or suffixes, floating names, wildcards, ranges, comparison
operators, caret or tilde ranges, and `v` prefixes fail closed.

Storage, route, TLS-policy, and authentication-flow IDs are bounded stable logical coordinates.
They are case-folded and reject paths, URLs, authorities, queries, fragments, wildcards, percent
encoding, mutable aliases, surrounding whitespace, and control characters. Storage declarations
contain no absolute, archive-local, application-sandbox, or device-local path and no raw value.

Deep links do not accept a full URI. The scheme is canonical and the host is optional. When
present, the host uses strict IDNA2008 with non-transitional UTS #46 ASCII normalization and an
A-label round trip, without resolution. An optional exact integer port from 1 to 65535 requires a
host. Android App Links and iOS Universal Links require `http` or `https` plus a host and must match
their package platform. Custom schemes cannot use `http` or `https`. Version 1 stores a stable
route ID and sanitized declaration digest rather than a raw path or path pattern. A later
package-analysis Observation may interpret the externally retained declaration under its own
Evidence contract.

Android network-security configuration and iOS App Transport Security policy kinds are restricted
to their respective package platforms. Certificate-pinning and custom policy kinds remain neutral
declaration categories. No locator stores a raw certificate, public-key pin, private key, signing
material, endpoint, request, redirect URI, secret, password, token, cookie, session, or credential
reference.

Every locator carries literal-false `packageBytesEmbedded`, `manifestEmbedded`,
`signingMaterialEmbedded`, `rawSecurityConfigurationEmbedded`, `secretMaterialEmbedded`,
`credentialReferenceEmbedded`, `deviceStateEmbedded`, and `deviceLocalPathEmbedded` markers and
forbids extra fields.

## Typed Surface identity

`MobileApplicationRuntimeSurface` binds:

- the exact Mobile classification reference;
- the exact `mobile.application-runtime` DOMAIN-002 type-set reference;
- the complete locator-registry reference;
- one revalidated discriminated Mobile locator;
- the code-owned class for that locator; and
- a content-addressed Surface ID and digest.

Public builders, typed-Surface and `reference()` boundaries dump nested Pydantic model instances to
alias JSON and validate them again. References independently bind ID to digest, locator kind to
class, and the exact registry identity. This prevents `model_copy(update=...)` or another
preconstructed model instance from bypassing child, parent, digest, platform, registry, reference,
or canonical-coordinate validation.

The typed value is pre-Observation knowledge and is not the established evidence-bound
`AttackSurface`. MOBILE-001A does not extend the existing discovery `SurfaceLocator` union,
`SurfaceObservation`, or `AttackSurface` wire.

## Threat model and fail-closed behavior

The primary threats are treating a package path or mutable application alias as content identity,
claiming APK/IPA format or manifest/signing truth from a supplied coordinate, confusing a declared
runtime with a live emulator or device, smuggling package bytes or raw security configuration into
a locator, storing device-local paths or storage values, converting a deep link into implicit
network Scope, converting TLS/auth metadata into credential-use authority, substituting APK and
IPA ancestry beneath an otherwise identical child, and bypassing nested validation with a forged
model instance.

Definitions, references, the complete registry, and typed Surfaces are content-addressed. Exact
resolution rejects locator class, order, source model, Domain, graph type-set, parent, platform,
digest, or Surface identity substitution. Models reject malformed or uppercase digests, invalid
application IDs, floating runtime versions, platform-inconsistent runtime/link/TLS declarations,
full URI or path syntax, sensitive extra fields, true authority markers, and boolean coercion.

## Trust boundary and non-authority guarantees

MOBILE-001A adds in-process typed values and exact registry resolution only. It creates no package
resolver, file reader, parser, mobile analysis Tool, sandbox, Worker, emulator, device session,
bridge, installer, debugger, instrumentation channel, storage reader, network request, TLS client,
authentication client, credential lease, durable store, publisher, audit event, Graph writer, or
execution boundary. In particular, all of these remain false:

- package resolution, byte and format verification, manifest/application/signing identity
  verification, runtime/storage/deep-link/TLS/auth declaration verification, app installation,
  device or emulator identity verification, vulnerability confirmation, Evidence sealing, and
  Graph admission;
- artifact resolution, package read, static or dynamic analysis, sandbox/emulator/device/Tool/
  Worker selection, device access, instrumentation, storage read, TLS validation, authentication
  invocation, network or credential access, package mutation, Finding authority, runtime-support
  assertion, and execution;
- Scope expansion, Capability activation, approval satisfaction, and Permit issuance.

MOBILE-001B may separately bind an exact typed Surface to a reviewed read-only package-analysis
Capability and a network-disabled static-analysis Worker boundary. Emulator or physical-device
instrumentation remains a later slice that requires exact deployment-owned emulator or device
identity and fresh authority.

## Audit and benchmark impact

Registry and Surface references are deterministic content-addressed values suitable for later
audit binding, but MOBILE-001A emits no audit Artifact or Event. It registers no package analysis,
Observation, Evidence, deterministic re-analysis, seeded application Ground Truth, device cleanup,
metric, validation-floor evidence, benchmark Result, Hypothesis, or Finding. MOBILE-001D owns those
later re-analysis and benchmark contracts.

## Compatibility, migration, and rollback

The implementation is additive. Existing discovery locators, `SurfaceLocator`,
`SurfaceObservation`, `AttackSurface`, DOMAIN-002 semantics, APP-001A identities, Artifact readers,
Scope, Capability, Worker, Graph, and runtime behavior remain unchanged. There is no data
migration.

Rollback removes the additive module, public exports, contract, ADR, tests, and consumers. New
locator classes, parent relationships, application-ID grammar, declaration kinds, raw route
syntax, identity fields, or digest algorithms require a versioned registry/schema change rather
than silent membership expansion.

## Verification

`tests/test_mobile_application_runtime_surfaces.py` covers exact Mobile Domain/type-set binding,
eight-class code-owned membership and ordering, content-addressed resolution, complete
Application-binary/package/application lineage, APK/IPA and platform substitution, canonical
application IDs, Android and iOS runtime versions, storage identity without paths or values,
non-transitional IDNA deep-link canonicalization without full URI content, platform-specific link
and TLS policy kinds, TLS/auth sensitive-field rejection, all eight typed Surfaces, legacy
discovery-wire compatibility, registry/Domain/model/digest drift, authority escalation, boolean
coercion, forged reference rejection, and revalidation of forged Pydantic child and parent
instances.
