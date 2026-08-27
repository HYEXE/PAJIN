# APP-001A: Binary, Configuration, Runtime, and Library Surface Model

- Status: Implemented, typed registry only
- API versions:
  - `pajin.dev/application-artifact-runtime-locator/v1alpha1`
  - `pajin.dev/application-artifact-runtime-locator-registry/v1alpha1`
  - `pajin.dev/application-artifact-runtime-surface/v1alpha1`
- Authority: `src/pajin/discovery/application_surfaces.py`
- Decision: [ADR-0232](../adr/0232-type-application-artifact-runtime-without-analysis-authority.md)

## Purpose

APP-001A implements the locator schema reserved by DOMAIN-002 for
`application.artifact-runtime`. It binds the exact DOMAIN-001 Application classification and
DOMAIN-002 Application type-set to secret-free binary, configuration, declared-runtime, and
library locators. It also provides a content-addressed typed Surface whose initial state is
`registered-not-authorized`.

This contract represents locally supplied identity knowledge only. It does not resolve an
Artifact reference, open a file, read or hash bytes, detect a binary format, parse configuration,
inspect or launch a process, attest an installed runtime, resolve dependencies, access a package
repository, use credentials, select a sandbox or Worker, access a network, attach a debugger,
admit Graph knowledge, or authorize analysis or execution.

## Locator classes and lineage

| Class | Locator kind | Exact fields | Required parent | Meaning |
| --- | --- | --- | --- | --- |
| `binary` | `application-binary` | lowercase SHA-256 artifact digest | none | One caller-supplied content coordinate; bytes, custody, format, provenance, and executability remain unverified |
| `configuration` | `application-configuration` | normalized namespace and identifier, lowercase SHA-256 artifact digest | exact binary | One content-bound configuration artifact coordinate with no path or raw value |
| `runtime` | `application-runtime` | normalized family, exact normalized version, lowercase SHA-256 artifact digest | exact binary | One declared runtime artifact coordinate, not a live process or environment attestation |
| `library` | `application-library` | normalized namespace, identifier, exact version, lowercase SHA-256 artifact digest | exact binary or runtime | One exact library artifact coordinate without repository or dependency-resolution claims |

The registry contains exactly these four mappings in code-owned order. Every non-binary locator
embeds its complete parent as a discriminated locator. Parent identity therefore contributes to
the typed Surface digest. The same configuration, runtime, or library coordinate beneath another
binary, or the same library beneath another runtime artifact, cannot retain the same Surface
identity.

Every class requires an artifact SHA-256 value, but APP-001A does not compute it. The caller must
supply the coordinate. Until a later trusted producer binds that digest to bytes and custody
Evidence, `artifactResolved` and `artifactBytesVerified` remain false.

## Canonical, immutable, and private identity

Configuration namespaces and IDs, runtime families, and library namespaces and IDs are
case-folded. They admit only bounded coordinate characters and reject mutable aliases such as
`latest`, `current`, `stable`, `default`, `auto`, `local`, `unknown`, and `x`. Paths, URLs, queries,
fragments, wildcards, surrounding whitespace, and control characters fail closed.

Runtime and library versions require a numeric dotted base and may include a normalized exact
pre-release or build suffix. Floating aliases, wildcard segments, comparison ranges, caret or
tilde ranges, unqualified major versions, and a `v` prefix are not v1 identity. This restriction
does not assert semantic-version compatibility; it only creates a deterministic exact coordinate.
The mandatory artifact digest remains the content identity when ecosystem version syntax is
ambiguous.

Every locator includes literal-false `rawArtifactContentEmbedded`, `mutablePathEmbedded`,
`runtimeProcessStateEmbedded`, `secretMaterialEmbedded`, and
`credentialReferenceEmbedded` markers and forbids extra fields. There is no path, filename,
repository URL, raw configuration value, PID, command line, environment, running state, package
range, password, token, Secret reference, credential lease, sandbox, debugger, or Worker field.

## Typed Surface identity

`ApplicationArtifactRuntimeSurface` binds:

- the exact Application classification reference;
- the exact `application.artifact-runtime` DOMAIN-002 type-set reference;
- the complete locator-registry reference;
- one discriminated binary, configuration, runtime, or library locator;
- the code-owned class for that locator; and
- a content-addressed Surface ID and digest.

The value is pre-Observation knowledge and is not the established evidence-bound `AttackSurface`.
It contains no Campaign, Scope authority, Capability, approval, Permit, artifact request, sandbox,
Worker, credential, Observation, Evidence, Graph-admission, Finding, or execution field. The
existing discovery `SurfaceLocator` union and `AttackSurface` wire remain unchanged.

## Threat model and fail-closed behavior

The primary threats are deriving artifact access or analysis authority from metadata, treating a
path or process as immutable identity, resolving a floating package alias with ambient network or
credentials, substituting another binary or runtime below an otherwise identical child, claiming
format/runtime/dependency truth from a supplied digest, and smuggling raw content, secrets, or
execution instructions through extra fields.

Definitions, references, the complete registry, and typed Surfaces are content-addressed. Exact
resolution rejects locator class or model substitution, registry reordering, Domain relabeling,
parent substitution, malformed or uppercase digests, mutable or active coordinates, non-exact
versions, digest drift, extra secret or authority metadata, true authority markers, and
non-boolean marker coercion.

## Trust boundary and non-authority guarantees

APP-001A adds only in-process typed values and exact registry resolution. It creates no Artifact
resolver, file reader, hasher, parser, disassembler, package client, process, sandbox, Worker,
network request, debugger session, durable store, publisher, audit event, Graph writer, or
execution boundary. In particular, all of these remain false:

- discovery, artifact resolution, byte verification, binary-format verification, configuration
  semantics, runtime-environment verification, library-dependency verification, vulnerability
  confirmation, sealed Evidence, and Graph admission;
- artifact read, static or dynamic analysis, credential access, network access, debugger attach,
  artifact mutation, Finding authority, runtime-support assertion, and execution;
- Scope expansion, Capability activation, approval satisfaction, Permit issuance, and sandbox or
  Worker selection.

[APP-001B](../capability/APP-001B-read-only-static-analysis-capability.md) separately binds an exact
typed Surface to a reviewed read-only static-analysis Capability, an authorized Artifact custody
reference, and a network-disabled sandbox requirement without reading or executing the artifact.
Dynamic execution, debugger attach, and network access remain separate future authority after
that preparation.

## Audit and benchmark impact

Registry and Surface references are deterministic content-addressed values suitable for later
audit binding, but APP-001A emits no audit Artifact or Event. It registers no deterministic
re-analysis, seeded binary/configuration Ground Truth, parser/analyzer result, metric,
validation-floor evidence, benchmark Result, or Finding. APP-001D owns those later contracts.

## Compatibility, migration, and rollback

The implementation is additive. Existing discovery locators, `SurfaceLocator`,
`SurfaceObservation`, `AttackSurface`, DOMAIN-002 semantics, Artifact readers, Scope, Capability,
Worker, Graph, and runtime behavior remain unchanged. There is no data migration.

Rollback removes the additive module, public exports, contract, ADR, and consumers. New locator
classes, parent relations, ecosystem coordinate syntax, identity fields, or digest algorithms
require a versioned registry/schema change rather than silent membership expansion.

## Verification

`tests/test_application_artifact_runtime_surfaces.py` covers exact Domain/type-set/class
membership, content-addressed resolution, complete binary/runtime parent lineage, all four typed
Surface classes, digest-only binary identity, declared runtime identity without process state,
configuration identity without raw values, exact library identity without repository resolution,
legacy discovery-wire compatibility, mutable aliases and range rejection, secret and credential
injection, class/order/Domain substitution, digest drift, authority escalation, and boolean
coercion.
