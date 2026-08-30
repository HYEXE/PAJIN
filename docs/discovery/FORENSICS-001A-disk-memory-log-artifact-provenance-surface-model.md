# FORENSICS-001A: Disk, Memory, Log, Artifact, and Provenance Surface Model

- Status: Implemented, typed registry only
- API versions:
  - `pajin.dev/forensics-source-provenance-coordinate/v1alpha1`
  - `pajin.dev/forensics-immutable-artifact-locator/v1alpha1`
  - `pajin.dev/forensics-immutable-artifact-locator-registry/v1alpha1`
  - `pajin.dev/forensics-immutable-artifact-surface/v1alpha1`
- Authority: `src/pajin/discovery/forensics_surfaces.py`
- Decision: [ADR-0244](../adr/0244-type-forensic-evidence-surfaces-without-source-access-or-evidence-mutation-authority.md)

## Purpose

FORENSICS-001A implements the locator schema reserved by DOMAIN-002 for
`forensics.immutable-artifact`. It binds the exact DOMAIN-001 Forensics classification and
DOMAIN-002 Forensics type-set to four code-owned, content-free locator classes. It provides a
content-addressed typed Surface whose initial state is `registered-not-authorized`.

This contract represents caller-supplied evidence class and provenance coordinates only. It does
not resolve a Run or artifact, verify a Run seal, authenticate or externally anchor a source root,
verify artifact membership, read or mount bytes, validate a digest or byte count, classify a
format, establish chain of custody, select or execute a parser, identify or use a credential,
mutate Evidence, create a Hypothesis, admit Graph knowledge, or authorize an operation.

## Locator classes

| Class | Locator kind | Exact payload | Meaning |
| --- | --- | --- | --- |
| `disk` | `forensics-disk` | complete source-provenance coordinate | Caller-declared disk evidence; geometry, partitioning, filesystem, format, and integrity remain unverified |
| `memory` | `forensics-memory` | complete source-provenance coordinate | Caller-declared memory evidence; OS, architecture, process, capture method, and format remain unverified |
| `log` | `forensics-log` | complete source-provenance coordinate | Caller-declared log evidence; source system, encoding, ordering, timeline, and format remain unverified |
| `artifact` | `forensics-artifact` | complete source-provenance coordinate | Opaque generic artifact; type, extension, MIME, parser compatibility, and content remain unverified |

The four classes are sibling roots. Version 1 does not encode that a log was extracted from a disk,
that an artifact came from memory, or that two retained copies share custody. Such relations are
claims that require later provenance-preserving Observation and Evidence. Changing only the class
changes typed Surface identity.

## Source provenance coordinate

Every locator embeds the complete `ForensicSourceProvenanceCoordinate`:

| Field | Constraint | Meaning |
| --- | --- | --- |
| `sourceRootKind` | code-owned `pajin.dev/run-integrity/v1` | Exact existing Run-integrity API vocabulary, not proof that a Run exists or is trusted |
| `sourceRootSha256` | lowercase 64-hex SHA-256 | Caller-supplied enclosing Run-integrity root coordinate |
| `sourceArtifactRecordSha256` | lowercase 64-hex SHA-256 | Caller-supplied digest of the external source artifact record |
| `provenanceRecordSha256` | lowercase 64-hex SHA-256 | Caller-supplied digest of the external provenance record |
| `artifactSha256` | lowercase 64-hex SHA-256 | Caller-supplied artifact content coordinate |
| `artifactBytes` | strict JSON integer, `0..2^63-1` | Caller-supplied byte-count coordinate; zero supports empty and corrupted-input fixtures |

All six dimensions participate in content identity. The same bytes under a different Run root,
artifact record, provenance record, byte-count declaration, or evidence class produce a different
Surface identity.

The v1 source-root enum is deliberately closed. `external`, `local-file`, and generic object-store
roots have no accepted trust or custody contract and cannot be smuggled into the coordinate. A new
source-root kind requires explicit review and a versioned registry/schema change.

The coordinate does not receive a path, URI, object key, filename, MIME, hostname, device serial,
case ID, operator, custodian, timestamp, parser, command, Tool, Worker, Capability, Scope, Permit,
raw artifact, raw provenance record, credential, Secret, or parser output. Unknown fields are
rejected.

SHA-256 is not redaction. A digest of a private or low-entropy acquisition record, credential,
token, password, key, operator name, or case identifier may remain guessable or correlatable.
Producers must not place such material in these coordinate preimages. FORENSICS-001A cannot inspect
a preimage and fixes provenance sanitization as unverified.

## Required versus verified state

Every registered locator fixes:

- `immutableSourceRequired=true`;
- `provenancePreservationRequired=true`;
- exact source-root kind/digest, source artifact-record digest, provenance-record digest, artifact
  digest, and artifact byte-count requirements; and
- `provenanceVerified=false` and `registrationOnly=true`.

The first two markers are requirements for a future authorized parser runtime. They do not describe
the current source. Every typed Surface fixes all of these state claims false:

- source resolution and source-seal verification;
- source authenticity, immutability, and artifact-membership verification;
- chain-of-custody verification;
- artifact digest and byte-count verification;
- evidence-class and provenance-sanitization verification;
- provenance preservation, source-format verification, and parser-result availability;
- Forensic Hypothesis creation, Evidence sealing, and Graph admission.

The DOMAIN-002 surface type contains the word `immutable`, but schema identity is not an
immutability attestation. ADR-0016 Run chaining is locally tamper-evident and does not authenticate
who created a Run or prove external anchoring. `PLAN.md` continues to list the production immutable
source and chain-of-custody trust root as an open decision.

## Content-free markers

Each provenance coordinate fixes literal-false markers for embedded raw source, disk, memory, log,
artifact, and provenance-record content; mutable paths and source URIs; secret and credential
material and references; and parser output. These markers state that the schema has no dedicated
field for those values. They do not prove that arbitrary digest preimages are safe.

All marker validators reject `true`, `0`, strings such as `"false"`, and other boolean coercion.
Unknown private, operational, analysis, or authority fields fail closed.

## Typed Surface identity

`ForensicImmutableArtifactSurface` binds:

- the exact Forensics classification reference;
- the exact `forensics.immutable-artifact` DOMAIN-002 type-set reference;
- the complete locator-registry reference;
- one revalidated discriminated disk, memory, log, or artifact locator;
- the code-owned class for that locator; and
- a content-addressed Surface ID and digest.

Registered definitions, registries, and typed Surfaces use domain-separated canonical digests.
Public builders, typed-Surface, `reference()`, and complete-Surface reference-binding boundaries
serialize nested Pydantic instances to alias JSON and validate them again. Unmodeled instance state
is rejected recursively. Unchecked instance-copy updates therefore cannot bypass provenance,
class, registry, reference, or digest validation before content identity is derived.

A Surface reference is an inert opaque content-addressed pointer. It carries the Surface digest,
ID, fixed type/schema, and exact code-owned registry reference, but deliberately carries no
unbound class or locator-kind claim. Standalone validation proves only this pointer shape; it does
not prove which complete Surface produced the digest or that the source Run, artifact record,
provenance record, or bytes exist. `bind_forensic_immutable_artifact_surface_reference`
revalidates a supplied complete Surface and provenance, derives its pointer, and accepts only an
exact match. A future Capability must use this binding rather than grant authority from a
standalone reference.

The typed value is pre-Observation knowledge and is not the established evidence-bound
`AttackSurface`. FORENSICS-001A does not extend the existing discovery `SurfaceLocator` union,
`SurfaceObservation`, or `AttackSurface` wire.

## Trust boundary and non-authority guarantees

FORENSICS-001A adds in-process typed values and exact registry resolution only. It creates no
source resolver, Artifact reader, repository grant, file handle, mount, memory reader, log reader,
write blocker, parser, analyzer, sandbox, Tool, Worker, network request, credential lease, durable
store, Audit Event, Graph writer, Hypothesis, Finding, or execution boundary.

All of these remain false:

- source resolution, acquisition, read, mount, and copy;
- parser selection and analysis;
- credential access or use and lateral movement;
- evidence mutation;
- Tool or Worker selection and network access;
- Scope expansion, Capability activation, approval satisfaction, and Permit issuance;
- Graph admission, Finding authority, and execution.

A later Observation may report possible credential material as bounded knowledge. Neither that
knowledge nor its digest may become credential identity or authorize its use. Credential use,
lateral movement, Evidence mutation, or active probing requires a separate Capability and fresh
authority.

## Threat model and fail-closed behavior

The primary threats are treating a path as source Scope, treating a Run root as authenticated or
externally anchored, classifying a source from a filename, erasing acquisition distinctions by
using only artifact digest, embedding raw acquisition/custody content, hashing a credential and
calling it redacted, turning discovered secrets into authority, selecting a parser from metadata,
and bypassing nested validation with a forged model instance.

Exact locator/registry resolution and complete-Surface reference binding reject locator membership,
order, source model, Domain, type-set, digest, class, or Surface identity substitution. Standalone
Surface-reference parsing is structural and not an identity proof. Models reject malformed or
uppercase digests, negative, overflowing, floating-point, string, or boolean byte counts, unknown
source-root kinds, private or operational fields, true authority markers, and boolean coercion.

## Audit and benchmark impact

Registry and Surface references are deterministic content-addressed values suitable for later
audit binding, but FORENSICS-001A emits no Artifact, Audit Event, Observation, Evidence,
Hypothesis, Finding, Replay, Ground Truth, metric, benchmark Result, or validation-floor evidence.
DOMAIN-006's independent parser comparison and Forensics metrics remain vocabulary only.

FORENSICS-001B may prepare an exact read-only parser boundary without reading a source or creating
a Worker job. FORENSICS-001C owns signed immutable-member resolution, no-mutation proof, and
provenance-preserving Observation/Evidence admission. FORENSICS-001D owns deterministic re-parse or
independent-parser comparison and benchmark measurement.

## Compatibility, migration, and rollback

The implementation is additive. Existing discovery locators, `SurfaceObservation`,
`AttackSurface`, DOMAIN-002 semantics, `RunIntegritySeal`, `SealedArtifact`, `ArtifactRef`, Artifact
readers and repositories, canonical digests, Scope, Graph, Capability, Permit, Gateway, Worker, and
runtime behavior remain unchanged. There is no data migration.

Rollback removes the additive module, public exports, contract, ADR, tests, and consumers without
modifying or deleting source Runs or artifacts. New root kinds, locator classes, provenance fields,
class semantics, or digest algorithms require a versioned registry/schema change. Future trust
attestations must not rewrite serialized v1 false-state claims.

## Verification

`tests/test_forensics_immutable_artifact_surfaces.py` covers exact Forensics Domain/type-set
binding, four-class membership and ordering, content-addressed resolution, full source provenance,
strict digest and byte-count coordinates, identity drift across every provenance dimension and
class, all four inert typed Surfaces, public export and legacy discovery-wire compatibility,
private and sensitive field injection, authority escalation, boolean coercion, registry and
Surface drift, code-owned source-root membership, detached registry/resolver output, forged
reference rejection, and revalidation of forged or hidden-state Pydantic instances.
