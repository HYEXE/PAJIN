# SYS-001A: Host, Process, Filesystem, Service, and Configuration Surface Model

- Status: Implemented, typed registry only
- API versions:
  - `pajin.dev/system-host-resource-locator/v1alpha1`
  - `pajin.dev/system-host-resource-locator-registry/v1alpha1`
  - `pajin.dev/system-host-resource-surface/v1alpha1`
- Authority: `src/pajin/discovery/system_surfaces.py`
- Decision: [ADR-0228](../adr/0228-type-system-host-resources-without-host-access-authority.md)

## Purpose

SYS-001A implements the locator schema reserved by DOMAIN-002 for `system.host-resource`. It binds
the exact DOMAIN-001 System classification and DOMAIN-002 System type-set to secret-free host,
process, filesystem, service, and configuration locators. It also provides a content-addressed
typed Surface whose initial state is `registered-not-authorized`.

This contract represents locally supplied identity knowledge only. It does not connect to a host,
inspect a process, read a filesystem entry or configuration value, query or control a service,
use credentials, select an agent, assert root privilege, expand Scope, or authorize execution.
Operating-system and architecture values are locator dimensions, not host attestation.

## Locator classes and lineage

| Class | Locator kind | Exact fields | Required parent | Meaning |
| --- | --- | --- | --- | --- |
| `host` | `system-host` | pseudonymous host ID, OS family, architecture | none | One deployment-stable host coordinate; existence, ownership, and reachability remain unverified |
| `process` | `system-process` | process-instance digest, executable digest | exact host | One snapshot identity; it has no PID, command line, executable path, or running-state claim |
| `filesystem` | `system-filesystem` | logical mount ID, portable relative path, entry kind, content digest | exact host | One content-bound file or directory coordinate; it contains no host-local absolute path or symlink alias |
| `service` | `system-service` | manager namespace, exact service ID, definition digest | exact host | One manager-qualified unit identity; it is not a display name, executable path, status, or control handle |
| `configuration` | `system-configuration` | namespace, portable record ID, sanitized record digest | exact host, process, filesystem, or service | One content-bound configuration-record identity; it contains no raw value |

The registry contains exactly these five mappings in code-owned order. Every non-host locator
embeds its complete parent as a discriminated locator. The parent therefore contributes to the
typed Surface digest, and an otherwise identical process snapshot, path, service, or configuration
record on another host cannot retain the same content identity.

The process instance digest is generated outside this representation boundary from a sanitized
snapshot identity. It must not be replaced with a mutable PID. Filesystem directory digests and
configuration digests likewise refer to deployment-produced sanitized inputs; SYS-001A neither
defines a live reader nor attests to how those inputs were collected.

## Canonical, portable, and private identity

Host IDs, logical mount IDs, and configuration namespaces are lower-cased and validated locally.
Host IDs require the opaque `host-<64 lowercase hexadecimal characters>` form. A deployment-owned
producer must derive or allocate that pseudonym with deployment separation and retain any reverse
mapping outside the Surface; raw hostname, address, credential, local path, or operator identity
cannot satisfy the locator schema. Mutable aliases such as `local`, `localhost`, `current`,
`default`, `latest`, and `this-host`, surrounding or control whitespace, path or URL syntax,
queries, fragments, and wildcards fail closed.

Filesystem paths and configuration record IDs use forward-slash-separated portable relative
references. They reject POSIX roots, Windows drive or UNC syntax, backslashes, `.` and `..`
segments, repeated or trailing separators, query or fragment syntax, and wildcards. A logical
mount ID is identity metadata only; it does not resolve to a host path in this contract. The
filesystem vocabulary is deliberately limited to `file` and `directory`; symlinks and other
alias-bearing entry kinds require a later versioned design.

Service identity is qualified by one of `systemd`, `windows-service`, or `launchd`. A systemd ID
must be an exact `.service` unit ID. Windows Service IDs are lower-cased because Service Control
Manager names are case-insensitive. Display names, filesystem paths, URLs, wildcard names, and
mutable aliases are rejected. A definition digest is mandatory, so reuse of the same local unit
name with changed sanitized definition material changes the Surface identity.

Every locator contains literal-false `secretMaterialEmbedded`,
`credentialReferenceEmbedded`, `hostLocalAbsolutePathEmbedded`, and
`privilegeClaimEmbedded` markers and forbids extra fields. There is no password, token, Secret
reference, credential lease, raw configuration value, PID, command line, display name, absolute
path, service handle, agent session, or privilege field.

## Typed Surface identity

`SystemHostResourceSurface` binds:

- the exact System classification reference;
- the exact `system.host-resource` DOMAIN-002 type-set reference;
- the complete locator-registry reference;
- one discriminated host, process, filesystem, service, or configuration locator;
- the code-owned class for that locator; and
- a content-addressed Surface ID and digest.

The value is pre-Observation knowledge and is not the established evidence-bound `AttackSurface`.
It contains no Campaign, Scope authority, Capability, approval, Permit, Tool, Worker, request,
credential, Observation, Evidence, or Graph-admission field. The existing discovery
`SurfaceLocator` union and `AttackSurface` wire remain unchanged.

## Threat model and fail-closed behavior

The primary threats are deriving host access from inventory metadata, treating a PID or local path
as stable identity, leaking private path or configuration content, substituting another host below
an otherwise identical child identifier, treating a service display name as a control handle,
and turning a host-agent or root claim into authority through extra metadata.

Definitions, references, the complete registry, and typed Surfaces are content-addressed. Exact
resolution rejects locator class or model substitution, registry reordering, Domain relabeling,
parent substitution, non-portable paths, mutable aliases, malformed or uppercase digests, digest
drift, extra secret or authority metadata, true authority markers, and non-boolean marker coercion.

## Trust boundary and non-authority guarantees

SYS-001A adds only in-process typed values and exact registry resolution. It creates no host
connection, agent protocol, process enumerator, filesystem or configuration reader, service
manager client, credential broker, network process, Worker, durable store, publisher, audit event,
or execution boundary. In particular, all of these remain false:

- discovery, host existence, process running state, filesystem entry, service state, and
  configuration-record verification;
- host access, process inspection, filesystem read, service inspection or control, configuration
  read, credential use, root authority, network access, and host mutation;
- Scope expansion, Capability activation, approval satisfaction, and Permit issuance;
- authenticated host-agent, Tool, or Worker selection, Graph admission, runtime-support assertion,
  and execution.

SYS-001B now separately binds an exact locator to a reviewed read-only inspection Capability,
current exact host/resource Scope, request, artifact-byte, and runtime ceilings, deployment mTLS
configuration, and the DOMAIN-004 authenticated non-root System Worker profile. It creates only a
request description and signed preparation, not a live agent session or host read. SYS-001C must
separately verify sealed host Observation/Evidence before the existing Graph writer can admit
knowledge or create a bounded Hypothesis. Service control, host mutation, credential use, and
privilege escalation are not part of those read-only slices. See the
[SYS-001B contract](../capability/SYS-001B-read-only-inspection-capability.md).

## Audit and benchmark impact

Registry and Surface references are deterministic content-addressed values suitable for later
audit binding, but SYS-001A emits no audit Artifact or Event. It registers no snapshot Replay,
fresh authenticated inspection, Ground Truth, disposable VM/container fixture, metric,
validation-floor evidence, benchmark Result, privilege-denial result, or evidence-completeness
measurement. SYS-001D owns those later contracts.

## Compatibility, migration, and rollback

The implementation is additive. Existing discovery locators, `SurfaceLocator`,
`SurfaceObservation`, `AttackSurface`, DOMAIN-002 semantics, Docker and host-local journals, Scope,
Capability, Worker, Graph, and artifact readers remain unchanged. There is no data migration.

Rollback removes the additive module, public exports, contract, ADR, and consumers. New locator
classes, operating-system or architecture values, service managers, entry kinds, identity fields,
or digest algorithms require a versioned registry/schema change rather than silent membership
expansion.

## Verification

`tests/test_system_host_resource_surfaces.py` covers exact Domain/type-set/class membership,
content-addressed resolution, host canonicalization, complete parent lineage, all five typed
Surface classes, process identity without PID, portable filesystem identity without absolute
paths, manager-qualified services without display names, sanitized configuration identity without
raw values, discovery-wire compatibility, mutable and active identity rejection, secret and
credential-field injection, class/order/Domain substitution, digest drift, authority escalation,
and boolean coercion.
