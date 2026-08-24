# CLOUD-001A: Account, Project, Resource, IAM, and Container Surface Model

- Status: Implemented, typed registry only
- API versions:
  - `pajin.dev/cloud-account-resource-locator/v1alpha1`
  - `pajin.dev/cloud-account-resource-locator-registry/v1alpha1`
  - `pajin.dev/cloud-account-resource-surface/v1alpha1`
- Authority: `src/pajin/discovery/cloud_surfaces.py`
- Decision: [ADR-0224](../adr/0224-type-cloud-resources-without-credential-authority.md)

## Purpose

CLOUD-001A implements the locator schema reserved by DOMAIN-002 for `cloud.account-resource`. It
binds the exact DOMAIN-001 Cloud classification and DOMAIN-002 Cloud type-set to secret-free
account, project, resource, IAM, and container locators. It also provides a content-addressed typed
Surface whose initial state is `registered-not-authorized`.

This contract represents identity knowledge only. It does not contact a provider, enumerate
resources, read or evaluate a policy, resolve an endpoint, inspect or attach to a container, issue
or use a credential, select a provider, assume a tenant role, expand Scope, or authorize execution.

## Locator classes

| Class | Locator kind | Exact fields | Meaning |
| --- | --- | --- | --- |
| `account` | `cloud-account` | provider ID, provider partition, account ID | One provider-local account identity; it is not ownership, tenant, or credential authority |
| `project` | `cloud-project` | exact parent account, project ID | One project in one account; the parent is part of content identity |
| `resource` | `cloud-resource` | account-or-project parent, service, location, resource type, resource ID | One provider-local resource coordinate; existence and configuration remain unverified |
| `iam` | `cloud-iam` | account-or-project parent, IAM object kind, IAM ID | One principal, role, group, policy, or binding identity; no policy content or effective-access claim |
| `container` | `cloud-container` | account-or-project parent, orchestrator, runtime scope, namespace, container ID, image digest | One immutable runtime/container/image coordinate; no live runtime claim |

The registry contains exactly these five mappings in code-owned order. The account-or-project
parent is embedded as a discriminated locator instead of copying provider and account strings into
every child. A resource, IAM object, or container therefore cannot silently substitute a different
provider, partition, account, or project while retaining the same content identity.

`locationId` is mandatory for a resource. A provider-global resource uses the explicit value
`global`; omission does not silently imply a provider default. The IAM v1 vocabulary is bounded to
`principal`, `role`, `group`, `policy`, and `binding`. These values classify identity only and do
not claim that an adapter supports the provider or object kind.

## Canonical and secret-free identity

Provider, partition, service, location, resource-type, orchestrator, and namespace coordinates are
lower-cased and validated locally. Provider-local account, project, resource, IAM, runtime-scope,
and container IDs preserve case because provider identity may be case-sensitive. Surrounding or
control whitespace, mutable `auto`, `current`, `default`, `latest`, or `unknown` identity aliases,
URL/query/fragment syntax, backslashes, and wildcards fail closed where they could make identity
ambiguous or active.

The container locator requires `sha256:<64 lowercase hexadecimal characters>` for image identity.
An image tag is not accepted. `default` remains valid only as an explicit namespace because it can
be an actual namespace name; it is not accepted as an account, project, resource, runtime, or
provider-coordinate identity.

Every locator contains literal-false `secretReferenceEmbedded` and
`credentialReferenceEmbedded` markers and forbids extra fields. There is no access key, token,
password, role session, provider endpoint, Secret reference, credential lease, policy document, or
runtime handle field.

## Relationship to existing provider and container contracts

The existing AWS production-selection contracts remain the authority for their exact S3 bucket,
STS credential-custody, KMS key, endpoint, and activation requirements. The MinIO inventory remains
a disposable conformance-provider contract. Docker Target Factory evidence remains lifecycle and
measurement evidence behind its own authority boundary.

CLOUD-001A does not import any of those runtime objects. A later reviewed adapter may project, for
example, an AWS account plus provider-local S3 bucket, IAM role, or KMS key ID into these locators.
Such a projection must not copy an STS session, presigned URL, provider endpoint, tenant credential,
live inventory assertion, Docker operation, or provider-activation decision. The resulting typed
Surface is still only `registered-not-authorized` knowledge.

## Typed Surface identity

`CloudAccountResourceSurface` binds:

- the exact Cloud classification reference;
- the exact `cloud.account-resource` DOMAIN-002 type-set reference;
- the complete locator-registry reference;
- one discriminated account, project, resource, IAM, or container locator;
- the code-owned class for that locator; and
- a content-addressed Surface ID and digest.

The value is pre-Observation knowledge and is not the established evidence-bound `AttackSurface`.
It contains no Campaign, Scope authority, Capability, approval, Permit, provider adapter, Tool,
Worker, request, credential, Secret, policy document, Observation, or Evidence field. The existing
discovery `SurfaceLocator` union and `AttackSurface` wire remain unchanged.

## Threat model and fail-closed behavior

The primary threats are treating an account or tenant identifier as credential authority, using a
provider or resource label to select an adapter, hiding a cross-account substitution inside a
resource or IAM identifier, using mutable aliases or image tags as identity, embedding secrets or
policy content in metadata, and relabeling another Domain's knowledge as Cloud authority.

Definitions, references, the complete registry, and typed Surfaces are content-addressed. Exact
resolution rejects locator class or model substitution, registry reordering, Domain relabeling,
parent substitution, mutable or active identifier syntax, IAM-kind mismatch, non-SHA-256 or
uppercase image digests, digest drift, extra credential or authority metadata, true authority
markers, and non-boolean marker coercion.

## Trust boundary and non-authority guarantees

CLOUD-001A adds only in-process typed values and exact registry resolution. It creates no provider
client, inventory reader, policy evaluator, credential broker, Secret lease, network process,
container connection, Worker, durable store, publisher, audit event, or execution boundary. In
particular, all of these remain false:

- provider selection, registration assertion, tenant authority, and ambient credential access;
- inventory, policy read or evaluation, resource existence, IAM policy, and container runtime
  verification;
- credential lease, container access, network access, resource mutation, and IAM mutation;
- Scope expansion, Capability activation, approval satisfaction, and Permit issuance;
- Tool or Worker selection, Graph admission, runtime-support assertion, and execution.

CLOUD-001B must separately bind an exact locator to a reviewed read-only inventory or policy
Capability, current exact account/project/resource Scope, an ephemeral credential lease, request
and credential-TTL budgets, and the DOMAIN-004 Cloud Worker boundary. CLOUD-001C must separately
seal resource or policy Observation/Evidence before the existing Graph writer can admit knowledge.

## Audit and benchmark impact

The registry and Surface references are deterministic content-addressed values suitable for later
audit binding, but CLOUD-001A emits no audit Artifact or Event. It registers no Ground Truth,
Replay, deterministic policy re-evaluation, metric, validation-floor evidence, benchmark Result,
disposable account, emulator, or container fixture. CLOUD-001D owns those later contracts.

## Compatibility, migration, and rollback

The implementation is additive. Existing discovery locators, `SurfaceLocator`,
`SurfaceObservation`, `AttackSurface`, DOMAIN-002 semantics, provider selections, object-storage
adapters, container lifecycle, Scope, Capability, Worker, Graph, and artifact readers remain
unchanged. There is no data migration.

Rollback removes the additive module, public exports, contract, ADR, and consumers. New locator
classes, IAM object kinds, identity fields, or digest algorithms require a versioned
registry/schema change rather than silent membership expansion.

## Verification

`tests/test_cloud_account_resource_surfaces.py` covers exact Domain/type-set/class membership,
content-addressed resolution, provider and resource-coordinate canonicalization, nested parent
identity, all five typed Surface classes, AWS object-storage coordinate projection without runtime
authority, discovery-wire compatibility, mutable and active identity rejection, strict container
image digests, secret and credential-field injection, parent/class/order/Domain substitution,
digest drift, authority escalation, and boolean coercion.
