# CLOUD-001C: Sealed Cloud Provider Observation Admission

- Status: Implemented, neutral Observation and digest-only Evidence receipts
- API versions:
  - `pajin.dev/cloud-provider-execution-worker-binding/v1alpha1`
  - `pajin.dev/cloud-provider-execution-trust-anchor/v1alpha1`
  - `pajin.dev/cloud-credential-use-receipt/v1alpha1`
  - `pajin.dev/cloud-provider-response-receipt/v1alpha1`
  - `pajin.dev/cloud-provider-execution-statement/v1alpha1`
  - `pajin.dev/cloud-provider-execution-bundle/v1alpha1`
  - `pajin.dev/cloud-provider-observation-admission-policy/v1alpha1`
  - `pajin.dev/cloud-provider-observation-candidate/v1alpha1`
  - `pajin.dev/cloud-provider-observation-admission/v1alpha1`
- Authority: `src/pajin/workflow/cloud_provider_admission.py`
- Decision: [ADR-0226](../adr/0226-admit-cloud-api-observations-without-credential-use-authority.md)

## Purpose

CLOUD-001C admits one neutral `cloud.api-observation` only after independently rechecking a
separately authorized, deployment-produced, signed read-only Cloud execution source. It does not
add a provider client, materialize a credential, open a connection, decode provider resource or
policy fields, evaluate effective permissions, or produce a Hypothesis or Finding.

The CLOUD-001A Surface remains `registered-not-authorized`. The CLOUD-001B adapter remains request
adaptation only. CLOUD-001C treats the source approval, Permit, mTLS identity, credential-use
receipt, and signature as provenance for an already completed action, never as authority for a new
action.

## Deployment-owned source contract

`CloudProviderObservationSourceInputs` contains the evidence root and signed-bundle reference plus
the expected Run ID, current Cloud activation, current Campaign, exact CLOUD-001B preparation, and
approved `CapabilityGraphCampaignJobInput`. The deployment pins the out-of-band trust anchor when
constructing `CloudProviderObservationAdmissionGate`; a source cannot submit or override it. The
repository does not create these execution artifacts in production.

`CloudProviderExecutionTrustAnchor` binds:

- one explicit trust domain and issuer;
- one deployment-owned Worker binding;
- the exact CLOUD-001B code-backed Capability and signed release;
- the exact DOMAIN-004 minimum Cloud Worker profile;
- one Worker mTLS policy and exact subject/SPKI binding;
- the exact provider adapter and credential audience; and
- a uniquely sorted Ed25519 keyring with exactly one active key.

The Worker binding and trust anchor are verification-only. Their current-activation, Campaign,
approval, Permit, credential-use, provider-invocation, Graph-admission, and execution authority
markers remain false. The external signature proves origin and integrity of the supplied statement;
it does not activate the Capability or make DOMAIN-004 a provider runtime registry.

## Signed execution statement

The Ed25519-signed statement binds all of the following exact identities:

- deployment, Worker binding, and signed `WorkerMTLSAdmission`;
- execution, Campaign ID, and Campaign digest;
- Run, CLOUD-001B preparation, provider request, request, and normalized parameters;
- consumed ActionPermit and durable approval-consumption receipt;
- fingerprint-only credential lease and signed one-use audit receipt;
- detached neutral response-receipt path, file SHA-256, receipt ID, and receipt digest; and
- start, finish, credential discard, and statement issue times.

The statement allows exactly one `GET`, zero provider writes, and a successful completion. It
requires direct mTLS, broker lease recheck, and response-receipt sealing. Raw provider response,
provider-field interpretation, policy-effect evaluation, fresh credential use, fresh provider
invocation, and mutation authority are fixed false.

`CloudCredentialUseReceipt` is a historical signed projection. It records that the deployment
rechecked the broker, materialized the exact lease, consumed its single use, used no ambient
credential, embedded neither raw lease ID nor material, and discarded the material before the
lease and Permit expired. CLOUD-001C has only the fingerprint-only lease reference and cannot
materialize or reuse it.

## Neutral response receipt

`CloudProviderResponseReceipt` is a separate strict JSON artifact. It binds execution, request,
route, operation, Surface, HTTP success status, response media type, byte length, body SHA-256, and
receipt time. Its own content-addressed identity and actual file SHA-256 are signed by the execution
statement.

The receipt does not embed the provider body or headers. Resource fields, policy fields, effective
permissions, existence, ownership, credential material, and mutation claims are fixed false. The
loader verifies the file digest and enforces the response ceiling from the exact CLOUD-001B route.
The body digest is provenance only and cannot be interpreted as a resource or policy conclusion.

## Current authority revalidation

Before trusting the external artifacts, the loader revalidates:

- the current signed Cloud activation and exact release;
- the current Campaign digest, Scope, allowed methods, and private-network authority;
- the exact CLOUD-001B preparation, provider adapter, request, and lease fingerprint;
- Graph Decision, ActionProposal, Capability Grant, and approval envelope;
- exactly one matching consumed ActionPermit and one matching durable approval receipt in the
  existing SQLite Graph authority store;
- the deployment-configured trust anchor, key lifecycle, Ed25519 signature, Worker profile, mTLS identity,
  and adapter/audience binding; and
- all timing, one-request, zero-write, response-budget, detached artifact, and content-addressed
  identities.

Any mismatch fails before a Graph lineage is registered. The loader never calls the provider,
SecretBroker, Tool, Gateway, or Worker.

## Observation and Evidence proposal

The proposal contains exactly:

- one succeeded `Action` bound to the consumed ActionPermit;
- one target-derived `cloud.api-observation` with a fixed neutral summary;
- two restricted `Evidence` nodes for the signed execution bundle and neutral response receipt;
- one `produces` edge; and
- two `supported-by` edges.

The Observation value digest binds the preparation, Surface, operation, request, approval receipt,
trust anchor, signed statement, neutral response receipt, response body digest and size, HTTP
status, and derived source root. The Graph event does not contain the raw provider body, headers,
resource inventory, policy document, effective-permission result, credential material, or target
coordinate prose.

No `cloud.policy-exposure` Hypothesis is created in CLOUD-001C. HTTP success and a response digest
are insufficient to state resource existence, ownership, policy effect, effective access,
vulnerability, or a negative conclusion.

## Existing single writer and retry behavior

`CloudProviderObservationAdmissionGate` requires a current non-empty Graph Snapshot and the exact
existing `GraphAdmissionAuthority`, SQLite event log, and trusted-lineage registry. The proposal is
submitted with a compare-and-set check against the caller-bound current head. Intervening Graph
activity fails closed.

The semantic attempt is content-addressed. An exact retry returns the prior admitted event and
does not call the provider, broker, Tool, Gateway, Worker, or network. There is no Cloud-specific
Graph store or writer.

## Explicit non-authority

Candidate and admission artifacts fix raw-response embedding, resource existence and ownership,
policy effect, effective permission, Surface mutation, Scope expansion, Capability activation,
approval authority, Permit issuance, provider and Worker selection, network access, credential use,
policy/IAM/container mutation, Replay, Finding confirmation, and execution authority to false.

The successful state remains `registered-not-authorized`. A signed receipt and admitted
Observation prove only that the exact separately authorized read-only request produced bounded
sealed response evidence. They do not authorize another request or establish what the response
means.

## Fail-closed behavior

Admission rejects absent, changed, oversized, multiply linked, non-JSON, duplicate-key, or
path-invalid evidence; signature, issuer, trust-domain, key lifecycle, Worker, mTLS, adapter,
Campaign, activation, Scope, preparation, Decision, Proposal, Grant, approval, Permit, request,
target, parameter, lease, timing, response, or digest substitution; missing or ambiguous Permit or
approval records; non-GET, multiple-request, write, response-body, interpretation, credential, or
mutation claims; stale Graph heads; Graph authority substitution; proposal or event drift; extra
fields; true authority markers; and boolean or integer coercion.

## Compatibility and rollback

CLOUD-001C is additive and explicitly imported. Existing CLOUD-001A/B, Campaign, Scope,
Capability, ToolRequest, approval, ActionPermit, SecretBroker, Worker, Graph, Replay, Finding, and
benchmark wires retain their versions. Rollback removes the specialized workflow, tests, this
contract, and ADR-0226. Existing external receipts and admitted immutable Graph events require no
migration.

## Verification

`tests/test_cloud_provider_admission.py` covers inventory and IAM-policy Observation admission,
exact Graph node and edge limits, idempotent retry, Ed25519 tampering, detached receipt tampering,
missing or foreign Permit identity, signed Permit substitution, response-budget overflow,
deployment trust-anchor substitution, execution-identity substitution, stale Graph heads,
Observation-only producer registration, authority-marker escalation, and response interpretation
or mutation claims.
