# SYS-001C: Sealed System Host Knowledge Admission

- Status: Implemented, neutral Observation and optional bounded open Hypothesis
- API versions:
  - `pajin.dev/system-inspection-execution-trust-anchor/v1alpha1`
  - `pajin.dev/system-inspection-result-receipt/v1alpha1`
  - `pajin.dev/system-inspection-execution-statement/v1alpha1`
  - `pajin.dev/system-inspection-execution-bundle/v1alpha1`
  - `pajin.dev/system-inspection-knowledge-admission-policy/v1alpha1`
  - `pajin.dev/system-inspection-knowledge-candidate/v1alpha1`
  - `pajin.dev/system-inspection-knowledge-admission/v1alpha1`
- Authority: `src/pajin/workflow/system_inspection_admission.py`
- Decision: [ADR-0230](../adr/0230-admit-system-host-knowledge-without-host-access-authority.md)

## Purpose

SYS-001C admits one neutral `system.host-observation` after independently rechecking a separately
authorized, deployment-produced, signed non-root System inspection. It may also admit one bounded
open `system.security-configuration` Hypothesis for a fixed service or configuration review signal.
It does not add a host-agent client, open a host session, read a host, interpret raw host content,
confirm a state, or produce a Finding.

SYS-001A Surfaces remain `registered-not-authorized`, and SYS-001B remains preparation-only.
Approval, Permit, mTLS, runtime, and signature records are historical provenance for one completed
action, never authority for another action.

## Deployment-owned source

`SystemInspectionObservationSourceInputs` provides an evidence root, signed-bundle reference,
expected Run, current activation, current Campaign, exact SYS-001B preparation, and approved
`CapabilityGraphCampaignJobInput`. `SystemInspectionKnowledgeAdmissionGate` receives the trust
anchor separately from deployment configuration; source data cannot override it.

`SystemInspectionExecutionTrustAnchor` binds the exact SYS-001B deployment, code-backed Capability,
signed release, trust domain, issuer, and an ordered Ed25519 keyring with exactly one active key.
The deployment already pins the opaque host, complete Worker mTLS policy, selected subject/SPKI,
agent executable digest, declared non-root identity, allowed operations, and artifact/runtime
ceilings. Trust-anchor markers explicitly deny activation, Campaign, approval, Permit, host-access,
Worker-selection, root, Graph-admission, and execution authority.

## Signed execution and non-root proof

The signed statement binds:

- deployment binding, `WorkerMTLSAdmission`, and Gateway outcome digest;
- execution, Campaign ID/digest, Run, SYS-001B preparation, and exact inspection request;
- request and normalized-parameter identities;
- consumed ActionPermit and durable approval-consumption receipt;
- `SystemNonRootRuntimeReceipt` for the exact host, run-as identity, executable digest,
  runtime-identity digest, confinement digest, and attestation time;
- detached result-receipt path, file digest, receipt identity, and content digest; and
- execution start, finish, and statement issue times.

It asserts one request, bearer authentication, direct mTLS, Gateway policy re-entry, consumed-Permit
and approval verification, exact Surface binding, metadata-only execution, non-root verification,
and result sealing. Content/value reads, process signals, service-control operations, and host writes
are zero. Raw metadata embedding, fresh host access, new agent invocation, Worker selection, root,
privilege escalation, mutation, Replay, Graph admission, Finding confirmation, and new execution
authority are false.

The runtime receipt contains no UID/SID/group/capability list or credential material. Its digest-only
identity and confinement fields are signed provenance. The loader requires all public deployment
coordinates to match exactly and keeps runtime attestation within the execution and Permit window.

## Neutral result receipt

`SystemInspectionResultReceipt` is a strict detached JSON artifact. It binds execution, request,
preparation, operation, exact Surface reference, signed input provenance, result-body SHA-256, byte
count, media type, optional review signal, and receipt time. `immutable-host-snapshot` requires one
lowercase snapshot SHA-256; `live-authenticated-host` forbids a snapshot digest. Its
content-addressed identity and actual file digest are covered by the signed statement.

The receipt never embeds the raw result, raw host metadata, host paths, or configuration values.
It cannot assert host existence, service state, Finding confirmation, or execution authority. Its
byte count must fit the exact SYS-001B artifact ceiling; the raw result body remains external.

## Current authority revalidation

Before any Graph lineage is registered, the loader:

1. rebuilds the exact SYS-001B preparation using the current activation, release, Campaign, exact
   Surface, operation, deployment adapter, request, and agent identities;
2. rechecks Graph Decision, ActionProposal, Capability Grant, and approval inputs;
3. resolves exactly one matching consumed ActionPermit and durable approval-consumption receipt
   from the existing SQLite authority store;
4. recomputes the current Gateway `PolicyDecision` from the Campaign, Grant, exact request, and
   network-disabled System Tool spec, then verifies its sanitized outcome digest together with the
   deployment-configured trust anchor, Ed25519 signature, `WorkerMTLSAdmission`, and non-root receipt; and
5. checks execution timing, one-request/zero-content-read/zero-write ceilings, result size,
   detached file paths, file digests, receipt identities, and source-root identity.

The loader never calls a Tool, host agent, Gateway, Worker, network, or credential service.

## Observation and Evidence

The Observation proposal contains exactly:

- one succeeded `Action` bound to the consumed ActionPermit;
- one target-derived `system.host-observation` with a fixed neutral summary;
- two restricted `Evidence` nodes for the signed bundle and neutral receipt;
- one `produces` edge; and
- two `supported-by` edges.

Its value digest binds the preparation, Surface, operation, request, approval receipt, trust anchor,
signed statement, Gateway and mTLS admissions, non-root runtime digests, result receipt, signed
source kind and optional immutable snapshot digest, body digest, byte count, optional signal, and
derived source root. Graph prose contains no raw host content, PID, path, service identifier,
configuration key, configuration value, or target coordinate.

## Bounded open Hypothesis

The only allowed signals are:

| Signal | Exact source | Result |
| --- | --- | --- |
| `configuration-metadata-drift` | configuration Surface plus `configuration-metadata-read` | open configuration metadata review Hypothesis |
| `service-status-review` | service Surface plus `service-status-read` | open service status metadata review Hypothesis |

Each produces one agent-derived confidence `0.5` `system.security-configuration` Hypothesis and one
`enables` edge from the neutral Observation. Its fixed expected observable requires a separately
authorized fresh metadata-only inspection to yield the same signal. A missing signal produces no
Hypothesis and no negative conclusion. Neither signal confirms state, effect, vulnerability, or
Finding.

## Existing writer and exact retry

The gate requires a current non-empty Graph Snapshot and the exact existing
`GraphAdmissionAuthority`, SQLite event log, and lineage registry. The Observation is compare-and-set
against the bound head. An optional Hypothesis must immediately follow that admitted Observation.
Intervening Graph activity fails closed.

Both proposals are content-addressed. Exact retries return the prior events and perform no host,
Tool, Gateway, Worker, or network operation. There is no System-specific Graph store or writer.

## Explicit non-authority

Candidate and admission artifacts fix raw metadata embedding; host existence, process running,
filesystem content, service state, configuration value, and Hypothesis confirmation authority;
Surface mutation; Scope expansion; Capability activation; approval; Permit issuance; host access;
agent/Worker selection; network and credential access; root and privilege escalation; service
control; host mutation; Replay; Finding confirmation; and execution authority to false.

Successful admission remains `registered-not-authorized`. Source identity and prior authority are
provenance only and cannot be converted into fresh host or execution authority.

## Fail-closed behavior

Admission rejects absent, changed, oversized, multiply linked, non-JSON, duplicate-key, or
path-invalid evidence; signature, issuer, key lifecycle, deployment, mTLS, non-root identity,
executable, Campaign, activation, Scope, preparation, Decision, Proposal, Grant, approval, Permit,
request, operation, Surface, timing, budget, receipt, source-kind/snapshot provenance, or digest
substitution; missing or ambiguous Permit/approval records; mismatched review signals; stale Graph
heads; Graph authority substitution; proposal/event drift; extra fields; true authority markers;
and boolean or integer coercion.

## Compatibility and rollback

SYS-001C is additive and explicitly imported. The required source-provenance field was incorporated
while SYS-001A~C remained an uncommitted `v1alpha1` checkpoint, so no published reader migration is
required. Existing Campaign, Scope, Capability, ToolRequest, approval, ActionPermit, Worker, Graph,
Replay, Finding, and benchmark wires retain their versions. Rollback removes the workflow, tests,
this contract, and ADR-0230. Already admitted immutable Graph events and external evidence require
no migration.

## Verification

`tests/test_system_inspection_admission.py` covers service/configuration Observation plus bounded
Hypothesis admission, signal-free host Observation, exact retry, signature and detached-receipt
tampering, absent Permit, signed Permit substitution, artifact budget overflow, trust-anchor and
Gateway outcome substitution, non-root/root identity substitution, Campaign Scope drift, stale
Graph heads, producer registration, authority-marker escalation, integer coercion,
raw-content/authority receipt claims, and Surface/signal mismatch.

SYS-001D additionally verifies source-kind/snapshot binding and uses it only to distinguish
same-snapshot re-analysis from separately authorized fresh inspection. See the
[SYS-001D contract](../benchmark/SYS-001D-system-replay-disposable-host-fixtures.md).
