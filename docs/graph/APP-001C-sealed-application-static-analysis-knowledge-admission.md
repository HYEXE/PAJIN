# APP-001C: Sealed Application Static-analysis Knowledge Admission

- Status: Implemented, neutral Observation and optional bounded open Hypothesis
- API versions:
  - `pajin.dev/application-static-analysis-execution-trust-anchor/v1alpha1`
  - `pajin.dev/application-static-analysis-result-receipt/v1alpha1`
  - `pajin.dev/application-static-analysis-execution-statement/v1alpha1`
  - `pajin.dev/application-static-analysis-execution-bundle/v1alpha1`
  - `pajin.dev/application-static-analysis-knowledge-admission-policy/v1alpha1`
  - `pajin.dev/application-static-analysis-knowledge-candidate/v1alpha1`
  - `pajin.dev/application-static-analysis-knowledge-admission/v1alpha1`
- Authority: `src/pajin/workflow/application_static_analysis_admission.py`
- Decision: [ADR-0234](../adr/0234-admit-application-analysis-knowledge-without-artifact-authority.md)

## Purpose

APP-001C admits one neutral `application.analysis-observation` after independently rechecking a
separately authorized, deployment-produced, signed APP-001B sandbox execution. It may also admit
one bounded open `application.vulnerability` Hypothesis for a fixed class-specific review signal.
It does not add an artifact resolver, custody client, parser, image registry, sandbox runtime,
Worker, network path, dynamic executor, debugger, result-body interpreter, or Finding producer.

APP-001A Surfaces remain `registered-not-authorized`, and APP-001B remains preparation-only.
Approval, Permit, custody, runtime, and signature records are historical provenance for one
completed action, never authority for another artifact read or execution.

## Deployment-owned source and trust

`ApplicationStaticAnalysisObservationSourceInputs` supplies an evidence root, signed-bundle
reference, expected Run, current activation, current Campaign, exact APP-001B preparation, and
approved `CapabilityGraphCampaignJobInput`. The admission gate receives its trust anchor through
deployment configuration; evidence files cannot select or replace it.

`ApplicationStaticAnalysisExecutionTrustAnchor` binds the exact APP-001B sandbox configuration,
code-backed Capability, signed release, trust domain, issuer, and an ordered Ed25519 keyring with
exactly one active key. It is verification-only. Current activation, Campaign, approval, Permit,
artifact access, sandbox invocation, Graph admission, and execution authority remain false.

The trust anchor and signature establish only that the configured deployment issuer made the
statement. Repository code does not independently inspect a live container namespace, UID/SID,
mount table, network namespace, image registry, parser executable, cgroup, seccomp profile, or
custody service.

## Signed sandbox execution

The signed statement binds:

- sandbox binding ID/digest and deployment ID;
- recomputable Gateway `PolicyDecision` and sanitized outcome digest;
- execution, Campaign ID/digest, Run, APP-001B preparation, and exact analysis request;
- request and normalized-parameter identities;
- consumed ActionPermit and durable approval-consumption receipt;
- one content-addressed `ApplicationSandboxRuntimeReceipt`;
- detached result-receipt path, file digest, receipt identity, and content digest; and
- execution start, finish, and statement issue times.

The runtime receipt binds the exact operation, logical parser, parser-executable and sandbox-image
digests, declared non-root identity, artifact digest and byte count, custody binding and
authorization-document digest, plus runtime-identity and confinement digests. Deployment assertions
cover custody authorization, artifact digest verification and read completion, executable/image
verification, non-root execution, disabled network, read-only root, read-only no-exec artifact
mount, no new privileges, and resource limits.

One request and one artifact read are recorded. Network requests, dynamic target executions,
debugger attaches, artifact writes, host-filesystem reads, and credential reads are zero. The
statement and runtime receipt cannot authorize a new artifact read, sandbox invocation, Worker
selection, network request, dynamic execution, debugger attach, mutation, Replay, Graph admission,
Finding confirmation, or new execution.

## Neutral result receipt

`ApplicationStaticAnalysisResultReceipt` is a strict detached JSON artifact. It binds execution,
request, preparation, operation, exact Surface reference, exact artifact SHA-256, fixed output
schema, result-body SHA-256, bounded byte count, media type, optional review signal, and receipt
time. Its content-addressed identity and actual file digest are covered by the signed statement.

The receipt never embeds raw parser output, artifact bytes, artifact paths, or configuration
values. It cannot assert an artifact format, runtime support, dependency relationship,
vulnerability confirmation, Finding confirmation, or execution authority. The body remains in
external custody and is not opened during admission. Its declared byte count must fit the exact
APP-001B output ceiling.

## Current authority revalidation

Before Graph lineage registration, the loader:

1. rebuilds the exact APP-001B preparation using the current signed activation, release, Campaign,
   Surface, operation, custody binding, sandbox binding, request, and agent identity;
2. rechecks the Graph Decision, ActionProposal, Capability Grant, and approval inputs;
3. resolves exactly one matching consumed ActionPermit and one durable approval-consumption
   receipt from the existing SQLite authority store;
4. recomputes the Gateway policy decision from the current Campaign, Grant, request, and
   network-disabled Application Tool spec;
5. verifies the configured trust anchor, Ed25519 signature, sandbox-runtime receipt, and sanitized
   Gateway outcome; and
6. checks exact custody/sandbox/artifact/parser/output identities, causal timing, zero-side-effect
   budgets, result size, detached paths, file digests, receipt identities, and source-root digest.

The loader never invokes the Tool, resolves or reads an artifact, verifies an authorization
document itself, launches a sandbox, calls a Worker, interprets the result body, or accesses a
network or credential service.

## Observation and Evidence

The Observation proposal contains exactly:

- one succeeded `Action` bound to the consumed ActionPermit;
- one target-derived `application.analysis-observation` with fixed neutral prose;
- two restricted `Evidence` nodes for the signed bundle and result receipt;
- one `produces` edge; and
- two `supported-by` edges.

Its value digest binds the preparation, exact Surface and artifact digest, operation, parser,
output schema, request, approval receipt, trust anchor, signed statement, Gateway outcome,
sandbox-runtime receipt and confinement digests, result receipt and result-body digest, bounded
byte count, optional review signal, and source-root digest. Graph prose contains no raw output,
artifact path, filename, format label, configuration value, runtime version conclusion, library
relationship conclusion, or vulnerability statement.

## Bounded open Hypothesis

The only allowed signals are exact class/operation pairs:

| Signal | Exact source | Result |
| --- | --- | --- |
| `binary-security-metadata-review` | binary plus `binary-metadata-read` | open binary metadata review Hypothesis |
| `configuration-structure-review` | configuration plus `configuration-structure-read` | open configuration structure review Hypothesis |
| `runtime-metadata-review` | runtime plus `runtime-metadata-read` | open runtime metadata review Hypothesis |
| `library-metadata-review` | library plus `library-metadata-read` | open library metadata review Hypothesis |

Each signal creates one agent-derived confidence `0.5` `application.vulnerability` Hypothesis and
one `enables` edge from the neutral Observation. Fixed prose requires independent static
re-analysis of the same exact artifact digest to reproduce the same review signal. It does not
name or confirm a vulnerability. A missing signal creates no Hypothesis and no negative
conclusion.

## Existing writer and exact retry

The gate requires a current non-empty Graph Snapshot and the exact existing
`GraphAdmissionAuthority`, SQLite event log, and lineage registry. The Observation is
compare-and-set against the bound head. An optional Hypothesis must immediately follow the
Observation; intervening Graph activity fails closed.

Both proposals are content-addressed. Exact retries return prior events and perform no artifact,
Tool, Gateway, sandbox, Worker, or network operation. APP-001C creates no Application-specific
Graph store or writer.

## Explicit non-authority

Candidate and admission artifacts fix raw artifact/output embedding; artifact format,
configuration value, runtime support, dependency relationship, vulnerability and Hypothesis
confirmation authority; mutation; Scope expansion; Capability activation; approval; Permit
issuance; artifact access; custody authorization; sandbox invocation; Worker selection; network;
dynamic execution; debugger attach; Replay; Finding confirmation; and execution authority to
false.

Successful admission remains `registered-not-authorized`. The signed execution is provenance for
knowledge only and cannot be converted into a new action.

## Fail-closed behavior

Admission rejects absent, changed, oversized, multiply linked, non-JSON, duplicate-key, or
path-invalid evidence; signature, issuer, key lifecycle, trust-anchor, Campaign, activation,
Scope, preparation, Decision, Proposal, Grant, approval, Permit, request, custody, artifact digest,
artifact size, sandbox, parser, executable, image, run-as identity, output schema, timing, budget,
receipt, or digest substitution; missing or ambiguous Permit/approval records; mismatched review
signals; stale Graph heads; Graph authority substitution; proposal/event drift; extra fields; true
authority markers; and boolean or integer coercion.

## Compatibility and rollback

APP-001C is additive and explicitly imported. APP-001A/B, Campaign, Scope, Capability,
ToolRequest, approval, ActionPermit, Graph, Replay, Finding, and benchmark wires retain their
versions. Rollback removes the workflow, tests, this contract, and ADR-0234. Already admitted
immutable Graph events and deployment-owned evidence require no migration.

## Verification

`tests/test_application_static_analysis_admission.py` covers all four class-bound review signals,
signal-free neutral admission, exact retry, signature and detached-receipt tampering, absent or
substituted Permit identity, recomputed Gateway policy, output overflow, artifact/image/run-as
substitution, Campaign Scope drift, stale Graph heads, producer registration, authority-marker
escalation, raw-content/truth claims, integer coercion, and Surface/signal mismatch.

APP-001D remains responsible for separately authorized deterministic re-analysis, seeded
artifacts, disposable sandbox fixtures, Controls, Ground Truth, and measurement.
