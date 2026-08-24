# NET-001C: Sealed Network Protocol Knowledge Admission

- Status: Implemented, neutral Observation and bounded open Hypothesis only
- API versions:
  - `pajin.dev/network-protocol-knowledge-admission-policy/v1alpha1`
  - `pajin.dev/network-protocol-knowledge-candidate/v1alpha1`
  - `pajin.dev/network-protocol-knowledge-admission/v1alpha1`
- Authority: `src/pajin/workflow/network_service_admission.py`
- Decision: [ADR-0222](../adr/0222-admit-network-protocol-knowledge-without-service-authority.md)

## Purpose

NET-001C turns one already approved, executed, and sealed NET-001B passive TCP result into a
neutral `network.protocol-observation` in the existing Canonical Graph. If and only if the
code-owned NET-001B classifier returned one of its five bounded labels, the same source also
enables one open `network.exposure` Hypothesis. The Hypothesis is a question for independently
authorized validation, not a service confirmation or Finding.

The typed `network-port` Surface remains a content-addressed reference. NET-001C does not propose
a new Surface, expand Scope, issue approval or a Permit, choose a Tool or Worker, open another
connection, or grant Replay, Finding, credential, network, or execution authority.

## Accepted source authority

`NetworkServiceObservationSourceInputs` carries the sealed Run path and expected Run ID together
with the current NET-001B activation, Campaign, exact preparation, and one
`CapabilityGraphCampaignJobInput` using `capability-graph-v1`. The loader reconstructs the
preparation through the current signed activation and current Campaign Scope before it trusts any
execution output.

The source is accepted only when all of the following agree:

- NET-001B release, activation set, preparation, Surface, fixed protocol budget, request, and
  normalized parameters;
- Campaign, Graph Decision, ActionProposal, Capability Grant, and approval envelope;
- exactly one consumed ActionPermit and its exactly one durable approval-consumption receipt in
  the same verified SQLite Graph store;
- one sealed `claimed -> completed` Capability dispatch reconciliation;
- the create-only Tool request reservation and Tool/Worker Evidence artifacts;
- successful Policy, Gateway, Tool, and Docker Worker outcomes;
- exact non-secret Worker metadata, empty secret request and lease lists, and one exact CONNECT
  egress rule with one request and a 1,024-byte response ceiling;
- exactly one matching host-observed HTTPS CONNECT receipt; and
- a recomputed Gateway outcome digest equal to the terminal dispatch event.

The approval receipt is durable Graph authority joined to the sealed Run by the exact Permit; it
is not represented as a new bearer artifact. Worker direct mTLS remains a prerequisite of the
deployment dispatch boundary. Admission does not fabricate or reissue that live authentication.

NET-001C composes no new end-to-end Network deployment or dispatcher. A source Run must already
have been produced through the ordinary Policy, approval, Permit, Gateway, deployment Worker, and
trusted host-receipt path.

## Neutral Observation proposal

The first proposal contains exactly:

- one succeeded `Action` bound to the consumed ActionPermit;
- one target-derived `network.protocol-observation` with a fixed neutral summary;
- two `Evidence` nodes for the request reservation and Tool execution Evidence;
- one `produces` edge; and
- two `supported-by` edges.

The Observation value digest binds the preparation and Surface reference, approval receipt,
Permit request, Gateway outcome, terminal and reconciliation records, sealed Run root, both
artifact hashes, passive-banner hash and length, connection state, and optional bounded service
label. Raw banner bytes, product strings, versions, Worker transcripts, target coordinates, and
approval identities are not copied into Graph prose.

## Bounded open Hypothesis

The classifier vocabulary is closed to `ftp`, `imap`, `pop3`, `smtp`, and `ssh`. When one of these
labels is present, a second proposal contains exactly one agent-derived `network.exposure`
Hypothesis and one `enables` edge from the newly admitted Observation. The statement says only
that the exact TCP endpoint may expose the observed protocol. Its expected observable requires a
separately authorized fresh passive handshake with a compatible label, and its fixed confidence
is `0.5`.

An absent label produces no Hypothesis and no negative conclusion. A label is not a confirmed
service, product, version, vulnerability, Finding, or benchmark result. NET-001D now provides the
separate fresh-execution Replay comparison and isolated-service fixture registration, but it still
does not turn either artifact into service confirmation or a numeric measurement.

## Existing single writer and retry behavior

`NetworkProtocolKnowledgeAdmissionGate` requires a current non-empty Graph Snapshot and the exact
existing `GraphAdmissionAuthority`, SQLite event log, and trusted-lineage registry. It submits the
Observation at the caller-bound head. If a Hypothesis exists, it submits that proposal only when
the admitted Observation is still the next current head. Intervening Graph activity fails closed.

Both semantic attempts are content-addressed. An exact retry returns the existing admitted events
and never invokes the Tool, Gateway, Worker, or network again. There is no Network-specific Graph
store or writer.

## Explicit non-authority

The policy, candidate, and admission artifacts fix service-label authority, Surface mutation,
Scope expansion, Capability activation, approval authority, Permit issuance, Tool selection,
Worker selection, network access, credential access, Replay, Finding confirmation, and execution
authority to false. The source approval and consumed Permit are provenance only and cannot
authorize another action.

The successful result state is `registered-not-authorized`. Graph membership, the Network Domain,
the typed Surface, protocol vocabulary, banner hash, service label, and open Hypothesis do not
change that state.

## Fail-closed behavior

Admission rejects unsealed, changed, failed, cancelled, incomplete, foreign, or ambiguously
reconciled Runs; current activation or Scope drift; release, Campaign, Decision, Proposal, Grant,
approval, receipt, Permit, request, parameter, Tool, or target substitution; missing or mismatched
CONNECT receipts; non-Docker or untrusted network evidence; Worker metadata, egress, secret, or
Gateway digest drift; unknown service labels; stale Graph heads; Graph authority substitution;
proposal or event drift; extra fields; true authority markers; and boolean or integer coercion.

## Compatibility and rollback

NET-001C is additive and explicitly imported. It changes no NET-001A, NET-001B, Campaign,
Capability, ToolRequest, ActionPermit, approval, Gateway, Worker, Run, Graph, Discovery, Replay,
Finding, or benchmark wire. Rollback removes the specialized module, tests, this contract, and
ADR-0222. Existing Runs, approvals, Permits, and Graph events require no migration.

## Verification

`tests/test_network_service_admission.py` covers successful Observation and Hypothesis admission,
unknown-service Observation without a negative Hypothesis, exact retry without redispatch,
approval/Grant substitution, service relabeling, authority escalation, current Scope drift,
untrusted CONNECT receipts, and sealed Evidence tampering.
