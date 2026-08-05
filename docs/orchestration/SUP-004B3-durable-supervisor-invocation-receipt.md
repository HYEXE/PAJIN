# SUP-004B3: Durable Supervisor Invocation Journal and Sealed Draft Receipt

- Status: Implemented
- Intent authority: `pajin.dev/supervisor-invocation-intent/v1alpha1`
- Context-bound intent: `pajin.dev/supervisor-invocation-intent/v1alpha2`
- Journal projection: `pajin.dev/supervisor-invocation-journal-entry/v1alpha1`
- Receipt authority: `pajin.dev/supervisor-invocation-receipt/v1alpha1`
- Context-bound receipt: `pajin.dev/supervisor-invocation-receipt/v1alpha2`
- Runtime boundary: `SupervisorCheckpointInvoker.invoke()`
- Decision: [ADR-0123](../adr/0123-durably-claim-and-seal-supervisor-invocations.md)

## Scope

SUP-004B3 completes the first model-backed Shadow Supervisor call. It re-verifies one current
SUP-004A checkpoint, durably claims its exact request before dispatch, requires the SUP-004B1
Campaign-and-dedicated budget boundary, calls the existing SUP-004B2 Provider path once, seals the
request reservation and Gateway evidence, then seals one receipt containing the complete bound
Provider outcome and untrusted draft. A consumer must re-verify the journal, both Run seals, every
artifact and event, all Provider/Gateway sources, and the current SUP-004A authorities before the
draft is passed directly to the SUP-003 compiler.

The resulting typed proposal remains advisory. This slice does not schedule a Task, mutate a Plan
or Graph, expand Scope, issue a Capability or Permit, authorize another execution, apply a Stop,
deliver an escalation, enable Supervisor activation, or authorize automatic Provider redispatch.

## Durable intent and state machine

`SupervisorInvocationJournal.claim()` derives a content-addressed intent from the exact Campaign,
checkpoint key, sealed schedule coordinates, request binding, dedicated budget policy, planned call
index, preplanned Provider Run ID, receipt path, and `campaign-and-dedicated` scope. It also derives
the portable stable request ID `supervisor_<sha256>`. Exact retries return the same intent; a second
intent for the same checkpoint with different authority is equivocation and fails closed.

The host-local SQLite journal has exactly three states:

```text
intent-recorded
-> dispatch-started-outcome-unknown
-> terminal-success
```

The transition to `dispatch-started-outcome-unknown` is committed before Run creation or Provider
dispatch. The state never grants redispatch. A process failure anywhere after that transition is
therefore conservatively unknown. Recovery may advance to `terminal-success` only when the exact
preplanned Run already contains a complete, valid two-seal receipt; otherwise manual review remains
required and the Provider is not called again.

The journal uses strict schema metadata, immutable intent rows, append-only hash-chained events,
compare-and-swap transitions, and exact row/index/state reconstruction. It opens only a regular,
single-link local database path, rejects unsafe sidecars and schema drift, and uses `BEGIN IMMEDIATE`
with full synchronous durability. These controls provide one canonical host-local journal boundary,
not distributed consensus or cross-host exactly-once execution.

SUP-005B1 adds an optional typed benchmark request assertion. When absent, intent serialization and
the stable-request v1 preimage remain exactly `v1alpha1`. When present, the journal stores the full
typed assertion in a `v1alpha2` intent and includes its digest in the stable-request v2 preimage.
The receipt repeats the same object under `v1alpha2`. This generic recording makes the caller's
namespace inspectable but does not attest that the referenced benchmark Plan is sealed; only the
SUP-005B candidate verifier reloads the Plan and predecessor sources and grants that meaning.

## Invocation and two-seal Run

Before the first dispatch, the invoker rebuilds the exact Provider request from the current
SUP-001/SUP-002/SUP-004A authorities and requires equality with the sealed schedule. It also checks
that the live Tool registration and grant are exact, the Campaign budget matches the Campaign, the
dedicated budget matches the scheduled policy, and the supplied `DualModelUsageBudget` binds those
same two controllers.

The Provider Run is created with the journal's preplanned Run ID. The existing policy-bound Provider
port receives the journal's stable request ID and the dual budget. The first seal contains exactly
the Gateway request reservation and evidence artifacts plus the complete Provider/Gateway audit
event prefix. The receipt records their paths and SHA-256 values, the first seal roots and event
head, the full SUP-004B2 outcome, and the strict untrusted draft. The receipt and its audit event are
then appended and a second final seal is created. The final root is stored in the external journal
terminal transition so the receipt does not contain a self-referential final root.

The receipt is content-addressed and binds:

- the immutable journal intent and dispatch event;
- the complete sealed SUP-004A schedule and request binding;
- source Snapshot and response schema identities;
- stable request and dedicated Provider Run identities;
- first-seal artifact root, event head, reservation, and Gateway evidence bytes;
- the complete secret-free SUP-004B2 outcome and its dual charged usage; and
- the complete strict JSON draft in `untrusted-draft-sealed-not-admitted` state.

For a context-bound call it additionally binds the complete typed benchmark request assertion.

The receipt copies no Provider secret reference or endpoint. Its draft is intentionally untrusted
model output and may contain target-tainted content. The pre-existing Gateway evidence remains a
sensitive artifact because it contains the complete execution sources; sealing it proves exact
bytes and provenance but does not sanitize it.

## Consumer admission

`consume_supervisor_invocation()` is the only public model-backed admission path. It requires the
published journal entry to equal the current `terminal-success` head, rebuilds the current
SUP-004A schedule and request, opens the exact final Run, and verifies:

- the two seals, exact artifact membership, SHA-256 values, event counts, order, uniqueness, and
  payloads;
- first-seal roots and event head embedded in the receipt;
- request reservation and Gateway evidence reconstruction;
- the exact code-owned Provider Worker job, egress policy, stdin digest, secret-request
  fingerprints, issued/revoked lease lifecycle, Worker execution identity, result lifecycle, and
  Tool result re-derived from the sealed Worker stdout;
- the full SUP-004B2 Provider outcome from the sealed raw sources;
- `budgetScope=campaign-and-dedicated`, stable request identity, usage, model, Provider, Tool,
  Worker, grant, and Campaign equality; and
- strict response JSON, refusal/tool-call exclusion, draft schema, Snapshot identity, receipt
  digest, journal receipt anchor, and final Run root.

Only after those checks does the consumer pass the draft directly to
`compile_supervisor_shadow_proposal()` and re-verify the typed SUP-003 result. No API returns a
standalone “verified raw draft” that could bypass the compiler.

## Negative boundaries

Construction, recovery, or consumption fails closed for:

- checkpoint equivocation, request/Run substitution, concurrent dispatch ownership, invalid state
  transitions, journal row/event/schema mutation, unsafe database paths, or receipt-anchor drift;
- any started invocation without a complete exact two-seal Run, including Provider error, invalid
  output, refusal, tool call, cancellation, or a crash before the final seal;
- forged or foreign schedule, Snapshot, binding, request, Provider registration, grant, budget,
  Policy, Tool, Worker, Gateway evidence, outcome, draft, event, seal, artifact, or terminal root;
- Campaign-only charging, a dual boundary wired to different ledgers, or dedicated budget policy
  drift; and
- any authority marker that attempts to permit redispatch, Task/Plan mutation, Scope expansion,
  Capability/Permit creation, execution, or activation.

## Compatibility, migration, and rollback

The journal, invoker, receipt, consumer, and dual-budget identity check are additive. Existing
Provider `chat()`, `complete()`, and `chat_bound()` callers, SUP-004A publications, SUP-004B1 budget
controllers, SUP-004B2 outcomes, Gateway evidence, and SUP-003 compilation remain compatible. No
existing artifact or database is migrated. Campaign set-backed fields now serialize as sorted JSON
arrays so embedded Supervisor authorities remain deterministic across Python hash seeds; the parsed
Campaign API remains set-valued.

Context-free callers continue to emit `v1alpha1` with no serialized `requestContext` field and the
same request identity. Context-bound calls opt into explicit `v1alpha2`; the canonical intent is
already stored in the existing journal column, so the SQLite schema and existing rows do not
change.

Rollback stops creating B3 journal databases and invocation Runs and removes the additive runtime
API. Existing B3 journals and sealed Runs should be retained as audit evidence; they do not grant
permission to redispatch. An operator must not downgrade a started unknown intent into an unclaimed
request.

## Explicit non-guarantees

- The SQLite journal is one canonical host-local file. Alternate journal files, copied databases,
  cross-host callers, and distributed dispatchers are outside this authority.
- SUP-004B1 budget reservation is process-local. Restarted consumption proves the sealed charged
  projection, not the current in-memory ledger balance or distributed accounting.
- A started intent without a fully sealed receipt remains outcome-unknown and requires operator
  resolution; availability is intentionally traded for no automatic duplicate dispatch.
- Current Graph/Snapshot verification and journal transition are separate transactions.
- Provider-reported usage and model semantics remain untrusted; the conservative charged bound and
  code-owned SUP-003 compiler remain authoritative.
