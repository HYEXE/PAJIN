# AGENTIC-003: Governed Specialist Execution

## Status

Phases 003A, 003B, 003C1, 003C2, 003C3A, 003C3B1, and 003C3B2 are implemented. The current
non-executing 003C3C foundation adds an audit-only dispatch binding, a Store/DB/Task-bound opaque
runtime capsule, and an additive SQL-injection v2 complete seven-role Capability bundle, externally
signed current Range activation, exact action registry, and deterministic `PreparedCapabilityAction`.
It also adds schema-v6 JobAttempt and terminal-receipt persistence, embedded typed claim/dispatch
verification preimages, explicit offline v5-to-v6 migration, audit-only recovery, a distinct SQLi v2
Plan/runtime generation, same-Task Grant/approval/Permit callback, private capsule transfer, and a
Store-owned one-shot runtime claim. The live pre-backend admission now consumes that predecessor
claim under the exact scheduler Task, rechecks current authority and deployment inventory, persists
one `claimed-before-backend` JobAttempt, and issues a non-copyable, non-serializable opaque claim.
Trusted owner completion, Store close, explicit discard, and post-insert mint failure produce an
`abandoned-before-backend` receipt while retiring all live authority. A structured v2 fake backend
pins its exact source bytes,
compiler, image, job template, backend, output verifier, and deployment Ed25519 verification key and
returns one signed zero-Target-I/O conformance result.

The zero-Target-I/O live execution boundary is now implemented. The same scheduler Task consumes
the opaque claim once, re-observes current authority and the exact runtime inventory, commits the
dispatch-start marker before awaiting the backend, invokes the private structured Worker once, and
verifies its signed result. Only the Gateway can mint the opaque, same-Task, one-shot completion
provenance consumed by the Store terminal producer. A proven zero-I/O result becomes
`failed-before-target-io`; post-marker failure or cancellation becomes `started-outcome-unknown`;
a proven-result receipt write failure remains unreceipted and outcome-unknown. Active dispatch also
fences trusted Store close. None of these paths performs browser, network, or Target I/O.

Only the v2 materializer and action compiler may prepare the sealed action; direct Tool dispatch and
the executor, normalizer, oracle, replay, and cleanup roles remain fail-closed until the specialist
execution Gateway owns them. These records, detached builders, capsules, and fake-backend results
are not production Target-I/O Gateway or Worker success. There is no durable conformance-success
terminal kind, no model, browser, network, or Target I/O occurred, and all execution,
independent-validation, Finding, Graph, reporting, SARIF, and PoC authorities remain false. A
target-capable successor, the approved live Juice Shop execution, and independent 003D validation
and promotion remain unavailable.

## Version

- Profile API: `pajin.dev/specialist-execution-profile/v1alpha1`
- Executor API: `pajin.dev/web-specialist-executor/v1alpha1`
- Preparation API: `pajin.dev/agentic-specialist-preparation/v1alpha1`
- Capability version: `1.0.0`
- Tool version: `1.0.0`
- Additive SQL-injection planning Capability version: `2.0.0`
- Additive SQL-injection planning Tool: `web.specialist.sql-login.v2@2.0.0`
- Additive SQL-injection authority version: `2.0.0`
- Additive SQL-injection activation API:
  `pajin.dev/agentic-web-sqli-specialist-activation-set/v2alpha1`
- Activation API: `pajin.dev/agentic-web-specialist-activation-set/v1alpha1`
- Dispatch-plan API: `pajin.dev/agentic-specialist-dispatch-plan/v1alpha1`
- SQL-injection v2 dispatch-plan API:
  `pajin.dev/agentic-sql-specialist-dispatch-plan/v2alpha1`
- SQL-injection v2 dispatch-plan kind: `AgenticSQLSpecialistDispatchPlanV2`
- SQL-injection v2 runtime generation: `sql-specialist-v2`
- Grant-consumption receipt API:
  `pajin.dev/agentic-specialist-capability-grant-consumption-receipt/v1alpha1`
- Dispatch-binding API: `pajin.dev/agentic-specialist-dispatch-binding/v1alpha1`
- Specialist Worker input API: `pajin.dev/agentic-web-specialist-worker-input/v1alpha1`
- Specialist Worker signed-output API:
  `pajin.dev/signed-agentic-web-specialist-worker-output/v1alpha1`
- JobAttempt API: `pajin.dev/agentic-specialist-job-attempt/v1alpha1`
- Terminal-receipt API: `pajin.dev/agentic-specialist-terminal-receipt/v1alpha1`
- Claim-verification API: `pajin.dev/agentic-specialist-claim-verification/v1alpha1`
- Dispatch-verification API: `pajin.dev/agentic-specialist-dispatch-verification/v1alpha1`
- Structured backend job-template API:
  `pajin.dev/agentic-specialist-backend-job-template/v1alpha1`
- Structured execution-inventory API:
  `pajin.dev/agentic-specialist-execution-inventory/v1alpha1`
- Structured backend result API: `pajin.dev/agentic-specialist-backend-result/v1alpha1`
- Signed structured backend result API:
  `pajin.dev/signed-agentic-specialist-backend-result/v1alpha1`
- Structured backend verification-key API:
  `pajin.dev/agentic-specialist-backend-verification-key/v1alpha1`
- Coordination Store schema: `6`
- Decisions: [ADR-0307](../adr/0307-register-inert-specialist-routes-before-governed-execution.md),
  [ADR-0308](../adr/0308-bind-specialist-profiles-to-closed-executor-definitions.md),
  [ADR-0309](../adr/0309-reserve-receiver-acknowledged-specialist-assignments-before-dispatch.md),
  [ADR-0310](../adr/0310-bind-specialist-action-preparation-without-execution-authority.md),
  [ADR-0311](../adr/0311-define-and-activate-exact-specialist-capabilities-without-dispatch-authority.md),
  [ADR-0312](../adr/0312-transfer-specialist-reservations-into-durable-awaiting-permit-plans.md),
  [ADR-0313](../adr/0313-enter-specialist-dispatch-crash-fence-inside-approved-permit-callback.md),
  [ADR-0314](../adr/0314-pin-specialist-permit-dispatch-to-one-deployment-and-record-grant-consumption.md),
  [ADR-0315](../adr/0315-separate-c3c-conformance-contracts-from-executable-specialist-dispatch.md),
  and [ADR-0316](../adr/0316-persist-specialist-job-attempts-and-typed-verification-without-recovering-dispatch-authority.md)
- Compatibility: additive; existing Skill, Web, Capability, Permit, Worker, Finding, and Graph
  contracts are unchanged

## Objective

AGENTIC-003 converts a durable logical specialist assignment into a least-privilege governed action
without allowing model output, Skill text, or a lifecycle command to become execution authority.
The complete intended path is:

```text
durable assignment + current Graph + exact Candidate/Exploit Group
        |
        | exact inert profile resolution
        v
code-owned diagnostic closure
        |
        | current reservation + exact Campaign/Target/Scope/budget
        v
content-addressed inert action preparation
        |
        | exact signed Range Capability + deterministic PreparedCapabilityAction
        v
durable one-use awaiting-Permit dispatch plan
        |
        | fresh signed approval verification + single-use Permit callback
        v
atomic plan/execution crash fence + exact child Grant-consumption receipt
        |
        | specialist binding installed inside the governed invocation
        v
Gateway -> specialist-specific Worker -> sealed Evidence
        |
        | independent fresh replay + controls + semantic oracle
        v
Candidate -> Finding promotion -> Graph admission -> deterministic report/PoC projection
```

Profile resolution, closed executor definitions, the durable assignment reservation boundary,
inert v1 action preparation, exact inert specialist Capability activation and action compilation,
the durable awaiting-Permit plan, and the one-winning approved-Permit callback crash fence exist
today. The callback returns only a process-local plan-bound started handle carrying the exact
durable Grant-consumption receipt. The C3C foundation can transfer its private runtime capsule once
to the same registered `asyncio.Task`, resolve the exact signed SQL-injection v2 release through its
complete code-backed authority set, prepare one deterministic v2 action, enter a distinct v2
Plan/Grant/signed-approval/Permit crash fence, transfer one Store-owned private capsule, and consume
it through a one-shot current-state claim. Separately, schema-v6 detached builders and Store methods
can persist structurally typed attempt state, and the source-byte-addressed fake backend can exercise
zero-I/O conformance. The private claim itself does not mint a JobAttempt. The public binding,
prepared action, canonical attempt rows, typed verifications, and signed fake result remain
preparation, audit, or conformance records only. They neither perform production
Gateway/Worker/Target execution nor grant validation or promotion authority.

## Phase 003A: implemented inert profiles

The closed production Web catalog exposes complete exact references only. Its profiles are:

| Profile | Selection Skill | Supporting Skill | Ordered closure | Promotable step/category |
| --- | --- | --- | --- | --- |
| XSS | `pajin.skill.web.assess-xss@1.1.0` | none | `dom-xss` | `dom-xss` / `CWE-79` |
| SQL injection | `pajin.skill.web.assess-sqli@1.1.0` | none | `sql-login` | `sql-login` / `CWE-89` |
| Authorization | `pajin.skill.web.assess-object-access@1.1.0` | `pajin.skill.web.assess-sqli@1.1.0` | `sql-login -> object-access` | `object-access` / `CWE-639` |

The authorization profile labels SQL login as a `session-acquisition` dependency. The dependency
does not authorize or automatically promote a SQL injection Finding.

Every profile binds the exact installed adapter and adapter-catalog digest but intentionally omits
the current aggregate diagnostic bundle. It is `registered-inert`, unbound, unsupported by a
runtime, requires fresh approval and independent validation, and carries no authority.

## Phase 003B: implemented exact executor definitions

The closed executor catalog binds each exact profile to a distinct executor ID, version, digest,
adapter identity, ordered diagnostic closure, optional minimal browser implementation, and
promotable-step allowlist. It provides no dynamic registration, fuzzy lookup, or fallback.

- XSS owns authenticated bootstrap plus exact `dom-xss-source -> dom-xss-replay` browser phases.
- SQL injection owns exact `sql-login-source -> sql-login-replay` phases and no browser.
- Authorization owns authenticated bootstrap, SQL-login source/replay, then object-access
  source/replay. SQL login is a required session dependency but is not promotable in that profile.

The specialist browser blocks its aggregate inherited entry point before startup. Its policies deny
registration, SQL-impact, and object-access endpoints during bootstrap and XSS execution. Exact
phase-group validation rejects unknown, missing, repeated, and reordered work. A failed
authorization dependency terminates before object-access I/O, and only locally reproduced allowed
steps can appear in the non-authoritative promotion-candidate subset.

The specialist browser creates no account and uses only supplied preprovisioned credentials. Its
observation fixes `accountCreationPerformed=false` and `provisionedAccountUsed=true`. Each SQL-login
phase receives only the exact login and impact endpoints, `GET`/`POST`, and three requests. Each
object-access phase receives only the exact object endpoint template, `GET`, and three requests.
The policy compiler function identities are pinned in executor provenance, and broadened or
substituted policies fail before additional I/O.

The testing catalog accepts injected transport and observation data solely to test deterministic
closure. The production catalog rejects binding and execution before I/O until 003C3C owns browser
and network provenance inside a governed invocation. Existing aggregate browser exploration,
passive discovery, diagnostic runner, attack-path builder, and Finding/Graph paths are not reused.

## Phase 003C1: implemented durable verified assignment reservation

The Linux descriptor-bound coordination store now issues an opaque, process-local verified
assignment handle only when the exact current durable head still contains a live `assign` or
`follow-up` command and all of the following agree:

- sender outbox state is `acknowledged`;
- receiver inbox receipt, delivery claim, acknowledgement, receiver, and command digest;
- immutable cycle, selected Candidate, proposal target/threat/specialization, and current Exploit
  Group specialist; and
- nonterminal issued command plus the currently assigned Agent Session's exact Task and Candidate.

Raw commands, receipts, Candidates, decisions, and serialized audit entries cannot reserve or begin
dispatch. A unique durable reservation is single-winner under concurrency. The specialist
execution row's only state advance is `reserved -> dispatch-started-outcome-unknown`; both handle
transfers consume non-copyable, non-serializable store-local values. Restart reloads audit state
without reissuing authority, and automatic redispatch remains false.

The entry also keeps execution, Finding, and Graph authority false. This phase performs no browser,
network, Gateway, Worker, Provider, target, or delivery I/O. Its outcome-unknown transition is the
pre-I/O crash fence that Phase 003C3B2 enters only inside one governed callback.

## Phase 003C2: implemented inert specialist action preparation

Preparation accepts only the concrete coordination store, its opaque live reservation handle, a
verified current Graph head, and an exact Campaign. The caller cannot supply a profile, executor,
transport, policy, payload, Tool request, or prepared Capability action. The store rechecks current
Graph and durable heads, full history, the reserved row, and the live admitted assignment without
consuming the reservation or changing its state.

The preparation path then resolves the exact Juice Shop target route, production profile, and
production executor from code-owned catalogs. It strictly reloads the Campaign and binds the exact
Campaign, single target, Scope, budget, assignment, Graph, reservation, profile, and executor into
a deterministic content-addressed record. Its nested future Capability requirement is only a
one-call, non-delegable, T2-or-lower requirement with fresh approval. It is not a Capability,
Grant, `ToolRequest`, or `PreparedCapabilityAction`. Every authority and execution marker remains
literal false, and the path performs no model, browser, network, target, Gateway, or Worker I/O.

The preparation and returned audit entry are never bearer authority. At the end of this phase the
original reservation remains the only process-local value that can be transferred into later
planning; Phase 003C3B1 consumes that handle without changing the durable execution row.

## Phase 003C3A: implemented exact non-dispatching specialist Capabilities

The Capability inventory defines separate experimental, read-only, T2 Capabilities and Tools for
XSS, SQL injection, and authorization. Each Tool accepts only the exact preparation ID/digest and a
signed preprovisioned-account receipt reference. Immutable registries and every request path
re-resolve the current preparation, installed adapter, account receipt, Target profile, specialist
profile, and executor. The Tool derives the request identity from the exact specialization, agent,
Target, and canonical parameters; a caller cannot supply a route, payload, policy, transport, or
account-creation operation.

Each Capability has all seven authority roles. The materializer and action compiler can produce one
deterministic `PreparedCapabilityAction`; Tool `prepare`/`interpret` and the executor, normalizer,
oracle, replay, and cleanup roles reject execution until a later one-shot binding exists. A signed
Range lifecycle activation admits exactly one current specialist release and rechecks it on each
use. The fixed 100 request-unit charge is a conservative bound rather than measured Worker cost.

No Grant, approval authority, Permit, Gateway, Worker, browser/network dispatch, Evidence, Finding,
Graph write, report, SARIF, PoC, or delivery authority is created. The prepared action remains a
non-bearer deterministic input to durable planning.

## Phase 003C3B1: implemented durable awaiting-Permit plan

Planning accepts the original live reservation handle and the exact C2 preparation, C3A activation
and action, Campaign, live `CapabilityLedger`, one-call non-delegable child Grant, approval envelope,
and verified current Graph head. It reruns the C2 and C3A resolution paths and binds the complete
Campaign, Target, profile, executor, Capability, request, budget, Grant, MissionEnvelope, proposal,
Graph Decision, approval, and expected-Permit tuple.

The Grant must be unrevoked, currently consumable, exactly T2, scoped to one Tool and one Target,
limited to one call, and assigned to the exact specialist agent and Campaign. Its identity is
uniquely reserved by the plan, but the ledger call is not consumed. The approval envelope is
strictly matched and currently within its declared window, but it is not treated as signed,
verified, or consumed approval.

The current schema-version-6 coordination Store retains the same content-addressed plan semantics:
it inserts one plan in `awaiting-permit`, consumes the original process-local reservation handle,
and returns one non-copyable, non-serializable, store-local `VerifiedSpecialistDispatchPlan`. The
durable specialist execution row remains `reserved`. Unique constraints prevent reuse of the
reservation, command, preparation, prepared action, request, Grant, approval, proposal, or expected
Permit. Restart exposes only an audit row and never reconstructs either one-use handle. Schema v6
adds later JobAttempt and terminal-receipt classification; it does not reinterpret this v1 plan as
v2 execution authority.

The process-local plan handle also captures the exact specialist deployment object that existed at
planning. A later bind cannot transfer the plan to a replacement deployment even if its serialized
inputs are equal.

The plan keeps approval, Permit, Gateway, Worker, execution, Finding, Graph, and automatic-
redispatch authority false. C3B1 creates or consumes no Permit, consumes no Grant call, performs no
Gateway/Worker/Target I/O, and exposes no transition to the future outcome-unknown plan states.

## Phase 003C3B2: implemented one-winning Permit callback and durable crash fence

Specialist execution is opt-in when `AgenticCoordinationStore` is constructed. Its all-or-none
deployment inventory owns the exact concrete `SQLiteGraphStore`, that object's exact
`SQLiteGraphActionPermitStore`, the exact live `CapabilityLedger` and its record/lock/clock
identity, an immutable ACTION_APPROVER key ring, and the approval clock. Opening the same database
path through another Graph Store is not equivalent authority. Planning and binding both require
the pinned Ledger object.

The deployment and approval trust-root handles are immutable, non-copyable, and non-serializable.
The Store, plan, and dispatcher separately pin the exact process-local runtime identity, including
the Graph/Permit objects and file identity, Ledger internals, approval key-ring mapping and
recomputed digest, approval clock/lock/registry, and the pinned unbound registry methods. An
internal same-path Graph/Permit swap or approval authority, key-ring, clock, registry, or method
replacement fails before approval, Permit, or Grant consumption.

`bind_specialist_permit_dispatcher()` requires the original plan handle, exact Campaign,
preparation, activation, prepared action, pinned live Ledger and child Grant, the exact
`SignedWebActionApproval` artifact, and the verified current Graph head. The public binder accepts
no caller-selected Graph Store, Permit Store, approval verifier, policy, writer, or dispatcher.
The deployment key ring checks the signature and exact `source` approval tuple; an unregistered
self-signed key fails before Permit or Grant consumption.

On its first valid binding, the deployment seals one complete three-specialist
`ActionCapabilityRegistry`, one complete read-only approval-policy registry, one compiler identity,
one `GraphApprovedActionPermitAuthority`, and one `GraphApprovedActionPermitDispatcher`. Later
plans reuse that shared Permit writer while keeping exact per-plan approval verification. Rebinding
the same signed approval returns the deployment's canonical verifier for that approval identity.
The first bind additionally fixes the shared Permit-authority clock and a code-owned 30-second TTL;
neither may be replaced for later plans.
The returned factory-only `VerifiedSpecialistPermitDispatcher` pins those objects, the live Ledger
and Grant, and the plan. Binding claims no Permit and consumes no Capability budget.

`dispatch_specialist_permit_once()` revalidates the current Graph and durable heads, complete
history, awaiting plan, reserved execution row, Campaign, preparation, activation, current profile
and executor catalogs, prepared action, signed source approval, concrete Graph Store, and live
one-call Grant before claiming the plan callback. The Graph dispatcher remains the one-winning
authority: its separate Graph transaction verifies the approval and current Decision, consumes
budgets, and commits the single-use Permit plus approval-consumption receipt before the callback.
An exact terminal retry never invokes the callback again.

Inside the first callback, the Store strictly reloads the Permit and approval receipt, repeats the
current authority checks, and holds its coordination write transaction and the exact live Ledger
lock. It snapshots the child Grant and ancestor lineage, consumes the child call, and proves that
each same, unrevoked record decreased by exactly one. It then constructs one content-addressed
`AgenticSpecialistCapabilityGrantConsumptionReceipt` binding the Store, coordination deployment,
plan, reservation, command, child Grant, Permit, approval receipt, one consumed call, and
consumption time. The Store compare-and-swaps that receipt and both rows:

```text
dispatch plan:        awaiting-permit -> dispatch-started-outcome-unknown
specialist execution: reserved        -> dispatch-started-outcome-unknown
```

Successful strict reload requires
`plannedAt <= permit.issuedAt <= permit.consumedAt <= callbackEnteredAt <= grantConsumedAt`.
A clock-rewound Permit issued before the plan may be reconciled only as terminal Permit evidence;
it cannot consume the Grant, publish a Grant receipt, or enter either dispatch-started row.

The two coordination rows and Grant-consumption receipt commit atomically with each other, but not
with the earlier Graph transaction or the in-memory Ledger. A post-Grant row-CAS failure rolls back
both rows and publishes no receipt while leaving the child and ancestor Capability budgets burned.
The callback never refunds or recredits that budget.

After strict reload, the callback returns a distinct non-copyable, non-serializable, store-local
`VerifiedPlannedSpecialistDispatchStarted` binding the plan, execution row, Permit, approval
receipt, and Grant-consumption receipt, and consumes the original plan handle. Its own transfer is
an atomic one-shot operation under an internal lock. Neither this audit state nor a raw plan,
Permit, receipt, dispatcher result, or legacy `VerifiedSpecialistDispatchStarted` is sufficient
Gateway or Worker authority. The plan-bound handle is only the future C3C input.

If an exception occurs after the Graph transaction may have committed, the sealed runtime reads
the exact terminal authorization directly from its pinned Permit Store. When the terminal approval,
Permit, and receipt match but callback entry is not durable, it advances only the plan to
`permit-consumed-entry-unknown`; the specialist execution remains `reserved`, no started handle is
returned, no Grant-consumption receipt is invented, and automatic retry is forbidden. That state
does not claim whether the live Grant was consumed. A hard process failure before this in-process
reconciliation can still leave an audit-only `awaiting-permit` row beside a terminal Graph
authorization. Restart reissues no Ledger, plan, Permit-dispatcher, Grant-receipt authority, or
started authority and performs no automatic reconciliation, refund, reissue, or redispatch.

C3B2 performs no Gateway, Worker, browser, network, or Target I/O and creates no Evidence, Finding,
Canonical Graph admission, report, SARIF, PoC, or delivery artifact.

## Phase 003C3C foundation: implemented durability and non-executing conformance contracts

The first C3C slice deliberately separates a serializable audit record from runtime authority.
`AgenticSpecialistDispatchBinding` binds the exact C3B2 execution, plan, reservation, command,
preparation, profile, executor, Capability, Tool, request, Grant-consumption receipt, Permit,
approval receipt, specialist Task, Target, and deployment identities. Every approval, Permit,
Grant, Capability, Gateway, Worker, execution, Evidence, validation, Finding, Graph, reporting,
SARIF, PoC, caller-authored-input, serialized-bearer, and Target-I/O marker remains literal false.
Reconstructing an equal wire never reconstructs authority.

The Store separately issues one private, non-serializable capsule. A deployment registry accepts
it only from the exact Store live-set, exact pinned database object, and exact owner
`asyncio.Task`. Transfer removes the Store live-set entry. Consumption rechecks the exact binding,
registry entry, capsule token, Store and database identity, Permit, Grant lineage, current profile
and executor, and advances only `AVAILABLE -> CONSUMED`. Retirement or terminal authority drift
advances to `RETIRED`; task completion and Store closure abandon remaining capsules. None of these
states claims Worker success. Restart, a different task, an equal object, a raw audit binding, or a
serialized handle receives no runtime authority.

The initial specialist Worker conformance contract accepts exactly ten secret-free references:
execution, binding, preparation, profile, executor, Capability, Tool, request, Permit, and
Grant-consumption receipt. It rejects route, payload, egress policy, transport, and catalog fields
at any depth. Its deterministic `WorkerJob` uses `NetworkMode.NONE`, has no egress or secret
request, and must be exactly recompiled immediately before any future handoff. Its deployment-key
signed output binds every reference while keeping backend invocation, Target I/O, production
authority, independent validation, Finding, Graph, report, SARIF, and PoC literal false. It is a
conformance statement, not Evidence or an execution result.

### Additive SQL-injection v2 Plan/Permit and private runtime claim

The v2 path accepts only the current signed SQL-injection v2 activation and exact prepared action,
creates a distinct durable runtime generation, and enters its Grant, signed approval, and Permit
callback on the creating scheduler Task. It never reinterprets a v1 artifact.

After transfer, the capsule remains Store-owned. This predecessor one-shot claim requires the exact Store,
database, owner Task, token, current Graph and durable history, deployment, preparation/action,
approval, terminal Permit, and Grant lineage. Success and terminal failure both retire the capsule.
This predecessor claim yields no bearer authority, mints no JobAttempt by itself, and performs no
model, browser, network, Gateway, Worker, backend, or Target I/O.

In this contract, Store close means invocation by the trusted owner through the exact unbound close
implementation captured during trusted composition. Ordinary `store.close()`, context-manager exit,
and finalizer cleanup are convenience paths and do not independently prove authority zeroization
under pre-call Python runtime mutation.

### Schema-v6 JobAttempt and typed verification foundation

The additive SQL-injection v2 path now binds its exact Tool and Capability Definition to a complete
seven-role code-backed authority set. A lifecycle registry admits one externally signed current
experimental release for Range use, produces one content-addressed activation set and exact action
registry, and deterministically compiles one `PreparedCapabilityAction` from sealed preparation and
account-receipt references. Only the materializer and action compiler may perform this preparation;
direct Tool dispatch and the executor, normalizer, oracle, replay, and cleanup authorities remain
fail-closed before I/O. The activated action provides no Grant, approval, Permit, durable plan,
Gateway, or backend authority. Existing v1 artifacts remain inert and cannot be upgraded after
planning or Permit issuance.

Schema v6 persists one canonical `AgenticSpecialistJobAttempt` and at most one canonical terminal
receipt. The JobAttempt pins the exact Store/database/deployment/control-plane Run, Campaign and
Graph Snapshot, scheduler Task name and opaque token digest, runtime-capsule token digest,
preparation/action/release/activation, Capability definition/runtime digest/complete authority-set
ID and digest, Tool, request, full Grant/approval/Permit/dispatch lineage, dispatch binding, Target,
Gateway, backend, immutable image, verifier, Worker job, and runtime inventory.

Claim and dispatch verification are complete typed canonical preimages embedded in the attempt and
also denormalized by indexed ID and digest. Their acyclic identity graph is:

```text
canonical claim subject
    -> claim verification
    -> immutable JobAttempt identity and claimed-state digest
    -> dispatch verification
    -> dispatch event and started-state digest
```

The one-way attempt transition is `claimed-before-backend -> dispatch-started-outcome-unknown`.
The closed terminal grammar distinguishes abandonment before backend, proven failure before Target
I/O, verified completion after Target I/O, proven failure after Target I/O, and an unknown started
outcome. Normal Store opening rejects v5; the explicit offline v5-to-v6 migration preserves legacy
rows and creates empty v6 tables only after exact v5 and v6 schema validation. Recovery validates
history and classifies unreceipted attempts and immutable receipts but never remints a Task, capsule,
handle, Gateway, backend, or dispatch authority.

Detached record builders remain audit-only and their opaque-token digests do not prove that live
objects remain available. In contrast, the Store-owned live admission below derives its opaque Task
and capsule token digests from exact process-local objects and performs current-state observation.
Neither its durable row nor an equal reconstructed value becomes bearer authority.

### Live pre-backend admission and abandonment

The public `VerifiedSpecialistGatewayDeploymentV2` is an opaque deployment token. It exposes no raw
backend, verifier, verification key, job template, or execution inventory reference. Those exact
objects remain in a private control-plane owner vault and are compared by object identity against
separate factory anchors. The public `VerifiedSQLSpecialistJobAttemptClaimV2` likewise exposes only
its audit-only JobAttempt and retains no Store, runtime context, deployment, or deployment lease.
The Store live-set privately retains those objects until consumption or retirement.

The exact scheduler Task may mint one claim only after the Store rechecks current Graph and durable
history, Campaign and prepared action, approval and terminal Permit, complete Grant lineage, runtime
capsule, deployment, inventory, backend, image, job, verifier, and verification key. The resulting
durable JobAttempt is `claimed-before-backend`; its embedded `ClaimVerification` is typed audit data,
not a separate bearer handle. This mint performs no backend, Worker, browser, network, or Target I/O.

Owner-Task completion, trusted Store close, explicit discard, and post-insert mint failure use a
Store-authorized producer to append `abandoned-before-backend` with Target I/O `not-started`,
`succeeded=false`, and `backendTerminalProven=false`, then retire the claim, deployment lease, and
private owner. This receipt is not backend provenance. A receipt-writer failure, or a hard process
failure after JobAttempt commit and before receipt commit, can leave an unreceipted claimed audit row.
Recovery never synthesizes a receipt, reconstructs a handle, or authorizes automatic redispatch.

The private owner vault is a control-plane interpreter TCB and drift-detection boundary, not a
sandbox against arbitrary same-interpreter reflection. Untrusted LLM, Skill, plugin, target, and
payload code must never execute in that interpreter and must remain out-of-process or sandboxed.

### Structured v2 fake backend conformance

The structured fake backend derives a contract implementation digest from the exact bytes of
`specialist_backend_v2.py`. That digest participates in the content-addressed Gateway, backend,
compiler, verifier, fake-image, job-template, execution-inventory, launch-envelope, and result
identities. The inventory pins the compiler, network-disabled immutable image, exact job template,
backend, output-verifier ID/digest, and deployment-owned Ed25519 verification key. The fake
backend accepts its launch envelope exactly once, including terminal rejection paths, and the
verifier checks the signed canonical result against every pin.

The signed result reports `conformance-completed-no-target-io`. When the separately pinned output
verifier accepts it, the result proves only that the fake backend signed its terminal conformance
statement; Target I/O, secret requests, production authority, Gateway authority, execution
authority, independent validation, Finding, Graph, report, SARIF, and PoC remain false. It performs
no model, browser, network, or Target I/O. This is not a specialist Gateway/Worker success and cannot
be persisted as `completed-verified`, which requires performed Target I/O and authorized result
proof. The current terminal grammar intentionally has no durable conformance-success kind.

Because its exact source bytes now participate in these v2 identities,
`specialist_backend_v2.py` is frozen for this version. A semantic or formatting change requires a
successor version and regenerated identity set rather than an in-place edit.

### Live zero-I/O execution and terminal provenance

The Store's public execution entry accepts only the exact live claim on its creating scheduler
Task. It consumes the claim once, rechecks current Graph and authorization lineage, observes the
factory-anchored Gateway inventory again, and commits
`claimed-before-backend -> dispatch-started-outcome-unknown` before the first backend await. No
Store, Ledger, or Gateway registry lock is held across that await, while the Store lifecycle lease
remains active to fence close.

The public deployment and claim still expose no raw runtime object. The private Gateway builds the
launch envelope from the durable marker, permanently spends the structured backend, verifies the
Ed25519 result against the exact envelope, verifier, key, template, image, and inventory, then
returns only a non-copyable, non-serializable, same-Task one-shot completion. The Store receipt
producer accepts that opaque provenance rather than caller-supplied signed-result or proof models.
The generic receipt writer separately rejects a proven terminal receipt without its private
proof-provenance insertion authority.

A verified `conformance-completed-no-target-io` statement is durably classified as
`failed-before-target-io`, never `completed-verified`. Backend failure or cancellation after the
marker records `started-outcome-unknown`; a failure to commit the verified terminal receipt leaves
the started attempt unreceipted and unknown rather than downgrading or synthesizing proof. Every
path retires the live claim, deployment lease, and private owner and forbids automatic redispatch.
This completes the governed lifecycle for the structured zero-I/O backend only. It is not proof of
the SQL-injection target action, independent Evidence, or promotion authority.

A fault-injected marker path also covers the split case where SQLite COMMIT succeeds but the marker
call does not return its started value. Durable row equality rejects false pre-backend abandonment;
recovery observes an unreceipted unknown attempt, the backend remains uninvoked, and no redispatch
authority is reconstructed.

The current cancellation regression classifies a `CancelledError` raised inside the pinned
zero-I/O backend path after the durable marker. Because that fake backend has no real suspension
point, this evidence does not yet cover scheduler `Task.cancel()` racing a suspended target-I/O
operation. The additive target-I/O successor must exercise that race while preserving the same
unknown-outcome, retirement, close-fencing, and no-redispatch rules.

## Required future work

### Target-I/O-capable specialist Gateway and Worker successor

The next additive slice must leave the identity-bearing `specialist_backend_v2.py` unchanged. A new
versioned Worker/Gateway contract must independently resolve its code-owned SQL-injection plan,
profile, executor, browser/network transport, target attestation, and cleanup; accept no
caller-supplied observation, route, policy, payload, catalog, transport, backend, image, verifier,
result, or proof; and preserve the implemented same-Task claim, dispatch marker, opaque completion,
terminal receipt, cancellation, close, and no-redispatch boundaries. Only after those pins pass may
the exact approved SQL-injection flow run against the local Juice Shop target.

### 003D: independent validation and promotion

Use a fresh account or session, separate Permit, independent executor identity, controls, and
semantic oracle. Only independently validated results may enter Finding promotion or Graph
admission. Reports, SARIF, and redacted PoCs must project deterministic admitted state; model prose
remains non-authoritative.

## Invariants

- Profile resolution never performs target I/O.
- ID-only, partial, `latest`, fallback, dynamic registration, and model-authored profiles are
  rejected.
- The exact adapter pair must remain installed in the exact production adapter catalog.
- Hidden Pydantic state, model/container/primitive subclasses, digest drift, reordered or cyclic
  dependencies, and self-consistent closure substitution fail closed.
- A supporting dependency is not automatically promotable.
- Every specialist request phase must match the exact complete contiguous profile sequence.
- A receiver inbox receipt without matching acknowledged outbox state is not assignment authority.
- A reservation, awaiting plan, or outcome-unknown audit row never reconstructs a one-use
  process-local handle.
- Stale durable or Graph heads fail before reservation, planning, or dispatch-state transition.
- Inert preparation neither consumes the reservation nor changes durable execution state.
- A raw preparation or audit entry cannot reserve, begin, or dispatch specialist execution.
- Foreign, stale, or consumed reservation handles fail before code-owned route resolution.
- Each specialist Capability has one exact Tool, complete authority set, current signed Range
  release, immutable preparation inventory, and code-owned request identity.
- A `PreparedCapabilityAction` is not a Grant, approval, Permit, Gateway binding, or execution
  authority.
- Planning consumes the original reservation handle, leaves the durable execution row `reserved`,
  and returns exactly one non-serializable plan handle.
- An awaiting plan binds but does not verify or consume its approval envelope, Permit, or child
  Grant call.
- C3B2 accepts only a signed approval artifact and resolves it through the deployment-owned key
  ring; the caller cannot choose its verifier, Graph Store, Permit Store, policy, writer, or
  dispatcher.
- The deployment pins the exact Graph Store object, Permit Store, live Ledger, complete three-
  specialist Capability/policy registries, compiler identity, and shared writer. A same-path Graph
  wrapper is foreign authority.
- The Graph approval/Permit transaction is separate from the atomic coordination plan/execution
  transaction; neither transaction implies the other completed.
- Only the first approved callback consumes the child and ancestor Capability call budgets. A
  successful crash-fence commit records the exact child Grant consumption in the plan-bound
  receipt after checking every locked ancestor's one-call decrease. The receipt does not enumerate
  the ancestor snapshots. A post-consumption commit failure publishes no receipt and never refunds
  or recredits any consumed budget.
- `permit-consumed-entry-unknown` proves terminal Permit evidence but no callback entry, execution,
  or durable Grant-consumption result and therefore contains no Grant-consumption receipt.
- Raw plans, Permits, receipts, dispatcher results, legacy started handles, and reopened audit rows
  cannot replace the distinct plan-bound started handle at the future Gateway boundary.
- Concurrent consumers can transfer a plan-bound started handle at most once.
- The serializable C3C binding is audit-only. Only the exact Store-issued capsule in the exact
  Store/DB/owner-Task live-set can enter the foundation registry, and it is consumed at most once.
- Foundation `AVAILABLE`, `CONSUMED`, and `RETIRED` states are capsule lifecycle states, not
  Gateway, Worker, execution, Evidence, or success claims.
- The foundation Worker job is network-disabled, secret-free, and deterministically recompiled;
  its signed output is a conformance statement and cannot become Evidence or Finding authority.
- The additive SQL-injection v2 bundle has exactly seven code-backed authority roles, a current
  signed Range release activation, one exact action registry, and deterministic
  `PreparedCapabilityAction`. Only its materializer and action compiler prepare that non-bearer
  action; it is not a Grant, approval, Permit, plan, Gateway binding, or backend authority.
- The distinct v2 Plan/Permit chain is generation-exact and same-Task; no v1 plan, Permit,
  activation, action, or started handle can be reinterpreted as v2 authority.
- A transferred v2 capsule remains Store-owned. Its predecessor runtime claim can be entered exactly
  once, revalidates current authority, and is retired after success or terminal rejection without
  itself minting a JobAttempt or public C3C authority.
- The exact scheduler Task can turn that predecessor claim into one durable `claimed-before-backend`
  JobAttempt and one opaque live claim. Public deployment and claim objects expose no raw runtime
  component, and retirement purges the private owner vault.
- A schema-v6 JobAttempt embeds the exact typed claim and dispatch verification preimages and pins
  their separately indexed IDs and digests. Its canonical bytes, database row, or recovery view are
  not bearer authority.
- Store-owned live-handle minting derives opaque Task and capsule token digests from exact live
  objects. Caller-built records or equal digests cannot substitute for that boundary.
- Store-authored pre-backend abandonment receipts are closed classifications, not backend
  provenance. A proven backend-result receipt requires the Gateway-minted opaque completion and the
  Store's private proof-provenance insertion authority; raw signed models are insufficient.
- The structured fake backend is one-call, source-byte-addressed, Ed25519-signed, and Target-I/O-
  zero. Its `conformance-completed-no-target-io` result is neither Gateway/Worker success nor
  `completed-verified`, and no durable conformance-success terminal kind exists.
- The exact bytes of `specialist_backend_v2.py` are frozen for this v2 identity; changes require a
  successor contract and regenerated pins.
- Duplicate reservation, command, preparation, action, request, Grant, approval, proposal, and
  expected-Permit identities cannot produce a second plan.
- The specialist browser creates no account and uses only supplied preprovisioned credentials.
- SQL-login and object-access phases accept only their exact code-owned endpoint, method, and
  per-phase request boundaries.
- The production target-I/O executor catalog remains non-executable even though the v2
  Plan/Grant/approval/Permit path and the structured zero-I/O governed execution lifecycle exist.
  Target activation requires an additive versioned Worker/Gateway with exact target attestation,
  code-owned route/payload/policy/transport, cleanup, and result-verifier pins; it cannot mutate or
  reinterpret the frozen fake backend.
- Profile, Skill, lifecycle command, and Supervisor selection never mint Scope, Capability, Permit,
  Gateway, Worker, Evidence, Finding, Graph, report, or delivery authority.

## Negative cases

The implementation rejects unknown or stale references, substituted Skill identity fields,
substituted adapter/catalog identities, modified closures and Finding categories, noncanonical
dependency order, authority-marker coercion, direct catalog construction, catalog mutation, and
runtime-shape smuggling. It also rejects the aggregate browser entry point, production binding,
unknown/reordered/missing/repeated request phases, extra diagnostic policies, browser Evidence for
the SQL-only profile, authorization dependency failure before object-access I/O, unacknowledged or
terminal assignments, stale verification handles, concurrent duplicate reservation, handle copy or
serialization, restart authority reconstruction, state rewind, automatic redispatch, raw audit rows
at the preparation seam, foreign/stale/consumed reservations, unsupported specialist routes, wrong
Campaign/Target/Scope/budget identities, account-semantics drift, and broadened SQL/object-access
policies. The C3A boundary additionally rejects incomplete Tool inventories, unsigned or foreign
account receipts and adapters, stale lifecycle releases, substituted request identity, mutable or
drifted preparation inventories, and every premature execution-role call. C3B1 rejects foreign or
consumed handles, stale Graph or durable heads, non-current preparations/actions/releases,
overbroad or spent Grants, mismatched Campaign/Target/profile/budget/approval tuples, expired
windows, and duplicate reservation/action/request/Grant/approval/proposal/Permit identities. C3B2
additionally rejects a foreign, unsigned, or untrusted-key source approval; caller-supplied or
same-path Graph replacements; substituted Permit Store, verifier, policy, or writer; stale Graph or
durable head; changed preparation/action/profile/executor; foreign or consumed plan handle;
changed Ledger/Grant lineage; inactive Permit; noncanonical Permit, approval receipt, or Grant-
consumption receipt; and callback or started-handle races. Pre-consumption rejection leaves
Capability budget unchanged. A post-consumption failure is terminal, may burn Capability budget,
publishes no false Grant receipt, and can only enter the non-executing reconciliation state. These
failures perform no model, production browser, governed network, Gateway, Worker, or Target calls.

The C3C foundation additionally rejects reconstructed-equal bindings, a foreign Store, database,
task, registry entry, capsule, token, Permit, Grant lineage, profile, executor, or hidden model
state; duplicate transfer or consume; task-completion and close races; executable input fields;
non-code-owned identity families; modified image, network, egress, secret, or limits; foreign
signing keys; and signed-output drift. Every rejection remains Target-I/O-zero.

The additive SQL-injection v2 activation boundary rejects an incomplete or substituted authority
set, a foreign or v1 release, non-Range or non-current lifecycle state, activation-set drift,
lifecycle/definition/action-registry replacement, preparation or account-receipt drift, and direct
Tool or non-preparation authority calls. Those failures occur before Gateway, browser, network, or
Target I/O.

The v2 planning and private-claim boundary additionally rejects v1 or mismatched runtime generation,
stale activation/action, foreign or reconstructed plan/started handles and capsules, duplicate or
post-close claims, non-owner Tasks, current Graph/history/deployment drift, expired or revoked
approval/Permit/Grant lineage, and replacement of pinned Store, activation, or capsule entry points.
A terminally rejected claim consumes and retires its capsule and performs no Target I/O. Ordinary
direct close, context-manager exit, and finalizer cleanup are not accepted as zeroization proof under
pre-call runtime mutation; only the trusted captured-close boundary is authoritative.

The schema-v6 attempt boundary additionally rejects typed verification preimage drift, indexed ID or
digest disagreement, authorization-lineage or runtime-inventory substitution, noncanonical state
advance, receipt/attempt mismatch, terminal rewrite, implicit schema-v5 opening, and recovery-based
handle reconstruction. The structured backend rejects source, compiler, image, job, backend,
verifier, key, launch-envelope, signature, or result drift and any second invocation. A zero-I/O
result labeled `completed-verified`, a caller-authored terminal proof, or a detached record presented
as a live claim must fail before production Gateway, browser, network, or Target I/O.

The implemented 003C3C-live zero-I/O boundary rejects a missing or foreign live v2
JobAttempt/ClaimVerification handle, unsupported profile, dependency-closure mismatch, specialist
binding drift, and same-Task Gateway/backend/verifier mismatch before Target I/O. The additive
target-I/O successor must preserve those regressions.
Phase 003D must prove that failed independent validation produces no Finding, Graph admission,
report, SARIF, or PoC promotion.

## Migration and rollback

The current local pre-release coordination schema is version 6. It retains the v5 Grant-consumption
receipt and plan semantics and adds JobAttempt and terminal-receipt tables plus strict indexed
verification identities. Normal Store opening rejects v5. The explicit offline
`migrate_agentic_coordination_schema_v5_to_v6()` operation requires the exact Store identity,
coordination binding, frozen complete v5 schema and digest, SQLite metadata and integrity, and an
exclusive transaction. It preserves every legacy row, creates empty v6 tables, validates the
complete v6 schema, and rolls back on disagreement. It creates no attempt, receipt, Task, capsule,
Gateway, backend, or execution authority. Version 4 and older drafts remain unsupported.

Rollback disables v2 planning admission, attempt minting, structured-backend registration, and any
future Gateway path without deleting or rewinding schema-v6 durable state. It cannot remove a
published Grant receipt or terminal receipt, refund Capability budget, undo a consumed approval or
Permit, rewrite an outcome-unknown attempt, downgrade to v5, replace the shared writer, or reissue
process-local authority. Existing capsules and live handles must be abandoned rather than migrated
or reconstructed. `specialist_backend_v2.py` must remain byte-identical for its current identity;
replacement requires a successor version. C3C-live still requires its own activation, recovery, and
Target-side rollback contract before execution.
