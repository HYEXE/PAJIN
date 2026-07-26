# ADR 0027: Independent restricted reproduction as the confirmation boundary

- Status: Accepted
- Date: 2026-07-15
- Amended: 2026-07-16 — Added the M6-05 negative KISA retest and M6-07A explicit
  Local KISA orchestration boundaries
- Implementation: In progress; restricted replay, the receipt-reloading common confirmation/retest
  gates, append-only versioned validation projections, exact KISA fresh-session integration,
  baseline-bound negative KISA retest, durable Local SQLite ticket verification, and explicit
  single-process Local KISA orchestration are implemented. The dedicated exact-KISA Control Plane
  claim → permit → execute/seal → server import/finalize → one-item common Gate slice is also
  implemented. Public Replay admission/read APIs, automatic fresh-identity retry issuance,
  negative Control Plane retest, and additional Modes remain planned
- Amends: [ADR 0025](0025-candidate-validation-ledger-and-replay-boundary.md), [ADR 0026](0026-trusted-kisa-candidate-admission.md)
- Clarifies: [ADR 0004](0004-dynamic-multi-agent-execution.md)
- Product baseline: [PAJIN Notion roadmap](https://app.notion.com/p/3a94b2ea35f081329974c7f57eda299a)

> **Normative security correction (2026-07-19):** A typed transcript, Worker/proxy receipt,
> ticket finalization, hash, and local seal establish internal consistency and lineage only. They
> do not establish that the intended target executed outside the source/replay Worker trust domain.
> Product confirmation therefore also requires independently verifiable execution/target
> attestation. Because no such verifier exists in the repository today, every Local, CLI, and
> Control Plane Worker-only supporting replay is capped at `needs-review` with
> `independent-execution-attestation-missing` and `verified-replay-evidence` semantics. Likewise,
> negative target transcripts—including the public deterministic-lab response tuple—cannot prove
> remediation and remain `inconclusive`. This correction supersedes any `CONFIRMED` or `FIXED`
> promotion rule described below; those passages record the earlier design.

## Context

The product baseline requires PAJIN to reproduce and independently validate a Candidate before it
is reported as confirmed. Reviewing an existing transcript with a different prompt or model can
detect unsupported claims and semantic mistakes, but it does not prove that the behavior is
reproducible. Semantic agreement over one execution is evidence review, not independent
reproduction.

ADR 0025 introduced the Candidate and Decision ledger, and ADR 0026 added trusted KISA Candidate
admission. Both boundaries remain necessary. Their interim confirmation rule, however, permits a
matching semantic Validator result plus the objective evidence gate to create `confirmed` without a
second execution. That rule conflicts with the product baseline.

Giving an LLM Validator general attack Tools does not correct the conflict safely. It would allow
untrusted evidence and model output to influence executable commands, targets, arguments, and
Capabilities. Independent reproduction therefore needs a separate, constrained execution boundary.

## Decision

### Confirmation invariant

A Candidate can become product-level `confirmed` only when all applicable conditions hold:

1. a trusted producer or compatibility adapter admits the Candidate with bounded provenance;
2. the objective Scope, target, request, and evidence gate passes;
3. a separate reproduction execution creates a successful `ReplayOutcome` bound to that Candidate;
4. the reproduction uses a new request identity and distinct evidence lineage;
5. a Mode-owned typed Oracle supports the precise claim from the reproduction observation; and
6. when the Mode declares semantic interpretation necessary, the Semantic Validator also supports
   the claim.
7. an authority outside the source/replay Worker trust domain independently attests execution by
   the intended target.

Semantic support, original evidence strength, producer admission, repeated Specialist observations,
or human confidence cannot replace the successful `ReplayOutcome` and independent execution
attestation. A separate Run, request ID, process, backend instance, or locally sealed receipt is not
by itself a separate trust domain.

### Validator is a pipeline, not one LLM agent

The product-level Validator consists of separated roles:

1. **Candidate Producer** admits observations from typed Mode contracts. It has no Provider, Tool,
   process, or replay authority.
2. **Semantic Validator** receives a bounded, redacted Validation Packet and evaluates the claim,
   evidence, impact, and reproduction conditions. Its only executable capability is its Provider
   call.
3. **Replay Compiler** resolves a typed, non-executable `ReplayIntent` against the Candidate, the
   original Specialist request, a registered Mode scenario, and an allowlisted Tool template.
4. **Restricted Reproducer** receives a dedicated replay Grant and executes the compiled operation
   through the ordinary Tool Gateway and Worker boundary.
5. **Mode Oracle and objective gate** evaluate the new observation and determine the final
   disposition.

For an exact replay, PAJIN should derive `ReplayIntent` deterministically from the trusted Plan and
original Tool request. A Semantic Validator may recommend a typed intent or bounded comparison
criteria, but it cannot emit a raw `ToolRequest`, command, process path, arbitrary URL, Capability
Grant, or executable code.

### Replay binding and authority

The Replay Compiler must bind all of the following before PAJIN issues a Grant:

- Candidate ID, original Run ID, target ID, Tool ID, scenario ID, and threat class;
- the exact original operation and allowlisted arguments, with secrets represented only by leases;
- Campaign Scope, deny rules, risk tier, expiry, call budget, and cancellation state;
- session reset or preserved preconditions defined by the Mode contract; and
- the expected typed observation and Oracle contract.

The Reproducer cannot reuse the Specialist Grant. It receives a new, shorter-lived Grant limited to
the compiled target and operation. It cannot broaden the target, choose a new Tool, add attack
steps, or follow instructions found in evidence. Every replay produces a new request ID, audit
events, and evidence records linked to both the Candidate and original request.

Automatic replay is limited to operations that explicitly opt in as replay-safe and idempotent and
that remain within T0-T2. T3/T4, non-idempotent, destructive, ambiguous, or unregistered operations
require an approved future manual-reproduction contract and cannot run automatically.

### Disposition rules

| Condition | Disposition | Required reason |
| --- | --- | --- |
| Semantic support and objective gate pass, but replay has not run or is not implemented | `needs-review` | `independent-reproduction-missing` |
| Operation is not replay-safe or requires approval | `needs-review` | `replay-not-eligible` or `replay-approval-required` |
| Replay is cancelled, times out, is rate-limited, the target is unavailable, or a non-deterministic miss cannot decide the claim | `inconclusive` | bounded execution reason |
| Replay Oracle supports the claim, the objective gate passes, and Semantic Validator support exists when required by the Mode | `confirmed` | successful ReplayOutcome reference |
| Scope, provenance, identity, or evidence binding fails | `rejected-objective` | objective gate reason |
| A typed Oracle deterministically contradicts the exact claim | `rejected-objective` | Mode Oracle reason |

A single negative replay does not prove rejection when the Mode declares the behavior stochastic.
The Mode contract must define repetition count, threshold, session policy, and comparison rules. An
unexplained or non-deterministic mismatch is `inconclusive` or `needs-review`, not an objective
rejection.

`findings.json` remains a compatibility projection, but only Decisions satisfying this ADR may
enter it after migration. Candidate preservation, duplicate triage, reporting state, and retest
state remain separate concerns.

### Retest invariant

Whether a reproduction-backed `confirmed` Finding has been fixed is recorded as a separate retest
lifecycle result without rewriting its confirmation disposition. At the confirmation Gate, a typed
Oracle's `contradicts` verdict is grounds for objective rejection of the Candidate; at the Retest
Gate, a verified `contradicts` verdict exactly bound to a sealed Confirmed baseline is grounds for
`fixed`. Historical Confirmed Decisions and Findings remain immutable history and are not
reinterpreted as `rejected-objective`.

The Retest Gate requires all of the following:

1. the baseline must contain a sealed `validation/v1alpha1` reproduction-backed Confirmed
   Decision/Finding and canonical receipt lineage. Legacy flat Findings, semantic-only Candidates,
   and unreproduced historical confirmations are not allowed;
2. the retest proof binds the exact Candidate, source Decision, versioned Finding, remediation
   action, baseline and retest Runs and integrity roots, original and replay requests, Mode,
   scenario, threat, Tool, and target. A display fingerprint or mutable in-memory record cannot
   substitute for this binding;
3. the normal parent retest covers the functional probe and regression. Only a separate
   Candidate-bound Restricted Replay attack Run and verified canonical receipt determine the
   baseline vulnerability state;
4. `fixed` is recorded only when every contractually required repetition succeeds and the trusted
   negative Oracle for the retest returns `ReplayOracleVerdict.CONTRADICTS` for the original claim.
   A verified `ReplayOracleVerdict.SUPPORTS` verdict means `still-vulnerable`;
5. mixed support and contradiction, a terminal outcome, insufficient repetitions, or missing
   explicit defense evidence yields `inconclusive`. Any Candidate or artifact binding or integrity
   mismatch is not reduced to a lifecycle state; the entire Gate rejects it under fail-closed
   semantics; and
6. functional regression is independent of each Finding's state. Scope-bounded success for
   `kisa-retest` is possible only when every baseline Finding is `fixed`, there are no unresolved
   Findings, no new Findings are observed during execution, and regression is `pass`. This boundary
   is a closed loop over the baseline and does not assess new threat types. The release Gate
   requires a separate fresh discovery Run for currently executable scenarios; unimplemented
   threats remain `not assessed`.

The existing meaning of the positive confirmation Oracle does not change. Zero support, a
non-match, or `supports_claim == false` may remain `inconclusive`; none constitutes negative proof.
A Worker-authored `vulnerable=false` or the mere absence of a compromise marker is also not grounds
for `fixed`. Only a trusted negative Oracle registered to verify an explicit defense result in the
canonical observations for every expected repetition can produce `contradicts`.

The first KISA negative predicates are deliberately narrow: exact deterministic-lab defense
responses registered for M03, M06, and both A04 turns, plus the absence of compromise markers,
tool calls, and memory writes. `safety.blocked` or its reason is not an independent contradiction
signal, and metadata inconsistent with the registered response fails closed. Unknown target wording
remains `inconclusive` until a separately reviewed predicate or trusted policy-enforcement receipt
is registered.

### Human reproduction

Human review cannot change a Candidate directly to `confirmed`. A future manual reproduction path
may confirm a Candidate only if it emits the same typed `ReplayOutcome`, request and evidence
provenance, actor identity, approval record, and Oracle result required of automated replay.

## Mode boundaries

- **KISA AI Red Team:** `ai.chat-probe` is designated as the first restricted-replay vertical slice.
  Reproduction must use the exact catalog scenario and target, a new request identity, a new session where the
  scenario requires isolation, and a separate evidence lineage. The Producer still ignores Worker
  verdict fields and independently recomputes catalog checks. Hardened retest separates the normal
  parent Run from baseline-bound attack Replay and consumes as `fixed` only verified receipts in
  which the trusted negative Oracle explicitly contradicts every expected repetition for the exact
  M03, M06, and A04 baseline Candidates.
- **Bug Bounty:** an existing deterministic control-set Oracle satisfies this ADR only when it
  evaluates a distinct reproduction execution and evidence lineage. Re-reading the original
  Specialist result is not reproduction.
- **CTF:** flag and artifact digest solve validation remains a Mode-specific solve state, not a
  security Finding confirmation. This ADR does not add LLM replay to CTF.

## Current implementation gap and migration

As of 2026-07-15, PAJIN implements Candidate admission, semantic reconciliation, objective evidence
gating, Decision snapshots, final Run sealing, and the first fail-closed migration step. Semantic
support without ReplayOutcome is retained as `needs-review` with
`independent-reproduction-missing` and is excluded from `findings.json`. PAJIN also defines strict,
versioned `ValidationPacket`, `ReplayIntent`, `ModeReplayContract`, `CompiledReplaySpec`,
`ReplayAttempt`, `ReplayOracleResult`, and `ReplayOutcome` contracts. The contracts bind Candidate,
Run, original and replay request, Mode, scenario, Tool, target, and threat identities; reject
executable intent fields and cross-artifact substitution; and give `ValidationDecision` an explicit
ReplayOutcome reference. `ai.chat-probe` Tool interpretation, trusted Candidate production, and
deterministic validation share the same strict `AIChatProbeOutput` contract while recomputing rather
than trusting Worker verdict fields.

The semantic authority boundary is durable as well as in-memory. Each validation phase writes its
exact Validator Agent and Task identity, Findings, and Candidate assessments to
`validator-output.json` in the same sealed source Run. Every assessment binds the exact canonical
Candidate claim digest, and positive support must cite non-empty evidence. For CP-eligible KISA
output adapted from legacy Findings, positive support must cite the Candidate's complete evidence
list and reconcile one-to-one with a validated Validator Finding whose every semantic field is
identical; only the legacy Finding's opaque ID and validation-state field are normalized by the
trusted Candidate-aware adapter. A durable consumer, including Control Plane replay derivation,
must reload those bytes and replay the deterministic Gate; it must not infer or synthesize Validator
support from the Candidate or a stored lifecycle state. This binding proves only what the Validator
assessed. It does not provide independent execution attestation, a successful `ReplayOutcome`,
product `confirmed`, or remediation evidence for `fixed`.

PAJIN also implements a pure deterministic `ReplayCompiler`. It checks the trusted Plan, the actual
Specialist-bound `ToolRequest`, the original Specialist Grant, Candidate evidence, trusted request
and evidence digests, registered Scenario and Tool contracts, Scope, cancellation, authorization,
and remaining repetition budget. It copies only allowlisted original arguments, rejects
secret-bearing fields and known plaintext secret values, and emits a separate five-minute-or-less,
non-delegable, single-Tool, single-target `ReplayCapabilityGrant`. Compiler IDs are deterministic
over the authority-bearing inputs, while Semantic Validator rationale and comparison text cannot
alter the compiled operation.

PAJIN now implements a Restricted Reproducer foundation for stateless operations and explicitly
registered Mode-owned materializers. The Compiler issues
an opaque, single-use ticket bound to the Candidate source seal, Campaign, Tool specification, and
Scenario digest. The runtime atomically claims the ticket, rechecks trusted inputs, executes exact
compiled arguments through the existing Tool Gateway and Worker, and consumes shared Campaign
budget and rate-limit state. Campaign duration and cancellation bound both dispatch and the async
Mode Oracle, while Tool-authored Secret Lease requests fail closed. The runtime accepts only fresh
request evidence whose JSON provenance exactly matches the Gateway and Worker result. A successful
or terminal replay is stored in a distinct replay Run; an initial seal binds the outcome and artifact
set, and a second seal binds a verified receipt that references the first root. A dedicated loader
reopens the Run, verifies both seal roots and canonical artifact digests, and checks ticket-ledger
finalization against the originally issued compilation digest, Candidate source root, and replay Run
instead of trusting a mutable in-memory result. Session-bearing contracts fail closed as
`unsupported` unless an exact trusted Mode session materializer is registered.

The `kisa-run` Multi-Agent path verifies a sealed source Run and coordinates exact M03, M06,
and A04 `ai.chat-probe` Candidates in separate replay Runs. These three scenarios are explicitly
allowlisted; a structural predicate cannot opt future scenarios into automatic replay. The trusted
materializer changes only `session_id`, the Gateway charges every chat turn against the Campaign
request-rate ledger, and the live Oracle recomputes catalog checks from the raw transcript without
trusting Worker verdict flags. After replay, the common gate accepts only replay Run paths, reloads
each twice-sealed receipt with the ticket verifier, checks source-seal membership and exact Candidate
binding, and applies the shared reason matrix. It appends `validation/v1alpha1` Decision, Finding,
index, and Markdown artifacts in a new seal instead of rewriting the flat pre-replay snapshot. The
KISA assessment and replay index consume that projection and expose confirmation basis and receipt
lineage.

M6-07A applies the same exact allowlist and common Gate to the ordinary Local runner only when the
operator supplies `pajin run ... --kisa-replay`. The Local source Run first persists its capability,
budget and request-rate snapshots and completed state, then seals before the coordinator reads it.
Source execution and replay share the same live Campaign budget, request-rate ledger and cancellation
context. Tickets use the stable `<output>/local-replay/replay-tickets.sqlite3` authority, and batch
coverage is verified from canonical receipts before the Gate runs. A missing Candidate or replay
record does not trigger the Gate or create confirmation. The flat `findings.json` remains the sealed
pre-replay snapshot; only the append-only `validation/v1alpha1` projection may gain a
reproduction-backed Confirmed Finding. This path is deliberately one process and one writer. The
default Local command has no implicit replay, generic replay predicate, distributed lock, lease, or
PostgreSQL authority.

The M6-05 `kisa-retest` path reverifies the sealed, versioned Confirmed baseline and executes a
separate Restricted Replay bound to each Finding's Candidate, source Decision, remediation action,
and every authority-bearing identity. It does not reuse the normal parent retest's functional
result as negative proof. The Retest Gate reopens the replay Run's canonical receipt and records
`fixed` only when the trusted negative Oracle `contradicts` every expected repetition; `supports`
means `still-vulnerable`, while mixed or terminal results and insufficient proof close as
`inconclusive`. Binding or seal mismatches hard fail. The remediation plan and events are appended
to the baseline without overwriting the versioned projection or existing seal entries, and the
retest binds the subsequently finalized current root into the receipt. If the baseline changes
after binding, the Gate produces no result.

Durable Local SQLite ticket verification across process restarts and explicit Local KISA
orchestration are implemented. Control Plane replay orchestration and additional Mode integrations
remain follow-up work. Control Plane work must start with ADR 0029 for sealed Artifact handoff,
lease fencing, PostgreSQL batch/item/ticket/event state, source-root CAS, exact Gate finalization,
and durable budget/request-rate state; a local absolute Run path or arbitrary Job result is not an
authority handoff. A CPU-bound production Oracle must still use a separately bounded execution
boundary instead of blocking the cooperative async runtime.

Migration proceeds in this order:

1. **Implemented:** prevent semantic-only Decisions from entering the confirmed compatibility
   projection and retain them as `needs-review` with `independent-reproduction-missing`;
2. **Implemented at the schema boundary:** add typed `ValidationPacket`, `ReplayIntent`, Mode
   contract, compiled replay specification, attempts, Oracle result, and `ReplayOutcome` contracts
   with Candidate and request lineage;
3. **Implemented at the pure compilation boundary:** add the deterministic Replay Compiler and
   replay-specific Capability Grant with fail-closed policy and lineage checks;
4. **Implemented at the standalone runtime boundary:** add opaque single-use tickets, stateless and
   registered-materializer Gateway/Worker execution, fresh evidence provenance, shared
   budget/rate/cancellation controls,
   bounded async Oracle dispatch, Secret Lease denial, distinct outcomes, and a twice-sealed replay
   receipt with a ticket-bound verified loader;
5. **Implemented at the KISA replay boundary:** add the exact M03, M06, and A04
   `ai.chat-probe` fresh-session driver, raw-transcript live Mode Oracle, sealed source/replay
   coordinator, and verified replay index;
6. **Implemented for the common gate and KISA path:** require a verified ReplayOutcome receipt,
   reloaded from its replay Run, before a Decision can become reproduction-backed `confirmed`;
7. **Implemented as an append-only v1alpha1 projection:** version Decisions, Findings, index, and
   report so consumers can distinguish legacy semantic confirmation from reproduction-backed
   confirmation;
8. **Implemented for M6-05 KISA retest:** accept only sealed reproduction-backed baselines, separate
   normal parent regression from baseline-bound attack replay, reload verified negative receipts,
   and require an all-repetition trusted `contradicts` verdict before `fixed`;
9. **Implemented for M6-06 Local durability:** persist KISA positive/negative replay tickets and
   transitions in stable SQLite authorities and verify finalization after process restart through a
   read-only loader;
10. **Implemented for M6-07A explicit Local KISA orchestration:** seal a complete Local source,
    share live budget/rate/cancellation state, run exact allowlisted Candidate replays through the
    SQLite authority, verify batch coverage, and invoke the common Gate only with canonical replay
    receipts; and
11. add Control Plane orchestration after ADR 0029 and eligible Mode contracts incrementally without
    introducing a generic replay predicate.

Existing sealed Runs are immutable and must not be rewritten. A historical `confirmed` Decision
without a ReplayOutcome is interpreted under legacy semantics and cannot be promoted by
reinterpretation; it must be reproduced in a new Run.

## Consequences

- PAJIN preserves the value of semantic review while restoring independent reproduction as the
  confirmation boundary.
- The LLM does not receive general offensive execution authority; the Reproducer gets only a
  compiled, candidate-bound Grant.
- Confirmed output remains fail-closed and is emitted only when the common gate consumes verified
  receipts; additional Modes require their own explicit replay integrations.
- Ordinary Local execution remains backward compatible: replay authority is created only for an
  explicit KISA opt-in, and the implemented Local sequencing cannot be treated as a distributed
  Control Plane protocol.
- `fixed` also remains fail-closed and is produced only when the baseline-bound Retest Gate consumes
  a verified canonical negative receipt. Historical baseline confirmation remains separate from
  the append-only retest relationship.
- Separating functional regression from vulnerability state prevents a Run with a functional
  regression from being reported as an overall success even when the original vulnerability is
  fixed.
- Replay adds target effects, latency, cost, evidence volume, and non-determinism management.
- Unsafe or non-idempotent Candidates require a separately designed approval and manual
  reproduction path.

## Validation requirements

Implementation is complete only when tests prove that:

- semantic agreement plus an objective gate cannot create a confirmed projection;
- no Candidate becomes confirmed without a fresh replay request and Candidate-bound evidence;
- executable model output and model-authored Tool requests are rejected;
- out-of-scope, out-of-grant, target, Tool, scenario, Candidate, and evidence substitution fail
  closed;
- T3/T4, non-idempotent, destructive, and non-opted-in operations do not replay automatically;
- cancellation, timeout, target unavailability, and non-deterministic misses preserve the Candidate
  as `inconclusive` or `needs-review` according to the disposition table;
- only a successful typed Oracle result plus the objective gate, and Semantic Validator support
  where required by the Mode, creates `confirmed`;
- Local and Multi-Agent runners enforce the same confirmation rule;
- KISA reports and versioned Finding artifacts distinguish legacy and reproduction-backed
  confirmation;
- migration does not rewrite historical Run seals;
- KISA retest rejects legacy flat, semantic-only, and unconfirmed baselines and consumes only a
  sealed `validation/v1alpha1` Confirmed baseline;
- any substitution of the exact Candidate, Decision, Finding, remediation, baseline or retest Run,
  root, request, scenario, threat, Tool, or target, or any tampering with a receipt or seal, causes
  a hard failure;
- `fixed` is produced only when the trusted negative Oracle verdict is `contradicts` for every
  expected repetition; `supports` yields `still-vulnerable`, while mixed or terminal outcomes,
  insufficient repetitions, and missing evidence yield `inconclusive`;
- zero support from the positive Oracle and a Worker-authored negative flag cannot produce
  `fixed`;
- the normal parent regression and baseline-bound attack replay are separated, and regression
  failure blocks CLI success without overwriting the Finding state; and
- appending the remediation plan does not overwrite the versioned baseline projection or an
  existing seal entry; it creates a new current root, and the retest binds that root exactly to the
  outcome, request, evidence, and receipt lineage before sealing it append-only.

The schema-boundary regression suites are `tests/test_replay_models.py` and
`tests/test_ai_chat_contracts.py`. The compiler boundary is covered by
`tests/test_replay_compiler.py`, and `tests/test_replay_runtime.py` covers single-use and concurrent
ticket claims, stateless and registered fresh-session dispatch, fresh request/evidence provenance,
substitution rejection,
shared budget/rate limits, child cancellation, dispatch/Oracle deadlines, Tool-authored Secret
Lease denial, timeout and unavailable outcomes, typed Oracle binding, mutable-memory substitution,
distinct replay storage, issued-compilation-bound ticket finalization, and twice-verified seals.
Together they cover executable intent
rejection, version and legacy-read policy, replay eligibility metadata, duplicate and same-request
rejection, Candidate/Run/target/scenario/Tool/argument/evidence/Grant substitution,
confused-deputy inputs, Scope·budget·authorization·cancellation checks, shared Tool/Producer output
typing, and untrusted verdict flags. `tests/test_confirmation_gate.py` fixes the common disposition
matrix for supporting, contradicting, inconclusive, failed, cancelled, timed-out, unavailable, and
unsupported ReplayOutcomes. Versioned-artifact tests cover fail-closed legacy separation and fixed
paths. `tests/test_kisa_replay.py` additionally covers the explicit
three-scenario opt-in, fresh and unique sessions, raw-transcript recomputation, multi-turn request
rate accounting, mutable record rejection, sealed source-state binding, receipt reloading, immutable
source artifacts, and reproduction-backed KISA projection. `tests/test_local_replay.py` covers the
explicit single-process Local source→SQLite replay→Gate path, shared source state, immutable flat
Finding snapshot, versioned projection, no-Candidate behavior, semantic omission, and bounded
repetitions. `tests/test_kisa_retest.py` and
`tests/test_kisa_retest_cli.py` cover the M6-05 sealed baseline admission, exact retest binding,
negative/supporting/mixed/terminal disposition matrix, canonical receipt reloading, forged negative
signal rejection, parent regression separation, immutable baseline, and CLI Exit Gate. The
remaining requirements apply to Control Plane replay orchestration, portable/off-host verification,
and additional explicitly opted-in Mode contracts.

## References

- [PAJIN Notion roadmap](https://app.notion.com/p/3a94b2ea35f081329974c7f57eda299a)
- [ADR 0002: Tool Gateway and Worker isolation](0002-tool-gateway-and-worker-isolation.md)
- [ADR 0004: Dynamic multi-agent execution](0004-dynamic-multi-agent-execution.md)
- [ADR 0009: Provider-backed Agent Runtime](0009-provider-backed-agent-runtime.md)
- [ADR 0016: Tamper-evident Run integrity](0016-tamper-evident-run-integrity.md)
- [ADR 0024: Cooperative execution cancellation](0024-cooperative-execution-cancellation.md)
- [ADR 0025: Candidate validation ledger and replay boundary](0025-candidate-validation-ledger-and-replay-boundary.md)
- [ADR 0026: Trusted KISA candidate admission](0026-trusted-kisa-candidate-admission.md)
- [ADR 0028: Durable Local replay ticket ledger](0028-durable-local-replay-ticket-ledger.md)
