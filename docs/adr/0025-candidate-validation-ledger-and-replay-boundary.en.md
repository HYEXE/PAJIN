> Languages: [English](0025-candidate-validation-ledger-and-replay-boundary.en.md) | [한국어](0025-candidate-validation-ledger-and-replay-boundary.ko.md)

# ADR 0025: Candidate validation ledger and replay execution boundary

- Status: Accepted for ledger and objective-gate design; confirmation semantics amended by ADR 0027
- Date: 2026-07-14
- Implementation: Stage 1 implemented; KISA trusted admission added by ADR 0026. The Restricted
  Reproducer and common confirmation gate were planned when this ADR was accepted and are now
  implemented for the explicit KISA/Local scope described in ADR 0027
- Amends: [ADR 0004](0004-dynamic-multi-agent-execution.en.md)
- Amended by: [ADR 0027](0027-independent-reproduction-confirmation-boundary.en.md)

## Context

ADR 0004 requires a separate Validator role and a deterministic final gate before a Finding can be
reported as confirmed. Before Stage 1, the Local and Multi-Agent runners reduced Validator output
to one Boolean, `Finding.validated`. Only accepted Findings entered `findings.json` and the canonical
report. A Validator disagreement, missing semantic marker, replay failure, and objective evidence
violation could therefore collapse into the same absence from the final artifacts.

That behavior is conservative about confirmation but destructive for later review. It also gives
Local and Multi-Agent execution different opportunities to enforce target and evidence provenance,
and it makes Validator quality difficult to measure. PAJIN needs to preserve what a Validator
actually returned while keeping existing consumers of `findings.json` stable.

The complete design requires independent restricted reproduction. A model must not,
however, turn a narrative replay proposal directly into executable authority. Replay adds new Tool
calls, target effects, evidence, budgets, and prompt-injection exposure. It therefore needs a
separate staged trust boundary rather than an extension of the Provider Validator's current model
call.

## Decision

### Canonical validation snapshot and compatibility view

Stage 1 writes two canonical Run snapshots before the final Run seal:

- `candidate-findings.json` preserves every Candidate Finding admitted to the validation boundary
  in stable creation order.
- `validation-decisions.json` contains exactly one Validation Decision for every admitted Candidate
  in the corresponding stable order.
- `validation-index.json` is a derived, ID-only disposition view and does not duplicate Candidate
  bodies.

Each Candidate has a stable ID and bounded source provenance. Its one Decision records the
producing Validator identity and method where applicable, same-Run evidence references, a bounded
reason summary, and machine-readable reason codes. It does not store private model chain-of-thought.
The Stage 1 schema rejects a Candidate with zero Decisions or more than one Decision.

`findings.json` remains the confirmed-only compatibility view. Its existing `Finding` shape and
`validated: true` expectation remain available to current CLI, Reporter, KISA, Bug Bounty, CTF, and
Control Plane consumers. At Run finalization PAJIN derives that view directly from the one
`confirmed` Decision for each Candidate. ADR 0027 now requires every such Decision to reference a
successful independent ReplayOutcome. Until that migration is implemented, the current projection
may contain legacy semantic confirmations and must not be interpreted as product-level Confirmed.
The canonical Candidate and Decision snapshots, the derived view, and their audit events are
covered together by the final Run integrity seal.

Stage 1 does not implement a physically append-only validation log, multiple Decisions per
Candidate, or a superseding Decision chain. Those require a future schema and lifecycle stage that
defines transition authority, ordering, review identity, and how a later Decision extends the
integrity chain without rewriting the sealed Stage 1 snapshot.

### Validation dispositions

Validation has exactly four dispositions:

| Disposition | Meaning |
| --- | --- |
| `confirmed` | A Candidate-bound independent ReplayOutcome and Mode Oracle support the claim, the objective gate passes, and semantic support exists when required by the Mode |
| `needs-review` | The claim remains plausible, but independent reproduction is missing, ineligible, awaiting approval, or semantically ambiguous |
| `inconclusive` | Replay or observation cannot reach a conclusion because execution or evidence is incomplete |
| `rejected-objective` | A deterministic, mode-aware rule proves the Candidate invalid for the stated claim |

`candidate` is a ledger record state, not a disposition. `duplicate` is also not a validation
disposition. Exact same-Run relationships and Bug Bounty known-finding or root-cause triage remain a
separate deduplication layer. Deduplication may suppress a submission or select a representative,
but it must not delete the original Candidate or rewrite its validation history.

Objective rejection is limited to facts such as an undeclared or out-of-scope target, absent or
foreign-Run evidence, invalid evidence integrity, a claimed Tool execution that did not occur, or a
typed mode Oracle that directly contradicts the precise claim. A missing exact KISA marker can
contradict an exact-marker claim; it does not by itself reject a different claim of partial or
semantic disclosure. A replay timeout, truncation, rate limit, or non-deterministic miss is
`inconclusive`, not objective rejection.

### Stage 1: legacy Candidate preservation and one deterministic gate

The first implementation stage preserves only `Finding` objects returned by an existing
`ValidatorRuntime`. A compatibility adapter admits each returned Finding as a Candidate before any
confirmation filtering. The implemented compatibility path currently allows a legacy
`validated: true` Candidate to become `confirmed` after the deterministic gate passes. ADR 0027
supersedes that confirmation meaning: without a successful independent ReplayOutcome the Candidate
must remain `needs-review` with `independent-reproduction-missing`. A legacy `validated: false`
Candidate that passes the objective gate remains `needs-review` with an explicit legacy-ambiguity
reason because the Boolean does not say whether the cause was disagreement or incomplete execution.

This stage does **not** recover a Candidate that the Validator never returned. The present
Specialist contract produces `ToolResult`, not `CandidateFinding`; a marker-based or deterministic
Validator can still return an empty list and leave no Candidate to preserve. Solving that omission
requires a typed Candidate-production boundary and is explicitly outside Stage 1. ADR 0026 now
implements that boundary for exact KISA `ai.chat-probe` catalog observations only; other Tool
families remain on this legacy path.

Local and Multi-Agent runners use the same PAJIN-owned deterministic classification gate. The gate
receives the Campaign, Run path and identity, Tool Results and evidence inventory, and an admitted
Candidate. It validates the declared target and allow/deny Scope. For every cited evidence path it
also requires that the resolved path remains contained by the Run's `evidence/` directory, names an
existing regular file, and parses as the Tool Gateway evidence record linked to the Candidate. The
Gateway record's request ID, Tool ID, target, and stored Tool Result must match the in-memory Tool
Result and Candidate provenance; a path that merely exists in the same Run is insufficient. Plan
request IDs are unique, and duplicate Tool Result request identities fail this provenance check so
one evidence path cannot ambiguously support multiple executions.

The gate runs before final Run sealing. Stage 1 has no intermediate cryptographic seal over
Specialist evidence or validation input, so it proves filesystem containment, existence, and
Gateway request/target linkage at classification time rather than pre-validation cryptographic
immutability. `candidate-findings.json`, `validation-decisions.json`, the confirmed compatibility
view, and referenced evidence are bound by the final Run integrity seal. The gate is deterministic
and has no Provider or Tool authority. A semantic Validator may support a claim, but it cannot
override an objective gate failure.

### Stage 2: required restricted reproduction without model execution authority

Restricted reproduction is the required second stage and follows this fixed authority chain:

1. A provider-only semantic Validator receives one bounded Validation Packet. Its only executable
   capability is its registered Provider call. It treats every evidence string as untrusted data.
2. The Validator may emit a typed, non-executable `ReplayIntent`. It cannot emit an executable
   command, process path, arbitrary URL, raw `ToolRequest`, or Capability Grant.
3. A trusted compiler resolves the intent against a registered Mode scenario and Tool template,
   binds the exact Candidate target, validates arguments and method, and clamps risk and call
   budgets. Unrecognized or ambiguous intent fails closed.
4. PAJIN issues a separate replay Grant to a trusted replay executor. The Grant is not the
   Specialist Grant or Provider Grant and contains only the compiled Tool, exact target, bounded
   calls, expiry, and risk ceiling.
5. Replay executes through the ordinary Tool Gateway and Worker boundary, producing a distinct
   request and evidence lineage. A typed, mode-owned Oracle evaluates the replay observations before
   the common deterministic gate records the final disposition.

Initial automatic replay is restricted to T0-T2 Tools whose Tool and Mode contracts explicitly opt
in as replay-safe and idempotent for the compiled operation. T3/T4, non-idempotent operations, and
Tools without that metadata are not automatically replayed. Adding approval-mediated or
compensating replay for those operations requires a later ADR.

### Mode boundaries

- KISA AI Red Team may combine semantic interpretation with typed transcript, marker, Tool-trace,
  baseline, and attack-response Oracles. Marker results remain explicit observations rather than a
  universal verdict.
- The fixed Bug Bounty SQL injection lab retains its deterministic control-set Oracle. Its
  validation disposition is evaluated before the separate reporting and duplicate-triage states.
- CTF remains deterministic-only. Flag and artifact digest comparison is the authoritative Oracle;
  no LLM semantic Validator or automatic LLM-planned replay is introduced. Existing CTF solve
  statuses remain Mode output rather than validation dispositions.

### Evidence retention and privacy

Candidate preservation does not authorize indefinite raw-evidence retention. Candidate and
Decision ledgers should reference evidence by Run-relative identifier and digest instead of copying
raw transcripts, responses, flags, secrets, or personal data. Reason summaries are bounded and
redacted, and model chain-of-thought is never a Run artifact.

Raw evidence remains subject to the Campaign and Mode retention, access-control, encryption,
redaction, and disposal policy. A Validation Packet sent to a Provider contains only the minimum
allowlisted and redacted excerpt needed for the Candidate; system prompts, credentials, unrelated
Candidates, and unrestricted Run transcripts are excluded by default. Evidence content remains
attacker-controlled even after redaction.

Append-style integrity and data minimization are separate concerns. Future retention processing may
make raw evidence unavailable while retaining its digest and a disposal record. Readers must then
report that the historical content is no longer re-verifiable; a seal over a digest is not evidence
that the deleted plaintext is still available.

## Consequences

- Candidate and Decision consumers can continue using the Stage 1 ledgers while review and
  inconclusive cases become auditable. Confirmed-Finding consumers require the ADR 0027 migration
  and artifact versioning before treating `findings.json` as product-level confirmation.
- Validator disagreement no longer grants deletion authority, and objective rejection reasons are
  machine-readable.
- Local and Multi-Agent validation stop drifting because both use one deterministic gate.
- The first stage is intentionally incomplete: it preserves legacy Validator output but cannot
  recover analysis that was never expressed as a Finding. ADR 0026 narrows this limitation for
  cataloged KISA AI chat observations without granting the Semantic Validator direct replay authority.
- Per-Candidate snapshot records and raw-evidence references increase artifact volume and require
  explicit retention handling; multi-Decision history remains a future schema.
- LLM replay gains no direct execution authority; the compiler, replay Grant, Tool Gateway, and
  typed Oracle remain trusted PAJIN boundaries.
- Mode-specific truth contracts remain intact, especially CTF digest validation and Bug Bounty
  duplicate triage.

## Validation requirements

The Stage 1 ledger implementation is complete only when tests prove that:

- Local and Multi-Agent runners preserve a returned `validated: false` Candidate and classify it
  without adding it to `findings.json`;
- the schema rejects zero or multiple Decisions for one Candidate;
- escaped or missing evidence paths and mismatched Gateway request ID or target provenance become
  `rejected-objective`;
- foreign-Run evidence and out-of-scope targets become `rejected-objective` with audit reasons;
- confirmed, needs-review, inconclusive, and rejected-objective records survive report generation
  and are covered by the final Run integrity seal without claiming an intermediate validation seal;
- legacy `findings.json` consumers still receive only confirmed Findings; and
- Bug Bounty duplicate states and CTF solve states remain separate from validation dispositions.

These tests describe the implemented legacy compatibility behavior; they do not satisfy the product
confirmation boundary. ADR 0027 migration additionally requires tests proving that semantic support
and the objective gate alone cannot create a confirmed projection, that a successful fresh
ReplayOutcome can, and that executable model output, compiler ambiguity, out-of-grant Tool or target
requests, non-idempotent replay, T3/T4 replay, evidence prompt injection, and replay evidence
substitution fail closed.

## References

- [ADR 0004: Dynamic multi-agent execution and attenuated delegation](0004-dynamic-multi-agent-execution.en.md)
- [ADR 0009: Policy-bound Provider Runtime for reasoning roles](0009-provider-backed-agent-runtime.en.md)
- [ADR 0014: Conservative Bug Bounty finding deduplication](0014-conservative-bug-bounty-deduplication.en.md)
- [ADR 0016: Tamper-evident Run integrity chain](0016-tamper-evident-run-integrity.en.md)
- [ADR 0017: Local-only CTF Web Mode vertical slice](0017-local-ctf-web-mode.en.md)
- [ADR 0018: Bounded inline artifacts for CTF Crypto Mode](0018-bounded-ctf-crypto-artifacts.en.md)
- [ADR 0019: Bounded CTF Suite orchestration](0019-bounded-ctf-suite-orchestration.en.md)
- [ADR 0026: Trusted KISA candidate admission](0026-trusted-kisa-candidate-admission.en.md)
- [ADR 0027: Independent restricted reproduction as the confirmation boundary](0027-independent-reproduction-confirmation-boundary.en.md)
