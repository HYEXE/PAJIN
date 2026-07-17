> Languages: [English](0026-trusted-kisa-candidate-admission.en.md) | [한국어](0026-trusted-kisa-candidate-admission.ko.md)

# ADR 0026: Trusted KISA candidate admission before semantic validation

- Status: Accepted for Candidate admission; confirmation semantics amended by ADR 0027
- Date: 2026-07-14
- Implementation: KISA AI chat Candidate admission implemented. The Restricted Reproducer and
  common confirmation gate were planned when this ADR was accepted and are now implemented for
  the explicit KISA/Local scope described in ADR 0027
- Amends: [ADR 0025](0025-candidate-validation-ledger-and-replay-boundary.en.md)
- Amended by: [ADR 0027](0027-independent-reproduction-confirmation-boundary.en.md)

## Context

ADR 0025 Stage 1 preserves every `Finding` returned by a Validator, but a semantic Validator may
validly return an empty list. In that case a strong Specialist observation can disappear before it
enters `candidate-findings.json`. Giving the Semantic Validator direct attack Tools or replay
authority does not solve this admission problem and would widen the least-privilege boundary.

PAJIN already has a narrower source of truth for several KISA AI chat scenarios: a trusted catalog
defines the exact Plan metadata, typed request, turns, checks, and expected markers. The Tool
Gateway binds the corresponding request and result to same-Run evidence. Those facts can admit an
observation as a Candidate without deciding its semantic validity.

Generic `ToolResult.data` remains untrusted and has no universal vulnerability meaning. In
particular, an arbitrary `vulnerable: true` field, a Worker's precomputed check result, or an MCP
content flag is not sufficient evidence for a security Finding.

## Decision

PAJIN adds an optional, trusted `CandidateProducerRuntime` boundary between Specialist execution
and Validator invocation. It is a synchronous, deterministic, Tool-less component. A runner gives
it only the typed Campaign, validated Plan, and completed Tool Results. It atomically returns a
`CandidateProduction`: immutable `CandidateFinding` records whose claims always have
`validated: false`, plus the request IDs and `(target, threat class)` claim space for which the
producer owns confirmation admission.

The first producer is restricted to the KISA `ai.chat-probe` catalog scenarios M03, M06, and A04.
It admits a Candidate only when all of the following hold:

1. the Campaign is AI Red Team mode;
2. one unique Plan request and one Tool Result share the request identity;
3. the Plan step exactly matches the catalog scenario's Tool, method, threat classes, attack
   surface, and persona;
4. the request parses as `AIChatProbeInput`, and its scenario, threat, turns, and checks exactly
   match the catalog template;
5. the Result succeeded and its Tool, target, scenario, threat, and session identities match the
   request and Plan;
6. the Result reports a real network execution and references same-Run evidence, and the
   Candidate source request set exactly matches those evidence-linked executions; and
7. PAJIN recomputes every catalog check over the raw response transcript and every check passes.

The producer does not trust `data.vulnerable`, the Worker's `checks[*].matched` values, or a model
summary. Repeated observations for the same catalog scenario, threat, and target become one
Candidate with ordered, unique request and evidence references. Producer provenance is recorded as
trusted core provenance rather than being attributed to the semantic Validator.

After the Validator returns, the common validation gate reconciles its output to admitted
Candidates one-to-one using the core-owned target, threat class, and overlapping same-Run evidence.
A title or narrative rewrite does not create a new identity. A Validator-only result inside the
producer's request or claim authority cannot become confirmed when the producer admitted no
matching Candidate. It is preserved as a separate review Candidate with
`candidate-producer-not-admitted`; overlapping or ambiguous Validator outputs are preserved the same
way rather than being deleted. An undeclared threat class is rejected by the objective gate when a
Campaign declares a threat set. An empty threat set is consistently treated as unconstrained by
both the gate and producer authority calculation.

ADR 0027 amends the resulting disposition rules:

| Producer observation | Semantic Validator result | Objective gate | Independent reproduction | Disposition |
| --- | --- | --- | --- | --- |
| admitted | matching support | pass | successful typed ReplayOutcome | `confirmed` |
| admitted | matching support | pass | not run or not implemented | `needs-review` with `independent-reproduction-missing` |
| admitted | omitted | pass | any | `needs-review` with `validator-omitted` |
| admitted | matching disagreement | pass | any | `needs-review` |
| not admitted | Validator-only claim inside producer authority | pass | any | `needs-review` with `candidate-producer-not-admitted` |
| admitted | Validator or replay cancelled or unavailable | pass | no conclusive outcome | `inconclusive` |
| admitted | any | fail | not run | `rejected-objective` |

The canonical Candidate claim remains `validated: false` even after confirmation. After ADR 0027
migration, the confirmed-only compatibility projection in `findings.json` may copy the core claim
and set `validated: true` only when the Decision references a successful ReplayOutcome. A Semantic
Validator can support or dispute the claim, but it cannot confirm it alone, rewrite the admitted
claim, or erase it by returning an empty list.

The M1 migration now blocks matching semantic support plus the objective gate from creating a
`confirmed` projection. Until Restricted Reproducer support is implemented, that Candidate is
persisted as `needs-review` with `independent-reproduction-missing`.

Validator-only Findings for Tool families without a trusted producer continue through the ADR 0025
legacy adapter. This preserves current compatibility while making the incomplete coverage explicit.
The new producer emits an ID-only admission audit event with candidate and authority counts before
Validator invocation. If cancellation, timeout, or an exception prevents validation, Local and
Multi-Agent finalization reruns the pure producer over the available completed results when needed
and records its Candidates as `inconclusive` with `validator-cancelled` or
`validator-unavailable`. The final Candidate and Decision snapshots remain covered by the Run's
final integrity seal.

## Explicit exclusions

- The Producer has no Tool, Provider, replay, capability-grant, or process execution authority.
- No generic `data.vulnerable` predicate is introduced.
- MCP results and normal-function regression probes cannot create Candidates through this producer.
- The synthetic `mock.agent-probe` path remains on the legacy Validator boundary until it has a
  strict typed observation contract.
- Bug Bounty keeps its existing typed deterministic control-set Oracle.
- CTF keeps flag and artifact digest validation separate from Finding dispositions.
- Direct LLM execution remains excluded. Independent reproduction must use the compiler,
  replay-specific Grant, Restricted Reproducer, and Mode Oracle defined by ADR 0027.

## Consequences

- A KISA AI chat observation no longer disappears solely because a semantic Validator returns an
  empty list, is cancelled, or becomes unavailable after Specialist evidence exists.
- Producer admission alone never writes a confirmed Finding, and Semantic Validator support alone
  must no longer do so after the ADR 0027 migration.
- Provider Validators may rephrase a title, while PAJIN keeps a stable core-owned claim and evidence
  identity.
- Candidate recovery is intentionally partial. Unsupported Tool families can still be omitted by
  their Validator until they gain a mode-owned typed producer.
- Candidate records are produced in memory before validation, or reconstructed from available
  results during failed/cancelled finalization, and sealed with the final snapshot. A future
  intermediate evidence/admission seal is still required to attest pre-Validator physical
  immutability.

## Validation

Candidate-admission tests must prove that:

- a real catalog transcript produces a Candidate even when the Validator returns `[]`, while
  `findings.json` stays empty;
- matching Semantic Validator support and objective evidence checks preserve the Candidate but do
  not satisfy the ADR 0027 confirmation boundary without a fresh ReplayOutcome;
- forged Worker verdict fields without the catalog marker produce no Candidate;
- mutated turns or checks, identity mismatches, non-network results, missing evidence, and duplicate
  request identities fail admission or objective validation;
- a mismatched Validator claim cannot reuse Candidate evidence to create a confirmed legacy
  Candidate, while the mismatched output remains reviewable;
- Validator-only confirmation cannot bypass an empty Producer result through a different evidence
  reference, modified catalog Plan, empty Campaign threat list, or undeclared threat label;
- cancellation and Validator failure retain available Candidates as sealed `inconclusive`
  Decisions; and
- existing Local, Multi-Agent, KISA retest, Bug Bounty, CTF, reporting, and integrity contracts
  remain compatible.

The Restricted Reproducer migration must additionally prove that only a successful Candidate-bound
ReplayOutcome plus the objective gate creates the confirmed projection. Tests now require semantic
support without ReplayOutcome to remain outside `findings.json`; historical sealed runs retain their
legacy interpretation without rewrite.

## References

- [ADR 0004: Dynamic multi-agent execution and attenuated delegation](0004-dynamic-multi-agent-execution.en.md)
- [ADR 0016: Tamper-evident Run integrity chain](0016-tamper-evident-run-integrity.en.md)
- [ADR 0025: Candidate validation ledger and replay execution boundary](0025-candidate-validation-ledger-and-replay-boundary.en.md)
- [ADR 0027: Independent restricted reproduction as the confirmation boundary](0027-independent-reproduction-confirmation-boundary.en.md)
