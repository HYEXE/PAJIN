# ADR-0327: Bind Hosted Reconnaissance to a Local Proposal and Inert Topology

- Status: Accepted
- Date: 2026-09-23
- Scope: Codex reconnaissance successor and the first WEB-008 planning boundary

## Context

ADR-0324 permits a separately approved, tool-free hosted reconnaissance turn. Its strict draft
parser can establish that a response fits the closed discovery projection, but a draft file by
itself does not prove which terminal attempt produced it. The existing WEB-007 local proposal
compiler and WEB-005 governed Campaign have different trust boundaries. The Campaign currently
creates source and validation action intents during provisioning and does not carry a model plan
digest to a Permit or Worker.

## Decision

Compile a hosted reconnaissance result only after independently pinned discovery Run/root and
terminal receipt digests are reloaded. Rebuild both the hosted and local projections from the
sealed source and require the same diagnostic, path, and evidence choices. Reparse the retained
no-tool event stream and response; check the exact prompt, output, usage, and admitted draft
digests against the terminal journal. Translate the admitted draft into the existing local
`WebAnalysisProposalDraft` wire using code-owned fields, then run its strict parser, compiler, and
verifier. Return a versioned digest-bound bridge record and the verified local Snapshot, draft,
and proposal. All execution, Finding, Graph, and delivery markers remain false.

The first WEB-008 successor is an **inert candidate topology**. Before constructing it, verify
the entire bridge again against the same independent source and receipt pins. Re-resolve the
installed adapter profile and diagnostic bundle against independent digests. Bind the bridge,
receipt, proposal, source, Snapshot, profile, catalog, and bundle to one plan digest. Record
separate source and validation future slots, both in `planned-no-dispatch` state. Execute all
three diagnostics only in the code-owned order `sql-login`, `object-access`, `dom-xss` if a later
Campaign version authorizes execution. The model's rank only expresses attention priority.

Neither the bridge nor the topology may mint policy approval, Capability, Permit, Gateway
dispatch, Finding, Graph admission, report delivery, or scope expansion. A bare compiled proposal
cannot enter this hosted topology because it lacks the terminal receipt lineage.

## Compatibility and next execution boundary

The historical Qwen Provider route and WEB-005/v1alpha1 parent, request, Permit, Worker, result,
and strict reader formats retain their existing meaning. The topology does not add a stage to that
parent or execute target requests. An executable WEB-008 successor needs a new parent grammar
with discovery, model evidence, and compiled plan before source. It must bind the plan digest
through each source and validation intent, decision, approval, single-use Permit, Gateway request,
Worker job, observation, and independent loader. Validation intent must be created from the
sealed source outcome under a fresh authority. WEB-009 diagnostic subsets and replanning require
another versioned result-to-promotion path; this fixed topology does not provide them.

## Verification

The previously approved Luna terminal receipt and sealed discovery were locally reloaded without
a new model or target call. They produced a verified compiled proposal and a receipt-bound inert
topology with two distinct slots. Synthetic tests reject changed source or receipt pins, a
forged bridge, tool events, projection drift, wire tampering, and attempts to assert authority.
No source or validation action was dispatched from this topology.

## Related decisions

- [ADR-0301](0301-bind-llm-web-analysis-to-inert-typed-proposals.md): local proposal authority
- [ADR-0324](0324-route-hosted-codex-advisory-by-stage.md): hosted model routing and terminal receipt
- [ADR-0325](0325-track-reconnaissance-coverage-without-diagnostic-order.md): coverage and rank semantics
