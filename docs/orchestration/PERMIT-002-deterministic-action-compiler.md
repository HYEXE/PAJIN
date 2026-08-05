# PERMIT-002: Deterministic General Attack Action Compiler

- Status: Implemented
- Contract version: `pajin.dev/general-attack-compiled-intent/v1alpha1`
- Decision: [ADR-0129](../adr/0129-bind-cap002-compilation-before-graph-authority.md)

## Scope

PERMIT-002 performs the first code-backed compilation of a PERMIT-001
`GeneralAttackActionProposal`. It reuses CAP-002's complete authority registry, Materializer, Action
Compiler, canonical `ToolRequest`, and existing request and normalized-parameter digest functions.
The result is one content-addressed `GeneralAttackCompiledIntent`.

The intent is not the existing GRAPH-006 `ActionProposal`. It carries no Capability release or
activation, Grant, MissionEnvelope, Graph Decision, budget reservation, Permit, dispatch, Gateway,
Worker job, or execution authority.

## Trusted inputs and compilation

`compile_general_attack_action_intent()` accepts:

1. one PERMIT-001 proposal and the complete current Campaign, Hypothesis Set, ORCH Plan, Task
   digest, CAP-001 definition reference, and Definition Registry needed to exact-rebuild it;
2. one exact `CodeBackedCapabilityRef`; and
3. one complete `CapabilityAuthorityRegistry` containing all seven CAP-002 roles.

The compiler:

1. invokes the PERMIT-001 external verifier and rejects any stale, foreign, legacy, or altered
   source authority;
2. exact-resolves the complete CAP-002 authority-set manifest and requires its Definition to equal
   the proposal Definition;
3. selects only the registered Materializer and Action Compiler wrappers;
4. reopens the exact Target endpoint and Tool binding from the current Campaign and Definition;
5. derives a fresh portable request ID from the source proposal digest, complete authority-set
   reference, and Materializer and Action Compiler authority digests;
6. materializes the proposal arguments once and requires canonical-JSON byte equality, including
   exact scalar types and no inserted defaults, renamed keys, removed values, or other
   normalization drift;
7. invokes the Action Compiler once and requires the complete output request to equal the
   code-owned seed request as canonical JSON;
8. re-resolves the complete seven-role authority set after both calls; registry resolution requires
   two consecutive complete observations, each role must retain its declared identity while stable
   context is captured, and a final stable-context-free declared-identity sweep rejects late scalar
   drift; and
9. binds the Gateway-compatible request digest, CAP-002 normalized-parameter digest, endpoint
   digest, complete source proposal, authority-set reference, and selected authority bindings into
   the intent identity.

The CAP-002 wrappers revalidate adapter identity before and after each call and independently
reject changes to request ID, Agent, target, method, Tool, or canonical argument bytes. PERMIT-002's
additional whole-request equality and final complete-set revalidation leave no permitted
compiler-selected request degree of freedom.

CAP-002 adapters are code-owned trusted computing-base components, and their
`stable_execution_context()` methods are required to be deterministic and side-effect-free. These
checks detect observed accidental or call-induced drift; they are not a sandbox for Byzantine
in-process Python code that mutates peer context only during inspection.

## Authority boundary

The compiled request uses the fixed code-owned Agent ID
`pajin.supervision.general-attack-action-compiler`. A `ToolRequest` is typed request material, not a
Grant or Permit. No Tool Gateway or Worker consumer is called by this module.

`GeneralAttackCompiledIntent` carries the following exact states:

- `compilationState="compiled-not-permitted"`;
- `materializerApplied=true`;
- `actionCompilerApplied=true`;
- `toolRequestCompiled=true`;
- `capabilityActivated=false`;
- `capabilityGranted=false`;
- `graphActionProposalCreated=false`;
- `missionEnvelopeBound=false`;
- `graphDecisionBound=false`;
- `budgetReserved=false`;
- `permitGranted=false`;
- `executionAuthorized=false`; and
- `scopeExpansionAuthorized=false`.

The output embeds the complete PERMIT-001 source. Risk, expected evidence, side-effect, and cleanup
metadata therefore remain bound by its action-semantics digest but are not reinterpreted. The
Success Oracle, Replay Strategy, Cleanup Handler, Executor Adapter, and other CAP-002 roles are not
invoked.

## Negative boundaries

Compilation or external verification fails closed for:

- same-name foreign Campaigns, missing Campaign digest, foreign Snapshot, Plan, Task, Hypothesis,
  Surface, Target, Scope, method, risk, evidence, cleanup, or CAP-001 Definition lineage;
- missing, incomplete, foreign, forged, or observably drifted CAP-002 authority sets, cross-role
  scalar identity mutation, and Materializer or Action Compiler identity substitution;
- Materializer schema rejection or any addition, removal, rename, default insertion, or value
  or scalar-type change in proposal arguments, including boolean/integer/float equivalence under
  Python comparison;
- compiler changes to request ID, Agent, target, method, Tool, or arguments;
- self-consistent request, request-digest, normalized-parameter, Target, compiler-binding, or intent
  substitution when rebuilt against current sources and the exact Registry;
- boolean coercion of true or false authority flags; and
- release, activation, Grant, Envelope, Graph Decision, GRAPH proposal, reservation, Permit,
  command, shell, Worker job, dispatch, or other extra-field injection.

Prompt-shaped values inside the exact argument object remain inert request data. They cannot
select the Tool, Target, method, Agent, request identity, compiler, authority set, or any later
execution authority.

## Compatibility, migration, and rollback

The module, exports, intent schema, tests, contract, and ADR are additive. Existing PERMIT-001,
CAP-001/002, Replay, `PreparedCapabilityAction`, Common Engine, GRAPH-006, Tool Gateway, and Worker
wire contracts and public APIs are unchanged. CAP-002 compiler acceptance and identity observation
are hardened globally: JSON-type-distinct arguments and ordered cross-role drift now fail closed.
`PreparedCapabilityAction` is deliberately not reused because it
requires signed release and activation authority that PERMIT-002 does not receive. No persistent
schema or artifact migration is required.

Rollback removes the new compiler module and consumers while retaining the generic CAP-002
correctness hardening. Serialized PERMIT-002 records remain non-executable historical intent and
cannot be reinterpreted as GRAPH proposals or Permits.

## Downstream boundary

PERMIT-003 exact-rebuilds the current compiled intent, verifies a current signed Capability release
and activation, receives an existing run-level MissionEnvelope, external current Graph Decision,
and trusted fixed-point cost through an explicit input authority, derives request units and the
existing reservation from the current activated Definition, and only then constructs the existing
GRAPH-006 `ActionProposal`. It uses the existing atomic single-use Permit store and dispatcher
rather than another Permit or request-consumption implementation.

PERMIT-004 remains responsible for Success Oracle, side-effect, data-flow, cleanup handler, cleanup
plan, and cleanup Permit enforcement.

## Related documents

- [PERMIT-001 contract](PERMIT-001-general-attack-action-proposal.md)
- [PERMIT-003 contract](PERMIT-003-exact-single-use-action-permit.md)
- [CAP-001 contract](../capability/CAP-001-versioned-capability-definition.md)
- [CAP-002 contract](../capability/CAP-002-metadata-code-backed-authority-interfaces.md)
- [GRAPH-006 contract](../graph/GRAPH-006-atomic-action-permit-authority.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
