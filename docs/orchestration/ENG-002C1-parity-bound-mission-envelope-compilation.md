# ENG-002C1: Parity-Bound MissionEnvelope Compilation

- Status: Implemented
- Contract versions:
  - `pajin.dev/common-engine-mission-envelope-compiler/v1alpha1`
  - `pajin.dev/common-engine-mission-capability-binding/v1alpha1`
  - `pajin.dev/common-engine-mission-envelope-compilation/v1alpha1`
- Decision: [ADR-0108](../adr/0108-compile-mission-authority-by-predecessor-intersection.md)

## Scope

ENG-002C1 compiles the existing GRAPH-006 `MissionEnvelope` only from the exact intersection of
one PROF-002 legacy Profile compilation, one complete ENG-002B2B behavioral-parity authority, and
one verified CAP-005 existing-Mode Capability activation. It is an additive, direct-call,
non-executable bridge. It does not apply Profile ROE defaults, issue an `ActionPermit`, construct a
Graph proposal, dispatch the Common runtime, or change a legacy default path.

The compiler accepts only the PROF-002 authority embedded in the measured parity chain. The source
Mode, complete Campaign, Profile, compiler, and all predecessor digests must therefore be exactly
the authorities whose behavior was measured.

## Exact Capability binding

Each request in the B2B normalized Plan is resolved through the supplied verified activation. A
request must match exactly one activated signed release after CAP-002 materialization. Each
`CommonEngineMissionCapabilityBinding` records:

- the Plan ordinal and complete `ToolRequest`;
- request, normalized-parameter, and exact target digests;
- activation-set and signed release identity;
- the complete signed release bundle and Capability definition;
- the GRAPH-006 `ActionCapabilityRef` and request-unit cost; and
- the release/review authority window.

The reader reconstructs the Plan order, activation subset, Capability definition, ToolSpec, risk,
request cost, and release/review window. Request IDs remain ordinary Plan-owned identities; the
ordinal is checked against Plan position instead of a fixture-specific string convention.

## Non-expanding Campaign intersection

Compilation revalidates every measured request against the source Campaign:

- method is allowed;
- Tool risk is at or below the Campaign ceiling;
- allowlisted Tool categories contain the Tool categories and no prohibited category is present;
- target matches at least one allow rule and no deny rule; and
- the measured B2B receipt is Policy-allowed, successful, Worker-succeeded, exit-zero, and backed
  by a trusted network log.

The resulting Envelope contains only selected exact Capability references and request target
digests. Its call limit is the measured Plan request count, request-unit limit is the sum of the
selected Capability costs, maximum risk is the maximum selected risk, and the rolling unit limit is
the lower of Campaign requests-per-minute and measured request units. The fixed-point cost ceiling
does not exceed the Campaign cost budget.

The requested start must be within Campaign authorization and use a Run ID fresh from both parity
fixture Runs. The actual start is attenuated to the latest requested, release, or signed-review
not-before time. Expiry is the earliest Campaign expiry, Campaign-duration end, or signed-review
expiry. Because `MissionEnvelope` cannot encode recurring weekly windows, compilation accepts only
no testing window or a set in which every entry is the exact seven-day `00:00`-to-`00:00` full-day
window. Any restricted or mixed recurring schedule fails closed.

## Authority and reader

`CommonEngineMissionEnvelopeCompilationAuthority` embeds the canonical predecessors, activation
set, exact request bindings, compiled Envelope, and their digests. Its own content address excludes
the duplicated predecessor bodies but includes their exact digests; model validation reloads every
body and requires equality before accepting the authority.

The execution flags are fixed as follows:

- `missionEnvelopeCompiled=true`;
- `actionPermitIssued=false`;
- `commonRuntimeDispatched=false`; and
- `commonExecutionAuthorized=false`.

The API is intentionally imported from `pajin.workflow.engine_mission_envelope`. Eager re-export
from `pajin.workflow` would create a cycle through Capability AI replay imports, so the package
initializer remains unchanged.

## Negative cases

Compilation or reload fails closed for:

- foreign, stale, cross-Mode, or substituted Campaign/Profile/compiler/parity authority;
- incomplete parity or forged Envelope/execution flags;
- a non-canonical or unverified activation input;
- zero or multiple activated Capability matches for one measured request;
- release, review, definition, Tool, request, parameter, target, risk, or cost drift;
- Campaign method, category, prohibition, Scope, risk, budget, rate, or time expansion;
- failed, denied, incomplete, or network-untrusted measured receipts;
- fixture Run ID reuse, inactive Campaign authorization, or empty release/review time
  intersection; and
- restricted or mixed recurring testing windows that the Envelope cannot preserve.

## Compatibility, migration, and rollback

The APIs are additive and opt-in. Existing Campaign, MissionEnvelope, Capability, Profile,
behavioral-parity, Graph, Mode, CLI, and artifact wire formats are unchanged. Removing the C1
module and its callers rolls back this bridge without changing any predecessor or legacy runtime.

The embedded signed bundle is audit material, not a portable replacement for the lifecycle Trust
Registry. A later execution gate must receive and revalidate a current verified activation, bind
the exact planned request and parameter digest into GRAPH-006 proposal/Permit authority, and check
the current release head immediately before dispatch. C1 alone never makes its Envelope executable.
