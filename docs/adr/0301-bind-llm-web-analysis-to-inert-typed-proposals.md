# ADR-0301: Bind LLM Web Analysis to Inert Typed Proposals

- Status: Accepted
- Date: 2026-09-16
- Scope: WEB-007 LLM-assisted Web analysis architecture
- Implementation status: Implemented in shadow mode; actual successful advisory remains unverified

## Context

ADR-0300 and WEB-006 establish a closed installed profile, authenticated same-context passive
discovery, bodyless boundary receipts, and a code-owned diagnostic catalog for the existing local
Juice Shop flow. That work supplies the browser and evidence safety substrate, but it intentionally
retains exactly three diagnostics and two attack paths and does not introduce model-assisted Web
analysis.

PAJIN's original architecture assigns contextual planning and validation judgments to a replaceable
Agent Runtime while PAJIN Core owns Campaign state, policy, budgets, Capabilities, Permits, execution,
Evidence, Findings, and Graph admission. A Web continuation should therefore make the LLM analysis
loop central again without treating model output as authority or weakening WEB-006 to accept
prompt-authored execution input.

The immediate design question is narrower than autonomous action planning. We need to close and
strictly reload a discovery-only Run before any diagnostic or DOM probe, then validate the model
input, invocation, output, and compiler boundaries against the current fixed code-owned hypotheses
before allowing a model proposal to reach an action compiler or target.

## Decision

### Keep the LLM loop central and PAJIN authority external

Adopt the PAJIN-owned sequence `sealed discovery-only observation -> model analysis/proposal ->
deterministic compilation -> separately authorized action -> fresh validation ->
Finding/Graph/report` as the central Web architecture.

The model owns only contextual analysis and proposal formation. It cannot create or widen Campaign
Scope, choose an unregistered executable, mint Capability or approval, issue a Permit, dispatch a
Gateway or Worker, confirm a Finding, admit Graph state, publish a report, or authorize external
delivery.

WEB-006 remains the required browser, discovery, diagnostic, and sealed-Evidence safety substrate.
The v1alpha1 source is a separate Run closed after bounded discovery and before any diagnostic or
DOM-probe dispatch. Model integration composes above the substrate and does not bypass or replace it.

### Introduce an analysis-only v1alpha1

Add a separate WEB-007 analysis Run. Its principal additive wires are:

- `pajin.dev/web-analysis-snapshot/v1alpha1`;
- `pajin.dev/web-analysis-model-projection/v1alpha1`;
- `pajin.dev/web-analysis-proposal-draft/v1alpha1`;
- `pajin.dev/web-analysis-compilation-policy/v1alpha1`; and
- `pajin.dev/compiled-web-analysis-proposal/v1alpha1`.

The private Snapshot is projected only from an exact strictly reloaded, sealed discovery-only source
Run and the current installed diagnostic bundle and path builder. It binds the actual source
Run/root, Campaign, installed profile, adapter, exact target, discovery Evidence, bundle, and
path-builder identities. Only its detached model projection is sent to the Provider. That projection
contains three target-neutral code-owned diagnostic hypothesis IDs, both code-owned path topologies,
bounded passive-discovery features expressed as code-owned enums and count buckets, and opaque
Evidence references. Each opaque reference is a domain-separated HMAC over the private source
identity using the sealed source root as a key that is not included in the model request. The
projection digest binds the exact Provider-visible bytes but supplies no lookup or execution
authority. Neither object contains diagnostic or DOM-probe outcomes.

The Provider-visible projection excludes
credentials, tokens, cookies, leases, request and response bodies, query values, raw DOM,
screenshots, selectors, routes, environment data, local paths, delivery destinations, target
locators, target identifiers, target-derived digests, source identifiers, and reversible low-
entropy hashes.

The model-visible Snapshot also excludes bundle IDs and digests, profile and adapter identities,
path-builder identities, and other product or target labels. Those exact bindings exist only in the
private Snapshot and compiler context.

The analysis policy permits exactly one call to an installed local model with a pinned provider,
immutable model revision or weights digest, fixed prompt and output schema, bounded tokens and time,
no tools, and no external egress or telemetry. A hosted model is not an alternate configuration for
v1alpha1. Any future external model use requires separate destination-bound authorization and data
handling review.

Each analysis Run permits at most one dispatched call attempt. Post-dispatch uncertainty, timeout,
provider failure, or malformed output is terminal for that Run, creates no compiled advisory, and
grants no automatic retry. A subsequent attempt requires a new analysis Run, a fresh strict reload
of the sealed discovery source and current catalog, a new opaque reference and Snapshot, and new
invocation-policy and budget records. It cannot trigger fallback diagnostics or Permit issuance.

### Require all three diagnostics and both paths

The v1alpha1 proposal ranks every current diagnostic hypothesis and assesses every current attack
path:

- `sql-login`, `object-access`, and `dom-xss`, each exactly once with ranks forming `1..3`; and
- the code-owned `sql-login -> object-access` and `dom-xss` paths, each exactly once in code-owned
  catalog order with one disposition: `investigate` or `insufficient-evidence`.

Every item remains present regardless of the projected discovery features. The proposal contains no
free-form rationale. It cannot omit or select a subset, add or rename an item, assert a diagnostic
outcome, change a code-owned hypothesis or canonical policy, or express an execution schedule.

The roadmap's v1alpha1 "priority only" wording remains the authority constraint. The closed
path disposition is bounded evaluation metadata; neither it nor diagnostic rank can influence
subset, dependency, action compilation, or execution.

This cardinality is deliberate. Variable diagnostic and path sets require a new version rather than
quietly changing the v1alpha1 interpretation.

### Parse as untrusted data and compile deterministically

Admit raw model output only through an alias-exact, extra-forbid, resource-bounded JSON parser. The
proposal schema contains no route, selector, credential, payload, method, Tool argument, import,
dependency, retry, concurrency, destination, or executable action field. It fixes Scope, scheduling,
Capability, approval, Permit, Gateway, execution, Finding, Graph, publication, and delivery authority
to false. Free-form rationale and explanation fields are also forbidden rather than ignored.

The deterministic compiler re-verifies the sealed discovery source, Snapshot, detached projection,
current bundle and path builder, invocation receipt, exact item membership, unique diagnostic ranks,
fixed path order, and all code-owned identities. It copies hypothesis identities and path structure
only from the reopened code-owned catalog. Model-provided diagnostic rank and path disposition remain
explicitly untrusted. The canonical envelope is compiler-authored, contains no free-form model text,
and preserves the private Evidence bindings instead of relabeling the model output as code-owned.

The compiled advisory is not accepted by any existing action, promotion, Graph, SARIF, PoC, report
publication, or delivery gate. Structural validity does not attest model quality or vulnerability
confirmation.

### Reserve action integration for v1alpha2

v1alpha2 will use distinct discovery-action and diagnostic-action proposal types. Neither type can be
reinterpreted as the other, and discovery completion cannot automatically schedule diagnostics.

Each compiled diagnostic plan must pass two complete, independent target-execution chains:

```text
proposal
-> deterministic compiler
-> compiled-plan digest

source chain:
compiled-plan digest
-> fresh source policy decision
-> distinct recorded source approval
-> exact one-use source ActionPermit
-> Gateway and isolated source Worker with a fresh login
-> sealed source outcome

validation chain:
the same compiled-plan digest, independently reinterpreted
-> fresh validation policy decision
-> distinct recorded validation approval
-> exact one-use validation ActionPermit
-> Gateway and isolated validation Worker with a fresh login
-> sealed validation Evidence
-> deterministic confirmation
-> Finding promotion and Graph admission
-> local report, SARIF, and redacted PoC
```

The source and validation chains never share an approval or Permit. Both always create a distinct
recorded approval decision. The future risk policy determines whether the approving actor must be
human; a human-review requirement cannot be satisfied by the model or inherited from the other
chain. Every discovery action and diagnostic action likewise requires its own compiler lineage,
fresh policy decision, distinct recorded approval, one-use Permit, Gateway dispatch, isolated
Worker, and budget reservation.

If v1alpha2 introduces bounded subset selection or dependencies, the compiler derives the executable
graph only from installed typed identities inside existing Campaign Scope. Raw model rationale never
supplies executable arguments. A later model turn requires a fresh model budget and receipt.

External delivery remains outside this chain until a distinct destination-bound action receives its
own authorization and delivery receipt.

## Consequences

### Positive

- The LLM regains its intended central role in Web analysis without becoming an authority source.
- WEB-006's login, browser, discovery, network, diagnostic, sealing, and provenance controls remain
  intact.
- A fixed all-item v1alpha1 makes omissions, invented checks, duplicate ranks, and hidden scheduling
  structurally rejectable.
- One local no-tool call bounds data movement, cost, retry, and prompt-injection blast radius.
- A separate analysis Run preserves existing WEB-003 through WEB-006 artifact bytes and digests.
- v1alpha2 has an explicit migration point for action semantics and variable cardinality.

### Tradeoffs and residual risks

- Local inference adds latency, memory use, model inventory, upgrade, and health-management work. The
  first actual Qwen3 4B Q8 dispatch reached the local Worker and Provider but hit the current 30-second
  upstream I/O ceiling before producing a response, despite the outer 180-second execution budget.
- A strict schema contains authority escalation but does not make model prioritization accurate,
  stable, or useful.
- Secret-free projected discovery features can still encode adversarial target influence;
  containment depends on their fixed enum representation and the compiler ignoring model semantics
  for authority, not on prompt robustness.
- v1alpha1 duplicates no target execution but also cannot improve diagnostic scheduling. It is a
  shadow analysis stage until v1alpha2 is implemented.
- The current exact three-diagnostic/two-path contract remains Juice Shop-specific and does not prove
  arbitrary-site support.
- The actual failure run verified local Docker dispatch, bounded host-provider egress, terminal
  no-redispatch semantics, cleanup, and no external delivery. Successful structured output, useful
  ranking, completion latency, and peak memory remain unverified.

## Compatibility, migration, and rollback

This decision is additive. Existing Result, Run, reconciliation, promotion, Graph, validation,
report, SARIF, PoC, and delivery formats are unchanged. Historical artifacts are not rewritten. A
WEB-007 Run references sealed source digests and owns its own Snapshot and Provider context. A
successful Run additionally owns the invocation receipt, raw untrusted draft, and compiled advisory;
a failed dispatched Run owns a terminal failure receipt instead.

Migration first evaluates the implemented analysis-only v1alpha1 in shadow mode. v1alpha2 uses new
wires and explicit action compiler consumers; a v1alpha1 advisory can never be upgraded in place or
treated as an action proposal.

Rollback disables new model invocation and advisory reading. Existing analysis Runs remain inert
audit evidence, while their WEB-006 source Runs continue to load under their original contracts.

## Rejected alternatives

- Treat the WEB-006 fixed diagnostic pipeline as the final product architecture with the LLM only
  summarizing the completed report.
- Feed completed diagnostic or DOM-probe outcomes into the immediate v1alpha1 model turn instead of
  closing a pre-diagnostic discovery-only Run.
- Allow the LLM to call the browser, HTTP client, diagnostic functions, Gateway, or Tools directly.
- Send sealed or projected target Evidence to a hosted model under the local v1alpha1 policy.
- Let prompt text, target content, or raw rationale define Scope, selectors, routes, payloads,
  executable identities, or action dependencies.
- Permit the model to omit low-ranked diagnostics or paths in v1alpha1.
- Convert ranking into execution order without a versioned action schema, deterministic compiler,
  approval, Permit, and Gateway path.
- Promote a Finding or write Graph state from one proposing execution or from model confidence.
- Deliver a report, SARIF, PoC, prompt, Snapshot, or model response externally without a separate
  destination-bound authorization and receipt.

## Verification status

The v1alpha1 Snapshot/projector, detached model projection, strict proposal schema and parser,
deterministic inert compiler, local Provider runtime, sealed success/failure Run loaders, and
operational CLI are implemented with focused positive and adversarial tests. A real pre-diagnostic
Juice Shop discovery Run was strictly reloaded, projected, and used for one actual local model
dispatch. The Provider and analysis failure Runs were sealed and independently reloaded after the
Worker reported `stage=provider-open`, `category=timeout`. The analysis receipt fixes
`modelDispatchAttempted=true`, `proposalCompiled=false`, and
`automaticRedispatchAuthorized=false`; no target request or external delivery occurred.

That execution did not produce model output, a compiled advisory, model-quality evidence, a
successful completion-latency measurement, or a peak-memory measurement. It also does not satisfy
the separate full WEB-006 governed runtime and PoC replay requirement, and it creates no source or
validation action, Finding, Graph admission, report, SARIF, or PoC. A versioned transport/runtime pin
that can honor the 180-second invocation budget is required before a fresh, separately initiated
analysis Run may make another single attempt. The failed Run itself must never be retried.

`DECISIONS.md` indexes this ADR as accepted. The remaining validation gaps are tracked in the
[WEB-007 proposal](../orchestration/WEB-007-llm-assisted-web-analysis-proposal.md), `PLAN.md`,
`HANDOFF.md`, and `KNOWN_ISSUES.md`.

## Related documents

- [WEB-007 proposal](../orchestration/WEB-007-llm-assisted-web-analysis-proposal.md)
- [Current implementation plan](../../PLAN.md)
- [WEB-006 contract](../orchestration/WEB-006-installed-profile-and-authenticated-discovery-evidence.md)
- [ADR-0300](0300-bind-governed-web-execution-to-a-closed-profile-and-passive-discovery-receipts.md)
- [ADR-0001](0001-agent-runtime-and-orchestration.md)
- [ADR-0004](0004-dynamic-multi-agent-execution.md)
- [SUP-003 contract](../orchestration/SUP-003-typed-non-executable-supervisor-proposal.md)
- [PERMIT-002 contract](../orchestration/PERMIT-002-deterministic-action-compiler.md)
