# ADR-0257: Project WEB-002D through a Read-only Operator Product Flow

- Status: Accepted
- Date: 2026-08-30
- Owners: PAJIN architecture, product, and security boundary maintainers
- Scope: Phase 23 roadmap selection and UX-009 authority boundary

## Context

Phase 22 closes one exact synthetic P0-D1 Boolean-SQLi lifecycle from a registry-governed ZAP
source measurement through independent controlled validation, the DOMAIN-006 floor, and one
bounded public-safe Finding. The WEB-002D authority is sealed and contextfully reloadable, but the
current checkpoint explicitly has no dedicated product entrypoint. An operator cannot consume
that result through one product flow without either reading internal artifacts directly or
confusing benchmark confirmation with generic production vulnerability reporting.

UX-008 is a structural precedent because it separates Scope, Evidence, Finding, and report
sections. It is not an authority predecessor: UX-008 consumes REDTEAM-002, has no Campaign Profile
mapping, and deliberately projects no Finding. WEB-002D has a different source chain and confirms
only benchmark-ground-truth-match, with impact and severity information-only and every reporting
or delivery marker false.

ADR-0250 retained Network as the preferred next new-domain runtime after Phase 22, subject to a
fresh roadmap review. A read-only product projection is a smaller intervening boundary. It adds no
Target, provider, Worker, network, credential, Graph write, or execution path and closes the
explicit product-entrypoint gap before another runtime trust boundary is opened. This does not
authorize or deprioritize the later Network runtime.

## Decision

Select Phase 23, Bounded Measured Web Operator Product Read, as the next single vertical slice after
the current WEB-002D tree regains its required real-Docker conformance evidence.
Use the UX namespace because this work consumes an existing domain authority for product display;
it does not introduce a new Web execution or measurement generation. Reserve WEB-003 for a future
Web runtime generation and do not append WEB-002E to the completed WEB-002A-through-D milestone.

Deliver Phase 23 as four sequential boundaries:

1. UX-009A creates one additive, content-addressed, sealed measured-Web product-flow projection.
   Publication and trusted reload first call the exact WEB-002D loader and rebuild the complete
   projection. It separates bounded measured-case Scope, content-free Evidence references, floor
   state, the bounded Finding, and an explicit unavailable report state. It has no HTTP or
   rendered UI entrypoint.
2. UX-009B introduces a deployment-pinned, contextful product reader. A deployment-owned registry
   or resolver selects the exact product Run and complete WEB-002D reopen context. Callers cannot
   supply a filesystem root, artifact path, provider, adapter, trust anchor, journal, private
   mapping, or alternate source authority.
3. UX-009C exposes one authenticated Operator-only Control Plane read and same-origin Web Console
   view over the UX-009B reader. The request is body-free, responses are non-cacheable, rendering
   is strict and text-only, and the read creates no database row, file, approval, Permit, Run,
   Graph event, Tool call, Worker dispatch, report, or external delivery.
4. UX-009D adds fresh-session deterministic product-read conformance. It independently reloads
   the exact source and projection, proves stable bytes and digests, exercises authentication and
   tamper or substitution failures, and verifies that product consumption causes no provider,
   Docker, network, Graph, report, or delivery side effect.

UX-009A treats the sealed pajin.dev/web-controlled-validation-authority/v1alpha1 Run and authority
ID and digest as its exact source. Trusted reconstruction also follows its WEB-002A
WebMeasuredCaseAuthorityRef, WEB-002B WebZAPSourceMeasurementAuthorityRef, registered floor and
Finding-projection policy references, WebValidationFloorEvaluationRef, and
WebBenchmarkFindingRef. It continues to require the exact source-owned ZAP provider,
controlled-validation adapter, claim ledger, Target journal, route trust context, and private
expected-reference mapping already required by load_web_controlled_validation_authority. Those
private or runtime inputs are verifier inputs only and do not enter the product wire.

WEB-002C is not a required predecessor. Its neutral Graph Observation and open Hypothesis do not
authorize WEB-002D execution, and UX-009 must not manufacture a causal link between them.
Canonical Graph composition remains a separate product decision.

## Product and security ceiling

The product flow may display only public-safe identities and bounded status derived from the exact
WEB-002D authority: measured-case, source-measurement, floor-policy, evaluation, and Finding
references; public metric applicability and rational values; Evidence requirement counts; denial
Control satisfaction; cleanup verification; and the exact benchmark-ground-truth-match claim
ceiling.

The projection preserves impactAssurance=not-evaluated-information-only and
severityAssurance=not-evaluated-information-only. WEB-002D's bounded product Finding may be shown
as confirmed only within that claim ceiling. The view must not present it as a general production
vulnerability, generic validation Finding, negative security conclusion, report, or delivery
authority.

The projection and every downstream reader fix all of the following as false or unavailable:

- Campaign Scope availability, Scope expansion, or Profile inference;
- private Ground Truth or expected-reference disclosure;
- raw SARIF, controlled-query, response body, transcript, or raw Evidence disclosure;
- route, approval, Permit, request, dispatch, container, network, or filesystem-coordinate
  disclosure;
- Graph inclusion or mutation;
- generic production-vulnerability confirmation, impact assurance, or severity assurance;
- report creation, report delivery, or external delivery;
- Capability activation, Permit issuance, route reuse, or additional execution; and
- Target, provider, Docker, Worker, network, credential, or external-system side effects.

An Operator read is observation, not approval or action authority. Approver, Auditor, and Worker
roles do not gain access merely because they are authenticated unless a later ADR explicitly
changes that product-read policy.

## Compatibility and rollback

Phase 23 is additive. It does not add fields to or reinterpret any WEB-002A, WEB-002B, WEB-002C,
WEB-002D, UX-008, P0-D1, P0-E2B, DOMAIN-006, Capability, approval, Permit, Worker, Graph, generic
Finding, report, or delivery wire. A WEB-002D Finding is not converted into the generic
independently replay-confirmed Finding accepted by UX-006A SARIF export.

UX-009A receives a new v1alpha1 API, artifact, and event. Later Control Plane settings and routes
are optional and require no database migration. Rollback stops publishing and reading UX-009
artifacts and removes its optional reader, route, and view. Existing WEB-002 authorities and
already sealed UX-009 Runs remain self-describing and are not rewritten.

## Consequences

- Operators gain an honest product-facing representation of the first measured and independently
  validated domain slice without opening another execution boundary.
- Benchmark confirmation remains distinct from production impact, severity, reporting, and
  delivery.
- Publication and every trusted reload inherit the full WEB-002D contextual verification cost
  and deployment dependencies rather than trusting a bare outer JSON object.
- WEB-002C Graph knowledge remains available through its own authority but is not silently joined
  to the controlled-validation result.
- Network remains the next preferred new-domain runtime after Phase 23 and a fresh checkpoint
  review.

## Rejected alternatives

### Add WEB-002E

Rejected because ADR-0250 defines WEB-002A through WEB-002D as the complete Phase 22 implementation
sequence. Current-tree conformance revalidation does not create a fifth implementation boundary,
and extending the sequence would blur the runtime milestone with a new product-consumption boundary.

### Use WEB-003A for the product view

Rejected because no new Web Target, scanner, controlled-validation runtime, Ground Truth class, or
measurement authority is introduced. WEB-003 remains available for a future Web runtime
generation whose execution boundary is reviewed on its own.

### Extend UX-008 or treat it as source authority

Rejected because UX-008 consumes REDTEAM-002 and explicitly has no confirmed Finding or Campaign
Profile floor. Changing its wire or semantics would conflate two distinct source chains.

### Read only the outer WEB-002D JSON

Rejected because a sealed outer object alone does not reproduce the source-owned provider,
controlled Worker, route, denial, cleanup, floor, private matcher, and Finding authority chain.
Publication and reload must use the existing contextual verifier.

### Expose a report or SARIF export in the first product slice

Rejected because WEB-002D fixes reporting and external delivery authority to false and its bounded
Finding is not the generic UX-006A export authority.

## Verification requirements

UX-009 must cover contextual source reload before publication and read, source Run or root and
authority substitution, product Run reuse, event equivocation, stale or appended source state,
nested-model and strict-boolean forgery, claim-ceiling or impact and severity escalation,
raw or private field leakage, caller-selected path or provider substitution, role denial,
response caching, strict safe rendering, deterministic fresh-session bytes and digests, and
absence of all prohibited side effects.

The final conformance may reuse the already bounded WEB-002D lifecycle result, but reading the
product must not trigger or imply another Docker run. Linux CI evidence and platform-specific
limitations remain separate from this product-read authority.

## Related decisions and contracts

- [ADR-0256](0256-bind-web-002d-independent-controlled-validation-to-durable-evidence-floor-and-finding.md)
- [ADR-0250](0250-prioritize-governed-measured-web-validation-before-new-domain-runtimes.md)
- [ADR-0210](0210-project-redteam-product-flow-without-finding-authority.md)
- [WEB-002D contract](../benchmark/WEB-002D-independent-controlled-validation-floor-and-finding-projection.md)
- [UX-008 contract](../orchestration/UX-008-redteam-product-flow-projection.md)
- [UX-006A contract](../orchestration/UX-006A-verified-finding-sarif-export.md)
