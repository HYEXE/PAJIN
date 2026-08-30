# ADR-0251: Require Additive Target Routing and Validation Policy for Measured Web

- Status: Accepted
- Date: 2026-08-28
- Owners: PAJIN architecture and security boundary maintainers
- Scope: WEB-002A through WEB-002D
- Supersedes: ADR-0250 direct predecessor-reuse details; the Phase 22 Web selection remains accepted

## Context

[ADR-0250](0250-prioritize-governed-measured-web-validation-before-new-domain-runtimes.md)
selects a governed measured Web/API slice because WEB-001, P0-D1, P0-E2B, and the fixed
Boolean-SQLi Tool provide the strongest existing asset chain. That priority and the synthetic-only,
no-external-target safety boundary remain valid.

Two direct-composition assumptions are not valid.

First, the existing REDTEAM Web Profile and digest fix
`http://host.docker.internal:8770/v1/users/lookup`. P0-D1 and P0-E2B instead fix
`http://target:8080/v1/users/lookup` inside a disposable Docker network with zero published ports.
Changing the REDTEAM endpoint would change its Profile identity. Publishing the benchmark port to
preserve the old endpoint would weaken P0-E2B isolation. The repository has no signed authority that
currently attaches a Gateway-managed validation Worker to one exact fenced Target Factory network.

Second, the existing metric and Finding objects do not form a WEB-002 validation policy.
DOMAIN-006 registers Web metric vocabulary but no denominator, threshold, applicability decision,
or floor-satisfaction authority. P0-D1 contains a private expected Finding reference. The existing
Bug Bounty validator emits a general UUID-backed `Finding` with `validated=true`, while Pentest uses
a separate content-addressed Finding projection. None may be silently reinterpreted as a measured
WEB-002 Profile floor or Finding identity.

## Decision

Retain Phase 22 as the next vertical slice, but require WEB-002A to establish four additive,
versioned authorities before any Target or Scanner execution:

1. an exact WEB-002 Profile and Capability release for the fixed synthetic Boolean-SQLi validation
   request, reusing the reviewed Tool implementation but not the existing REDTEAM Profile target or
   digest;
2. a public-safe measured-case binding over the P0-D1 selection, private Ground Truth digest,
   P0-E2B Scanner plan and registration, WEB-001A internal Surface, and DOMAIN-006 Web metric plan;
3. an operation-scoped signed Target-session route authority; and
4. a versioned Web validation-floor and Finding-projection policy.

The new Profile and Capability must have additive IDs, versions, and digests. They may reuse the
existing `BooleanSQLiProbeTool` implementation only after rebuilding its exact Tool identity,
three-request budget, T2 risk, fixed method/path/scenario, host-observed receipts, and zero
caller-authored payload semantics. Existing REDTEAM, Bug Bounty, WEB-001, PENTEST, Capability, and
Tool identities remain unchanged. WEB-002A registers the new release and binding but grants no
activation, approval, Permit, route materialization, Worker, network, or execution authority.

The Target-session route authority must be issued from the current registry-governed Target
operation and bind at least:

- benchmark, Target profile, Target Run authority, operation coordinate, operation fence, and
  provider identity;
- exact internal network identity and digest, target container identity, service alias, port,
  scheme, method, and path;
- exact WEB-002 Profile, Capability release, request semantics, Gateway policy, Worker deployment,
  Campaign, and Scope;
- issue, expiry, single-use consumption, and cleanup/fence invalidation identities; and
- a deployment-owned signature and key lifecycle distinct from caller input and private Ground
  Truth.

The authority contains no Docker socket, host port, command, credential, private key, arbitrary
network name, or caller-selected route. It cannot publish a port, attach to another network, widen
Scope, select a Tool or Worker, issue a Permit, or survive operation-fence advancement or Target
cleanup. WEB-002A defines and verifies the inert wire only. WEB-002B may materialize it through a
deployment-owned adapter after the existing signed measurement and provider authorities are
current. The Gateway and Worker must consume the same exact route once and retain an attachment and
detachment receipt in sealed Evidence.

The validation-floor policy must have an exact policy ID, version, digest, applicable Profile and
Capability, required DOMAIN-006 metric references, denominators, thresholds, not-applicable rules,
required source/validation/Replay/Control evidence, and private Ground Truth binding. WEB-002A
registers all requirements with every observed, measured, satisfied, and Finding marker false.
Neither metric registration nor presence of a P0-D1 case satisfies a denominator or threshold.

The policy must define an explicit mapping from the private P0-D1 expected Finding reference to a
new public-safe, content-addressed WEB-002 Finding projection identity. The mapping does not expose
private matcher contents or make the expected reference a Finding. Existing Bug Bounty
`validated=true`, an existing UUID Finding, a P0-D1 expected Finding ID, or a Pentest Finding cannot
satisfy the floor by type, string equality, or identity reuse.

WEB-002D may evaluate the registered policy only after contextfully reopening:

- one completed WEB-002B ZAP measurement on the exact P0-D1 case;
- a fresh disposable Target operation with a new fence and signed route;
- a separately approved Capability activation, ActionPermit, Worker session, dispatch, and three
  fixed controlled requests;
- host-observed route, request, response, detachment, Target cleanup, and sealed Evidence; and
- the exact private matcher, Ground Truth, metric inputs, denominators, applicability decisions,
  and Replay/Control evidence required by the policy.

The ZAP source and controlled validation must not reuse Target Run, operation, fence, route,
approval, Permit, Worker, request, response, result, or Evidence identity. Only the versioned
WEB-002 evaluator can produce floor satisfaction and the new Finding projection. The product view
may display that projection after re-verifying the complete sealed lineage but gains no report
delivery, Graph mutation, Target, Tool, Worker, or execution authority.

## Consequences

- Phase 22 remains the selected next slice, while the impossible direct endpoint reuse in ADR-0250
  is replaced with an explicit additive Profile and route boundary.
- P0-D1/P0-E2B keeps zero published ports. The fixed REDTEAM endpoint and digest remain valid for
  their existing lab and are not rewritten.
- Route attachment becomes a security-sensitive deployment action with its own signed, single-use,
  cleanup-bound authority instead of an inferred Docker network operation.
- DOMAIN-006 remains vocabulary only. WEB-002 adds a separate policy authority rather than changing
  domain metrics into thresholds.
- The P0-D1 expected Finding remains private adjudication input. The new projection has explicit
  lineage and cannot be forged by reusing existing Bug Bounty or Pentest Finding objects.
- WEB-002A is larger than a simple profile binding, but it still performs no Docker, network,
  Scanner, Graph, validation, or Finding action.

## Rejected alternatives

### Change the existing REDTEAM endpoint

Rejected because the endpoint is part of the accepted Profile digest and request validator.
Changing it would silently reinterpret existing artifacts and deployments.

### Publish the P0-D1 Target port

Rejected because P0-E2B explicitly depends on an internal-only network and zero published ports.
Host publication widens the reachable attack surface and invalidates the current isolation proof.

### Pass a Docker network name through Campaign or Tool parameters

Rejected because a caller-controlled network name is ambient routing authority. The route must be
deployment-signed, exact, operation-fenced, single-use, and invalid after cleanup.

### Reuse the existing Bug Bounty Finding

Rejected because its UUID identity and `validated=true` flag are not bound to P0-E2B measurement,
DOMAIN-006 denominators, private Ground Truth, the fresh route, or WEB-002 Controls.

### Treat the P0-D1 expected Finding ID as the result

Rejected because it is private Ground Truth input, not observed validation evidence or a public
Finding. The new projection may reference it only through the registered private mapping.

### Let DOMAIN-006 determine the floor

Rejected because DOMAIN-006 intentionally registers metrics without values, denominators,
thresholds, applicability decisions, or validation authority.

## Security and authority impact

This ADR introduces planned authority schemas and policy identities; it executes nothing.
WEB-002A must keep route materialization, provider execution, Worker attachment, network access,
Graph admission, metric observation, floor satisfaction, Finding projection, product activation,
and report delivery false.

Future route materialization is limited to one current signed Target operation, exact internal
service and separately approved request. It cannot carry a Docker socket, credential, host port,
arbitrary network, command, image, target, or Tool. Cleanup or fence advancement invalidates it.
Failure to attach, attest, detach, or clean up fails the case closed and prevents measurement,
validation, floor satisfaction, and Finding projection.

Private Ground Truth and matcher contents remain outside public Graph and product prose. Only their
content-addressed references and the public-safe mapping identity may cross the policy boundary.
No existing `validated` flag, expected Finding string, Domain metric, Graph node, or model output is
authority.

## Compatibility and rollback

The correction is additive. Existing REDTEAM, Bug Bounty, P0-D1, P0-E2B, WEB-001, PENTEST,
DOMAIN-006, Capability, Tool, ActionPermit, Gateway, Worker, Graph, Evidence, benchmark, and Finding
identities remain unchanged. New WEB-002 authorities use new versions and require no migration of
sealed Runs, Graph events, Results, or Findings.

Rollback stops issuing WEB-002 Profile, Capability, measured-case, route, floor-policy, and Finding
projection authorities. Because WEB-002A executes nothing, rollback at that checkpoint requires no
Target or network cleanup. After WEB-002B, rollback must first reconcile and clean every current
Target operation and invalidate all unconsumed routes; historical sealed Evidence remains readable.

## Verification requirements

Positive and adversarial tests must cover exact WEB-002 predecessor reconstruction, old REDTEAM
Profile/digest preservation, new Profile/Capability identity, public/private Ground Truth
separation, literal false markers, canonical digest stability, nested-model forgery, and unknown
field rejection.

Route tests must reject host-port publication, caller-selected network or service coordinates,
foreign Target Runs, stale operation fences, provider/Worker/Gateway drift, expiry, replay,
double-consumption, post-cleanup use, wrong Campaign or Scope, route-to-Permit substitution, missing
attachment/detachment Evidence, and cleanup failure.

Floor-policy tests must reject missing or extra denominators, threshold or N/A drift, unmeasured
metrics, source/validation identity reuse, missing Replay or Controls, private matcher leakage,
direct Bug Bounty `validated=true`, UUID/P0-D1/Pentest Finding substitution, and product projection
before the exact floor is satisfied.

WEB-002B and WEB-002D still require opt-in real-Docker conformance. Unit tests, fake command runners,
or a host-published substitute do not count as internal-route, Scanner, validation, or cleanup
evidence.

## Related contracts and decisions

- [ADR-0250](0250-prioritize-governed-measured-web-validation-before-new-domain-runtimes.md)
- [WEB-001D](../benchmark/WEB-001D-independent-web-replay-ground-truth.md)
- [P0-D1](../benchmark/P0-D1-traditional-web-api-target-catalog.md)
- [P0-E2B](../benchmark/P0-E2B-zap-scanner-baseline-measurement.md)
- [DOMAIN-006](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
- [ADR-0215](0215-bind-web-replay-and-ground-truth-without-measurement-authority.md)
- [ADR-0097](0097-run-concrete-zap-baseline-with-raw-sarif.md)
