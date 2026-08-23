# WEB-001D: Independent Web Replay and Benchmark Ground Truth

- Status: Implemented, bounded composition and private profile
- Replay projection: `pajin.dev/web-discovery-replay-validation/v1alpha1`
- Ground Truth profile: `pajin.dev/web-api-benchmark-ground-truth-profile/v1alpha1`
- Decision: [ADR-0215](../adr/0215-bind-web-replay-and-ground-truth-without-measurement-authority.md)
- Predecessors: [WEB-001C](../graph/WEB-001C-sealed-web-discovery-graph-admission.md),
  [PENTEST-002B](../orchestration/PENTEST-002B-independently-authorized-recon-replay.md),
  [P0-D1](P0-D1-traditional-web-api-target-catalog.md), and
  [DOMAIN-006](DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)

## Purpose

WEB-001D closes two distinct first-slice requirements without inventing a new Web executor or
benchmark engine:

1. bind one WEB-001C admitted neutral Web Observation to an actual independently authorized
   PENTEST-002B Replay comparison; and
2. bind the existing private P0-D1 Traditional Web/API Ground Truth to the exact DOMAIN-006 Web
   plan as code-owned benchmark input.

These are deliberately separate artifacts. A matching GET response is Replay evidence, not the
P0-D1 Boolean SQLi Ground Truth matcher result. Registering Ground Truth is not a measurement,
Target Factory selection, Finding, or validation-floor decision.

## Independent Replay projection

`bind_web_discovery_independent_replay` reopens the sealed PENTEST-002B comparison and requires:

- the complete WEB-001C Pentest admission to equal the Replay plan's source admission;
- exact source admission ID and digest equality;
- the concrete WEB-001A URL and GET method to equal the Replay plan target and method;
- the exact DOMAIN-006 Web plan and `independent-replay` strategy;
- PENTEST-002B's fresh Run, request, Graph Decision, approval, one-use ActionPermit, receipt,
  Worker admission, dispatch, and execution identities; and
- the sealed comparison publication event and body-free response coordinates.

The projection reports either `independent-replay-response-match` or
`independent-replay-response-changed`. Both states prove that the separate Replay occurred; only
the first reports a response match. Neither state grants another replay, network call, Scope,
Capability activation, approval, Permit, Worker selection, execution, Finding, or benchmark
measurement authority. The source ActionPermit remains consumed provenance.

## Private Ground Truth profile

`registered_web_api_benchmark_ground_truth_profile` reconstructs the existing P0-D1 profile from:

- one exact provisioned `DockerBugBountyTargetProfile`;
- `registered_traditional_web_api_ground_truth` for the code-owned Boolean SQLi case and matcher;
- `registered_traditional_web_api_target_catalog` and its exact public registration;
- `BenchmarkTargetGroundTruthBinding`, which retains the complete private case; and
- the exact DOMAIN-006 Web plan reference.

The resulting content-addressed profile is private because it contains the complete Ground Truth.
It fixes its state to `registered-ground-truth-not-measured`. It does not create a Manifest,
select or activate a Target Factory, authorize a provider, execute Docker or ZAP, bind Replay
evidence to the SQLi case, publish numeric metrics, establish detection quality, satisfy a Profile
validation floor, or confirm a Finding.

## Required rejection behavior

The implementation fails closed for:

- unsealed, foreign, or altered PENTEST-002B comparison publication;
- WEB-001C admission, typed Surface, URL, method, or source-admission substitution;
- DOMAIN-006 plan, Domain, strategy, or digest drift;
- P0-D1 target profile, catalog, public registration, private Ground Truth, case, matcher, or
  Target Factory digest substitution;
- inconsistent response-match state; and
- boolean coercion or attempts to enable Finding, measurement, provider, Permit, Scope, Worker,
  network, or execution authority.

## Compatibility and rollback

WEB-001D is additive. It changes no WEB-001A/B/C, PENTEST-002B, P0-D1, DOMAIN-006, BENCH-001,
Graph, Capability, ActionPermit, Gateway, Worker, Evidence, Replay, validation, Finding, or artifact
reader identity. Rollback removes the two projections, tests, contract, and ADR while preserving
all sealed Runs, Graph events, Target catalogs, and private Ground Truth objects.

## Remaining work

- The generic GET Replay proof and P0-D1 SQLi Ground Truth are not a measured case pair.
- No WEB-001D Benchmark Result, score, production Target, general scanner, or validation-floor
  evaluation is implemented.
- A future measurement path must independently bind an activated exact Target Factory, admitted
  raw measurement evidence, the applicable matcher, and sealed metric lineage.
- General auth/data-flow/API hypotheses and active probing remain later Web slices.
