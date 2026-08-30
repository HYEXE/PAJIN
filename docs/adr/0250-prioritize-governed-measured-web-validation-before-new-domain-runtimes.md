# ADR-0250: Prioritize Governed Measured Web Validation before New Domain Runtimes

- Status: Accepted
- Date: 2026-08-28
- Owners: PAJIN architecture and security boundary maintainers
- Scope: Phase 11 through Phase 21 integration checkpoint and Phase 22 roadmap selection

## Context

Phase 11 through Phase 21 establish an executable Pentest and limited AI/MCP product core, a
common nine-domain classification and authority model, and bounded A-through-D bootstrap slices for
Web, AI, Network, Cloud, System, Application, Mobile, Cryptography, and Digital Forensics. The
implemented markers are accurate within each contract's explicit boundary. They do not mean that
all nine domains have repository-owned runtimes, materialized fixtures, measured Ground Truth,
Profile validation floors, or production Finding paths.

The integration checkpoint must choose one next vertical slice rather than continuing breadth-first
contract work or opening several runtimes in one change. The selection criteria are existing asset
reuse, the feasibility of materialized private Ground Truth, a bounded read-only or synthetic first
target, safe Worker isolation, deterministic evidence, and the size of the new authority boundary.

Web has the strongest complete predecessor chain:

- WEB-001A through WEB-001D already bind an exact typed HTTP Surface, approved GET Recon,
  neutral Graph admission, independent GET Replay, the DOMAIN-006 Web plan, and a private P0-D1
  Boolean-SQLi Ground Truth profile;
- P0-D1 already provides the fixed synthetic target profile, private Ground Truth, public catalog,
  catalog-bound Docker Target Factory, and code-owned matcher;
- P0-E2B already provides a runnable bounded ZAP 2.17.0 local-Docker scanner, raw SARIF retention,
  strict normalization, registry-governed measurement authority, cleanup, and a completed
  `BenchmarkResult`; and
- the fixed Boolean-SQLi Capability already has a controlled baseline, negative Control, Boolean
  probe, and the existing approval, ActionPermit, Gateway, Worker, and product-reporting paths.

WEB-001D deliberately keeps the private profile in
`registered-ground-truth-not-measured`. It does not bind the generic GET Replay to the SQLi case,
activate a Target Factory, run ZAP, publish numeric metrics, satisfy a Profile floor, or confirm a
Finding. That explicit gap can be closed without inventing a new target provider, scanner runtime,
or arbitrary Web executor.

Network is the next closest candidate because a repository-owned egress-proxy passive-banner
Worker action exists. Its six isolated-service fixtures remain requirements only, however, and it
has no disposable Target Factory, governed measurement, or product entrypoint. AI has runnable KISA
and local RAG/MCP assets but no concrete AI-001D Ground Truth case and a larger nondeterminism,
session-isolation, provider, credential, and cost boundary. Cloud, System, Application, Mobile,
Cryptography, and Forensics require a new provider, host agent, parser, artifact source, sandbox, or
device runtime before their registered fixtures can be observed.

## Decision

Select Phase 22, Governed Measured Web/API Validation, as the next single vertical slice. Constrain
it to one exact synthetic P0-D1 Boolean-SQLi lab. Do not generalize it to arbitrary targets,
scanners, images, commands, credentials, external networks, or Web vulnerability classes.

Deliver Phase 22 as four independently reviewable, sequential boundaries:

1. `WEB-002A` introduces an exact measured-case authority. It content-addresses one concrete
   WEB-001A Boolean-SQLi HTTP Surface with the exact P0-D1 selection and private Ground Truth,
   P0-E2B scanner registration and measurement plan, and DOMAIN-006 Web metric plan. It keeps
   public-safe registration and selection separate from private Ground Truth. It grants no target,
   scanner, Graph, Finding, Profile-floor, or product activation authority.
2. `WEB-002B` activates only the existing registry-governed P0-D1/P0-E2B local-Docker lifecycle
   through a bounded operator entrypoint. It requires immutable selected image identities, an
   internal-only network with no published ports, pinned scanner configuration, raw SARIF
   retention, signed measurement-registry authority, durable recovery, and verified cleanup. Domain
   or Graph metadata cannot select or authorize the provider.
3. `WEB-002C` contextfully reloads the sealed Target, Harness, Scanner, raw-evidence,
   normalization, and measurement sources and admits only public-safe neutral Web knowledge through
   the existing Canonical Graph single writer. Private Ground Truth, raw response bodies, raw SARIF,
   and routable target coordinates do not enter Graph prose. Admission grants no new execution or
   Finding authority.
4. `WEB-002D` performs a separately approved controlled validation on a fresh disposable Target
   lifecycle using the existing fixed Boolean-SQLi baseline, negative Control, and Boolean probe.
   Its ActionPermit, Worker session, execution, and evidence identities must differ from the ZAP
   source. Only the exact private matcher, measured source, controlled validation and Replay/Control
   evidence, and DOMAIN-006 metrics may satisfy the fixed Profile floor and project the seeded
   Finding. The product view remains read-only.

Ground Truth is adjudication input, never execution authority. A registered private case cannot
select a Target, Scanner, Capability, Tool, Worker, Scope, approval, Permit, network route, Graph
write, or Finding. A generic GET Replay cannot stand in for SQLi detection or controlled validity.
Likewise, a ZAP alert is a measured candidate, not a confirmed Finding, until the independent
controlled validation floor is satisfied.

Keep the existing P0-D1, P0-E2B, WEB-001, PENTEST, BENCH-001, DOMAIN-006, Capability,
ActionPermit, Gateway, Worker, Graph, Evidence, and Finding wire identities. Each WEB-002 task must
add its own versioned contract and positive/adversarial tests before it can be marked implemented.
Phase 22 remains planned until the opt-in real-Docker path has materialized the exact target and
scanner and verified cleanup on the current implementation.

## Consequences

- The next milestone converts an already registered Web Ground Truth profile into one observed,
  measured, independently validated vertical slice instead of adding another unexecuted domain
  registry.
- Existing Target Factory, Scanner, measurement, Capability, and Graph authorities are composed
  rather than replaced. The main design risk is authority confusion at their joins, so each join is
  a separate task with a fail-closed versioned boundary.
- The first materialized domain benchmark remains a local synthetic lab result. It does not claim
  production Web coverage, general scanner quality, external target safety, or cross-host provider
  fencing.
- Network disposable service fixtures are the preferred next runtime candidate after Phase 22,
  subject to a fresh roadmap review. This ADR does not authorize that work.
- AI and the remaining domain runtimes stay deferred. Their existing false authority and
  unmeasured markers must not be weakened to reuse the Web result.

## Rejected alternatives

### Continue breadth-first with another domain contract slice

Rejected because Phase 13 through Phase 21 already expose the difference between a bounded contract
and executable product support. Another registry-only slice would not reduce the largest integrated
product gap.

### Materialize Network fixtures first

Rejected for this milestone because the passive-banner Worker exists but the disposable service
Target Factory, governed measurement, and product entrypoint do not. Web already has all three and
therefore requires a smaller new authority boundary. Network remains the next-ranked runtime
candidate.

### Materialize AI Ground Truth first

Rejected because AI-001D has no concrete Ground Truth case and introduces larger provider,
credential, cost, nondeterminism, and session-contamination risks. The fixed Web lab is a more
deterministic first measured domain slice.

### Start an offline Cryptography or Application parser runtime

Rejected because those slices would require a new artifact source, sandbox materializer, parser or
analyzer runtime, independent implementation, cleanup observer, and measurement path. Reusing a CTF
XOR solver would also overstate general cryptographic support.

### Bind the existing GET Replay directly to Boolean-SQLi Ground Truth

Rejected because response stability and vulnerability validation have different targets, actions,
evidence, Oracles, and denominators. Combining them would manufacture measurement and Finding
authority from unrelated provenance.

### Implement several domain runtimes together

Rejected because it would cross multiple Worker, provider, credential, artifact, device, and
benchmark trust boundaries in one review unit and violate the one-domain-runtime rule.

## Security and authority impact

This ADR selects work; it does not itself activate a Target Factory, run Docker or ZAP, issue an
ActionPermit, admit Graph knowledge, measure a case, confirm a Finding, or grant product authority.

Future WEB-002B execution is restricted to the existing fixed synthetic local-Docker profile and
measurement-registry authority. It must retain internal-only networking, no published ports,
immutable selected image identities, fixed Scanner registration and configuration, bounded output,
raw evidence retention, recovery, and cleanup. Local Docker host privilege remains an explicit
operator opt-in and is not inferred from Campaign, Domain, Surface, Ground Truth, or Graph metadata.

Future WEB-002D active validation requires a fresh exact Capability activation, approval,
ActionPermit, Worker admission, dispatch, and sealed evidence lineage. The benchmark Target and
Ground Truth cannot bypass those controls. No external target, arbitrary scanner, shell, plugin,
credential, host filesystem, mutation, or cross-domain authority is introduced by this decision.

## Compatibility and rollback

The roadmap decision is additive. Existing public imports, CLI commands, schemas, artifact readers,
sealed Runs, Graph events, benchmark Results, and wire identities are unchanged. No migration is
required.

Rollback removes Phase 22 from `PLAN.md`, restores the checkpoint to an unselected next milestone,
and supersedes this ADR with a new decision. It does not rewrite or reinterpret any P0-D1, P0-E2B,
WEB-001, Pentest, benchmark, Graph, or Finding artifact.

## Verification requirements

Each WEB-002 task must cover exact predecessor reconstruction, public/private Ground Truth
separation, authority-marker literalness, digest and nested-model forgery, cross-profile and
cross-target substitution, identity reuse, stale measurement authority, Scanner and provider drift,
raw-evidence mutation, cleanup failure, Ground Truth leakage, generic-GET/SQLi conflation, and
attempted Scope, Permit, Worker, network, Graph, Finding, or product-authority escalation.

WEB-002B and WEB-002D additionally require opt-in real-Docker conformance with the fixed images,
internal network, no published ports, raw evidence, and observed cleanup. Unit tests or fake Docker
adapters do not count as that conformance evidence.

## Related contracts and decisions

- [WEB-001D](../benchmark/WEB-001D-independent-web-replay-ground-truth.md)
- [P0-D1](../benchmark/P0-D1-traditional-web-api-target-catalog.md)
- [P0-E2B](../benchmark/P0-E2B-zap-scanner-baseline-measurement.md)
- [DOMAIN-006](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
- [ADR-0215](0215-bind-web-replay-and-ground-truth-without-measurement-authority.md)
- [ADR-0097](0097-run-concrete-zap-baseline-with-raw-sarif.md)
- [ADR-0087](0087-traditional-web-api-target-catalog.md)
