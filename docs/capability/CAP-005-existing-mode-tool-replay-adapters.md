# CAP-005: Existing Mode, Tool, and Replay Adapters

- Status: locally implemented with hard-exit dispatch recovery verification
- Date: 2026-07-28
- Prerequisites: ARCH-001, CAP-001, CAP-002, CAP-003, CAP-004, ADR-0051 through ADR-0054

## Purpose

Expose PAJIN's already bounded KISA, Bug Bounty, and CTF Tool contracts as exact CAP-001
definitions and complete CAP-002 authority sets without scanning modules, changing existing Mode
execution, or treating registration as CAP-004 activation.

CAP-005 is an explicit compatibility bootstrap. Callers provide a `ToolRegistry` and receive a
frozen definition/authority bundle. No CLI, Campaign, Graph, Tool Gateway, or Replay path invokes
the bootstrap automatically.

## Task contract

- **Task ID:** CAP-005
- **Threat model:** dynamic Tool discovery, Tool-version substitution, cross-scenario parameter
  reuse, Worker-authored verdict trust, hidden replay authority, mutable adapter context,
  automatic activation, and cleanup or side-effect underdeclaration
- **Changed trust boundary:** existing bounded Mode Tool contracts to CAP-001/002 registration
- **Schema/API versions:** existing CAP-001/002 schemas plus
  `pajin.existing-mode-capability-adapter/v1` and
  `pajin.dev/existing-kisa-replay-plan/v1alpha1`,
  `pajin.dev/existing-mode-capability-activation-set/v1alpha1`, and
  `pajin.dev/prepared-capability-action/v1alpha1`, and
  `pajin.dev/capability-dispatch-audit-event/v1alpha1`
- **Audit artifacts:** seven canonical `CapabilityDefinition` records, seven complete
  `CodeBackedCapability` authority sets, and content-addressed Permit dispatch events in the
  RunStore hash chain
- **Benchmark impact:** none until CAP-006 records coverage and runtime wiring executes an
  activated release

## Explicit inventory

| Capability | Tool | Surface | Threat | Replay |
| --- | --- | --- | --- | --- |
| `pajin.ai.kisa.indirect-tool-hijacking@1.0.0` | `mock.agent-probe@1.0.0` | `mock-agent` | A01, A02 | none |
| `pajin.ai.kisa.system-prompt-disclosure@1.0.0` | `ai.chat-probe@1.0.0` | AI/RAG chat API | M03 | exact KISA fresh session |
| `pajin.ai.kisa.jailbreak-policy-bypass@1.0.0` | `ai.chat-probe@1.0.0` | AI/RAG chat API | M06 | exact KISA fresh session |
| `pajin.ai.kisa.memory-poisoning-persistence@1.1.0` | `ai.chat-probe@1.0.0` | AI/RAG chat API | A04 | exact KISA fresh session |
| `pajin.bug-bounty.boolean-sqli-lab@1.0.0` | `bug-bounty.boolean-sqli-probe@1.0.0` | synthetic Bug Bounty API | CWE-89 | none |
| `pajin.ctf.web-exposed-backup-config@1.0.0` | `ctf.web-backup-probe@1.0.0` | local CTF Web | CTF-WEB | none |
| `pajin.ctf.crypto-single-byte-xor@1.0.0` | `ctf.crypto-single-byte-xor@1.0.0` | offline CTF Crypto | CTF-CRYPTO | none |

The inventory is code-authored and closed. An additional registered Tool does not become a
Capability, and a missing or non-`1.0.0` Tool makes bootstrap fail.

## Definition and authority binding

`existing_mode_capability_bundle()`:

1. validates every exact Tool ID/version against the caller's `ToolRegistry`;
2. derives a scenario-specific parameter-schema digest from the typed Pydantic input schema and
   fixed catalog constraints;
3. creates all seven CAP-001 definitions at `experimental` maturity;
4. creates materializer, action compiler, executor adapter, result normalizer, success Oracle,
   replay strategy, and cleanup handler for each definition; and
5. freezes the complete sets in a `CapabilityAuthorityRegistry`.

Every adapter context binds the Capability ID/version, method, parameter model/schema digest,
scenario, semantic policy, Tool implementation context, and any replay identity. Registry access
recomputes that context, so Tool or catalog drift after bootstrap fails.

All current adapters declare either `none` or `read-only` side effects. Cleanup handlers
explicitly return no plan. A future write-capable adapter requires a new definition and real
cleanup authority; it cannot reuse this contract.

The ToolSpec carries the minimum network request cost. A registration may declare an explicit
reviewed `requestUnitCost` only when one fixed Capability action always performs more exchanges.
A04 `1.1.0` is the first such definition: its exact two-turn catalog request reserves two units.
The other registrations continue to use their ToolSpec cost. This is code-owned definition
metadata, not caller-selected dynamic authority.

## Parameter and semantic boundaries

- KISA AI parameters must match the exact catalog turns and checks. Only a valid session identity
  varies; Replay freshness remains enforced by the existing KISA materializer.
- KISA A01/A02 accepts only the existing typed mock simulation contract.
- Bug Bounty remains fixed to the one synthetic Boolean SQLi scenario.
- CTF remains fixed to the typed local Web backup and content-addressed offline XOR scenarios.
- Compilers preserve request, agent, target, method, Tool, and materialized arguments; CAP-002
  wrappers reject expansion.

Success Oracles do not create Finding authority. They independently classify normalized results:

- KISA AI recomputes every catalog check from the transcript and ignores Worker-authored
  `vulnerable` and `matched` flags;
- the mock adapter recomputes the expected observation from the authorized simulation;
- Boolean SQLi recomputes the three-observation predicate and ignores Worker-authored verdict
  fields;
- CTF Crypto recomputes the complete 256-key XOR result on the host; and
- CTF Web validates typed request/result identity and candidate discovery semantics.

Tool Gateway trusted-execution validation, evidence sealing, Candidate admission, replay
confirmation, and independent Finding validation remain separate required boundaries.

## Replay boundary

Only M03, M06, and A04 bind the existing KISA replay materializer, confirmation/impact/severity
Oracles, negative-retest Oracle, observation schema, scenario digest, and fresh-session policy.

The CAP-002 replay strategy returns an information-only
`ExistingKISAReplayPlan` after semantic support. It sets `executable: false` and
`newAuthorizationRequired: true`; the existing Replay Compiler, grant, ticket, Policy, Gateway,
receipt, and sealed-run checks still authorize and execute replay. A01/A02, Bug Bounty, and CTF
return no replay plan.

## Opt-in activation and GRAPH dispatch

`activate_existing_mode_capabilities()` accepts only an explicit subset of exact release
references from one verified `ExistingModeCapabilityRollout`. CAP-004 revalidates every release
against the requested profile. The resulting content-addressed activation set binds the source
release-set digest, exact code authority, GRAPH-006 registration, domain, and supported surfaces.
Input order does not change its identity. A missing, duplicated, historical, profile-ineligible,
or registration-drifted release fails closed.

`ExistingModeCapabilityActivation.action_registry()` exposes only that subset to the GRAPH-006
Permit compiler. `prepare_action()` then runs the selected release's CAP-002 materializer and
action compiler and binds the exact canonical Tool request and normalized-parameter digests.

`ExistingModeCapabilityGatewayDispatcher` revalidates the signed release before the atomic Permit
claim and again immediately before its callback. It requires the Proposal and consumed Permit to
match the prepared Capability, release, request ID/digest, parameter digest, and declared
request-unit cost, then invokes the existing Tool Gateway. The Gateway still owns Campaign,
Capability Grant, Scope, risk, method, rate, Secret, Worker, receipt, and evidence policy. A
response-loss retry remains non-dispatchable through GRAPH-006.

Construction now requires an append-only audit store whose Run ID equals the consumed Permit.
After the Graph claim, the dispatcher emits `capability.dispatch.claimed` before Gateway entry and
exactly one observed terminal stage: `completed`, `failed`, `cancelled`, or `expired`. Every
content-addressed event binds the activation set, release, Permit/dispatch/proposal/request
identities, and normalized parameters. A completed event additionally binds a domain-separated
digest of the exact `GatewayOutcome`, execution ID when present, policy/execution/success flags,
and canonical evidence references without copying result data into the audit event. Failure and
cancellation expose only an audit-safe exception type.

The bridge fails closed before Gateway entry when the claimed event cannot be appended, the audit
Run differs, or the Permit has expired. Terminal append failure is surfaced to the caller and the
consumed Permit is never retried.

This path is never installed automatically. The legacy Mode planners and coordinators continue to
use their existing paths unless a caller explicitly builds the signed activation and dispatcher.
The local Web + AI fixture proves the structural activation gate but does not claim
organization-issued releases or an operational Campaign run.

## Sealed Web + AI operational exit gate

`CapabilityOperationalEvidenceSet` carries the exact seven delivery records, seven-or-more Oracle
observations, and three-or-more Replay observations used by CAP-006. Its content identity binds
the source release set and every evidence record. `verify_web_ai_hybrid_campaign_exit_gate()`
loads this set only from a fully integrity-verified Run and requires every delivery source,
Oracle observation, and Replay observation digest to match the SHA-256 of another sealed artifact
in that same Run.

The gate then rebuilds the CAP-006 report from the verified rollout and sealed evidence instead of
accepting a caller-supplied completion flag. All CAP-006 gaps must be closed, but CAP-006 decision
and verdict counts remain measurements rather than invented numeric acceptance thresholds.

The same immutable Run must contain exactly two dispatch lifecycles for the bounded Range
activation: `pajin.ctf.web-exposed-backup-config` and
`pajin.ai.kisa.system-prompt-disclosure`. Each lifecycle must be an ordered
`claimed → completed` pair bound to the exact activation, signed release, Campaign, Run, Permit,
Proposal, request, and normalized parameters. Both completions must attest policy allowance,
Worker execution, Tool success, a Gateway outcome digest, a Worker execution ID, and evidence
paths that are themselves sealed in the Run. The two requests and dispatches must be distinct and
belong to one Campaign.

Only a passing gate is materialized. `WebAIHybridCampaignExitGate` content-addresses the sealed
Run root, release and activation sets, raw operational-evidence artifact, rebuilt CAP-006 report,
and both successful dispatch summaries. Fixture-signed tests validate this admission contract;
they do not satisfy the production exit gate.

## Lifecycle, compatibility, and rollback

- Every definition is `experimental` because the generalized adapter path is new, even where the
  underlying Tool is mature.
- Registration is not activation. CAP-004 still requires a reviewed publisher-signed first
  release before any profile may resolve the Capability.
- `admit_existing_mode_capability_releases()` accepts only externally supplied policy, public
  trust keys, and seven signed first-release bundles. It creates no key, review, signature, or
  approval and rejects incomplete, duplicated, untrusted, future-dated, or authority-drifted
  inventories through CAP-004 verification.
- A content-addressed `ExistingModeCapabilityReleaseSet` binds each exact code authority to its
  signed bundle digest, release reference, maturity, and exact benchmark-mapping digest.
- `existing_mode_capability_benchmark_mappings()` provides one closed CAP-003 mapping for every
  adapter. Mapping registration declares what must be observed; it is not execution evidence.
- CAP-005 changes no existing Mode planner, validator, CLI, API, database, or Replay coordinator
  path. The GRAPH/Gateway bridge is additive and requires explicit construction.
- Rollback means not constructing the activation/dispatcher; existing execution remains unchanged.
- Tool or behavior changes require a new Tool/Capability version and reviewed lifecycle release.

## Verification

- exact seven-Capability inventory and complete seven-role authority sets;
- deterministic, distinct scenario-specific parameter-schema digests;
- missing Tool, extra Tool, and post-registration Tool-drift behavior;
- exact KISA catalog materialization, compilation, and Worker preparation;
- independently recomputed KISA, mock, Boolean SQLi, and CTF Crypto semantic outcomes;
- non-executable KISA Replay plan and no Replay plan for A01/A02;
- bounded side-effect and empty-cleanup declarations;
- exact seven-item benchmark mapping and externally signed release-set coverage;
- release, trust-key, and Web + AI activation input-order independence;
- range-only signed activation, inactive Capability rejection, CAP-002 request compilation, exact
  Proposal/Permit/request binding, and request-unit cost enforcement;
- hash-chained claimed/completed linkage, exact Gateway outcome digest, tamper rejection,
  failure/cancellation/expiry terminal events, and pre-execution audit-write fail-closed behavior;
- real subprocess termination after Permit commit, after the claimed RunStore append, and after a
  durable external Gateway side-effect marker, with zero retry Worker calls and one reconciliation;
- missing, duplicated, substituted-key, release-set tamper, and mapping-drift rejection;
- exact seven-delivery/seven-Oracle/three-Replay operational evidence with sealed source hashes;
- exact successful Web + AI dispatch pair, distinct request/dispatch identity, sealed evidence
  paths, and content-addressed exit-gate identity; and
- unsuccessful dispatch, absent source/evidence, activation expansion, and post-seal mutation
  rejection.

## Crash-window reconciliation

The Worker now seals one content-addressed `CapabilityGraphRunAuditAnchor` before the SQLite Permit
claim. The anchor binds the deployment, Campaign, Run, MissionEnvelope, release/activation sets,
and compiler. `RunStore.append_unique_event()` installs that exact anchor once under the existing
cross-process mutation lock, so a concurrent reopen cannot create a second authority record.

An exact retry first seals any hash-valid extension left by the interrupted attempt, then
`reconcile_capability_dispatch()` compares the consumed Permit with the verified Run snapshot:

- no `claimed` event becomes `consumed-without-claim`; Gateway was not entered through this bridge,
  the omitted action remains consumed, and manual review is required;
- exactly one `claimed` event becomes `claimed-outcome-unknown`; an external side effect may have
  occurred, manual review is required, and completion is never inferred; and
- `claimed` plus one exact terminal event becomes the observed terminal status.

Every reconciliation is content-addressed to the Permit, the relevant outer audit event hash, and
the earliest Run seal covering that evidence. Incomplete states are recorded once as
`capability.dispatch-reconciliation.recorded`. The record fixes `redispatchAllowed=false`; a
repeated retry resolves the same record and cannot append another record or enter Gateway.

## Follow-up boundaries

- CAP-006 measurement contracts, seven code-authored benchmark mappings, and signed release-set
  admission are implemented; organization-issued releases, delivery evidence, and sealed
  execution observations remain follow-up work;
- the sealed Web + AI gate verifier and Worker-daemon deployment wiring are implemented; one
  actual isolated Hybrid Campaign run using organization-issued releases remains required;
- exhaustive process-kill and power-loss injection at the remaining internal RunStore, SQLite,
  Worker, and filesystem synchronization boundaries;
- additional Bug Bounty, CTF, discovery, RAG, and administrative adapters; and
- Linux CI and clean-clone verification.

The Graph claim, RunStore event append, and external Worker side effect remain separate durability
domains. The implemented reconciliation makes their ambiguity explicit and durable; it does not
make the external side effect transactional or authorize an automatic retry.

## Related documents

- [ARCH-001 PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
- [CAP-001 Versioned Capability Definition](CAP-001-versioned-capability-definition.md)
- [CAP-002 Metadata + Code-backed Authority Interfaces](CAP-002-metadata-code-backed-authority-interfaces.md)
- [CAP-003 Capability Authoring SDK and Scaffold](CAP-003-capability-authoring-sdk-scaffold.md)
- [CAP-004 Maturity, Signing, Review, and Deprecation](CAP-004-maturity-signing-review-deprecation.md)
- [CAP-006 Registry Quality Metrics](CAP-006-registry-quality-metrics.md)
- [ADR-0055 Explicit Existing Mode Capability Adapters](../adr/0055-explicit-existing-mode-capability-adapters.md)
