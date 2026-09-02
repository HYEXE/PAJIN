# ARCH-002: Multi-domain Security Analysis Architecture

- Status: Accepted
- Date: 2026-08-20
- Extends: [ARCH-001](0001-pajin-architecture-v2.md)
- Implementation status: DOMAIN-001 through DOMAIN-006 foundations, bounded WEB-001A through D and
  WEB-002A through WEB-002D,
  AI-001A through D, NET-001A through D, CLOUD-001A through D, SYS-001A through D, APP-001A through
  D, MOBILE-001A through D, CRYPTO-001A through D, and FORENSICS-001A through D are implemented
  within their contracts.
  Cryptography coverage ends at sealed-provenance comparison and unmaterialized vector requirements;
  it provides no general analyzer, key-use runtime, semantic Oracle, or benchmark execution.
  Forensics coverage ends at sealed deterministic/independent parser-result comparison and twelve
  unmaterialized evidence requirements; it provides no source provider, parser runtime, semantic
  adjudication, Ground Truth verification, or benchmark measurement.
  General domain runtimes remain planned.

## 1. Purpose

PAJIN's long-term product definition is:

> Policy-governed autonomous multi-domain security analysis and validation platform.

The target domains are Web, Network, System, Application, Mobile, Cloud, AI, Cryptography, and
Digital Forensics. They share one Canonical Graph, one Capability authority model, and the existing
Policy, Approval, ActionPermit, Gateway, Worker, Evidence, Replay, and validation boundaries.

This RFC does not claim that all nine domains are executable. It preserves the current Phase 11
Pentest and REDTEAM work, defines the architecture required after that milestone, and prevents a
domain label, discovered Tool, or model output from becoming an authority root.

## 2. Verified baseline

The baseline audited for this RFC is `main@c429a1b5bf76aa6d9cbe6d6218e951fd6a343f5c`.
This section preserves the acceptance-time baseline rather than acting as current operational
status; [PLAN.md](../../PLAN.md) and [HANDOFF.md](../../HANDOFF.md) own the current checkpoint.

### Implemented

- the ARCH-001 Canonical Graph vocabulary: `Surface`, `Hypothesis`, `Action`, `Observation`,
  `Evidence`, and `CampaignFact`, with the eight typed relations defined by ARCH-001;
- single-writer Graph admission, append-only event/projection/snapshot state, stale-decision guards,
  and atomic single-use ActionPermit dispatch claims;
- exact CAP-001 definitions and CAP-002 seven-role code-backed authority sets;
- code-owned `pentest`, `bug-hunt`, `ctf`, and `ai-assessment` Campaign Profiles;
- Tool Gateway policy re-entry, Worker isolation, sealed evidence, Replay, validation-depth policy,
  and Profile assurance floors;
- provider-neutral Benchmark Manifest, Ground Truth, Result, measurement attestation, and Target
  Factory lifecycle contracts;
- PENTEST-004C2B2 concrete child deployment adapters;
- REDTEAM-001A single-turn M03/M06 LLM execution; and
- REDTEAM-001B exact two-turn A04 LLM/RAG execution.

### Contract or scaffold only

- several discovery and walking-chain contracts describe Web, RAG, MCP, tenant, and internal API
  Surfaces without turning discovery into execution authority;
- the Profile catalog is code-owned, but the legacy `CampaignMode` compatibility input still owns
  several existing runtime branches;
- CAP-002 authoring scaffolds and benchmark provider protocols exist without a general
  multi-domain inventory or production provider fleet; and
- CLOUD-001A implements exact secret-free account/project/resource/IAM/container typed identity;
  CLOUD-001B binds signed read-only preparation, exact Scope, explicit GET adaptation, and a trusted
  lease fingerprint but creates no provider client, credential use, Worker job, or network result;
  and CLOUD-001C verifies a deployment-produced signed execution and raw-body-free response receipt
  before admitting neutral Graph knowledge, without interpreting resource or policy fields; and
  CLOUD-001D compares two separately authorized policy reads through signed sanitized exact-rule
  artifacts and registers unprovisioned disposable fixtures without provider-effective permission,
  benchmark measurement, or action authority; and
- SYS-001A implements exact secret-free host/process/filesystem/service/configuration typed identity;
  SYS-001B binds signed network-disabled metadata-only preparation, exact Surface-token Scope,
  bounded ceilings, and deployment public Worker mTLS/non-root configuration without inventing an
  agent endpoint or granting live authentication, host access, or a Worker job; and SYS-001C
  verifies deployment-signed Gateway/mTLS/non-root/result provenance before admitting one neutral
  Observation with digest-only Evidence and, for two fixed review signals only, one open bounded
  Hypothesis, without granting root, mutation, Replay, Finding, or further execution authority; and
  SYS-001D distinguishes signed same-snapshot re-analysis from a separately authorized fresh
  authenticated inspection, projects only neutral match/change/unresolved, and registers
  unexecuted disposable-host controls without measurement or host authority; and
- APP-001A implements exact digest-only binary and exact-parent configuration/runtime/library
  typed identity without artifact resolution or analysis authority; and APP-001B binds signed
  read-only preparation, an opaque custody/authorization reference, exact parser, network-disabled
  non-root read-only sandbox requirements, and bounded ceilings without artifact read, mount,
  Worker job, result, Graph admission, Finding, or execution authority; and
- MOBILE-001A implements exact APP-binary-parent APK/IPA declarations and exact-parent
  application/runtime/storage/deep-link/TLS/authentication typed identity without package read,
  analysis, emulator/device access, instrumentation, network, credential, or execution authority;
  and MOBILE-001B binds exact selected/root-package identity, opaque custody, lineage-derived parser,
  selected-and-package Scope, and static sandbox requirements into signed preparation without
  profile conformance, package read, WorkerJob, device runtime, result, or execution authority; and
  MOBILE-001C verifies one externally signed static-sandbox execution and admits neutral digest-only
  Observation/Evidence with an optional bounded open Hypothesis while preserving the device/profile/
  Worker boundary; and MOBILE-001D independently reverifies one stored source and one separately
  authorized exact-package execution, projects only neutral match/change/unresolved, and registers
  28 unexecuted seeded Mobile fixture requirements without measurement or package/device authority.
- CRYPTO-001A implements exact protocol-root and sibling key-usage/ciphertext/configuration typed
  identity without artifact access or analysis authority; and CRYPTO-001B binds one exact Surface,
  its full class/input/digest/operation/analyzer mapping, signed current Range Capability, exact
  Scope, code-classified digest-derived custody/authorization metadata, code-owned signal
  vocabulary, and the exact offline Cryptography profile, code-owned runtime identities, and
  sandbox requirements into preparation while all key/credential/cryptographic-operation/Oracle/
  network budgets remain zero and no Worker, result, Graph admission, or execution is created.
  CRYPTO-001C rebuilds that current authority, verifies one deployment-signed consumed-Permit
  offline execution and strict detached result receipt, and uses a workflow-owned pure structural
  Oracle to derive only class-bound review metadata or an inconclusive no-signal state before the
  existing Graph writer admits neutral Observation/Evidence and an optional open Hypothesis; and
  CRYPTO-001D reopens two separately authorized C contexts under distinct executable/image/sandbox/
  signer provenance, projects only neutral opaque-result comparison, and registers eight
  unmaterialized vector requirements without semantic truth, measurement, or execution authority.
- FORENSICS-001A implements exact disk/memory/log/generic-artifact sibling identity with a complete
  content-free PAJIN Run-root/artifact-record/provenance-record/artifact digest and strict
  byte-count coordinate. It verifies no source, seal, authenticity, external anchoring, artifact
  membership, digest/size, immutability, custody, format, parser result, credential, Hypothesis, or
  Graph knowledge and grants no source access, mutation, Worker, or execution authority.
- FORENSICS-001B binds one complete A Surface and its code-owned class/input/operation/parser map
  to a current signed CAP-002 release, an exact parser-bound non-routable Scope token, opaque
  custody and authorization coordinates, the exact DOMAIN-004 provenance-preserving Forensics
  profile, and executable/configuration/image digests plus bounded parser safety ceilings. It
  produces only `PreparedCapabilityAction`; source resolution/read/mount, profile conformance,
  Worker materialization, parser execution, mutation, result, Observation/Evidence, Graph,
  Hypothesis, Finding, and execution authority remain absent.
- FORENSICS-001C reads only exact-byte-SHA-256-canonical outer execution and detached result-receipt
  metadata beneath a Gate-owned absolute existing non-symlink root, with traversal/alias/hardlink/
  symlink/junction rejection. It verifies disjoint deployment source-membership and parser-execution
  Ed25519 roles, rebuilds current Range/Scope/preparation/approval/consumed-Permit authority and the
  exact Grant ID/digest bound by the signed outer statement plus Gateway Grant digest, and uses a
  pure structural Oracle before
  the existing Graph writer admits one neutral Observation, exactly two restricted Evidence nodes,
  and only for `review` one confidence `0.5` open Hypothesis. Raw bodies, semantic truth, mutation,
  credential/lateral action, Replay, Finding, benchmark, and further authority remain absent.
- FORENSICS-001D contextfully reopens one stored C admission and a later separately authorized C
  execution under the same source-membership authority. It derives `deterministic-reparse` only
  when every concrete parser coordinate is equal and `independent-parser-comparison` only when
  execution trust, signer, executable, configuration, image, and sandbox coordinates all differ;
  partial drift fails closed and only independent mode satisfies DOMAIN-006. Both modes project
  only neutral opaque-result/structural-disposition match, change, or unresolved and write no
  Graph knowledge. A separate profile registers twelve disk/memory/log/artifact positive,
  no-signal, and corrupted-input bounded-rejection requirements without source/parser execution,
  Ground Truth, rejection observation, metric measurement, Finding, Replay scheduling, or further
  authority.

## 3. Orthogonal taxonomy

| Concept | Meaning | May grant execution authority? |
| --- | --- | --- |
| Campaign Profile | Operating semantics, ROE expectations, reporting semantics, validation floor, and authority ceiling for `pentest`, `bug-hunt`, `ctf`, or `ai-assessment` | No; it constrains compilation |
| Security Domain | Classification of a Surface, Capability, Observation, or benchmark case as `web`, `network`, `system`, `application`, `mobile`, `cloud`, `ai`, `cryptography`, or `forensics` | No |
| Capability | Exact versioned semantic action with a registered Tool binding and complete CAP-002 authority set | Only after current release activation, Campaign intersection, approval where required, and Permit issuance |
| Tool | Mechanism used to prepare and interpret one Worker operation | No |
| Worker boundary | Deployment-owned execution isolation and identity contract | No; it is a required execution constraint |

Valid combinations include `pentest + web`, `pentest + system`, `pentest + mobile`,
`pentest + cloud`, `ai-assessment + ai`, and `ctf + cryptography`. Adding another domain does not
create another Profile. A Profile can admit multiple exact domain-classified Capabilities when its
Campaign, activation, Policy, and Permit authorities allow them.

The current `CapabilityDefinition.domain` field is a legacy namespace that contains values such as
`ai-redteam`, `bug-bounty`, `ctf`, and `pentest`. ARCH-002 does not reinterpret or rewrite those
signed identities. [DOMAIN-003](../capability/DOMAIN-003-domain-aware-capability-inventory-projection.md)
adds an exact, content-addressed classification projection bound to a `CapabilityDefinitionRef`.
Neither this projection nor `supportedSurfaceTypes` can activate a release, issue a Grant or Permit,
select a Tool, or widen Campaign Scope.

MCP is not a Profile, Security Domain, or authority system. It can be a Surface and a Tool transport
or integration mechanism. A discovered MCP server or Tool remains non-executable until an exact
Capability, release, Campaign intersection, approval, Permit, and Worker boundary are separately
established.

## 4. Preserved authority invariants

Every domain reuses the existing execution path:

```text
Surface
-> Hypothesis
-> Capability
-> Proposal
-> Policy / Approval
-> ActionPermit
-> Gateway / Worker
-> Observation
-> Evidence
-> Graph Admission
-> New Snapshot
-> Replan
```

Every confirmed Finding reuses the validation path required by its Profile:

```text
Candidate / Claim
-> Independent Replay
-> Controls / Oracle
-> Validation
-> Finding
-> Retest
```

The following rules are non-negotiable:

- discovery is not authorization;
- an Observation, model output, Tool category, plugin, or domain label is not authority;
- a Worker-reported success is not a trusted Finding;
- a discovered Surface starts as knowledge only and remains registered-not-authorized;
- Graph admission cannot expand Campaign Scope, egress, filesystem, credential, risk, budget,
  Capability, Worker, or validation authority;
- every execution requires an exact registered Capability, current activation and Campaign
  authority, and a single-use Permit;
- exact retry reuses the consumed terminal identity and never repeats the side effect;
- Finding confirmation requires the Profile's independent Replay and validation floor;
- arbitrary shell agents and silent Tool or plugin execution remain prohibited; and
- all mismatches fail closed.

## 5. One multi-domain Canonical Graph

ARCH-002 keeps the ARCH-001 graph node and relation vocabulary unchanged:

```text
Surface motivates Hypothesis
Hypothesis tested-by Action
Action produces Observation
Observation supported-by Evidence
Observation supports Hypothesis
Observation contradicts Hypothesis
Observation discovers Surface
Observation enables Hypothesis
```

Domain-specific meaning is expressed through registered Surface types and locator schemas,
Hypothesis and Observation types, Capability references, producer identities, and evidence lineage.
No domain receives a separate graph ledger or writer.

Examples of cross-domain knowledge edges include:

- a Web Observation discovering a Cloud resource Surface and enabling an IAM Hypothesis;
- a Mobile analysis Observation discovering a Web/API Surface;
- an AI Agent Observation discovering an MCP Tool or internal API Surface;
- a System artifact Observation discovering a cryptographic-configuration Surface; and
- a Forensic log Observation enabling a Network or System investigation Hypothesis.

These edges extend knowledge only. The Graph Admission Authority must mark newly discovered
Surfaces as registered-not-authorized in the domain admission projection. Any later action requires
a new Proposal compiled against current Campaign Scope, exact Capability activation, Policy,
approval, Permit, and Worker boundary. The originating action's authority is never transferable to
the discovered Surface.

[DOMAIN-005](../graph/DOMAIN-005-cross-domain-graph-admission.md) now implements one exact
AI-Observation-to-Web-Surface-or-Hypothesis producer through the existing single writer. That
bounded bootstrap does not implement the other example pairs, arbitrary extraction, general Web or
AI analysis, or execution against the admitted knowledge.

## 6. Common Capability lifecycle

Every executable domain action must first be expressible through the existing CAP-002 roles:

```text
precondition
-> materialize
-> compile
-> authorize
-> execute
-> normalize
-> observe
-> oracle
-> replay
-> cleanup
```

The registered roles remain Materializer, Action Compiler, Executor Adapter, Result Normalizer,
Success Oracle, Replay Strategy, and Cleanup Handler. A domain may return a non-executable Replay or
Cleanup plan from those roles, but a later execution still requires fresh authority. A new attack
DSL or parallel execution engine is rejected unless CAP-002 is proven insufficient by a concrete
vertical slice and a separate decision.

Tools answer how an operation is executed. Capabilities answer what bounded semantic action is
authorized. External scanners, protocol clients, SDKs, debuggers, mobile tools, model clients,
cryptographic analyzers, forensic parsers, MCP clients, and plugins must remain behind exact
Capabilities and the existing Permit/Gateway path.

## 7. Domain-specific Worker trust boundaries

Domain classification does not select a Worker. DOMAIN-004 registers code-owned minimum Worker
boundary profiles and can bind an exact profile to a lifecycle-verified Capability release bundle
and deployment-owned mTLS subject/SPKI. The implemented registry is non-executable and does not
prove concrete Worker conformance. The minimum boundaries are:

| Domain | Minimum Worker boundary |
| --- | --- |
| Web | bounded network egress; no host filesystem access; exact HTTP target and method policy |
| Network | explicit host, address family, protocol, and port Scope; only reviewed protocol privileges |
| System | isolated lab or authenticated host agent; explicit host authorization; no ambient root |
| Application | sandboxed read-only artifact analysis by default; dynamic execution requires separate authority |
| Mobile | exact APK/IPA/app and emulator or device identity; device access is deployment-owned |
| Cloud | ephemeral credential lease; exact account/project/resource Scope; no ambient credentials |
| AI | exact provider/model/RAG/agent/MCP/Tool identity plus bounded requests, tokens, and cost |
| Cryptography | offline content-addressed artifact analysis preferred; network use is separately authorized |
| Forensics | immutable read-only evidence source, provenance-preserving parser, and no evidence mutation |

Every boundary still requires the existing Policy, approval, ActionPermit, Gateway, Worker identity,
receipt, evidence, and retry invariants. A broader Worker cannot be selected merely because two
Capabilities share a Security Domain. Deployment signing, profile-conformance authority, concrete
domain Workers, and runtime adoption remain later vertical-slice work.

## 8. Repository gap analysis

| Domain | Existing reusable assets | Missing Surface model | Missing Capability | Required Worker boundary | Replay strategy | Benchmark strategy | Risk / approval implications |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Web | HTTP/OpenAPI/auth/file-upload locators, HTTP GET Pentest Capability, fixed Boolean SQLi and CTF Web Capabilities, Docker/ZAP benchmark assets | WEB-001A implements the exact HTTP operation and URI-template registry; WEB-002A adds one exact internal Boolean-SQLi measured case, signed controlled route, floor, denial Control, and expected-Finding policy without generalizing auth/data-flow/API typing | WEB-001B reuses exact signed Pentest GET Recon; WEB-001C binds one approved sealed Recon result; WEB-002B executes only the plan-owned registry-governed ZAP source coordinate, WEB-002C admits bounded neutral knowledge, and WEB-002D consumes one separately controlled validation route; general scanners and product Capabilities remain missing | WEB-002D pins the controlled Worker to a proxy-only network while only the proxy bridges the exact Target network, seals Worker and cleanup Evidence, and passed exact-commit Ubuntu real-Docker conformance; the covered runtime/test/workflow paths remain unchanged at the current checkpoint; production, external, cross-host, and general Web Worker boundaries remain absent | WEB-001D binds independent GET Replay; WEB-002B source measurement and WEB-002D controlled validation are distinct fresh lifecycles and neither schedules general Replay | WEB-001D keeps private P0-D1 Ground Truth separate; WEB-002D connects the exact source and controlled-validation Evidence, evaluates the fourteen-metric floor, and projects only a bounded claim-ceiling Finding for one synthetic case with that exact-commit conformance, not a production score or multi-case benchmark | Exact route consumption, Target/ZAP/Worker execution, measurement, floor satisfaction, and Finding projection are case-bounded; no arbitrary target, production/external probing, Graph Finding admission, product/report delivery, or further execution authority is granted |
| AI | KISA catalog, LLM/RAG tools, REDTEAM-001A/B, RAG/MCP discovery, local AI benchmark provider | AI-001A exact model/RAG/agent/MCP/Tool classification is implemented; AI-001C consumes only exact references and general discovery/data-flow remain missing | AI-001B binds four existing REDTEAM-001A/B/D read-only CAP-002 identities through preparation; AI-001C reverifies their existing sealed execution and admits neutral Observation/Evidence; broader agent/data-flow Capabilities remain missing | AI-001B pins the DOMAIN-004 minimum AI profile without selecting a Worker; AI-001C verifies the deployment-produced Worker evidence but creates no Worker, network, or credential authority | AI-001D binds exact M03/M06/A04 source semantics to separately sealed two-repetition KISA fresh-session Replay and three-Control evidence without dispatching from Graph knowledge; MCP Replay remains unavailable | AI-001D binds the matching REDTEAM-002 Profile, Capability, Ground Truth vocabulary and negative-control/Replay requirements to the DOMAIN-006 AI plan without a concrete case or measurement; production Ground Truth and numeric metrics remain missing | prompt content, provider registration, model identity, Surface classes, and discovered tools never grant authority; AI-001C source Permit remains consumed provenance, AI-001D creates no action or confirmation authority, and T2+ approval remains profile/deployment bound |
| Network | Scope engine, egress policy, trusted network receipts, Worker identity | NET-001A exact host/port/service registry and NET-001C neutral protocol Observation/Evidence plus optional bounded open Hypothesis are implemented; product/version typing remains missing | NET-001B implements one signed read-only IP-literal TCP passive service-identification Capability and preparation; general scanners and active handshakes remain missing | NET-001B pins the DOMAIN-004 minimum Network profile, exact address/port CONNECT Scope, one connection, zero target writes, 1,024 response bytes, and host-observed receipt without selecting a Worker; NET-001C reverifies the sealed Docker Worker/Gateway evidence but creates no Worker | NET-001D binds a separately authorized sealed passive execution with disjoint Run/request/Decision/Permit/Worker/Evidence identity and reports only neutral label match/change/unresolved; it does not schedule Replay or prove a distinct physical Worker | NET-001D registers five known-positive protocol banners and one unknown negative Control with disposable loopback-container isolation requirements; fixture provisioning, numeric service accuracy, recall, denial correctness, and request cost remain missing | NET-001B grants no DNS, UDP, raw socket, broad scan, credential, approval, Permit, Worker, Graph, or execution authority; NET-001C source authority remains provenance, and NET-001D creates no service confirmation, measurement, Replay, or further action authority |
| Cloud | ephemeral Secret leases, object-storage provider contracts, attestation, Docker/container lifecycle | CLOUD-001A exact account/project/resource/IAM/container registry is implemented; typed values remain secret-free `registered-not-authorized` knowledge and general discovery remains missing | CLOUD-001B implements one signed read-only inventory/policy preparation and explicit exact-GET request adapter; CLOUD-001C verifies one external signed execution and admits a neutral `cloud.api-observation` with digest-only Evidence, while no repository provider runtime or provider-specific response interpreter exists | CLOUD-001B pins the minimum Cloud profile and exact request/lease ceilings; CLOUD-001C verifies a deployment-configured Worker/direct-mTLS/provider/key trust anchor, current Campaign authority, consumed Permit, approval receipt, and historical credential-use receipt without selecting a Worker or authorizing another credential use | CLOUD-001D reopens two separately admitted policy reads with disjoint Run/Permit/single-use lease/execution/admission identity, verifies separately signed sanitized exact-rule artifacts, and reports only deterministic input/decision match or change; a response digest alone is never policy input | CLOUD-001D registers exact allow, explicit deny override, and implicit-deny negative-Control Ground Truth with disposable account/emulator, fresh credential, and cleanup-evidence requirements; provisioning, execution, cleanup, resource-policy coverage, denial correctness, and cost remain unmeasured | provider/account/tenant identity, lease fingerprints, signed receipts, admitted observations, and deterministic projections never grant credential, runtime, effective-permission, mutation, Replay, Finding, or further action authority; writes and privilege changes are later T3+ slices |
| System | isolated Docker Worker, host-local journals, direct mTLS identities | SYS-001A exact host/process/filesystem/service/configuration registry is implemented; typed values preserve parent lineage and remain secret-free `registered-not-authorized` knowledge, while live state and general discovery remain missing | SYS-001B implements one signed network-disabled metadata-only read preparation and exact-Surface request adapter; SYS-001C verifies one external signed non-root execution and admits neutral `system.host-observation` knowledge with digest-only Evidence, while no repository host-agent runtime or raw host-result interpreter exists | SYS-001B pins the minimum System profile, exact public Worker mTLS policy/subject/SPKI, declared non-root identity, Surface-token Scope, and request/artifact/runtime ceilings; SYS-001C verifies the deployment trust anchor, consumed Permit, approval receipt, recomputed Gateway policy outcome, direct-mTLS admission, non-root identity/confinement, and signed live-host-or-snapshot result provenance without selecting a Worker or granting another host read | SYS-001D reopens one stored C admission and a separately authorized sealed execution, requires disjoint authority identities and a signed replay start after source finish, distinguishes same-snapshot re-analysis from fresh authenticated inspection, and reports only neutral digest/byte-count/signal match/change/unresolved; trusted wire reload requires the receiver trust anchor and both exact Graph stores, and only same-snapshot mode satisfies DOMAIN-006 | SYS-001D registers five all-Surface known-positive, negative-Control, and privilege-denial requirements with disposable non-root container/VM, cleanup, and evidence-completeness requirements; private Ground Truth verification, provisioning, execution, cleanup, coverage, denial correctness, and numeric metrics remain unobserved | host identity, deployment configuration, signed execution provenance, admitted Observation, comparison, and open review Hypothesis never grant access; root, privilege escalation, service control, mutation, Replay, Finding, and further execution remain separate authority |
| Application | content-addressed Artifacts, sealed evidence, Worker sandbox patterns | APP-001A exact digest-only binary and exact-parent configuration/declared-runtime/library registry is implemented; APP-001C admits only neutral result provenance and an optional open Hypothesis, while artifact resolution, byte/format/runtime/dependency verification, and general discovery remain missing | APP-001B implements one signed read-only static-analysis preparation and exact class-owned parser mapping; APP-001C reverifies one external signed offline execution and admits digest-only Evidence, while no repository parser or sandbox runtime exists | APP-001B pins an opaque custody reference plus exact parser/image digests, non-root identity, read-only no-exec artifact mount, disabled network, and bounded resources as configuration; APP-001C verifies the deployment trust anchor and runtime assertion without selecting another sandbox or Worker | APP-001D reopens one stored C admission and a separately authorized exact-artifact execution, requires disjoint action/evidence identities and a signed causal order, rejects equal result digests with unequal signed byte counts, and reports only neutral digest/byte-count/signal match/change/unresolved without scheduling Replay; trusted wire reload requires the external trust anchor, both evidence contexts, and exact Graph stores | APP-001D registers binary/configuration/runtime/library known-positive and negative-Control requirements with disposable offline non-root sandbox and cleanup-evidence requirements; Ground Truth verification, materialization, provider/fixture execution, cleanup, artifact-analysis coverage, quality, and numeric metrics remain unobserved | supplied digest, custody/sandbox configuration, signed provenance, admitted knowledge, comparison, or seeded Ground Truth requirement grants no artifact read, Scope expansion, approval, Permit, sandbox/Worker selection, network, dynamic execution, debugger, mutation, Replay, Finding, or further execution authority |
| Mobile | APP-001A content coordinates plus Artifact and container patterns | MOBILE-001A exact APP-binary-parent APK/IPA, application, declared-runtime, logical-storage, sanitized deep-link/TLS/authentication registry is implemented; MOBILE-001C admits only neutral package-analysis provenance and an optional open Hypothesis, while package resolution, byte/format/manifest/signing verification, and general discovery remain missing | MOBILE-001B implements one signed read-only package-analysis preparation with eight exact Surface operations and root-lineage APK/IPA parser selection; MOBILE-001C reverifies one external signed device-free static execution and admits digest-only Evidence, while no repository parser or sandbox runtime exists | MOBILE-001B pins opaque custody, selected/root package Scope, parser/image digests, non-root network/DNS-disabled read-only/noexec configuration and archive ceilings; MOBILE-001C verifies the deployment trust anchor and runtime/archive assertions but deliberately keeps the current device-bound Mobile profile deferred and cannot materialize a WorkerJob | MOBILE-001D reopens one stored C admission and a separately authorized exact-package execution, requires equal selected/root/platform/package/parser/archive semantics, disjoint action/evidence identities and signed causal order, and reports only neutral digest/byte-count/signal match/change/unresolved; trusted wire reload requires both evidence contexts, both Graph stores, and the external trust anchor | MOBILE-001D registers one known-positive and one no-signal negative Control for all fourteen valid Android/APK and iOS/IPA selected Surface lineages, exactly 28 cases, with seeded packages, disposable offline static sandbox, archive-safety, and cleanup-evidence requirements; Ground Truth verification, materialization, provider/fixture execution, cleanup, manifest-component coverage, quality, and numeric metrics remain unobserved | typed identity, custody/sandbox configuration, signed provenance, admitted knowledge, comparison, and seeded Ground Truth requirements grant no package read, Scope expansion, approval, Permit, profile conformance, Worker, network/DNS, credential, emulator/device access, install/launch/instrumentation, storage/TLS/auth invocation, mutation, Replay, Finding, measurement, or execution authority; signing identity and runtime instrumentation require separate Evidence and approval |
| Cryptography | offline CTF single-byte XOR Capability and host recomputation Oracle | CRYPTO-001A exact protocol-root and sibling key-usage/ciphertext-digest/sanitized-configuration registry is implemented; CRYPTO-001C admits only neutral signed result provenance, while protocol/declaration/artifact verification and general discovery remain missing | CRYPTO-001B implements one signed read-only offline misuse-analysis preparation with four exact Surface/locator/input/digest/operation/analyzer rows and a code-owned bounded signal vocabulary; CRYPTO-001C reverifies one external signed offline execution and strict detached receipt and admits digest-only Evidence, while no general analyzer, result-body interpreter, or executable runtime exists and the fixed XOR lab is not generalized | CRYPTO-001B pins the exact DOMAIN-004 offline read-only-artifact profile, code-classified digest-derived custody metadata, exact rule/analyzer/image identity, code-owned deployment/non-root runtime identities, network/DNS-disabled read-only/noexec sandbox requirements, bounded resources, and zero key/credential/crypto/Capability-Oracle channels without selecting a Worker; CRYPTO-001C verifies the deployment trust anchor and signed runtime assertion without selecting another sandbox or Worker | CRYPTO-001D reopens one stored C source and one later separately authorized execution, requires exact logical input semantics plus distinct executable/image/sandbox/signer/action/evidence provenance, and reports only neutral opaque-result and structural-disposition match/change/unresolved without scheduling Replay or proving source-code, algorithmic, organizational, physical-host, or common-mode independence; the C structural Oracle and CTF host Oracle are not independent semantic analyzers | CRYPTO-001D registers eight protocol/key-usage/ciphertext/configuration positive and no-signal Control requirements; vector materialization, Ground Truth, test-vector coverage, recomputation-success rate, evidence completeness, quality, and validation-floor measurement remain absent | Surface, custody, profile, rule, preparation, signed provenance, structural verdict, admitted knowledge, comparison, and vector requirements grant no artifact/result-body read, key or credential use, target cryptographic operation, protocol negotiation, Capability/external Oracle, plaintext/key output, Worker, Graph write, Replay scheduling, Finding, or further execution authority |
| Forensics | immutable Run artifacts, hashes, evidence lineage, read-only verification | FORENSICS-001A exact disk/memory/log/generic-artifact sibling registry with complete content-free PAJIN Run-root/artifact-record/provenance-record/artifact digest and strict byte-count coordinates is implemented; FORENSICS-001C admits only neutral provenance-preserving knowledge, while source, seal, authenticity, membership, immutability, custody, format, and general discovery remain unverified | FORENSICS-001B implements one signed read-only preparation with a neutral complete class/input/operation/parser map, code-owned signal vocabulary, opaque custody/authorization coordinate, exact parser-bound Scope, and zero live channels; FORENSICS-001C verifies supplied canonical signed execution/result metadata and admits bounded Graph knowledge, while no repository parser, source provider, result-body interpreter, or executable runtime exists | FORENSICS-001B pins the exact DOMAIN-004 provenance-preserving profile, code-owned deployment/non-root identity, immutable read-only/noexec input and read-only root requirements, exact parser executable/configuration/image digests, bounded parser ceilings, and pre/post no-mutation evidence requirements; FORENSICS-001C verifies disjoint deployment source/execution trust anchors plus the signed sandbox/runtime assertions without selecting or attesting another Worker | FORENSICS-001D reopens one stored C admission and a later separate C execution under the same source authority, automatically accepting only exact deterministic re-parse or wholly distinct execution-trust/signer/executable/configuration/image/sandbox independent-parser mode, rejects partial drift, and projects neutral match/change/unresolved without Graph write or Replay scheduling; only independent mode satisfies DOMAIN-006 | FORENSICS-001D registers exactly twelve disk/memory/log/artifact positive, no-signal, and corrupted-input bounded-rejection requirements; artifact coverage, parsing accuracy, provenance-preservation rate, corrupted-input handling rate, Ground Truth, rejection, evidence completeness, quality, and Profile-floor measurement remain unobserved | typed identity, prepared action, signed provenance, structural Oracle verdict, neutral Observation, restricted Evidence, open review Hypothesis, replay comparison, and requirement registry grant no source/result-body read, parser execution or correctness, semantic truth, mutation, credential use, lateral movement, Graph admission, Replay, Finding, measurement, or further execution authority |

The principal remaining blockers are fresh-session product-read conformance, production and
cross-host runtime conformance, and measured multi-case evidence, not taxonomy or nine new engines.
The Canonical Graph, CAP-002, Permit/Gateway, evidence, and Target Factory foundations are reusable.

## 9. Domain-aware benchmark contract

The current BENCH-001 v1 contract requires twelve attack-oriented metrics in a fixed order. It is
retained for compatibility. DOMAIN-006 implements an additive, non-executable domain-aware registry
with:

- common metrics: ground-truth coverage, recall or task success where applicable, false-positive
  rate or precision, replay or deterministic re-analysis success, time to first valid result,
  request/Tool/cost usage, evidence completeness, policy-denial correctness, and cleanup success;
- domain-specific metric registrations bound to an exact domain, metric definition, unit, and
  aggregator; and
- explicit `not-applicable` semantics without inventing zero-valued measurements.

Forensics uses task success, artifact coverage, parsing accuracy, provenance preservation, and
damaged-input handling rather than exploit Finding recall. Cryptography registers vector coverage
and independent recomputation. These are registry requirements, not measured quality or runtime
support. The benchmark registry remains non-executable; Target Factory activation, Ground Truth,
measurement admission, Profile validation floors, and Replay Evidence continue to be separate
authorities. The exact contract is [DOMAIN-006](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md).

### 9.1 WEB-001A typed Web Surface registry

WEB-001A implements the DOMAIN-002 `web.http-operation` locator schema by binding the exact Web
classification and type-set to the unchanged concrete `HTTPSurfaceLocator` and bounded URI-template
`HTTPRouteSurfaceLocator`. It adds a content-addressed typed Surface whose initial state is
`registered-not-authorized`, without changing `SurfaceObservation`, `AttackSurface`, or Graph wire
identities.

The registry is representation authority only. It does not discover a target, seal Evidence, admit
a Graph node, expand Scope, activate a Capability, select a Tool or Worker, issue a Permit, grant
network access, or assert runtime support. The exact contract is
[WEB-001A](../discovery/WEB-001A-typed-http-api-surface-locator-registry.md).

### 9.2 WEB-001B read-only Web discovery binding

WEB-001B adds a content-addressed binding, not a Campaign Profile. It pins the concrete WEB-001A
GET locator, the existing complete `pajin.pentest.http-get-recon@1.0.0` CAP-002 identity, its exact
DOMAIN-003 Web classification, and the DOMAIN-004 minimum Web Worker profile. The Worker profile
requires bounded egress, no host filesystem, no credentials, and an isolated non-root runtime, but
the reference neither selects a Worker nor proves deployment conformance.

Preparation requires the existing current signed Pentest Recon activation and delegates to its
materializer/action compiler. The output remains `prepared-not-authorized`: it contains no Worker
job or egress policy, Observation, Evidence, Graph admission, Scope expansion, approval, Permit,
dispatch, or execution authority. A pre-Gateway executor job remains network-disabled; only the
existing Gateway may grant exact bounded egress after current authority checks. URI templates and
non-GET methods fail closed. The exact contract is
[WEB-001B](../capability/WEB-001B-read-only-web-discovery-binding.md).

### 9.3 WEB-001C sealed Web knowledge admission

WEB-001C exact-binds the WEB-001B preparation to the same already approved and executed Pentest
Recon intent. It delegates sealed Run, reservation, execution Evidence, normalized outcome,
ActionPermit, approval receipt, Worker admission, trusted HTTP receipt, and Oracle verification to
the existing PENTEST-002A gate. The new content-addressed Web candidate/proof classifies that
neutral source under the DOMAIN-002 Web semantics without using Domain metadata as authority.

PENTEST-002A remains the producer and `GraphAdmissionAuthority` remains the only writer. The event
admits one succeeded Action, one neutral Observation, three Evidence nodes, and only `produces` and
`supported-by` edges. The WEB-001A Surface stays an exact reference with
`registered-not-authorized` knowledge state; no Surface/Hypothesis/CampaignFact/Finding node,
Scope expansion, Capability activation, approval or Permit authority, Worker/network authority,
execution, or Replay is created. Exact Graph retries reuse the prior event and never repeat the HTTP
request. The exact contract is
[WEB-001C](../graph/WEB-001C-sealed-web-discovery-graph-admission.md).

### 9.4 WEB-001D independent Replay and Ground Truth profile

WEB-001D reuses PENTEST-002B instead of adding a Web-specific Replay executor. A content-addressed
projection reopens its sealed comparison and exact-binds the complete WEB-001C admission, concrete
URL and GET method, source admission identity, and DOMAIN-006 Web `independent-replay` plan. The
underlying Replay retains a fresh Run, request, Graph Decision, approval, one-use ActionPermit,
receipt, dedicated Worker admission, dispatch, and execution identity. The projection records
response match or change without granting another request or Finding authority.

A second private profile reconstructs the existing P0-D1 Traditional Web/API catalog, public
registration, complete Boolean SQLi Ground Truth, and code-owned matcher from one exact provisioned
Docker profile, then binds them to the same DOMAIN-006 Web plan. This profile is
`registered-ground-truth-not-measured`: it does not select or activate a Target Factory, execute a
provider, admit a raw measurement, publish metrics, satisfy a Profile validation floor, or confirm
a Finding. The generic GET Replay proof is not relabeled as the SQLi matcher result. The exact
contract is [WEB-001D](../benchmark/WEB-001D-independent-web-replay-ground-truth.md).

### 9.5 WEB-002A measured-case, controlled-route, floor, and Finding policy

WEB-002A adds one content-addressed measured Profile and complete code-backed read-only Capability
authority set for the fixed P0-D1 Boolean-SQLi endpoint. It contextfully binds the current signed
Capability release, WEB-001A Surface, exact P0-D1 Target and private Ground Truth, exact P0-E2B ZAP
Scanner plan and registration, and DOMAIN-006 Web plan into one public-safe measured-case identity.

The slice also registers a deployment-signed `controlled-validation` proxy-route statement. The
signer and verifier reload the measured case from its trusted predecessors, read the exact consumed
T2 approval and Permit from a durable approval store, and read the open Target attempt, effective
fence, exact Scanner-plan coordinate, succeeded ordinal-1 reset and isolation receipts, and pending
ordinal-1 execution operation from the durable operation journal. Records must be monotonic and
causal through route issuance, and reset/isolation must preserve one environment without overlap.
Route validity remains inside the
Permit, approval, Mission Envelope, Campaign authorization, and one continuous Campaign testing
window occurrence. Every authority minted from the same approval receipt and Permit converges on
one stable atomic-consumption slot even when nonce or operation context differs; WEB-002A itself
does not implement that consumption ledger or a materializing adapter. WEB-002D materializes and
atomically consumes the registered route for its three-request validation. WEB-002B ZAP source measurement remains on the
existing registry-governed Scanner lifecycle and its Scanner-specific Target-network route; the two
paths cannot reuse execution or Evidence identity.

Finally, WEB-002A registers all fourteen DOMAIN-006 metric requirements, exact source and
controlled-validation Evidence sets, quality floors, a content-addressed denial-control
denominator, and a separate private Ground Truth to public expected-Finding commitment. Every
activation, route materialization or consumption, Target/ZAP or Worker execution, measurement,
floor satisfaction, Graph mutation, Finding, reporting, and product authority marker remains
false. The exact contracts are
[WEB-002A Capability/Profile](../capability/WEB-002A-measured-validation-capability-profile.md),
[WEB-002A benchmark policy](../benchmark/WEB-002A-exact-measured-case-route-floor-finding.md), and
[ADR-0253](../adr/0253-separate-zap-measurement-routing-from-controlled-validation-routing.md).

### 9.6 WEB-002B source measurement and WEB-002C sealed knowledge admission

WEB-002B reconstructs the exact WEB-002A measured case and one plan-owned Scanner coordinate
through constructor-owned provider, registry, trust-anchor, activation, signed-distribution, and
Target-journal dependencies. It executes only the fresh P0-D1/P0-E2B registry-governed lifecycle
on immutable images and an internal network with no published ports. Its public-safe authority
binds raw SARIF custody, strict normalized output, the exact completed eight-record Target
operation journal, and receipt-bound cleanup with observed resource absence. Contextful reload
reopens every predecessor and requires canonical stored authority and audit payloads. It neither
imports the controlled-validation route nor grants Ground Truth, Graph, floor, Finding,
comparison, product, report, or further execution authority.

WEB-002C reopens that sealed source and all scanner predecessors, then takes a second outer
snapshot and compares canonical authority bytes and all three audit payloads exactly. It derives
only whether a normalized result belongs to the registered Web Surface, without consulting
`knownFindingMatched` or private Ground Truth. The verified public projection retains only
content-addressed Surface, domain-type-set, and source-authority references plus bounded scalar
metadata.

The current Graph Snapshot must already contain the exact trusted-core Surface. An additive
`sealed-source-authority` lineage is mutually exclusive with Capability, Grant, and Permit
lineage and is bound to the exact Proposal digest and predecessor event-log head. Generic direct
submission, lineage reuse for a different payload or head, and cross-domain source-authority
transfer fail closed. The existing single writer admits one succeeded Action, one neutral
Observation, and authority-reference Evidence; only a registered-Surface signal permits an
immediately following confidence-`0.5` open Hypothesis. A head race after Observation rejects the
Hypothesis while preserving the append-only Observation. No raw SARIF, runtime identity, route,
Scope, Capability, Permit, Worker, network, Replay, floor, Finding, product, report, or additional
execution authority enters the Graph. The exact contracts are
[WEB-002B](../benchmark/WEB-002B-distinct-registry-governed-zap-source-measurement.md) and
[WEB-002C](../graph/WEB-002C-sealed-zap-source-knowledge-admission.md).

### 9.7 AI-001A classification through AI-001D independent validation binding

AI-001A registers secret-free typed model, RAG, agent, MCP, and Tool Surfaces as
`registered-not-authorized` knowledge. AI-001B reopens four exact existing REDTEAM-001A/B/D
read-only CAP-002 identities and binds them to the required ordered Surface set, current provider
registration when applicable, request/token/cost ceilings, and the DOMAIN-004 minimum AI Worker
profile.

AI-001B delegates only to the existing signed lifecycle `prepare_action` and stops at
`PreparedCapabilityAction`. AI-001C then accepts only an exact AI-001B preparation paired with an
existing REDTEAM Capability Graph Run that was policy-allowed, executed under the consumed
ActionPermit, and sealed. It reverifies dispatch reconciliation, request reservation, Tool/Worker
evidence, code-owned adapter result, trusted receipt or network-disabled MCP boundary, and Gateway
outcome digest. It admits one neutral `ai.behavior-observation` and two Evidence nodes through the
existing Graph single writer.

The ordered AI Surface references remain classification input; AI-001C does not propose Surface,
Hypothesis, or Finding nodes and does not turn source output, Profile, Domain, provider/model, MCP,
or Tool metadata into Scope, approval, Permit, Worker, network, credential, Replay, or further
execution authority.

AI-001D reopens that exact source/admission and separately sealed VAL-004A KISA evidence. For M03,
M06, or A04 it exact-matches target, Tool, scenario, threat class, turns, and checks while requiring
the admitted source, KISA source, two Replay repetitions, and three Controls to have disjoint
sessions and request identities. It also reconstructs the matching REDTEAM-002 Profile,
Capability, CAP-003 mapping, CAP-006 Replay contract, Ground Truth vocabulary, and DOMAIN-006 AI
plan. The KISA lane may satisfy its own Profile floor, but no concrete benchmark case or
measurement is produced and the AI Observation is not confirmed. The exact contracts are
[AI-001A](../discovery/AI-001A-model-rag-agent-mcp-tool-surface-classification.md),
[AI-001B](../capability/AI-001B-provider-model-tool-bound-read-only-analysis.md),
[AI-001C](../graph/AI-001C-cross-surface-observation-evidence-admission.md), and
[AI-001D](../benchmark/AI-001D-fresh-session-replay-controls-benchmark.md).

NET-001A now implements the reserved `network.host-service` locator schema as three additive,
secret-free classes: a canonical unresolved DNS/IP host, an exact host/TCP-or-UDP/port coordinate,
and an explicitly named service at that coordinate. Unknown services remain port locators, DNS
construction performs no resolution, and no new locator enters the established discovery wire.
The registry and typed Surface grant no Scope, scanner, raw-socket, credential, Worker, network,
Graph-admission, or execution authority. The exact contract is
[NET-001A](../discovery/NET-001A-host-service-protocol-port-surface-model.md).

NET-001B binds only an exact IP-literal TCP `network-port` Surface to a complete signed CAP-002
passive service-identification Capability, current Campaign Scope, fixed one-connection and
1,024-byte banner budget, and the DOMAIN-004 minimum Network Worker profile. The preparation stops
at `PreparedCapabilityAction`. The additive Tool/Worker/Gateway path uses the existing egress
proxy, sends no target application bytes, attenuates CONNECT to one exact authority, and requires
one host-observed receipt, but actual use still requires Policy/Approval, ActionPermit, Gateway,
deployment Worker identity, and direct mTLS. Returned output is not Graph-admitted Evidence. The
exact contract is [NET-001B](../capability/NET-001B-passive-service-identification-capability.md).

NET-001C rebuilds the current NET-001B preparation and jointly verifies one approved sealed Run,
its exactly consumed Permit and durable approval receipt, completed dispatch reconciliation,
Gateway/Worker Evidence, exact egress metadata, and matching host-observed CONNECT receipt. The
existing Graph single writer then admits one neutral `network.protocol-observation` with the
succeeded Action and two Evidence references. A fixed classifier label may enable one confidence
`0.5` open Hypothesis that requires a separately authorized fresh passive handshake; an unknown
label creates no Hypothesis or negative conclusion. Raw banner and target-controlled prose stay
out of the Graph, and the label, Graph membership, source approval, and consumed Permit grant no
service confirmation or action authority. The exact contract is
[NET-001C](../graph/NET-001C-sealed-network-protocol-knowledge-admission.md).

NET-001D reopens that exact source/admission and one separately authorized sealed NET-001B
execution. It requires identical Surface, Campaign Scope, Capability, Tool semantics, and passive
protocol budget with disjoint Run root, request, envelope, Graph Decision, ActionProposal,
approval receipt, ActionPermit, dispatch, Worker execution, artifact, terminal, and reconciliation
identities. It reports only protocol-label match, change, or unresolved plus separate banner-digest
equality; none confirms the service. A separate profile registers synthetic ftp, imap, pop3, smtp,
ssh positive banners and one unknown negative Control with disposable per-case isolation, but does
not select or provision a Target or publish a measurement. The exact contract is
[NET-001D](../benchmark/NET-001D-fresh-worker-replay-isolated-service-fixtures.md).

The post-Phase 23 fresh checkpoint selects
[ADR-0258](../adr/0258-select-governed-measured-network-service-identification-after-phase-23.md)
as the Phase 24 roadmap. NET-002A now adds a Network-specific content-addressed public six-case
registration, separate private Ground Truth binding, fixed-case TCP emitter profile, immutable
Target/Worker/proxy image-contract identities, exact DOMAIN-006 source/Replay protocol, and an
unevaluated validation-floor policy. It builds no image, creates no Target or network, selects no
provider, and grants no approval, Permit, Worker, measurement, product, or execution authority.
NET-002B adds the source half of that protocol. It binds deployment-provided Target, Worker, and
proxy references to independently observed OCI IDs, materializes one fresh internal
no-published-port Target and network per case, keeps the Worker proxy-only while the proxy bridges
the exact Target network, and consumes one ordinary Approval and one-use Permit through the
existing Gateway. Public lineage is sealed separately from private raw banner, label,
Worker/Tool, topology, journal, and cleanup evidence. Five code-owned substitutions are denied
before dispatch. NET-002C runs a second fresh six-case set with globally disjoint
Run/request/Decision/approval/Permit/Worker/Target identities, contextfully reopens both sets and
private Ground Truth, and evaluates the exact fourteen-metric DOMAIN-006 floor. Its public artifact
contains only case references, digest lineage, aggregate rational observations, and false-authority
markers; raw banners, labels, and runtime identities remain private. A satisfied floor is synthetic
benchmark evidence, not service confirmation or a Finding. NET-002D projects only the public-safe
case references, ordered aggregate metrics, applicability, satisfied floor state, and literal-false
ceiling into a separate versioned Network product. An immutable deployment registration pins the
exact product, NET-002C source, and complete verifier context for a zero-argument non-cacheable
Operator GET; callers cannot select paths, providers, profiles, cases, or metric policy. The manual
exact checkpoint `9b3d8035252d26334d35caa55c0270356c71683a` passed Ubuntu 24.04
real-Docker run `33494188536`, job `99812441408`, with twelve source/Replay executions and
unconditional zero residue. Existing Finding-oriented
benchmark catalog, Ground Truth, and Walking observation wires remain unchanged and cannot be
relabeled as Network measurement authority. DNS, UDP, ranges, enumeration, active protocol writes,
credentials, external targets, service confirmation, Findings, and general Network scanning remain
outside the selected phase. The additive contracts are
[NET-002A](../benchmark/NET-002A-exact-isolated-service-measured-case-authority.md),
[NET-002B](../benchmark/NET-002B-registry-governed-disposable-network-source-measurement.md),
[NET-002C](../benchmark/NET-002C-independent-fresh-worker-network-floor-evaluation.md), and
[NET-002D](../orchestration/NET-002D-bounded-network-measurement-product-read-and-conformance.md).

The post-Phase 24 checkpoint
[ADR-0259](../adr/0259-select-governed-measured-ai-system-prompt-disclosure-after-phase-24.md)
selects the exact code-owned single-turn KISA M03 system-prompt-disclosure case as the
Phase 25 slice. [AI-002A](../benchmark/AI-002A-exact-m03-measured-case-authority.md) adds a neutral
public measured-case registration and separate private known-positive Ground Truth binding, the
exact AI-001D predecessor requirement, immutable deterministic Target/Worker/proxy contracts, the
canonical source/two-Replay/three-Control protocol, the DOMAIN-006 AI floor, and strict
content-addressed validation. It builds no image, creates no Target or network, selects no provider,
materializes no prompt, issues no approval, Permit, or Grant, runs no Tool or Worker, records no
measurement, and exposes no product.
[AI-002B](../benchmark/AI-002B-registry-governed-disposable-m03-source-measurement.md) now adds only
one fresh internal no-published-port vulnerable Target source execution through the existing
approval, one-use Permit, Gateway, proxy-only Worker, and Target-receipt path. It seals prompt,
check, transcript, runtime, topology, and approval material privately; publishes only
content-addressed lineage and eight canonical pre-dispatch denials; and grants no downstream
authority.
[AI-002C](../benchmark/AI-002C-independent-fresh-session-replay-controls-ai-floor.md) now adds two
independently authorized supporting fresh-session Replay repetitions, the exact Baseline,
Negative, and Counterfactual Controls, pairwise-disjoint source/Replay/Control execution
identities, measured request/Tool/zero-cost accounting, mandatory cleanup, and the exact
fourteen-observation DOMAIN-006 AI floor. Its additive operation preparation revalidates the
current signed M03 Capability without widening the existing AI-001B catalog-only preparation, and
the measurement reopen path cannot create an AI-001C Graph candidate. AI-002D now implements the
public-safe, content-addressed product, deployment-pinned zero-argument reader, authenticated
Operator-only non-cacheable GET, and fresh-process no-mutation reload described in
[its versioned contract](../orchestration/AI-002D-bounded-ai-measurement-product-read-and-conformance.md).
The exact-clean Ubuntu real-Docker run and unconditional residue audit remain pending and are
required for the Phase 25 Exit Gate. ADR-0259 implements none of those authorities by itself.
Prompt, check, transcript, session,
request, and runtime material remain private, while M06, A04, MCP, RAG, arbitrary caller prompts,
external providers or targets, credentials, general model or agent testing, Graph/Finding/report/
delivery, and additional execution authority remain outside the phase. Existing AI-001, KISA,
VAL-004A, REDTEAM, P0-D2/P0-D2B, Walking, and DOMAIN-006 wires keep their established meanings.

CLOUD-001A implements the reserved `cloud.account-resource` locator schema as five additive,
secret-free classes for provider-partition accounts, nested projects, provider-local resources,
IAM objects, and immutable container/image coordinates. Parent identity is nested rather than
inferred, and mutable aliases, active URL syntax, credential fields, and image tags fail closed.
The registry and typed Surface grant no provider selection, tenant or credential authority,
inventory or policy access, container runtime access, Scope, Worker, network, Graph-admission,
mutation, or execution authority. Existing AWS S3/STS/KMS, MinIO, and Docker contracts keep their
separate runtime and custody boundaries. The exact contract is
[CLOUD-001A](../discovery/CLOUD-001A-account-project-resource-iam-container-surface-model.md).

CLOUD-001B binds one exact CLOUD-001A Surface to a complete current signed CAP-002 release, a local
Cloud classification, the DOMAIN-004 minimum Cloud Worker profile, two exact Campaign Scope rules,
an explicit provider/partition and Surface/operation GET route, the Campaign private-network flag,
and a trusted active one-use Campaign credential-lease snapshot. Non-global IP literals and
`localhost` names require an explicit private-network opt-in; deployment egress must still enforce
DNS/connect-time resolution. Only the lease-ID and secret-reference fingerprints enter the
preparation; the bearer lease ID and credential material do not. The adapter produces a bounded
secret-free request description but has no provider runtime, WorkerJob, network invocation, result
normalization, or conclusive Oracle. Preparation stops at `PreparedCapabilityAction` and grants no
credential-use, provider-call, mutation, approval, Permit, Worker, egress, Observation/Evidence,
Graph-admission, or execution authority. The exact contract is
[CLOUD-001B](../capability/CLOUD-001B-read-only-inventory-policy-capability.md).

CLOUD-001C consumes neither a credential nor a provider API. It reverifies the admission gate's
deployment-configured trust anchor, Ed25519-signed execution statement, direct-mTLS Worker
identity, exact current Campaign and CLOUD-001B preparation, one consumed ActionPermit and durable
approval receipt, a signed historical single-use credential audit receipt, and a detached neutral
response receipt whose raw provider body remains external. Only one succeeded Action, one neutral
`cloud.api-observation`, two digest-only Evidence nodes, one `produces`, and two `supported-by`
edges enter the existing Graph single writer. HTTP success and the body digest do not establish
resource existence, ownership, policy effect, effective permission, a Hypothesis, a Finding, or
authority for another request. The repository still supplies no Cloud provider runtime or response
interpreter. The exact contract is
[CLOUD-001C](../graph/CLOUD-001C-sealed-cloud-provider-observation-admission.md).

CLOUD-001D reopens two independently admitted CLOUD-001C policy reads through the same
deployment-configured trust anchor and their own Graph authority stores. Surface, Scope,
Capability, release, provider route, credential principal, evaluator, and exact query remain the
same, while Run, preparation, request, Decision, Proposal, approval, consumed Permit, single-use
lease, signed statement, external execution, source root, Graph admission, and policy-artifact
identities must be disjoint. The response digest itself is never policy input. Each execution has a
separately signed, source-bound, provider-neutral exact-rule artifact; the code-owned evaluator
uses exact principal/action/resource matching with explicit deny overriding allow and reports only
input/decision match or change. These states do not confirm provider policy semantics or effective
access. A separate profile registers exact allow, deny override, and implicit-deny negative-Control
cases with disposable account/emulator and cleanup-evidence requirements, but provisions,
executes, cleans up, and measures nothing. The exact contract is
[CLOUD-001D](../benchmark/CLOUD-001D-fresh-credential-policy-replay-disposable-fixtures.md).

SYS-001A implements the reserved `system.host-resource` locator schema as five additive,
secret-free classes for pseudonymous hosts, content-bound process snapshots, logical-mount-relative
filesystem entries, manager-qualified services, and sanitized configuration records. Every child
embeds exact parent lineage, while mutable PID, host-local absolute or ambiguous path, symlink,
service display name, raw configuration value, credential, and privilege fields fail closed. The
registry and typed Surface grant no host existence or state claim, Scope, Capability, approval,
Permit, authenticated host agent, Tool/Worker, filesystem or service access, credential/root,
network, Graph-admission, mutation, or execution authority. The exact contract is
[SYS-001A](../discovery/SYS-001A-host-process-filesystem-service-configuration-surface-model.md).

SYS-001B binds one exact SYS-001A Surface to a complete current signed CAP-002 release, a local
System classification, and the DOMAIN-004 authenticated non-root System profile. One metadata-only
operation is fixed per Surface class, with one request, bounded artifact bytes and runtime, and
zero content/value reads, process signals, service control, and host writes. An explicit
content-addressed deployment binds the exact opaque host, complete public Worker mTLS policy and
selected subject/SPKI, executable digest, declared non-root identity, and an attenuated operation
set. Preparation requires exact non-routable Surface-token Scope and GET, then stops at
`PreparedCapabilityAction`. It does not invent a host-agent endpoint: the existing Worker initiates
its authenticated Control Plane session, and Tool network access remains disabled. It does not
perform live bearer/direct-mTLS authentication, attest non-root confinement, open a session or host
connection, materialize a Worker job, read the host, produce knowledge, or grant root, mutation, or
execution authority. The exact contract is
[SYS-001B](../capability/SYS-001B-read-only-inspection-capability.md).

SYS-001C invokes no host runtime. It rebuilds the current SYS-001B activation, Campaign Scope, and
exact preparation, then joins the approved job to one consumed ActionPermit and durable approval
receipt in the existing authority store. A deployment-configured Ed25519 trust anchor fixes the
exact host-agent deployment and Capability/release, recomputes the current Gateway policy outcome,
and verifies `WorkerMTLSAdmission`, non-root runtime identity/confinement receipt, execution window,
and detached raw-result-free receipt. The signed receipt distinguishes live authenticated host input
from an immutable snapshot digest without embedding raw host data. The existing Graph single writer admits one succeeded Action, one neutral
`system.host-observation`, and two restricted Evidence nodes. A fixed configuration-metadata-drift
or service-status-review signal may add only one confidence `0.5` open
`system.security-configuration` Hypothesis that calls for a separately authorized fresh inspection;
absence of a signal creates no conclusion. Raw host content, paths, service/configuration values,
host access, root or privilege escalation, service control, mutation, Replay, Finding, and further
execution authority remain outside the contract. The repository still supplies no live host-agent
connector. The exact contract is
[SYS-001C](../graph/SYS-001C-sealed-system-host-knowledge-admission.md).

SYS-001D invokes no Replay runtime. It reopens the exact stored SYS-001C source and one separately
authorized sealed execution through the current C verifier and the same deployment trust anchor.
Capability/release, Surface/operation, deployment, Scope, budget, and normalized request semantics
must match, while Run, request, Decision, Permit, approval, execution, statement, attestation, and
result identities must all differ. The replay statement's signed start must be strictly later than
the source statement's signed finish, preventing an older sealed execution from being relabeled as
Replay without claiming physical Worker freshness. Trusted wire reload requires both original
evidence contexts, both exact Graph stores, and the receiver deployment trust anchor; bare model
parsing and embedded anchor or Graph events are structural only. Two receipts for the same signed immutable
snapshot satisfy the DOMAIN-006 `immutable-snapshot-reanalysis` strategy. Two live authenticated
receipts form a fresh inspection comparison but explicitly do not satisfy that strategy. Mixed
modes and different snapshot identities fail closed. The projection reports only result match,
changed, or unresolved, and equal result digests require equal signed byte counts; it confirms no
host state or Finding and writes no Graph event.

The separate content-addressed fixture profile covers all five System Surface classes with two
known-positive review signals, two negative Controls, and one filesystem privilege-denial Control.
Every case requires a disposable non-root container or VM plus execution, runtime, result-or-denial,
and cleanup evidence. The profile records registered Ground Truth requirements while keeping
private verification false; it provisions, executes, cleans up, and measures nothing and grants no
Target Factory, host-agent, root, mutation, Replay, or further execution authority. The exact contract
is [SYS-001D](../benchmark/SYS-001D-system-replay-disposable-host-fixtures.md).

APP-001A invokes no artifact repository, parser, analyzer, process, or sandbox. Its code-owned
registry contains exactly binary, configuration, declared-runtime, and library classes. Binary
identity is one caller-supplied lowercase artifact SHA-256. Configuration and runtime locators
embed the complete exact binary parent; a library embeds the complete exact binary or runtime
parent. Normalized coordinates reject mutable aliases, path/URL/wildcard syntax, and floating or
range versions, while all locators reject raw content, process state, secret, credential, and
unknown fields. The content-addressed typed Surface binds the exact Application Domain and
`application.artifact-runtime` semantics and remains `registered-not-authorized`. It does not
resolve or verify bytes, identify format, parse configuration, attest runtime support, resolve a
dependency graph, change the legacy discovery wire, admit Graph knowledge, or grant static or
dynamic analysis, Scope, Capability, approval, Permit, sandbox/Worker, network, debugger, Finding,
mutation, or execution authority. The exact contract is
[APP-001A](../discovery/APP-001A-binary-configuration-runtime-library-surface-model.md).

APP-001B adds the complete experimental read-only CAP-002 identity and requires a current signed
Range release plus the exact non-routable Application Surface token in current Campaign Scope. A
content-addressed custody binding carries only opaque deployment authority/object/authorization
coordinates, authorization-document digest, declared byte count, and the exact APP-001A Surface;
it neither reuses the sealed Run `ArtifactRef` nor resolves or verifies bytes. A separate
configuration-only sandbox binding pins the class-owned parser, executable and image digests,
explicit non-root identity, fixed read-only no-exec artifact mount, disabled network, no new
privileges, fixed output schema, and artifact/output/runtime/memory/process ceilings. Preparation
stops at a secret-free `PreparedCapabilityAction`; authorization verification, artifact read,
mount, sandbox selection or attestation, Worker job, network, dynamic execution, debugger attach,
result, Observation/Evidence, Graph admission, Finding, and execution remain absent. The exact
contract is [APP-001B](../capability/APP-001B-read-only-static-analysis-capability.md).

APP-001C rebuilds the exact current APP-001B preparation and approved execution inputs, resolves
one consumed ActionPermit and durable approval-consumption receipt from the existing authority
store, recomputes Gateway policy, and verifies a deployment-configured Ed25519 signature over the
exact custody/artifact/sandbox identities and a detached digest-only result receipt. The configured
deployment assertion binds non-root, disabled-network, read-only/no-exec mount and resource-limit
conformance, but repository code does not independently inspect a live sandbox, custody service,
image, executable, or parser output. The existing Graph writer admits one succeeded Action, one
fixed neutral `application.analysis-observation`, two restricted Evidence nodes, and only for a
fixed class-bound review signal one confidence `0.5` open Hypothesis. It grants no artifact access,
format/runtime/dependency/vulnerability truth, raw output, sandbox or Worker invocation, network,
dynamic execution, debugger, mutation, Replay, Finding, or further action authority. The exact
contract is
[APP-001C](../graph/APP-001C-sealed-application-static-analysis-knowledge-admission.md).

APP-001D invokes no parser, sandbox, Worker, or Replay runtime. It reopens the exact stored
APP-001C source and one separately authorized sealed execution through the current C verifier,
receiver deployment trust anchor, and both exact Graph stores. Immutable artifact, Surface,
operation, custody/sandbox, parser executable/image, output schema, Scope, release, request, and
budget semantics must match, while every action and evidence authority coordinate must be disjoint
and causally ordered. Equal result-body digests require equal signed byte counts. The projection
reports only neutral digest/byte-count/signal match, change, or unresolved and confirms no artifact
format, runtime, dependency, vulnerability, Hypothesis, or Finding truth. Bare model parsing is
structural only; trusted reload rebuilds the complete projection from the external evidence
contexts. A separate eight-case profile registers one known-positive and one negative-Control
requirement for each binary, configuration, runtime, and library Surface plus disposable offline
non-root sandbox and cleanup-evidence requirements. It materializes, executes, cleans up, and
measures nothing. The exact contract is
[APP-001D](../benchmark/APP-001D-application-reanalysis-seeded-artifact-fixtures.md).

MOBILE-001A implements the reserved `mobile.application-runtime` locator schema as eight additive,
secret-free classes. APK and IPA declarations embed one exact APP-001A binary coordinate;
applications embed the complete package; and runtime, storage, deep-link, TLS-policy, and
authentication-flow declarations embed the complete application. Android/iOS application-ID,
runtime, link, and platform-policy mismatch fails closed. Deep links store a canonical scheme plus
an optional strict IDNA host and optional host-dependent exact port, stable route ID, and a
sanitized declaration digest rather than a full URI or path. Public builders revalidate nested
Pydantic instances before deriving
identity. Package bytes, manifest, signing material, raw security configuration, secrets,
credentials, device state, and device-local paths cannot enter the locator. The registry and typed
Surface grant no package resolution/read or verification, static/dynamic analysis, sandbox,
emulator/device/Tool/Worker selection or access, instrumentation, storage/network/TLS/auth use,
Scope, Capability, approval, Permit, Graph admission, Finding, mutation, runtime support, or
execution authority. The exact contract is
[MOBILE-001A](../discovery/MOBILE-001A-apk-ipa-app-runtime-storage-deeplink-tls-auth-surface-model.md).

MOBILE-001B registers a new seven-role, read-only T2 CAP-002 bundle for all eight MOBILE-001A
Surface classes. Each operation is owned by the selected Surface class, while the logical parser
family is derived only from the canonical root package lineage: APK selects the Android structure
parser and IPA selects the iOS structure parser. The exact selected Surface, reconstructed root
package Surface, APP binary digest, declared byte count, and opaque deployment custody/object/
authorization digest reference are content-addressed together. Both selected and root package
non-routable Surface tokens require exact current Campaign allow rules, with deny taking
precedence. The sandbox binding records exact parser/image digests, explicit non-root identity,
network/DNS-disabled read-only/noexec requirements, and bounded archive entry, uncompressed-size,
path, nesting, and compression-ratio ceilings with traversal, symlink, and duplicate-name
rejection. These are configuration requirements, not runtime conformance evidence. Because the
current DOMAIN-004 Mobile minimum profile is device-bound, MOBILE-001B records
`domainWorkerProfileBound=false`, defers profile binding, and cannot materialize a WorkerJob. It
stops at `PreparedCapabilityAction` and grants no package resolution/read, parser or sandbox
execution, emulator/device selection or access, install/launch/instrumentation, storage/network/
TLS/auth/credential use, result, Observation/Evidence, Graph admission, Hypothesis, Finding,
mutation, Replay, or execution authority. The exact contract is
[MOBILE-001B](../capability/MOBILE-001B-read-only-package-analysis-capability.md).

MOBILE-001C rebuilds current MOBILE-001B activation, selected/root exact Scope, preparation,
Decision, approval, consumed Permit, and durable approval-consumption receipt. A
deployment-configured Ed25519 trust anchor verifies one external non-root network/DNS-disabled
static-sandbox execution whose selected/root/platform/package/custody/parser/image identity,
resource and archive ceilings, six bounded archive observations, recomputed Gateway decision,
causal zero-live-channel budget, and detached digest-only result receipt match that current
authority. The existing Graph writer admits one neutral `mobile.analysis-observation`, two
restricted Evidence nodes, and only for eight class-owned review signals one confidence `0.5` open
`mobile.security-property` Hypothesis. It does not inspect package bytes or parser output and grants
no package/manifest/signing/runtime/security truth, device/profile/Worker binding, network,
credential, mutation, Replay, Finding, or further action authority. The exact contract is
[MOBILE-001C](../graph/MOBILE-001C-sealed-mobile-package-analysis-knowledge-admission.md).

MOBILE-001D invokes no parser, sandbox, Worker, Replay runtime, emulator, or device. It reopens one
stored MOBILE-001C source and one separately authorized sealed execution through the current C
verifier, deployment trust anchor, and both exact Graph stores. Selected/root Surface and complete
platform lineage, immutable package, custody/sandbox, operation/parser/image, selected/root Scope,
release, resource and archive ceilings, and all signed archive observations must match. All action
and evidence authority coordinates must differ and the signed re-analysis start must follow the
source finish. Equal result-body digests require equal signed byte counts; the projection otherwise
reports only neutral digest/byte-count/signal match, change, or unresolved without interpreting
either result body. A separate 28-case content-addressed profile registers known-positive and
no-signal negative Controls across all fourteen valid Android/APK and iOS/IPA selected Surface
lineages, with seeded packages, disposable network/DNS-disabled non-root static sandbox,
read-only/noexec mount, archive safety, and execution/runtime/result/cleanup evidence requirements.
It materializes, executes, cleans up, and measures nothing, and the device-bound Mobile profile,
Worker job, emulator/device path, Finding, Replay, measurement, and further execution authority
remain absent. The exact contract is
[MOBILE-001D](../benchmark/MOBILE-001D-package-reanalysis-seeded-mobile-fixtures.md).

CRYPTO-001A implements the reserved `cryptography.protocol-key-artifact` locator schema as four
additive, content-free classes. One canonical protocol declaration is the only root. Key-usage,
ciphertext, and configuration declarations embed that complete protocol parent as siblings, so
the model preserves exact lineage without claiming that a particular key produced or protects a
ciphertext. Stable ASCII coordinates reject mutable aliases and path/URL/authority syntax. The
locators contain only sanitized declaration digests and one ciphertext artifact digest; they
contain no key identity, fingerprint, handle, reference or material, plaintext, raw ciphertext,
cryptographic parameters, raw configuration, path, endpoint, credential, or Oracle result. A
declaration digest is caller-supplied and is neither redaction nor proof that the external
declaration was sanitized or parsed.

Public builders, references, registry resolution, and typed-Surface construction revalidate
nested models and reject unmodeled instance state before deriving content identity. The registry
and typed Surface remain `registered-not-authorized` and change no existing discovery or CTF wire.
They resolve or read no artifact, perform no cryptographic analysis or operation, use no key or
credential, negotiate no protocol, invoke no Oracle, select no Tool or Worker, admit no Graph
knowledge, and grant no Scope, Capability, approval, Permit, network, Finding, mutation, runtime,
or execution authority. The fixed single-byte XOR Capability remains a separate bounded lab asset,
not general runtime support. The exact contract is
[CRYPTO-001A](../discovery/CRYPTO-001A-protocol-key-usage-ciphertext-configuration-surface-model.md).

CRYPTO-001B adds an experimental T2 read-only Capability whose seven CAP-002 roles accept only a
current externally signed Range release. One complete CRYPTO-001A Surface deterministically
selects its locator/input kind, declaration-or-ciphertext digest source, logical read operation,
and analyzer contract; that complete mapping is part of the signed code-backed identity. The
static binding also pins a four-signal code-owned vocabulary, the exact DOMAIN-004 Cryptography
profile, code-owned/digest-derived custody identifiers plus one externally supplied authorization-
document digest, exact non-routable Campaign Scope, analyzer and sandbox-image digests, code-owned
exact deployment and non-root service identities, a network/DNS-disabled read-only/noexec artifact
mount requirement, and bounded resources. No caller-controlled identity text is accepted. The
request fixes network, host read/write, credentials, keys, key stores, cryptographic operations,
key search, protocol negotiation, Oracle calls, plaintext/key output, target execution, and shell
commands to zero.

The custody reference is configuration, not verified authorization or artifact access, and the
sandbox reference is configuration, not runtime attestation or Worker selection. Preparation
stops at `PreparedCapabilityAction`; executor and normalizer fail closed, the Oracle is
inconclusive, and Replay and cleanup have no plan. It emits no result, Observation, Evidence,
Graph knowledge, Hypothesis, Finding, or execution authority. The existing XOR Tool, inline
ciphertext, fixed key search, recovered output, Worker command, and host Oracle remain independent.
The exact contract is
[CRYPTO-001B](../capability/CRYPTO-001B-offline-cryptographic-misuse-analysis-capability.md).

CRYPTO-001C accepts only two bounded deployment-owned evidence files: one Ed25519-signed execution
bundle and one strict detached digest-only result receipt named by that statement. It rebuilds the
current B activation, Campaign Scope, preparation, approved job, consumed Permit, durable approval
receipt, and Gateway decision, then checks exact Surface lineage, mapping, rule set, custody and
artifact coordinates, analyzer/image/non-root runtime assertion, resource ceilings, causal timing,
and zero network/key/credential/target-cryptographic-operation channels. This authenticates
historical provenance but does not independently attest a live sandbox or result semantics.

A workflow-owned pure structural Oracle opens neither artifact nor result body and invokes neither
the inconclusive B Capability Oracle nor the CTF XOR host Oracle. From the signed `review` or
`no-signal` routing disposition, exact B mapping, and Surface class, it deterministically derives
one class-owned signal with `structurally-consistent-review`, or no signal with
`inconclusive-no-signal`. Neither state is cryptographic misuse truth or a negative conclusion.
The existing Graph writer admits exactly one succeeded Action, one fixed neutral
`cryptography.analysis-observation`, two restricted Evidence nodes, and only for a derived review
signal one confidence `0.5` open Hypothesis requiring separately authorized future re-analysis.
No artifact/result-body/key access, analyzer/Worker execution, protocol negotiation, Replay,
Finding, or further action authority is added. The exact contract is
[CRYPTO-001C](../graph/CRYPTO-001C-oracle-recomputed-cryptographic-analysis-knowledge-admission.md).

CRYPTO-001D invokes no analyzer, sandbox, Worker, key service, target-domain cryptographic
primitive, Replay scheduler, or benchmark Harness. It independently reopens the stored CRYPTO-001C
source and one later separately authorized sealed execution through two exact SQLite authority
stores and two deployment-configured trust anchors. Source and recomputation must retain the same
complete Surface, artifact/custody/authorization coordinates, logical rule/operation/analyzer,
Scope, Capability release, output schema, resource ceilings, and zero-channel semantics. Their
executable, sandbox image and binding, trust-anchor and active-signer provenance plus all action,
execution, evidence, and Oracle identities must differ, and the signed recomputation start must be
strictly after source finish.

The comparison reports only opaque result-body digest/byte-count and structural Oracle
disposition/signal `matched`, `changed`, or `unresolved`. It rejects an equal digest with a
different signed byte count and never opens either body or promotes structural agreement to
misuse, safety, Hypothesis, or Finding truth. Different executable/image/signer coordinates prove
only distinct configured implementation provenance, not independent source code, algorithms,
organizations, supply chains, physical hosts, or freedom from common-mode bugs.

The separate content-addressed profile registers exactly eight future requirements: one bounded
class-owned review expectation and one no-signal Control for each protocol, key-usage, ciphertext,
and configuration Surface. It requires immutable external inputs, two offline non-root
read-only/noexec implementation lanes, complete sealed execution/runtime/result evidence, private
Ground Truth attestation, and cleanup evidence, but materializes, provisions, executes, cleans up,
or measures none of them. DOMAIN-006 test-vector coverage and independent-recomputation success
rate remain required references with no numeric observation or validation-floor claim. The exact
contract is
[CRYPTO-001D](../benchmark/CRYPTO-001D-independent-implementation-replay-seeded-vector-requirements.md).

FORENSICS-001A implements the reserved `forensics.immutable-artifact` locator schema as four
additive disk, memory, log, and generic-artifact sibling classes. Each locator embeds the complete
`ForensicSourceProvenanceCoordinate`: the closed `pajin.dev/run-integrity/v1` root kind, source-root
digest, source artifact-record digest, provenance-record digest, artifact digest, and strict
`0..2^63-1` byte-count coordinate. All dimensions and the caller-declared class participate in
content identity. The model does not encode extraction or custody relations between sibling
Surfaces because those relations require later Observation and Evidence.

The root kind reuses a versioned vocabulary, not trusted runtime state. The Surface does not verify
that a Run or artifact exists, that a Run seal is current, that the root is authentic or externally
anchored, that the artifact belongs to the source record, that digests or byte counts match bytes,
or that a source is immutable. ADR-0016 remains only a local tamper-evidence contract, and the
production immutable-source and chain-of-custody trust root remains an open roadmap decision.
Evidence class, format, acquisition completeness, custody continuity, parser compatibility, and
provenance sanitization also remain unverified.

The coordinate carries no path, URI, object key, filename, host, device, case, operator, timestamp,
raw evidence, raw provenance record, credential, Secret, parser output, Tool, Worker, Capability,
Scope, or Permit. SHA-256 coordinates are not redaction for private or low-entropy preimages.
Public construction and complete-Surface reference-binding boundaries recursively reject unmodeled
state and revalidate nested models before deriving canonical identity. A standalone Surface
reference is an opaque digest pointer without an unbound class or locator-kind claim; exact use
revalidates the complete Surface and derives the pointer again. The registry and typed Surface
remain `registered-not-authorized` and do not change existing discovery, AttackSurface,
Run-integrity, Artifact, or Graph wires.

FORENSICS-001A resolves, acquires, reads, mounts, or copies no source; selects or invokes no parser,
analyzer, Tool, or Worker; accesses or uses no credential; performs no lateral movement or evidence
mutation; and creates no Hypothesis, Evidence, Graph admission, Finding, Replay, benchmark result,
or execution. The exact A contract is
[FORENSICS-001A](../discovery/FORENSICS-001A-disk-memory-log-artifact-provenance-surface-model.md).

FORENSICS-001B adds an experimental T2 read-only Capability with all seven CAP-002 roles. It
requires a current signed Range release and stops after materialization and action compilation;
executor and result normalization fail closed, the success Oracle is inconclusive, and Replay and
cleanup create no plan. Disk, memory, log, and artifact Surfaces map exactly to one input kind,
read-only parsing operation, and logical parser through a code-owned content-addressed rule set.

Custody binds the complete Surface and its provenance artifact digest and byte count to an opaque
authorization digest coordinate without verifying or resolving either. The parser sandbox pins
the exact DOMAIN-004 Forensics profile, code-owned deployment and non-root identity, parser
executable/configuration/image digests, immutable read-only/noexec evidence mount requirements,
read-only root, network/DNS denial, provenance preservation, pre/post no-mutation evidence, and
bounded artifact/output/runtime/memory/process/byte-defined parser-work/recursion/
decompression-ratio/absolute-expanded-byte ceilings. The
request fixes credential and secret access, host reads, source writes/copies, lateral movement,
target execution, devices, plugins, shell, network, and DNS channels to zero.

Campaign Scope must explicitly allow the canonical `GET` token containing both exact Surface ID
and derived parser; wildcard-only coverage is insufficient and deny rules override it. Preparation
produces `PreparedCapabilityAction` but no approval, Permit, Gateway dispatch, Worker job, mount,
source read, parser execution, result, mutation, Observation/Evidence, Graph, Hypothesis, Finding,
or execution authority. Preparation does not verify custody/root/records, attest sandbox or parser
conformance, or prove no mutation. FORENSICS-001C separately authenticates supplied historical
assertions without turning them into independently recomputed facts. The exact B contract is
[FORENSICS-001B](../capability/FORENSICS-001B-immutable-source-read-only-parser-analysis-capability.md).

FORENSICS-001C accepts only two bounded metadata evidence files beneath the evidence root owned by
`ForensicEvidenceAnalysisKnowledgeAdmissionGate` constructor configuration. The root must be an
absolute existing directory that is not itself a symlink. The only valid references are code-owned
names derived from the SHA-256 of the exact outer execution-bundle and detached result-receipt
bytes. Reference validation and the shared bounded regular-file reader reject traversal, aliases,
multiple hard links, every symlink or junction path component and leaf, oversized or changed
files, and ambiguous JSON.

The nested source-membership/custody statement and outer parser-execution statement are verified
under distinct deployment-owned Ed25519 trust roles with disjoint anchors and keyrings. Neither
caller nor evidence can select an anchor, and absent production anchors fail closed. The nested
statement binds the complete revalidated FORENSICS-001A Surface and provenance coordinates to the
exact B custody/authorization/object-generation assertions. The outer statement binds that nested
statement and signature plus the exact B preparation, parser, sandbox, resource ceilings, and
signed pre/post no-mutation and zero-channel runtime assertions. These remain attributable
historical assertions, not independently verified source, custody, format, immutability, parser,
runtime, or result truth.

Before proposal construction, C rebuilds the current signed Range activation/release, exact
parser-bound Scope and preparation, approved job, durable approval-consumption receipt, and exactly
one consumed ActionPermit. The signed outer statement binds the exact Capability Grant ID and
canonical digest, and the recomputed sanitized Gateway outcome includes that Grant digest. A
workflow-owned pure structural Oracle reads no raw result body and recomputes only the strict
detached receipt's inconclusive `review` or `no-signal` disposition and code-owned class signal.

The existing Graph CAS single writer admits one fixed neutral `forensics.analysis-observation` and
exactly two restricted Evidence nodes: the outer bundle containing the separately signed source
assertion and the detached result receipt. Only `review` may immediately add one confidence `0.5`
open `forensics.forensic-proposition` Hypothesis; `no-signal` creates neither a Hypothesis nor a
negative conclusion. No raw source/result/provenance/custody body, source/result read, semantic or
Finding truth, mutation, credential or secret use, lateral movement, Replay, benchmark/measurement,
or further action authority is added. The exact C contract is
[FORENSICS-001C](../graph/FORENSICS-001C-sealed-forensic-analysis-knowledge-admission.md).

FORENSICS-001D invokes no parser, sandbox, Worker, Replay scheduler, fixture provider, or benchmark
Harness. `bind_forensic_evidence_analysis_replay` reopens the exact stored C admission and a later
separately authorized C execution through their configured evidence roots, Graph stores, one
shared source-membership trust anchor, and explicit source/comparison execution trust anchors.
Both contexts must retain the same immutable A Surface/provenance and B
custody/Scope/rule/logical-parser/confinement semantics. All action and evidence coordinates are
disjoint, and the second signed start must follow the source finish.

`ForensicEvidenceAnalysisReplayMode` is derived rather than caller selected.
`deterministic-reparse` requires equal execution trust, signer, executable, configuration, image,
and sandbox coordinates; `independent-parser-comparison` requires all of those coordinates to
differ. Partial drift fails closed. The mode-neutral comparison is only
`forensic-analysis-result-match`, `forensic-analysis-result-changed`, or
`forensic-analysis-result-unresolved`; the validation derives one of six mode-prefixed states.
Only independent mode satisfies the exact DOMAIN-006 strategy. Neither mode proves source,
custody, provenance, deterministic semantics, parser correctness, source-code or organizational
independence, clock authority, Ground Truth, or a Finding, and neither writes Graph knowledge or
authorizes another execution.

A separate content-addressed profile registers exactly twelve future requirements: known-positive
review, `no-signal` negative Control, and corrupted-input bounded rejection for every disk,
memory, log, and generic artifact Surface. Corrupted cases require future versioned rejection
evidence rather than fabricated successful C receipts. Artifact coverage, parsing accuracy,
provenance-preservation rate, and corrupted-input handling rate remain required DOMAIN-006
references with no observation, numerator, denominator, aggregate, quality claim, or Profile-floor
measurement. The exact D contract is
[FORENSICS-001D](../benchmark/FORENSICS-001D-independent-parser-comparison-seeded-evidence-requirements.md).

## 10. Delivery order

1. Complete REDTEAM-001C as the current bounded Web product slice.
2. Complete REDTEAM-001D as the current exact registered MCP product slice.
3. Finish the remaining Phase 11 benchmark and product-flow milestones.
4. Implement DOMAIN-001 through DOMAIN-006 as additive Phase 12 contracts and code-backed
   foundations.
5. Add one domain vertical slice at a time in the order Web, AI, Network, Cloud, System,
   Application, Mobile, Cryptography, and Forensics, subject to benchmark feasibility and safe
   Worker isolation.

Each first domain slice stops at typed Surface, read-only discovery or analysis Capability, sealed
Observation/Evidence, Graph admission, bounded Hypothesis, independent replay or deterministic
re-analysis, and benchmark ground truth. Active probing, mutation, reversible writes, credential
use, debugger attach, device instrumentation, and privilege-changing actions require later
separately reviewed slices.

## 11. Initial implementation candidate at acceptance

REDTEAM-001C remains the next implementation task. The audit identifies the safest existing
bootstrap as an explicit product ceiling over the already registered
`pajin.bug-bounty.boolean-sqli-lab@1.0.0` Capability and its fixed synthetic local endpoint. The
slice should bind the exact Capability, `bug-bounty.boolean-sqli-probe@1.0.0`, GET method, three
request units, T2 approval, matching Campaign target, trusted three-request receipts, and no-cleanup
semantics before Permit creation. It must not generalize to arbitrary payloads, endpoints, scanners,
or Web execution based on the `web` domain label.

This candidate is planned, not implemented by this RFC. Its versioned REDTEAM-001C contract and
ADR must be reviewed with positive and adversarial tests before runtime code is added.

Post-acceptance status: REDTEAM-001C/D, REDTEAM-002, UX-008, DOMAIN-001 through DOMAIN-006,
WEB-001A through WEB-001D, AI-001A through AI-001D, NET-001A through NET-001D, CLOUD-001A through
CLOUD-001D, SYS-001A through SYS-001D, APP-001A through APP-001D, MOBILE-001A through
MOBILE-001D, CRYPTO-001A through CRYPTO-001D, and FORENSICS-001A through FORENSICS-001D were
implemented within the bounded claims of their separate versioned contracts and tests. WEB-002A
was subsequently implemented as an inert exact measured-case, controlled-route, validation-floor,
denial-control, and expected-Finding projection-policy authority. WEB-002B added the bounded
registry-governed ZAP source lifecycle, and WEB-002C added sealed-source neutral Graph admission
with an optional bounded open Hypothesis. WEB-002D subsequently implemented one independently
controlled route consumption, durable success Worker Evidence and separate cleanup-before-execution
denial Evidence, independent floor
evaluation, and bounded Finding projection with required real-Docker conformance. Ubuntu 24.04 run
`33310558350` verified exact commit `975bf7876a186cefae66c289d09f530f3e0fe7aa`. It grants no
general production or external probing, report, Graph Finding admission, or cross-domain runtime
authority. UX-009A subsequently added a distinct content-addressed read-only product Run. Its
publication and reload paths first contextually reopen the exact WEB-002D authority, then expose
only measured-case Scope, content-free Evidence references, fourteen public floor metrics, the
`benchmark-ground-truth-match` claim ceiling with impact and severity unevaluated, and an
unavailable report state. It does not require WEB-002C as a causal Graph predecessor and grants no
Graph, report, HTTP/UI, Target, provider, Worker, network, or execution authority. UX-009B then
added an immutable process-local deployment registry and zero-argument reader that pins the exact
product Run, flow and source identities plus the complete private WEB-002D reopen context. Every
read calls the UX-009A loader again; callers cannot supply paths, verifier dependencies, alternate
source or projection material, or bare JSON, and the reader creates no new Run or application
durable state. UX-009C subsequently added one fixed body/query-free and non-cacheable Operator-only
Control Plane GET over that exact reader plus a same-origin strict text-only Console view. It returns
the unchanged UX-009A wire, rejects non-Operator roles and caller selectors before reading, clears
stale credential generations, and creates no application durable state, Graph event, report,
delivery, or execution authority. UX-009D now implements fresh-spawn production composition,
deterministic publication/read comparison, isolated fail-closed product cases, and a whole-call
side-effect audit in the existing WEB-002D real-Docker test. Exact checkpoint
`6cb58c1cf69795c86a4ccb6614b4e6fdf445ecbf` completed Ubuntu run `33410801762`, job
`99549584968`: the fresh-spawn conformance passed in 836.08 seconds and the unconditional PAJIN
Docker-residue audit succeeded. This completes the Phase 23 Exit Gate without adding Graph,
report, delivery, or execution authority. The paragraph
above is
retained as the acceptance-time design record; it is not the current roadmap authority.

## 12. Compatibility and migration

- ARCH-001, existing Graph schemas, Profile IDs, CampaignMode inputs, Capability IDs, Tool IDs,
  REDTEAM-001A/B, PENTEST contracts, and artifact readers remain unchanged.
- Security Domain classification is additive and cannot be inferred by rewriting the legacy
  `CapabilityDefinition.domain` field.
- Existing domain-like strings remain readable as historical namespaces.
- No Graph node or edge is migrated merely to add classification. A future schema change requires
  an explicit reader and digest migration contract.
- Rollback ignores the new classification and Worker-boundary projections while retaining all
  historical authority and evidence records.

## 13. Definition of done

A multi-domain vertical slice is complete only when it is backward compatible, uses the one
Canonical Graph and CAP-002 authority model, binds exact Campaign and Scope authority, consumes an
ActionPermit through the existing Gateway/Worker path, admits new Surfaces as
registered-not-authorized, preserves evidence lineage, satisfies its Profile validation floor,
and includes positive and adversarial tests, Ruff, strict mypy, focused pytest, feasible full
pytest, and Linux CI evidence. Documentation-only acceptance of this RFC does not satisfy those
runtime conditions.

## Related decisions

- [ADR-0204](../adr/0204-separate-security-domain-from-profile-and-authority.md)
- [ADR-0205](../adr/0205-admit-cross-domain-knowledge-without-scope-expansion.md)
- [ADR-0206](../adr/0206-bind-domain-workers-to-existing-authority-path.md)
- [ADR-0211](../adr/0211-register-domain-metrics-without-measurement-authority.md)
- [ADR-0212](../adr/0212-type-web-http-surfaces-without-discovery-authority.md)
- [ADR-0213](../adr/0213-reuse-get-recon-for-web-discovery-without-egress-authority.md)
- [ADR-0214](../adr/0214-compose-web-knowledge-through-existing-graph-writer.md)
- [ADR-0215](../adr/0215-bind-web-replay-and-ground-truth-without-measurement-authority.md)
- [ADR-0220](../adr/0220-type-network-services-without-scan-authority.md)
- [ADR-0221](../adr/0221-bind-passive-service-identification-without-network-authority.md)
- [ADR-0222](../adr/0222-admit-network-protocol-knowledge-without-service-authority.md)
- [ADR-0223](../adr/0223-bind-network-replay-and-fixtures-without-service-authority.md)
- [ADR-0224](../adr/0224-type-cloud-resources-without-credential-authority.md)
- [ADR-0225](../adr/0225-bind-cloud-read-only-preparation-without-credential-use-authority.md)
- [ADR-0226](../adr/0226-admit-cloud-api-observations-without-credential-use-authority.md)
- [ADR-0227](../adr/0227-bind-cloud-policy-replay-and-fixtures-without-provider-authority.md)
- [ADR-0228](../adr/0228-type-system-host-resources-without-host-access-authority.md)
- [ADR-0229](../adr/0229-bind-system-read-only-inspection-without-host-access-authority.md)
- [ADR-0230](../adr/0230-admit-system-host-knowledge-without-host-access-authority.md)
- [ADR-0231](../adr/0231-bind-system-replay-and-fixtures-without-host-authority.md)
- [ADR-0232](../adr/0232-type-application-artifact-runtime-without-analysis-authority.md)
- [ADR-0233](../adr/0233-bind-application-static-analysis-without-artifact-access-authority.md)
- [ADR-0234](../adr/0234-admit-application-analysis-knowledge-without-artifact-authority.md)
- [ADR-0235](../adr/0235-bind-application-reanalysis-and-fixtures-without-artifact-authority.md)
- [ADR-0236](../adr/0236-type-mobile-application-runtime-without-package-or-device-authority.md)
- [ADR-0237](../adr/0237-bind-mobile-package-analysis-without-package-or-device-access-authority.md)
- [ADR-0238](../adr/0238-admit-mobile-package-analysis-knowledge-without-package-or-device-authority.md)
- [ADR-0239](../adr/0239-bind-mobile-package-reanalysis-and-fixtures-without-package-or-device-authority.md)
- [ADR-0257](../adr/0257-project-web-002d-through-a-read-only-operator-product-flow.md)
- [ADR-0046](../adr/0046-common-engine-and-campaign-profiles.md)
- [ADR-0048](../adr/0048-minimum-graph-and-admission-consistency.md)
- [ADR-0052](../adr/0052-code-backed-capability-authority-set.md)
