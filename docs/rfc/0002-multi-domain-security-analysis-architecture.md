# ARCH-002: Multi-domain Security Analysis Architecture

- Status: Accepted
- Date: 2026-08-20
- Extends: [ARCH-001](0001-pajin-architecture-v2.md)
- Implementation status: DOMAIN-001 through DOMAIN-006 foundations, WEB-001A typed HTTP-operation
  locator registry, WEB-001B exact read-only discovery binding/preparation, and WEB-001C bounded
  sealed-source Graph admission are implemented within their contracts; general domain runtimes
  remain planned

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
  multi-domain inventory or production provider fleet.

### Planned

- REDTEAM-001C bounded Web and REDTEAM-001D registered MCP product profiles;
- a first-class non-authoritative Security Domain taxonomy;
- domain-aware Capability inventory projections and Worker trust-boundary registrations;
- multi-domain cross-Surface admission and domain-aware benchmark extensions; and
- Network, System, Application, Mobile, Cloud, general Cryptography, and Digital Forensics vertical
  slices.

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
| Web | HTTP/OpenAPI/auth/file-upload locators, HTTP GET Pentest Capability, fixed Boolean SQLi and CTF Web Capabilities, Docker/ZAP benchmark assets | WEB-001A exact HTTP operation and URI-template registry is implemented; generalized auth/data-flow/API Surface typing remains | WEB-001B reuses exact signed Pentest GET Recon for concrete GET preparation; WEB-001C binds one already approved sealed Recon result into neutral Graph knowledge; broader non-lab analysis remains | egress-only, no host filesystem, exact target/method; WEB-001B pins the DOMAIN-004 minimum profile without selecting a Worker | WEB-001D binds the exact Web source to PENTEST-002B fresh-Permit, dedicated-Worker independent Replay and preserves match/change | WEB-001D binds the existing private P0-D1 Boolean SQLi Ground Truth to the DOMAIN-006 Web plan without measurement; general Web quality measurement remains | preparation grants no egress; WEB-001C source authority remains provenance only, WEB-001D creates no new action authority, and active probes require exact T2+ approval and request budgets |
| AI | KISA catalog, LLM/RAG tools, REDTEAM-001A/B, RAG/MCP discovery, local AI benchmark provider | unified model/RAG/agent/MCP/tool classification projection | REDTEAM-001D exact MCP Capability; broader agent/data-flow Capabilities | exact provider/model/tool identity and request/token/cost ceilings | fresh-session semantic replay and controls | threat-class ground truth, false-positive, replay, request/token/cost, and policy-denial metrics | prompt content and discovered tools never grant authority; T2+ approval remains profile/deployment bound |
| Network | Scope engine, egress policy, trusted network receipts, Worker identity | host/service/protocol/port Surface and locator schemas | read-only service-identification Capability | bounded protocol privileges and exact address/port Scope | independent protocol handshake from a fresh Worker identity | isolated service fixtures, service recall, protocol accuracy, denial correctness, packet/request cost | no raw socket or broad scan authority from discovery; privileges require explicit deployment review |
| Cloud | ephemeral Secret leases, object-storage provider contracts, attestation, Docker/container lifecycle | account/project/resource/IAM/container Surfaces | read-only inventory and policy-evaluation Capabilities | ephemeral credentials and exact account/project/resource Scope; no ambient credentials | fresh credential lease plus deterministic policy re-evaluation | disposable accounts or emulators, IAM ground truth, resource coverage, denial and cleanup metrics | credentials and tenant identity require separate custody; writes and privilege changes are later T3+ slices |
| System | isolated Docker Worker, host-local journals, direct mTLS identities | host/process/filesystem/service/configuration Surfaces | read-only host inventory/configuration Capability | authenticated host agent or isolated lab; no implicit root | immutable snapshot re-analysis or fresh authenticated inspection | disposable VM/container ground truth, coverage, privilege-denial, evidence completeness | host access is explicit authority; privilege escalation and mutation are separate high-risk Capabilities |
| Application | content-addressed Artifacts, sealed evidence, Worker sandbox patterns | binary/config/runtime/library Surfaces | static analysis Capability; dynamic analysis remains separate | sandboxed read-only artifact mount; no network by default | deterministic re-analysis of the exact artifact digest | seeded binaries and configs, parser/analyzer recall and precision | code execution, debugger attach, or network access requires new authority and stronger isolation |
| Mobile | Artifact and container patterns only | APK/IPA/app/runtime/storage/deeplink/TLS/auth Surfaces | static package analysis Capability; emulator analysis later | exact artifact and emulator/device identity; no ambient device access | exact package re-analysis, then fresh emulator replay when authorized | seeded apps, manifest/storage/deeplink ground truth, device cleanup | device identity, signing material, and runtime instrumentation require explicit approval |
| Cryptography | offline CTF single-byte XOR Capability and host recomputation Oracle | protocol/key-usage/ciphertext/configuration Surfaces | general offline cryptographic misuse analysis Capability | offline artifact analysis by default | deterministic independent recomputation with another implementation or Oracle | seeded vectors, classification accuracy, false positives, coverage, evidence completeness | key material is sensitive evidence, never an implicit credential-use authority |
| Forensics | immutable Run artifacts, hashes, evidence lineage, read-only verification | disk/memory/log/artifact forensic Surfaces and provenance schema | read-only parser/analyzer Capability | immutable source, provenance-preserving parser, no evidence mutation | deterministic re-parse or independent parser comparison | artifact coverage, parsing accuracy, provenance preservation, corruption handling | evidence may create a Hypothesis only; credential use, lateral movement, or mutation requires new authority |

The principal blockers are therefore taxonomy and binding gaps, not a need for nine new engines.
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

Post-acceptance status: REDTEAM-001C/D, REDTEAM-002, UX-008, DOMAIN-001 through DOMAIN-006, and
WEB-001A through WEB-001D were implemented within the bounded claims of their separate versioned
contracts and tests. The paragraph above is retained as the acceptance-time design record; it is
not the current roadmap authority.

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
- [ADR-0046](../adr/0046-common-engine-and-campaign-profiles.md)
- [ADR-0048](../adr/0048-minimum-graph-and-admission-consistency.md)
- [ADR-0052](../adr/0052-code-backed-capability-authority-set.md)
