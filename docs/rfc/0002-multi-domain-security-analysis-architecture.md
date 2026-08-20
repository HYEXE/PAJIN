# ARCH-002: Multi-domain Security Analysis Architecture

- Status: Accepted
- Date: 2026-08-20
- Extends: [ARCH-001](0001-pajin-architecture-v2.md)
- Implementation status: architecture and roadmap only; multi-domain runtime work is planned

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
signed identities. DOMAIN-003 will add an exact, content-addressed classification projection bound
to a `CapabilityDefinitionRef`. Neither this projection nor `supportedSurfaceTypes` can activate a
release, issue a Grant or Permit, select a Tool, or widen Campaign Scope.

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

Examples of planned cross-domain knowledge edges include:

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

Domain classification does not select a Worker. DOMAIN-004 will register deployment-owned Worker
boundary profiles and bind an exact profile to a Capability release and deployment. The minimum
planned boundaries are:

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
Capabilities share a Security Domain.

## 8. Repository gap analysis

| Domain | Existing reusable assets | Missing Surface model | Missing Capability | Required Worker boundary | Replay strategy | Benchmark strategy | Risk / approval implications |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Web | HTTP/OpenAPI/auth/file-upload locators, HTTP GET Pentest Capability, fixed Boolean SQLi and CTF Web Capabilities, Docker/ZAP benchmark assets | generalized Web/API Surface taxonomy and exact domain projection | REDTEAM-001C product ceiling and later non-lab Web analysis Capabilities | egress-only, no host filesystem, exact target/method | deterministic re-request or independent fixed-probe replay with fresh Permit | existing traditional Web/API Target catalog plus recall, precision, replay, policy-denial, cost, and evidence metrics | read-only recon can remain low risk; active probes require exact T2+ approval and request budgets |
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
retained for compatibility. DOMAIN-006 will define an additive domain-aware measurement contract
with:

- common metrics: ground-truth coverage, recall or task success where applicable, false-positive
  rate or precision, replay or deterministic re-analysis success, time to first valid result,
  request/Tool/cost usage, evidence completeness, policy-denial correctness, and cleanup success;
- domain-specific metric registrations bound to an exact domain, metric definition, unit, and
  aggregator; and
- explicit `not-applicable` semantics without inventing zero-valued measurements.

Forensics may emphasize artifact coverage, parsing accuracy, provenance preservation, and damaged
input handling rather than exploit Finding recall. Cryptography may emphasize vector coverage and
independent recomputation. The benchmark registry remains non-executable; Target Factory activation
and measurement admission continue to be separate authorities.

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

## 11. Initial implementation candidate

REDTEAM-001C remains the next implementation task. The audit identifies the safest existing
bootstrap as an explicit product ceiling over the already registered
`pajin.bug-bounty.boolean-sqli-lab@1.0.0` Capability and its fixed synthetic local endpoint. The
slice should bind the exact Capability, `bug-bounty.boolean-sqli-probe@1.0.0`, GET method, three
request units, T2 approval, matching Campaign target, trusted three-request receipts, and no-cleanup
semantics before Permit creation. It must not generalize to arbitrary payloads, endpoints, scanners,
or Web execution based on the `web` domain label.

This candidate is planned, not implemented by this RFC. Its versioned REDTEAM-001C contract and
ADR must be reviewed with positive and adversarial tests before runtime code is added.

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
- [ADR-0046](../adr/0046-common-engine-and-campaign-profiles.md)
- [ADR-0048](../adr/0048-minimum-graph-and-admission-consistency.md)
- [ADR-0052](../adr/0052-code-backed-capability-authority-set.md)
