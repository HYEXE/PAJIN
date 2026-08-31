# PAJIN

PAJIN is a policy-governed autonomous multi-domain security analysis and validation platform.

Its long-term architecture covers Web, Network, System, Application, Mobile, Cloud, AI,
Cryptography, and Digital Forensics through one Canonical Graph and one Capability authority
model. This is a target architecture, not a claim that every domain is currently executable.

## Product model

PAJIN separates knowledge, intent, authority, execution, and validation:

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

A potential issue becomes a confirmed Finding only through the applicable Profile's validation
path:

```text
Candidate / Claim
-> Independent Replay
-> Controls / Oracle
-> Validation
-> Finding
-> Retest
```

Discovery does not expand Scope. Model output, Tool metadata, plugin metadata, Worker-reported
success, and Security Domain labels are not authority. A discovered Surface is campaign knowledge
only and remains registered-not-authorized until a new exact Proposal is admitted through current
Campaign, Capability, Policy, approval, Permit, and Worker authority.

## Profile, Domain, Capability, and Tool

These concepts are orthogonal:

| Concept | Responsibility |
| --- | --- |
| Campaign Profile | Operating semantics, rules-of-engagement expectations, reporting semantics, validation floor, and authority ceiling |
| Security Domain | Non-authoritative classification of security subject matter |
| Capability | Exact versioned semantic action with code-backed lifecycle authorities |
| Tool | Mechanism used to prepare and interpret a Worker operation |
| Worker boundary | Deployment-owned isolation, identity, credential, filesystem, network, and evidence constraints |

The code-owned Campaign Profiles are `pentest`, `bug-hunt`, `ctf`, and `ai-assessment`.
The code-owned Security Domain taxonomy is `web`, `network`, `system`, `application`, `mobile`,
`cloud`, `ai`, `cryptography`, and `forensics`. Its current implementation is classification-only
and explicitly asserts no runtime support or execution authority.

A Profile may use exact Capabilities from multiple domains. For example, `pentest + web`,
`pentest + system`, `ai-assessment + ai`, and `ctf + cryptography` are valid combinations.
Adding a domain does not create a new Profile or execution authority.

MCP is a Surface and Tool transport where applicable. Discovering an MCP server or Tool does not
authorize invocation. External scanners, protocol clients, SDKs, debuggers, mobile tools, model
clients, cryptographic analyzers, forensic parsers, and plugins must remain behind registered
Capabilities and the existing Permit/Gateway path.

See [ARCH-001](docs/rfc/0001-pajin-architecture-v2.md) for the common-engine foundation and
[ARCH-002](docs/rfc/0002-multi-domain-security-analysis-architecture.md) for the additive
multi-domain architecture and repository gap analysis.

## Canonical Graph

PAJIN maintains one campaign knowledge graph with six common node types:

- `Surface`
- `Hypothesis`
- `Action`
- `Observation`
- `Evidence`
- `CampaignFact`

The common relations are:

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

Domain-specific Surface locators, Hypothesis types, Observation types, and evidence schemas reuse
these meanings. PAJIN does not create a separate graph ledger per domain. Cross-domain discovery
extends knowledge only; it never transfers the source action's Scope, Capability Grant, Permit,
credential, egress, filesystem, or Worker authority.

## Capability authority

An executable Capability binds an immutable definition and exact Tool contract to seven CAP-002
roles:

1. Materializer
2. Action Compiler
3. Executor Adapter
4. Result Normalizer
5. Success Oracle
6. Replay Strategy
7. Cleanup Handler

The common lifecycle is:

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

Registration is not activation. Execution additionally requires a current reviewed release,
Campaign intersection, Graph Decision, approval when required, a single-use ActionPermit, Tool
Gateway policy re-entry, a deployment-bound Worker, trusted receipts, and sealed evidence. Exact
retry reuses the terminal consumed identity and does not repeat the side effect.

## Current implementation status

The table distinguishes implemented runtime behavior from contract-only and planned work.

| Area | Status | Current boundary |
| --- | --- | --- |
| Common engine and Profiles | Implemented | Legacy `ai-redteam`, `bug-bounty`, and `ctf` compatibility plus code-owned `pentest`, `bug-hunt`, `ctf`, and `ai-assessment` Profile semantics |
| Canonical Graph | Implemented | Single-Campaign append-only Event, Projection, Snapshot, Graph Decision, ActionPermit, cleanup, backup, and recovery authorities |
| Capability lifecycle | Implemented | Exact CAP-001 definitions, complete CAP-002 authority sets, signed lifecycle/activation, Gateway dispatch, Oracle, Replay-plan, and cleanup boundaries |
| Pentest | Implemented, bounded | Signed assessment compilation, approved one-shot GET Recon, independently authorized Replay, three Controls, durable five-stage coordination, controlled validity, and local Finding/report projection |
| AI / LLM / RAG | Implemented, bounded | REDTEAM-001A exact single-turn M03/M06 and REDTEAM-001B exact two-turn A04 against approved AI/RAG targets |
| AI typed Surface classification | Implemented, registry only | AI-001A classifies exact model, RAG, agent, MCP, and Tool knowledge under DOMAIN-002, reuses existing RAG/MCP/Tool locators, and adds secret-free model/agent identities; typed values remain `registered-not-authorized` and provide no Profile, Scope, Capability, Permit, Tool/Worker, network, credential, Graph, runtime, or execution authority |
| AI read-only analysis binding | Implemented, preparation only | AI-001B binds four existing REDTEAM-001A/B/D read-only CAP-002 identities to exact provider/model/RAG/MCP/Tool Surfaces, request/token/cost ceilings, and the DOMAIN-004 minimum AI Worker profile; it stops at `PreparedCapabilityAction` and grants no Profile, Scope, approval, Permit, budget, credential, Worker, network, Observation/Evidence, Graph, Finding, or execution authority |
| AI sealed Observation admission | Implemented, bounded | AI-001C reverifies one successful sealed REDTEAM LLM, LLM/RAG, or registered MCP Capability Graph Run and admits only one neutral `ai.behavior-observation` plus exact Evidence through the existing Graph single writer; Surface references remain classification-only and grant no Tool, Scope, Permit, Worker, replay, Finding, or further execution authority |
| AI Replay, Controls, and benchmark contract | Implemented, bounded | AI-001D binds one exact AI-001C M03/M06/A04 source to separately sealed KISA two-repetition fresh-session Replay, three-Control evidence, the matching REDTEAM-002 Capability contract, and the DOMAIN-006 AI plan; it binds no concrete Ground Truth case or measurement and grants no confirmation, Finding, Scope, Permit, Worker, network, credential, Replay, or execution authority |
| Web / API | Implemented, bounded | HTTP/OpenAPI/auth/file-upload discovery, exact Pentest GET Recon, and REDTEAM-001C exact three-request Boolean SQLi profile against one fixed synthetic local endpoint; no general scanner or arbitrary target authority |
| Web/API typed Surface | Implemented, registry only | WEB-001A binds the DOMAIN-002 `web.http-operation` semantics to existing concrete endpoint and bounded URI-template locator models; typed values remain `registered-not-authorized` and provide no Observation, Evidence, Graph, Scope, Capability, Permit, Worker, network, runtime, or execution authority |
| Web/API read-only discovery binding | Implemented, preparation only | WEB-001B binds only a concrete WEB-001A GET Surface to the existing signed Pentest Recon CAP-002 and DOMAIN-004 minimum Web Worker profile; it stops at `PreparedCapabilityAction`, leaves pre-Gateway network disabled, and grants no Scope, approval, Permit, Worker selection, Observation/Evidence, Graph, Finding, runtime, or execution authority |
| Web/API sealed knowledge admission | Implemented, bounded | WEB-001C exact-binds WEB-001B to an already approved sealed Pentest Recon source, reuses PENTEST-002A and the existing Graph single writer to admit only Action/neutral Observation/three Evidence nodes, and leaves typed Surface knowledge `registered-not-authorized` with no Scope, execution, Replay, or Finding authority |
| Web/API Replay and Ground Truth | Implemented, bounded | WEB-001D binds WEB-001C to an actual PENTEST-002B fresh-authority Replay proof and separately binds the private code-owned P0-D1 Boolean SQLi Ground Truth to the DOMAIN-006 Web plan; it creates no Target selection, benchmark measurement, Profile-floor, Finding, Scope, Permit, Worker, network, or execution authority |
| Web/API measured-case authority | Implemented, registered and non-executable | WEB-002A adds a distinct internal-target Profile and complete T2 read-only Capability authority set, binds exact P0-D1/P0-E2B and DOMAIN-006 predecessors into a public-safe measured case, and registers a controlled-validation-only signed route whose issuer, verifier, and reload path resolve the durable `ActionApprovalAuthorization` plus the current Target journal head and effective fence instead of trusting caller snapshots. Its floor policy binds exact metric denominators, including a content-addressed code-owned denial-Control registry, but it provides no route-consumption ledger or runtime adapter, materializes or consumes no route, executes no Target/ZAP/Worker/network path, observes no metric, satisfies no floor, and authorizes no Finding, product, report, Graph write, or execution |
| Web/API ZAP source measurement | Implemented, bounded | WEB-002B reconstructs the exact WEB-002A case and executes only its plan-owned registry-governed P0-D1/P0-E2B coordinate. Its public-safe authority binds the exact signed distribution bundle, immutable images, internal network with zero published ports, raw SARIF custody, strict normalization, completed Target authority, the exact eight-record operation journal, and receipt-bound cleanup resource absence. Contextful reload reopens every predecessor and canonical stored wire. It never uses the controlled-validation route and grants no Ground Truth disclosure, floor, Graph, Finding, comparison, Supervisor, product, report, or further execution authority. Current opt-in real-Docker conformance passed through the same outer runner and loader with observed cleanup; the successful audit's six exact container/network label/name queries found no matching resources. |
| Web/API sealed ZAP knowledge admission | Implemented, bounded | WEB-002C reopens the exact WEB-002B authority and scanner normalization, recomputes only registered-Surface presence, requires that trusted-core Surface in the current Graph Snapshot, and admits one neutral Observation plus authority-reference Evidence and only on signal one confidence-0.5 open Hypothesis. Sealed-source trust is bound to the exact Proposal digest and CAS predecessor head, is non-transferable cross-domain, and grants no Capability, Permit, route, Worker, network, Replay, floor, Finding, product, report, or further execution authority. |
| Web/API independently controlled validation | Implemented, conformance verified | WEB-002D consumes one signed controlled-validation route through an atomic single-use claim, executes a fresh Target through proxy-only Worker routing, seals exact Worker and cleanup Evidence plus a separate zero-side-effect denial, independently evaluates the fourteen-metric DOMAIN-006 floor, and projects only a `benchmark-ground-truth-match` claim-ceiling Finding. Commit `975bf7876a186cefae66c289d09f530f3e0fe7aa` passed the dedicated Ubuntu 24.04 exact-commit real-Docker run `33310558350`; Graph mutation, product, report, external delivery, and additional execution authority remain absent. |
| MCP | Implemented, bounded | Discovery remains non-authoritative; REDTEAM-001D admits one approval-required, network-disabled registered `demo-security:inspect_text` Capability with one fixed synthetic input and no Replay or Finding authority |
| Benchmark | Implemented, bounded | BENCH-001 measurement/Target Factory lifecycle plus REDTEAM-002 exact profile detection, false-positive, Replay, request/Tool cost, evidence, and policy-denial contract with sealed aggregation; reference fixtures are not production scores |
| Product projection | Implemented, bounded; conformance pending | UX-008 reopens the sealed REDTEAM-002 aggregate and every source into profile-bound, non-confirming product sections. UX-009A separately seals one exact WEB-002D authority as measured-case Scope, content-free Evidence references, fourteen public floor metrics, a `benchmark-ground-truth-match` claim-ceiling Finding, and unavailable report state. UX-009B adds an immutable deployment registry and zero-argument reader that pins the exact product/source identities and complete private reopen context, then invokes the UX-009A loader on every read. UX-009C exposes that unchanged wire through one body/query-free, non-cacheable Operator-only Control Plane GET and a same-origin strict text-only Console view. UX-009D now supplies fresh-spawn deterministic publication/read, isolated integrity-failure, and whole-call side-effect conformance code through the existing real-Docker test, but the exact-commit workflow has not yet run for this code checkpoint. Caller-selected paths or verifier inputs, Campaign Scope/Profile inference, raw/private disclosure, Graph mutation, report delivery, and additional execution remain absent. |
| Security Domain taxonomy | Implemented, classification only | DOMAIN-001 registers the exact nine content-addressed values with Profile mapping, runtime-support assertion, Scope, Capability, Permit, Tool, Worker, network, filesystem, credential, Graph, Finding, and execution authority fixed absent |
| Multi-domain Graph semantics | Implemented, semantics only | DOMAIN-002 binds exact nine-domain Surface/locator/Hypothesis/Observation semantic type-sets to the unchanged six-node, eight-relation Canonical Graph and existing single writer; locator implementations, producers, admission, runtime support, and authority remain absent |
| Capability Domain projection | Implemented, inventory only | DOMAIN-003 binds the exact current nine CAP-001/CAP-002 identities to explicit Web 3, AI 5, and Cryptography 1 classifications; signed release/activation, Profile, Scope, Permit, Tool, Worker, runtime-support, and execution authority remain absent from the projection |
| Domain Worker boundaries | Implemented, registry only | DOMAIN-004 registers nine code-owned minimum profiles and can bind an exact lifecycle-verified release bundle to one DOMAIN-003 record and deployment mTLS subject/SPKI; profile conformance, current activation, Permit/Gateway authority, runtime support, and execution remain absent |
| Cross-domain Graph admission | Implemented, one bounded producer | DOMAIN-005 admits an exact existing AI Observation to a Web Surface through `discovers` or Web Hypothesis through `enables` using the existing single writer; target knowledge remains `registered-not-authorized`, source authority is provenance only, and other domain pairs and runtime extraction remain planned |
| Domain benchmark registry | Implemented, registry only | DOMAIN-006 registers 13 common and 13 exact domain-specific metric definitions, explicit applicability, and one Replay/re-analysis strategy per Domain while preserving BENCH-001/REDTEAM-002 wire identities; it asserts no measurement, quality, validation-floor, Finding, Target Factory, Permit, runtime-support, or execution authority |
| Network typed Surface | Implemented, registry only | NET-001A binds unresolved canonical DNS/IP hosts, exact TCP/UDP ports, and explicit service names to the Network Domain and `network.host-service` semantics without resolution, service inference, Scope, scanner, Worker, network, Graph, or execution authority |
| Network passive service identification | Implemented, preparation and bounded adapter path | NET-001B binds one IP-literal TCP `network-port` to an exact signed read-only CAP-002 Capability, current exact CONNECT Scope, fixed one-connection/zero-target-write/1,024-byte budget, and DOMAIN-004 minimum Network profile; preparation grants no approval, Permit, Worker, egress, Observation/Evidence, Graph, or execution authority, and actual dispatch must use the existing Gateway/deployment/trusted-receipt path |
| Network sealed protocol knowledge | Implemented, bounded admission only | NET-001C reverifies one approved sealed NET-001B Run, consumed Permit and approval receipt, completed dispatch, Gateway/Worker Evidence, and host-observed CONNECT receipt before the existing Graph writer admits neutral protocol Observation/Evidence and an optional open Hypothesis; service labels and source provenance grant no confirmation, Replay, Finding, or action authority |
| Network fresh Worker Replay and fixtures | Implemented, bounded and unmeasured | NET-001D binds the NET-001C source to a separately authorized sealed passive TCP execution with disjoint Run/request/Decision/Permit/Worker/Evidence identities and reports neutral label match/change/unresolved; it separately registers five positive protocol banners and one unknown negative Control as isolated fixture Ground Truth without Target selection, fixture execution, measurement, validation-floor, service confirmation, Finding, Replay, network, or action authority |
| Cloud typed Surface | Implemented, registry only | CLOUD-001A binds exact provider-partition accounts, nested projects, provider-local resources, IAM objects, and immutable container/image coordinates to the Cloud Domain and `cloud.account-resource` semantics without provider selection, inventory or policy reads, credential lease, tenant authority, container access, Scope, Worker, network, Graph, mutation, or execution authority |
| Cloud read-only inventory and policy binding | Implemented, preparation and request adaptation only | CLOUD-001B binds one exact typed Cloud Surface to a current signed CAP-002 release, exact Campaign Surface-token and provider-GET Scope, literal private-network authority, an explicit bounded provider route, a trusted active one-use Campaign credential-lease fingerprint, and the minimum Cloud Worker profile; non-global literals and fixed local names require explicit opt-in, while the preparation provides no bearer lease ID, credential materialization or use, provider runtime, WorkerJob, network call, result, Observation/Evidence, Graph, mutation, or execution authority |
| Cloud sealed provider knowledge | Implemented, bounded admission only | CLOUD-001C reverifies a deployment-produced signed read-only execution statement, neutral detached response receipt, exact consumed Permit and durable approval receipt, current Cloud activation and Campaign Scope, Worker/mTLS trust anchor, and historical credential-use receipt before the existing Graph writer admits one neutral `cloud.api-observation` with digest-only Evidence; no provider runtime, raw response, resource/policy interpretation, Hypothesis, Finding, Replay, credential use, mutation, or further action authority is added |
| Cloud fresh-credential policy Replay and fixtures | Implemented, bounded and unmeasured | CLOUD-001D reopens two separately admitted policy reads with disjoint Run/Permit/single-use lease/execution/admission identities, verifies separately signed sanitized exact-rule artifacts, and reports only deterministic input/decision match or change; it registers exact allow, deny-override, and implicit-deny negative-Control fixtures with disposable account/emulator and cleanup-evidence requirements without provisioning, provider execution, effective-permission confirmation, measurement, validation-floor, Finding, Replay, credential, or action authority |
| System typed Surface | Implemented, registry only | SYS-001A binds pseudonymous hosts and exact process, logical-mount-relative filesystem, manager-qualified service, and sanitized configuration identities to the System Domain and `system.host-resource` semantics; mutable PID, absolute path, service display name, raw configuration, secret, credential, and privilege metadata fail closed, while host access, inspection, Scope, Capability, Permit, agent/Worker, network, Graph, root, mutation, and execution authority remain absent |
| System read-only inspection binding | Implemented, preparation and request adaptation only | SYS-001B binds one exact typed System Surface to a current signed metadata-only, network-disabled CAP-002 release, its exact non-routable Surface-token Scope, one deployment-owned public Worker mTLS policy and selected subject/SPKI, a declared non-root identity, operation membership, and request/artifact/runtime ceilings; it invents no agent endpoint, and preparation performs no live authentication, session, host read, WorkerJob, network call, Observation/Evidence, Graph admission, root action, mutation, or execution |
| System sealed host knowledge | Implemented, bounded admission only | SYS-001C rebuilds current SYS-001B authority, recomputes the Gateway policy decision, and verifies one deployment-signed consumed-Permit/direct-mTLS/non-root execution plus a raw-result-free receipt whose signed source kind distinguishes a live authenticated host from an immutable snapshot before the existing Graph writer admits one neutral `system.host-observation`, two restricted Evidence nodes, and only for fixed service/configuration review signals one confidence `0.5` open Hypothesis; it provides no host-agent runtime, raw host interpretation, state confirmation, host/root access, mutation, Replay, Finding, or further execution authority |
| System snapshot/fresh-inspection Replay and fixtures | Implemented, bounded and unmeasured | SYS-001D reopens one stored SYS-001C admission and a separately authorized sealed execution with disjoint Run/request/Decision/Permit/approval/execution/evidence identities and a signed start strictly after source finish, distinguishes exact same-snapshot re-analysis from fresh authenticated inspection, and reports neutral digest/byte-count/signal match/change/unresolved; trusted wire reload requires the receiver trust anchor and both exact Graph stores, while five disposable non-root container/VM Ground Truth requirements register full Surface coverage, negative Controls, privilege denial, and evidence completeness without verification, host provisioning, fixture execution, cleanup observation, measurement, Profile-floor, host-state/Finding, Replay scheduling, root, mutation, or action authority |
| Application typed Surface | Implemented, registry only | APP-001A binds caller-supplied digest-only binaries and exact-parent configuration, declared-runtime, and library artifact coordinates to the Application Domain and `application.artifact-runtime` semantics; paths, raw content, process state, floating versions, secrets, credentials, artifact resolution/read, analysis, Scope, Capability, Permit, sandbox/Worker, network, debugger, Graph, Finding, mutation, and execution authority remain absent |
| Application read-only static analysis | Implemented, preparation and request adaptation only | APP-001B binds one exact APP-001A Surface to a current signed CAP-002 release, exact non-routable Surface-token Scope, a path-free deployment custody/authorization reference, exact class-owned parser, image/executable digests, non-root network-disabled read-only sandbox requirements, and artifact/output/runtime/memory/process ceilings; preparation performs no authorization verification, artifact resolution/read, mount, sandbox/Worker execution, network, dynamic execution, debugger attach, Observation/Evidence, Graph admission, Finding, or execution |
| Application sealed static-analysis knowledge | Implemented, bounded admission only | APP-001C rebuilds current APP-001B authority, resolves one consumed Permit and durable approval receipt, recomputes Gateway policy, and verifies a deployment-signed exact-artifact/offline-sandbox execution plus a digest-only detached result receipt before the existing Graph writer admits one neutral `application.analysis-observation`, two restricted Evidence nodes, and only for fixed class-bound review signals one confidence `0.5` open Hypothesis; it adds no artifact resolver, parser/sandbox runtime, raw-output interpretation, format/runtime/dependency/vulnerability truth, network, dynamic execution, debugger, mutation, Replay, Finding, or further action authority |
| Application deterministic re-analysis and seeded fixtures | Implemented, comparison and requirement registry only | APP-001D reopens one stored APP-001C admission and one separately authorized sealed exact-artifact execution, verifies disjoint causal authority and exact parser/image/Scope/budget provenance, requires equal signed byte counts for equal result digests, and emits only neutral digest/byte-count/signal match/change/unresolved comparison; it registers eight seeded fixture requirements but performs no artifact materialization, parser/sandbox execution, cleanup, measurement, Replay scheduling, Finding, or further action |
| Mobile typed Surface | Implemented, registry only | MOBILE-001A reuses exact APP-001A binary coordinates for APK/IPA package declarations and binds exact application, declared runtime, logical storage, sanitized deep-link, TLS-policy, and authentication-flow coordinates to the Mobile Domain and `mobile.application-runtime` semantics; package bytes/format/manifest/signing, device/emulator state, full URI/path, secrets, credentials, package analysis, Scope, Permit, Worker, network, instrumentation, Graph, Finding, mutation, and execution authority remain absent |
| Mobile read-only package analysis | Implemented, preparation and request adaptation only | MOBILE-001B binds one exact MOBILE-001A Surface and its canonical root APK/IPA package to a current signed CAP-002 release, opaque deployment custody/authorization metadata, exact selected-and-package non-routable Scope, lineage-derived APK/IPA parser, image/executable digests, and a non-root network/DNS-disabled read-only/noexec static sandbox configuration with archive-bomb ceilings; it deliberately does not bind the current device-bound Mobile Worker profile and performs no package resolution/read, mount, parser or Worker execution, emulator/device access, install/launch/instrumentation, storage/network/TLS/auth/credential use, Observation/Evidence, Graph, Hypothesis, Finding, mutation, or execution |
| Mobile sealed package-analysis knowledge | Implemented, bounded admission only | MOBILE-001C rebuilds current MOBILE-001B selected/root Scope, preparation, and approved execution inputs, resolves one consumed Permit and durable approval receipt, recomputes Gateway policy, and verifies a deployment-signed external non-root network/DNS-disabled static-sandbox execution whose exact package lineage, parser/image, archive ceilings and observations, zero live channels, and detached digest-only result receipt match the preparation; the existing Graph writer admits one neutral `mobile.analysis-observation`, two restricted Evidence nodes, and only for eight exact class/operation signals one confidence `0.5` open `mobile.security-property` Hypothesis, while the device-bound DOMAIN-004 profile and Worker job remain deferred and no raw output, package/manifest/signing/runtime/security truth, device/network/credential use, Replay, Finding, mutation, or further action authority is added |
| Mobile deterministic package re-analysis and seeded fixtures | Implemented, comparison and requirement registry only | MOBILE-001D reopens one stored MOBILE-001C admission and one separately authorized sealed exact-package execution through the current verifier, requires equal selected/root/platform/package/custody/parser/image/Scope/budget and observed-archive provenance plus disjoint causal action/evidence identities, and emits only neutral digest/byte-count/signal match/change/unresolved; it separately registers 28 known-positive and negative-Control requirements covering all 14 valid Android/APK and iOS/IPA Surface lineages with disposable offline static-sandbox, archive-safety, and cleanup-evidence requirements, but performs no package materialization, parser/sandbox execution, device/profile/Worker binding, cleanup, measurement, Replay scheduling, Finding, or further action |
| Cryptography typed Surface | Implemented, registry only | CRYPTO-001A binds exact protocol roots and sibling key-usage, ciphertext-digest, and sanitized configuration declarations to the Cryptography Domain and `cryptography.protocol-key-artifact` semantics; key identity/material/reference, plaintext, raw ciphertext/configuration/parameters, artifact access, analysis, cryptographic operations, Scope, Capability, Permit, Tool/Worker, network, Oracle, Graph, Finding, mutation, and execution authority remain absent |
| Cryptography offline misuse-analysis preparation | Implemented, non-executable | CRYPTO-001B binds one exact CRYPTO-001A Surface and its full class/input/digest/operation/analyzer mapping, current signed Range Capability and exact Scope, code-classified digest-derived custody/authorization metadata, code-owned rule vocabulary, exact Cryptography Worker profile, code-owned deployment/non-root runtime identities, and network-disabled read-only/noexec sandbox requirements; it resolves no bytes, uses no key or credential, performs no cryptographic operation or Oracle call, materializes no Worker, and admits no result or Graph knowledge |
| Cryptography sealed analysis knowledge | Implemented, bounded admission only | CRYPTO-001C rebuilds current CRYPTO-001B authority, verifies one deployment-signed consumed-Permit offline execution and strict detached digest-only result receipt, and uses a workflow-owned pure structural Oracle to recompute the exact Surface/mapping/rule/custody/output/result declaration before the existing Graph writer admits one neutral `cryptography.analysis-observation`, two restricted Evidence nodes, and only for a code-derived class signal one confidence `0.5` open Hypothesis; `no-signal` stays inconclusive, and no artifact/result body/key read, semantic misuse or negative truth, Capability Oracle, Finding, Replay, or further action authority is added |
| Cryptography independent recomputation and seeded vectors | Implemented, comparison and requirement registry only | CRYPTO-001D reopens one stored CRYPTO-001C admission and a later separately authorized execution under distinct executable, image, sandbox, trust-anchor, signer, action, and Evidence identities while requiring exact logical Surface/artifact/custody/rule/Scope/budget semantics; it emits only neutral opaque-result and structural-disposition match/change/unresolved and registers eight unmaterialized seeded-vector requirements without proving source-code, algorithmic, organizational, host, or common-mode independence, semantic correctness, Ground Truth, measurement, Finding, Replay scheduling, key use, target cryptographic execution, or further authority |
| Cryptography executable analysis | One fixed CTF lab plus external sealed provenance only | The bounded single-byte XOR Capability remains independent; CRYPTO-001B is preparation-only, CRYPTO-001C verifies one external execution, and CRYPTO-001D compares two supplied sealed provenance contexts and registers future vector requirements without providing a general analyzer, sandbox/Worker runtime, vector materializer, key search, recovered output, semantic Oracle, or executable benchmark path |
| Digital Forensics typed Surface | Implemented, registry only | FORENSICS-001A binds caller-declared disk, memory, log, and generic artifact classes plus a complete content-free PAJIN Run-root/artifact-record/provenance-record/artifact digest and strict byte-count coordinate to the Forensics Domain and `forensics.immutable-artifact` semantics; source existence, seal, authenticity, external anchoring, membership, digest/size, immutability, custody, format, parser result, credential use, lateral movement, evidence mutation, Scope, Capability, Permit, Tool/Worker, network, Graph, Hypothesis, Finding, and execution authority remain absent |
| Digital Forensics read-only parser preparation | Implemented, non-executable | FORENSICS-001B binds one complete FORENSICS-001A Surface and its neutral class-owned input/operation/parser mapping to a current signed CAP-002 release, exact parser-bound non-routable Scope, opaque custody/authorization coordinates, the exact provenance-preserving DOMAIN-004 Forensics profile, exact executable/configuration/image digests, and immutable read-only/noexec non-root network/DNS-disabled sandbox requirements with bounded byte-defined parser work, recursion, decompression ratio, and absolute expanded bytes; it resolves or reads no source, attests or executes no parser/Worker, mutates no evidence, and admits no result, Observation/Evidence, Graph, Hypothesis, Finding, or execution authority |
| Digital Forensics sealed analysis knowledge | Implemented, bounded admission only | FORENSICS-001C loads only byte-SHA-256-canonical outer execution and detached result-receipt metadata beneath a Gate-owned absolute existing non-symlink root, rejects traversal/alias/hardlink/symlink/junction paths, and verifies disjoint deployment source-membership and parser-execution Ed25519 roles; it rebuilds current Range/Scope/preparation/approval/consumed-Permit authority, the signed outer statement's exact Grant ID/digest, and the Gateway Grant digest, then uses a pure structural Oracle before the existing Graph writer admits one neutral `forensics.analysis-observation`, exactly two restricted Evidence nodes, and only for `review` one confidence `0.5` open Hypothesis; no raw source/result/provenance body, semantic truth, mutation, credential/lateral action, Replay, Finding, benchmark, or further authority is added |
| Digital Forensics re-parse/comparison and seeded evidence requirements | Implemented, comparison and requirement registry only | FORENSICS-001D reopens one stored FORENSICS-001C admission and one later separately authorized sealed execution against the same deployment source-membership authority, automatically deriving `deterministic-reparse` only when all concrete parser coordinates are equal or `independent-parser-comparison` only when execution trust/signer/executable/configuration/image/sandbox coordinates all differ; partial drift fails closed, only independent mode satisfies DOMAIN-006, and both emit only neutral opaque-result and structural-disposition match/change/unresolved. A separate profile registers twelve unmaterialized disk/memory/log/artifact positive, no-signal, and corrupted-input bounded-rejection requirements without proving source/custody/provenance or parser correctness, observing Ground Truth or rejection, executing a parser, writing Graph knowledge, measuring any metric, confirming a Finding, scheduling Replay, or granting further authority |

REDTEAM-001A/B/C/D, REDTEAM-002, UX-008, and PENTEST contracts remain stable compatibility
boundaries. Phase 11 and DOMAIN-001 through DOMAIN-006 are complete within their stated bounded
classification, semantics, inventory, Worker-registry, one-producer Graph-admission, and
benchmark-registry contracts. WEB-001A is complete as a typed registry only, WEB-001B as a
non-Campaign binding and preparation boundary only, and WEB-001C as one bounded sealed-source
knowledge-admission composition only. WEB-001D adds a bounded independent Replay projection and a
separate private Ground Truth profile; it does not claim that the two form a measured benchmark
case. WEB-002A now registers that exact case composition, a controlled-validation-only signed route
whose issue, verify, and reload paths reopen the durable approval authorization and current Target
journal head/effective fence, a Web-specific floor policy with an exact code-owned denial-Control
denominator, and a separated private/public expected-Finding mapping. It has no consumption ledger
or runtime adapter. WEB-002B now provides the distinct bounded ZAP source-measurement runner and
contextful reload path over the plan-owned fresh Target lifecycle, raw SARIF, completed journal, and
verified cleanup. That source path was reverified at exact commit
`975bf7876a186cefae66c289d09f530f3e0fe7aa` by Ubuntu 24.04 combined run `33310558350`, so the
WEB-002B runtime precondition is complete. WEB-002C now adds bounded neutral Graph
Observation/Evidence admission and an optional open Hypothesis without exposing raw SARIF, private
Ground Truth, or runtime identity. WEB-002D now consumes one independently controlled route with an
atomic single-use claim and a separate zero-side-effect denial, executes a fresh Target through the
proxy-only Worker boundary, seals exact Worker and cleanup Evidence, evaluates the fourteen-metric
DOMAIN-006 floor, and projects only the bounded claim-ceiling Finding. Exact-commit Ubuntu 24.04
run `33310558350`, job `99254722600`, passed in 12 minutes 20 seconds, completing the Phase 22
Exit Gate. The verified WEB runtime, Docker test, and conformance workflow paths remain unchanged.
UX-009A now contextually reopens that exact WEB-002D authority before publication and reload, then
writes a distinct content-addressed read-only product Run containing only measured-case Scope,
content-free Evidence references, public floor metrics, the bounded Finding, and unavailable report
state. Production or external probing, report delivery, Graph Finding admission, HTTP/UI, and
general Domain runtime authority remain absent. UX-009B supplies the
deployment-pinned reader through an immutable process-local registry: callers cannot provide a Run
path, provider, adapter, trust anchor, journal, private mapping, source, projection, or bare JSON,
and every zero-argument read reuses the exact UX-009A contextual loader without creating a new Run
or changing application durable state. UX-009C now adds fixed
`GET /v1/products/web-measured-flow`: authentication is evaluated before its Operator-only role
gate, query and request bodies are rejected, responses are non-cacheable, and reader failures are
mapped without reflecting private context. The existing same-origin Console validates the complete
bounded wire before rendering selected facts through text nodes only; lock, credential replacement,
and page teardown clear the view and discard stale responses. UX-009A's false entrypoint literals
remain unchanged because C is a separate consumption boundary rather than authority in the sealed
projection. UX-009D now rebuilds the production provider, adapter, registry, reader, and Control
Plane in spawned interpreters; compares two publications and independent reads; rejects isolated
sealed integrity mutations through fixed `409` responses; and audits the complete call so only the
four exact read-only Docker Evidence queries per product read are allowed. The existing dedicated
Ubuntu workflow invokes that path against the same completed WEB-002D lifecycle, but no
exact-commit run exists for this code checkpoint yet, so Phase 23 conformance remains open.
AI-001A is
complete as a typed classification registry only. AI-001B adds exact binding and
signed lifecycle preparation for four existing read-only REDTEAM Capabilities. AI-001C admits a
bounded sealed Observation/Evidence result without making Surface, Profile, Domain, MCP, or Tool
metadata authoritative. AI-001D adds a bounded semantic binding to independently sealed KISA
fresh-session Replay and Controls plus the existing REDTEAM-002 benchmark contract. It does not
claim a measured Ground Truth case, confirm the AI Observation, or provide general model, agent,
RAG, MCP, or Tool discovery or execution support. NET-001A adds typed Network identity without scan
authority. NET-001B adds one signed, Scope-bound passive TCP preparation and bounded
Tool/Worker/Gateway adapter path. NET-001C admits only a neutral sealed protocol Observation with
two Evidence references and, for one bounded label, an open Hypothesis requiring separately
authorized validation. NET-001D reopens a separately authorized sealed passive execution and
compares only bounded labels and banner digests, then separately registers five positive protocol
fixtures and one unknown negative Control. It adds no DNS, UDP, broad scan, active application
write, automatic Replay scheduling, physical Worker identity proof, service confirmation, Finding,
numeric benchmark result, or general Network runtime. CLOUD-001A adds a secret-free typed registry
only: account, project, resource, IAM, and container identity is content-addressed knowledge, not
provider support, live inventory, policy evaluation, credential or tenant authority, container
runtime access, or an executable Cloud analysis path. CLOUD-001B adds a current signed read-only
preparation with exact Surface/provider Scope, explicit GET request adaptation, and a trusted
single-use lease fingerprint. Private-network authority is a literal Campaign boolean; non-global
IP literals and fixed local names fail closed without opt-in, while deployment egress retains
DNS/connect-time enforcement. The adapter does not call a provider, and the preparation contains no
bearer lease ID or credential material and grants no credential-use, Worker, network, result,
knowledge-admission, mutation, or execution authority. CLOUD-001C then verifies one separately
authorized deployment-produced signed execution source and admits only a neutral API-response
Observation plus digest-only Evidence through the existing Graph writer. The repository still has
no Cloud provider runtime; the raw response and provider-derived resource or policy fields stay
outside the Graph, and HTTP success establishes neither resource existence nor effective access.
CLOUD-001D requires two independently authorized CLOUD-001C policy reads and separately signed,
source-bound sanitized exact-rule artifacts; a response digest alone is never policy input. Its
deny-overrides exact-match evaluator distinguishes unchanged input, changed input with the same
decision, and changed decision without claiming provider-effective permission. A separate
three-case disposable account/emulator profile remains registered but unprovisioned, unexecuted,
uncleaned, and unmeasured, so no Ground Truth result, numeric Cloud metric, Profile floor, Finding,
credential use, automatic Replay, provider runtime, or mutation authority is created.
SYS-001A adds a secret-free typed registry only: pseudonymous host coordinates and content-bound
process, logical filesystem, manager-qualified service, and sanitized configuration identities
preserve exact parent lineage without importing PID, host-local absolute path, display name, raw
configuration value, Docker metadata, host journal, mTLS identity, or agent privilege. These typed
values are `registered-not-authorized` knowledge and provide no host existence or state claim,
Scope, Capability, approval, Permit, host agent/Worker, credential/root, filesystem or service
access, network, Graph admission, mutation, or executable System analysis path.
SYS-001B adds a current signed metadata-only preparation and explicit host-agent request adaptation
for that exact identity. It pins public Worker mTLS deployment configuration, one selected
subject/SPKI, an explicit non-root run-as identity, exact Campaign Surface-token Scope, and bounded
request/artifact/runtime ceilings. It deliberately adds no routable agent URL: the existing Worker
is the authenticated Control Plane client, and Tool network access remains disabled. The repository
still has no live authenticated host agent; the Tool fails closed before Worker materialization,
and the preparation grants no bearer or direct-mTLS admission, non-root attestation, session, host
access, result, knowledge admission, root privilege, mutation, or execution authority.

SYS-001C accepts only deployment-produced detached evidence for an already approved and consumed
SYS-001B action. A deployment-configured Ed25519 trust anchor binds the exact host-agent
deployment, Capability/release, Worker direct-mTLS admission, recomputed Gateway policy outcome,
declared non-root runtime identity/confinement, and digest-only result receipt. The signed receipt
explicitly identifies live-host or immutable-snapshot input provenance without embedding raw host
data. After rebuilding current activation, Campaign Scope, preparation, approval, and Permit
authority, it reuses the existing Graph single
writer for one neutral `system.host-observation` and two restricted Evidence nodes. A fixed service
status or configuration metadata review signal may add only a confidence `0.5` open
`system.security-configuration` Hypothesis; no signal creates no conclusion. Raw host content,
paths, service/configuration values, host access, root or privilege escalation, mutation, Replay,
Finding, and further execution authority are never admitted. The repository still does not provide
the live host-agent runtime that produced the external signed evidence.

SYS-001D does not execute Replay. It reopens the exact stored SYS-001C source and one separately
authorized sealed execution under the same Surface, operation, release, deployment, Scope, request
semantics, and trust anchor. Every authority and execution coordinate must be disjoint, and the
replay statement's signed start must be strictly later than the source statement's signed finish.
Trusted wire reload requires both original evidence contexts, both exact Graph stores, and the
receiver deployment trust anchor; bare model parsing and an embedded anchor or Graph event are
structural only and cannot establish those claims.
Two receipts for the same signed immutable snapshot form the DOMAIN-006 re-analysis path; two live
receipts form a fresh authenticated comparison that explicitly does not satisfy that
immutable-snapshot strategy. The signed causal order does not prove physical Worker freshness.
Equal result-body digests must retain equal signed byte counts. Only neutral digest/byte-count/
signal match, change, or unresolved state is projected. A separate five-case fixture profile
covers all System Surface classes and registers disposable non-root host,
known-positive, negative-Control, privilege-denial, cleanup, and evidence-completeness requirements,
but keeps private Ground Truth verification false, provisions, executes, cleans up, and measures
nothing, and grants no host, root, mutation, Finding, Replay, or further execution authority.

APP-001A adds a secret-free typed registry only. Binary identity is one caller-supplied lowercase
artifact SHA-256; configuration and declared runtime identities embed an exact binary parent, and
library identity embeds an exact binary or declared-runtime parent. Configuration, runtime, and
library coordinates reject path, URL, wildcard, mutable alias, and floating or range versions.
The registry does not resolve or read an artifact, verify bytes or format, parse configuration,
attest a runtime, resolve dependencies, launch a process, select a sandbox or Worker, access a
network, attach a debugger, admit Graph knowledge, or authorize analysis or execution. The exact
contract is
[APP-001A](docs/discovery/APP-001A-binary-configuration-runtime-library-surface-model.md).

APP-001B adds a current signed read-only preparation for one exact APP-001A Surface. It binds a
deployment-supplied opaque custody object and authorization-document digest without reusing the
sealed Run `ArtifactRef`, accepting a path or URL, resolving bytes, or verifying custody. A
class-owned logical parser, parser executable and sandbox image digests, explicit non-root identity,
fixed read-only no-exec artifact mount, disabled network, and bounded artifact/output/runtime/
memory/process ceilings are content-addressed configuration requirements. The Tool fails closed
before Worker materialization, and preparation grants no authorization verification, artifact
read, mount, sandbox/runtime attestation, network, dynamic execution, debugger, result, Graph,
Finding, or execution authority. The exact contract is
[APP-001B](docs/capability/APP-001B-read-only-static-analysis-capability.md).

APP-001C reopens neither custody nor a sandbox. It rebuilds current APP-001B activation, Scope,
preparation, Decision, Proposal, Grant, approval, consumed Permit, and approval-consumption receipt,
then verifies a deployment-configured Ed25519 signature over the exact artifact/custody/sandbox
identity, recomputed Gateway decision, causal execution window, and detached digest-only result
receipt. The existing Graph writer admits one fixed neutral Observation and two restricted Evidence
nodes; an exact class-bound review signal may add only a confidence `0.5` open Hypothesis. This is
verification of deployment provenance, not independent live sandbox conformance or parser-output
truth. No raw artifact/output, format, runtime, dependency, vulnerability, Finding, Replay, network,
dynamic execution, debugger, mutation, or new execution authority is created. The exact contract is
[APP-001C](docs/graph/APP-001C-sealed-application-static-analysis-knowledge-admission.md).

APP-001D does not invoke a parser or schedule Replay. It reopens the exact stored APP-001C source
and one separately authorized sealed execution under the same immutable artifact, Surface,
operation, custody/sandbox, parser executable, image, output schema, Scope, release, and budgets.
Trusted wire reload requires the deployment trust anchor, both original evidence contexts, and both
exact Graph stores; bare model parsing is structural only and cannot establish those claims.
Every action and evidence authority coordinate must be disjoint, and the signed re-analysis start
must be strictly later than the source finish. Equal result-body digests must retain equal signed
byte counts. Only neutral digest/byte-count/signal match, change, or unresolved state is projected;
none confirms format, configuration, runtime support, dependency, vulnerability, Hypothesis, or
Finding truth. A separate eight-case profile registers one
known-positive and one negative Control for each binary/configuration/runtime/library Surface plus
disposable offline non-root sandbox, read-only noexec mount, and execution/runtime/result/cleanup
evidence requirements. It materializes, executes, cleans up, and measures nothing. The exact
contract is
[APP-001D](docs/benchmark/APP-001D-application-reanalysis-seeded-artifact-fixtures.md).

MOBILE-001A adds a secret-free typed registry only. APK and IPA declarations embed one exact
APP-001A binary coordinate, applications embed their complete package lineage, and declared
runtime, logical storage, deep-link, TLS-policy, and authentication-flow identities embed the
complete application. Platform-specific application IDs, runtime families, link kinds, and TLS
policy kinds fail closed on Android/iOS mismatch. Deep links store a canonical scheme plus an
optional strict IDNA host and optional host-dependent port, stable route ID, and sanitized
declaration digest rather than a full URI or path. Public builders
revalidate preconstructed nested models before deriving content identity. The registry does not
resolve or read a package, verify format/manifest/signing identity, analyze or install an app,
select or access an emulator/device, instrument a process, read storage, invoke network/TLS/auth,
use credentials, admit Graph knowledge, or authorize execution. The exact contract is
[MOBILE-001A](docs/discovery/MOBILE-001A-apk-ipa-app-runtime-storage-deeplink-tls-auth-surface-model.md).

MOBILE-001B adds one complete seven-role CAP-002 bundle and stops at a
`PreparedCapabilityAction`. Its eight code-owned operations follow the selected Surface class,
while the parser family is derived only from the complete root package lineage: APK selects the
Android package parser and IPA selects the iOS package parser. Custody binds the selected Surface,
root package Surface, APP binary digest, exact byte count, and opaque deployment authorization
reference without exposing a path, URL, bytes, credential, or device identity. The selected and
root package Surface tokens must both be exact current Campaign allows. Parser/image names,
digests, sandbox settings, and archive limits are configuration requirements, not proof that an
artifact was read, is a valid or signed APK/IPA, or that a parser, image, sandbox, or Worker exists.
The current DOMAIN-004 Mobile minimum profile remains device-bound, so this static preparation
records `domainWorkerProfileBound=false` and cannot materialize a Worker job. The exact contract is
[MOBILE-001B](docs/capability/MOBILE-001B-read-only-package-analysis-capability.md).

MOBILE-001C reopens neither package custody nor a sandbox. It rebuilds the current MOBILE-001B
activation, selected and root package Scope, preparation, Decision, Proposal, Grant, approval,
consumed Permit, and approval-consumption receipt. It then verifies a deployment-configured
Ed25519 signature over the exact selected/root lineage, package digest and bytes, custody,
operation, parser, executable/image, non-root network/DNS-disabled sandbox identity, configured
and observed archive ceilings, recomputed Gateway decision, causal zero-live-channel execution,
and detached digest-only result receipt. The existing Graph writer admits one fixed neutral Mobile
Observation and two restricted Evidence nodes; one of eight exact class/operation review signals
may add only a confidence `0.5` open `mobile.security-property` Hypothesis. Repository code does
not inspect the live sandbox or parser output, and the device-bound DOMAIN-004 profile, Worker job,
emulator/device access, install/launch/instrumentation, network/storage/TLS/auth/credential use,
package/manifest/signing/runtime/security truth, Replay, Finding, mutation, and new execution
authority remain absent. The exact contract is
[MOBILE-001C](docs/graph/MOBILE-001C-sealed-mobile-package-analysis-knowledge-admission.md).

MOBILE-001D invokes no parser, sandbox, Worker, Replay runtime, emulator, or device. It reopens the
exact stored MOBILE-001C source and one separately authorized sealed execution under the same
selected and root package Surfaces, complete platform lineage, immutable package, custody and
sandbox bindings, operation, parser executable, image, output schema, selected/root Scope, release,
resource ceilings, and signed archive observations. Every action and evidence authority coordinate
must be disjoint, and the signed re-analysis start must be strictly later than the source finish.
An equal result-body digest must carry the same signed result byte count; otherwise the evidence is
inconsistent and fails closed. Only neutral digest, byte-count, and bounded-signal match, change, or
unresolved state is projected, and trusted wire reload requires both original evidence contexts,
both exact Graph stores, and the deployment trust anchor. A separate 28-case profile registers one
known-positive and one no-signal negative Control for all fourteen valid Surface/platform/root
lineages, with seeded APK/IPA, disposable network/DNS-disabled non-root static-sandbox,
read-only/noexec mount, archive-safety, and execution/runtime/result/cleanup evidence requirements.
It materializes, executes, cleans up, and measures nothing; the device-bound DOMAIN-004 Mobile
profile remains deferred and no package, Worker, device, manifest/security truth, Finding, Replay,
or further execution authority is created. The exact contract is
[MOBILE-001D](docs/benchmark/MOBILE-001D-package-reanalysis-seeded-mobile-fixtures.md).

CRYPTO-001A adds a content-free typed registry only. One exact protocol declaration is the root;
key-usage kind, ciphertext digest, and sanitized configuration declarations are sibling children
with complete protocol lineage. There is no free-form key-usage ID and no key identity, reference,
fingerprint or material, plaintext, raw ciphertext, cryptographic parameter, raw configuration,
path, endpoint, credential, or Oracle result. Declaration digests are unverified caller
coordinates, not redaction or proof that their external preimages were sanitized. The registry
does not resolve or read an artifact, analyze cryptographic misuse, perform a cryptographic
operation, use a key or credential, negotiate a protocol, invoke an Oracle, select a Tool or
Worker, access a network, admit Graph knowledge, or authorize execution. The existing fixed
single-byte XOR lab remains independent. The exact contract is
[CRYPTO-001A](docs/discovery/CRYPTO-001A-protocol-key-usage-ciphertext-configuration-surface-model.md).

CRYPTO-001B adds a non-executable offline misuse-analysis preparation boundary. It binds one
complete CRYPTO-001A Surface and its full class/locator/input/digest/operation/analyzer mapping to
a current signed Range Capability, exact non-routable Campaign Scope, code-classified
digest-derived custody metadata, an externally supplied authorization-document digest, a
code-owned bounded signal vocabulary, and the exact DOMAIN-004 Cryptography profile.
The sandbox record fixes code-owned deployment and non-root service identities, requires
network/DNS-disabled read-only/noexec operation and exact image, executable, rule, and resource
ceilings, and accepts no caller-controlled identity text, but it is configuration rather than
runtime attestation. All network, key, credential, key-store, cryptographic-operation, key-search,
protocol-negotiation, Oracle, plaintext/key-output, command, and mutation budgets are zero. The
Tool and CAP-002 runtime roles materialize no Worker or result, and the CTF XOR runtime is not
reused. The exact contract is
[CRYPTO-001B](docs/capability/CRYPTO-001B-offline-cryptographic-misuse-analysis-capability.md).

CRYPTO-001C admits only structurally verified knowledge from an already approved and completed
external execution. It reopens a deployment-signed Ed25519 execution bundle and strict detached
result receipt, rebuilds current B preparation/Scope/Grant/Decision/Permit/approval and Gateway
policy, and checks exact Surface lineage, custody, analyzer/rule/image, resource ceilings, causal
timing, and zero network/key/credential/cryptographic-operation channels. A repository-owned pure
Oracle reads neither artifact nor result body: it recomputes metadata consistency and derives one
class-owned review signal from `review`, or `inconclusive-no-signal` from `no-signal`. The existing
Graph writer receives one succeeded Action, one fixed neutral Observation, and two restricted
Evidence nodes; a review signal may add one open confidence `0.5` Hypothesis that explicitly
requires separately authorized future re-analysis. Neither disposition is misuse truth or a
negative conclusion, and no key use, external Oracle, Replay, Finding, or further execution is
authorized. The exact contract is
[CRYPTO-001C](docs/graph/CRYPTO-001C-oracle-recomputed-cryptographic-analysis-knowledge-admission.md).

CRYPTO-001D compares that stored source with one later, separately authorized sealed execution.
Both CRYPTO-001C contexts are reopened through their exact Graph stores and separate deployment
trust anchors. The logical Surface, artifact and custody coordinates, rule, operation, analyzer,
Scope, release, schema, resources, and zero-live-channel semantics must match, while executable,
image, sandbox, active signer, Run, approval, Permit, execution, runtime, attestation, result, and
Oracle identities must differ. The projection reports only opaque result-body digest/byte-count
and structural disposition/signal `matched`, `changed`, or `unresolved`; it reads neither body and
turns no state into semantic cryptographic truth or a negative conclusion. A separate exact
eight-case registry covers protocol, key usage, ciphertext, and configuration positive and
no-signal Control requirements, but materializes no vector or sandbox and records no Ground Truth,
cleanup, coverage, recomputation-success, quality, or validation-floor measurement. Distinct
implementation provenance is limited to the configured executable/image/sandbox/signer identities;
source-code, algorithmic, organizational, supply-chain, physical-host, and common-mode independence
remain unverified. The signed timestamp order is not a source-root-bound causal chain and does not
prove cross-signer clock synchronization. The exact contract is
[CRYPTO-001D](docs/benchmark/CRYPTO-001D-independent-implementation-replay-seeded-vector-requirements.md).

The authoritative priority and status are in [PLAN.md](PLAN.md) and the verified checkpoint is in
[HANDOFF.md](HANDOFF.md).

## Forensics boundary

Forensics uses the same Graph, Capability, Permit, Worker, Observation, Evidence, and benchmark
infrastructure but defaults to immutable read-only analysis:

```text
Artifact
-> forensic Surface
-> Hypothesis
-> Parser / Analyzer Capability
-> Observation
-> Evidence
-> Graph Admission
```

FORENSICS-001A implements only the first content-free representation boundary. Each disk, memory,
log, or generic artifact locator embeds the complete caller-supplied `pajin.dev/run-integrity/v1`
source root, source artifact-record, provenance-record, artifact digest, and byte-count coordinate.
The coordinate does not resolve or verify the Run, artifact, provenance, source immutability, or
chain of custody and carries no path, URI, raw evidence, credential, secret, or parser output.
The standalone Surface reference is an opaque digest pointer with no unbound class or locator-kind
claim; exact use requires rebinding it to the complete revalidated Surface. The established
discovery and Run-integrity wires remain unchanged.

FORENSICS-001B adds a non-executable read-only parser preparation boundary. It rebinds every
custody and sandbox reference to the complete Surface, derives one exact input, operation, and
logical parser from the Surface class, and binds a current signed CAP-002 release, an exact
`GET` Scope token containing both Surface and parser identity, opaque authorization/custody
coordinates, the exact provenance-preserving Forensics Worker profile, and a fixed non-root
network/DNS-disabled immutable read-only/noexec sandbox requirement. Parser executable,
configuration, and image digests plus artifact/output/runtime/memory/process/byte-defined
parser-work/recursion/decompression-ratio/absolute-expanded-byte ceilings are content-addressed.
Live credential and secret access, source writes and copies, evidence mutations, lateral movement,
target execution, device sessions, plugin loads, shell commands, host reads, network, and DNS
channels are fixed to zero.

The slice stops at `PreparedCapabilityAction` with state `prepared-not-authorized`. It does not
resolve or read a source, verify root/record/provenance/custody/digest/size/immutability, materialize
a mount or Worker job, attest or execute a parser, or create a result or Graph knowledge. See the
[FORENSICS-001B contract](docs/capability/FORENSICS-001B-immutable-source-read-only-parser-analysis-capability.md).

FORENSICS-001C admits knowledge only from a Gate-owned, deployment-configured absolute existing
non-symlink evidence root. The two accepted metadata files have code-owned references derived from
the SHA-256 of their exact bytes: one outer parser-execution bundle containing the separately
signed source-membership assertion, and one detached digest-only result receipt. Reference
validation and the shared bounded reader reject traversal, aliases, multiple hard links, every
symlink or junction component and leaf, oversized or changed files, and ambiguous JSON.

The nested source-membership/custody signature and outer parser-execution signature use distinct
deployment-owned Ed25519 trust anchors and disjoint keyrings; caller or evidence anchor selection
is forbidden and missing production anchors fail closed. Verification authenticates the complete
FORENSICS-001A provenance and FORENSICS-001B custody assertions plus the exact B preparation,
parser, sandbox, resource, pre/post, and zero-channel runtime assertions. It does not turn those
signed assertions into independently verified source, custody, format, immutability, parser, or
result truth.

Before Graph proposal construction, C rebuilds the current signed Range activation/release, exact
parser-bound Scope and preparation, approved job, durable approval-consumption receipt, and one
consumed ActionPermit. The signed outer statement binds the exact Capability Grant ID and canonical
digest, and the recomputed Gateway outcome includes that Grant digest. A workflow-owned pure
structural Oracle opens no raw result body and accepts only inconclusive `review` or `no-signal`.

The existing Graph CAS single writer admits one fixed neutral Observation and exactly two
restricted Evidence nodes. Only `review` may immediately add one confidence `0.5` open Hypothesis;
`no-signal` creates no Hypothesis or negative conclusion. C provides no raw-source/result/provenance/
custody admission, semantic or Finding truth, source/result read, mutation, credential or secret
use, lateral movement, Replay, benchmark/measurement, or further action authority. See the
[FORENSICS-001C contract](docs/graph/FORENSICS-001C-sealed-forensic-analysis-knowledge-admission.md).

A FORENSICS-001C Observation may enable only the fixed open class-owned review Hypothesis above.
It cannot name or confirm credential material, authorize credential use, lateral movement,
evidence mutation, or another active probe. Those actions require separate Evidence, Capabilities,
and fresh authority.

FORENSICS-001D invokes no parser, sandbox, Worker, Replay scheduler, or benchmark Harness. It
contextfully reopens the exact stored C admission and a later separately authorized C execution
through two evidence roots and Graph stores. One deployment source-membership trust anchor must
authenticate equal immutable Surface/provenance/custody/source-state semantics for both contexts.
The gate automatically derives `deterministic-reparse` when execution trust, signer, executable,
configuration, image, and sandbox coordinates all match, or `independent-parser-comparison` when
all differ; partial drift fails closed. All action and evidence identities are disjoint, and the
second signed start must follow the source finish. Neither mode proves independent source code,
organizations, physical hosts, clock authority, source truth, provenance truth, deterministic
semantics, or parser correctness.

The projection reports only opaque result digest/byte-count, result disposition, structural-Oracle
disposition, and bounded signal match, change, or unresolved. Equal result digests with different
signed byte counts fail closed, and neither agreement nor disagreement becomes semantic or Finding
truth. A separate profile registers exactly twelve requirements: known-positive review,
`no-signal` negative Control, and corrupted-input bounded rejection for each disk, memory, log,
and generic artifact Surface. Only independent mode satisfies the DOMAIN-006 strategy. All four
Forensics metrics remain required references but unmeasured; the registry materializes, executes,
rejects, cleans up, and measures nothing. See the
[FORENSICS-001D contract](docs/benchmark/FORENSICS-001D-independent-parser-comparison-seeded-evidence-requirements.md).

## Safety invariants

- Scope, risk, budget, rate, egress, credentials, Capabilities, and Workers are explicit ceilings.
- Discovery, planning, Graph admission, Agents, and Supervisors cannot expand those ceilings.
- Arbitrary shell authority and silent Tool or plugin execution are prohibited.
- T2+ and mutating actions retain explicit approval and cleanup requirements.
- Worker success is normalized and checked by registered Oracles; it is not a trusted Finding.
- Finding confirmation preserves Profile-specific independent Replay and validation floors.
- Evidence is content-addressed, lineage-bound, sealed, and reverified before later authority use.
- Failures and mismatches fail closed.

Deployment topology does not replace these controls. The target-lab and host-facing Control
Plane/PostgreSQL networks are ordinary Docker bridges: they segment service attachment but do not
deny container outbound traffic and therefore are not an outbound-deny boundary. Production needs
host firewall or equivalent egress controls in addition to PAJIN's per-execution proxy boundary.

For HTTPS CONNECT, the proxy can enforce only authority-wide rules. The exact encrypted method and
path remain bound to the Gateway-selected fixed Worker action rather than proxy inspection. CONNECT
events state `receiptEligible=false`, `methodEnforcement=trusted-worker-only`, and
`pathEnforcement=authority-only`; they are not request/response receipts. Proxy policy input and
response buffering are bounded, and the fixed 64 MiB proxy rejects configured response limits above
8 MiB before execution.

## Development setup

Python 3.12 or newer is supported. The repository `.python-version` and Linux CI use Python 3.12
as the portable baseline. The root `uv.lock` is the canonical dependency lock.

```powershell
uv sync --locked --extra dev --extra control-plane
```

An editable pip environment is supported for development but is not the reproducible lock-based
quality gate:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev,control-plane]"
```

On POSIX systems use `.venv/bin/python` and `.venv/bin/pajin`.

## Command surface

Run `pajin --help` or `pajin <command> --help` for the authoritative option list.

| Group | Main commands |
| --- | --- |
| Core | `validate`, `run`, `multi-run`, `multi-cancel-check` |
| Capability authoring | `capability-scaffold` |
| Provider and bounded Tool loop | `provider-check`, `provider-agent-run`, `tool-loop-run`, `tool-loop-approval-check` |
| Pentest | `pentest-compile`, `pentest-recon-dispatch`, `pentest-replay-dispatch`, `pentest-workflow-stage-dispatch`, `pentest-workflow-run` |
| KISA AI assessment | `kisa-run`, `kisa-plan-remediation`, `kisa-retest` |
| Bug hunt | `bug-bounty-review`, `bug-bounty-compile`, `bug-bounty-report`, `bug-bounty-run` |
| CTF | `ctf-run`, `ctf-web-run`, `ctf-suite-run` |
| Evidence and infrastructure | `evidence-verify`, `replay-verify`, `replay-attestation-verify`, `sarif-export`, `worker-check`, `egress-check`, `mcp-check` |

Optional processes are installed as `pajin-control-plane`, `pajin-worker-daemon`, and
`pajin-replay-worker-daemon`. Deployment-specific authority, trust, and environment requirements
live in the relevant versioned contracts under [docs/orchestration](docs/orchestration/), not in a
milestone history embedded in this README.

## Verification

```powershell
.venv\Scripts\python -m pytest
.venv\Scripts\ruff check src tests containers scripts
.venv\Scripts\python -m mypy src
```

The SHA-pinned [Linux CI workflow](.github/workflows/ci.yml) installs the locked dependency set on
Ubuntu 24.04 with Python 3.12. It separates a 60-minute Quality job for Ruff and strict mypy from
twenty-four `fail-fast: false` pytest matrix shards with 120-minute timeouts. A SHA-256 digest of
each canonical full node ID deterministically assigns every collected test to exactly one shard; local
pytest remains unsharded unless both CI shard options are supplied.
The separate [WEB-002D conformance workflow](.github/workflows/web-002d-conformance.yml) is off by
default and runs only after its required confirmation input. It builds the four repository-owned
images for `linux/amd64`, pulls the registered ZAP image by its amd64 registry digest, records
runtime and exact image identities, runs only the exact opt-in node, and requires six independent
container/network label/name residue queries to return no matches. `workflow_dispatch` verifies only a committed ref; it is not evidence for uncommitted
working-tree changes. Other live Docker, PostgreSQL, Control Plane, Worker, and external-provider
tests remain environment-gated and must not be reported as executed without their prerequisites.

## Documentation

- [Documentation index](docs/README.md)
- [Documentation authority policy](docs/DOCUMENTATION_POLICY.md)
- [Architecture v2](docs/rfc/0001-pajin-architecture-v2.md)
- [Multi-domain architecture](docs/rfc/0002-multi-domain-security-analysis-architecture.md)
- [Implementation plan](PLAN.md)
- [Current handoff](HANDOFF.md)
- [Known issues](KNOWN_ISSUES.md)
- [Decision index](DECISIONS.md)
- [Capability contracts](docs/capability/)
- [Graph contracts](docs/graph/)
- [Discovery contracts](docs/discovery/)
- [Orchestration contracts](docs/orchestration/)
- [Benchmark contracts](docs/benchmark/)
