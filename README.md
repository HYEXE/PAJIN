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
The long-term Security Domain taxonomy is `web`, `network`, `system`, `application`,
`mobile`, `cloud`, `ai`, `cryptography`, and `forensics`.

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
| Web / API | Implemented, bounded | HTTP/OpenAPI/auth/file-upload discovery, exact Pentest GET Recon, and REDTEAM-001C exact three-request Boolean SQLi profile against one fixed synthetic local endpoint; no general scanner or arbitrary target authority |
| MCP | Implemented, bounded | Discovery remains non-authoritative; REDTEAM-001D admits one approval-required, network-disabled registered `demo-security:inspect_text` Capability with one fixed synthetic input and no Replay or Finding authority |
| Benchmark | Implemented, bounded | BENCH-001 measurement/Target Factory lifecycle plus REDTEAM-002 exact profile detection, false-positive, Replay, request/Tool cost, evidence, and policy-denial contract with sealed aggregation; reference fixtures are not production scores, and domain-aware metrics are planned |
| Network, System, Application, Mobile, Cloud | Planned product domains | Infrastructure primitives may exist, but no general executable security-analysis vertical slice is claimed |
| Cryptography | One fixed CTF lab only | General cryptographic analysis is planned |
| Digital Forensics | Planned | No general forensic Surface, Capability, Worker, replay, or benchmark vertical slice is implemented |

REDTEAM-001A/B/C/D, REDTEAM-002, and PENTEST contracts remain stable compatibility boundaries.
UX-008 remains before the broader multi-domain foundation begins after the current Phase 11
milestone.

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

A forensic Observation may enable a Hypothesis such as possible credential material. It cannot
authorize use of that credential, lateral movement, evidence mutation, or another active probe.
Those actions require separate Capabilities and fresh authority.

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

The SHA-pinned [Linux CI workflow](.github/workflows/ci.yml) installs the locked dependency set and
runs Ruff, strict mypy, and the default pytest suite on Ubuntu 24.04 with Python 3.12. Live Docker,
PostgreSQL, Control Plane, Worker, and external-provider tests remain environment-gated and must not
be reported as executed when their prerequisites are absent.

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
