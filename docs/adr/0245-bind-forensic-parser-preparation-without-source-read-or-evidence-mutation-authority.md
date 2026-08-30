# ADR-0245: Bind Forensic Parser Preparation without Source-read or Evidence-mutation Authority

## Status

Accepted

## Context

FORENSICS-001A represents caller-declared neutral disk, memory, log, and generic artifact evidence
classes as exact typed Surfaces. Each Surface includes caller-declared source-root, source-artifact-record,
provenance-record, artifact SHA-256, and byte-count coordinates, but grants no authority to resolve,
read, mount, copy, parse, or mutate the source. The next slice needs a reviewed read-only analysis
Capability without treating those coordinates as proof of existence, authenticity, custody, or
immutability.

The DOMAIN-004 Forensics profile supplies the minimum policy vocabulary: disabled network,
immutable evidence filesystem, no credentials, a provenance-preserving parser runtime,
`evidence-source` and `parser` identity dimensions, and `artifact-bytes` and `runtime` budget
dimensions. A profile reference is not deployment conformance, Worker selection, mount
materialization, or execution authority.

Forensic source handling has an additional integrity constraint. Parser input must remain bound to
the complete FORENSICS-001A Surface, and a future runtime must prove that the source did not change
across execution. A digest-only or class-bearing standalone pointer is insufficient because it
cannot independently establish source-root, record, provenance, byte-count, or class semantics.

## Decision

Add an experimental, T2, read-only, approval-required Capability and Tool:

- `pajin.forensics.read-only-evidence-analysis@1.0.0`; and
- `forensics.read-only-evidence-analysis@1.0.0`.

Register all seven CAP-002 authority roles and require a current externally signed Range release.
Materialization and action compilation may create one exact `PreparedCapabilityAction`. Executor
and result normalization fail closed, the success Oracle returns `INCONCLUSIVE`, and Replay and
cleanup return no plan. FORENSICS-001B provides no parser or Worker runtime.

Bind the complete FORENSICS-001A Surface at custody, sandbox, request, and preparation boundaries.
The standalone Surface reference remains opaque and is accepted only after rebinding it to the
complete canonical Surface. Derive the input kind, operation, and logical parser from the Surface
class through one code-owned mapping:

| Surface class | Input kind | Operation | Logical parser |
| --- | --- | --- | --- |
| `disk` | `disk-evidence` | `disk-evidence-parse` | `disk-evidence-parser` |
| `memory` | `memory-evidence` | `memory-evidence-parse` | `memory-evidence-parser` |
| `log` | `log-evidence` | `log-evidence-parse` | `log-evidence-parser` |
| `artifact` | `artifact-evidence` | `artifact-evidence-parse` | `artifact-evidence-parser` |

Register one content-addressed code-owned parser rule set,
`pajin.forensics.parser-rules.baseline@1.0.0`. Its identity contains the complete mapping and four
neutral future signal kinds. It allows no caller-selected rule, plugin, runtime, analysis-truth
claim, Finding, or execution authority.

Represent custody as content-addressed configuration containing the complete Surface, its derived
input kind, artifact digest and byte count, a code-owned opaque custody-authority class, an object
identifier derived from the complete Surface digest, and an authorization reference derived from
an externally supplied lowercase SHA-256. The reference is a coordinate, not proof. It carries no
path, URI, object key, filename, raw source or provenance, credential, secret, or parser output.
Authorization, source-root, records, seal, authenticity, immutability, membership, custody,
digest, bytes, class, format, provenance sanitization, source resolution, read, mount, and
no-mutation verification remain false.

Bind one configuration-only parser sandbox to the exact Forensics DOMAIN-004 profile, complete
Surface, rule set, operation and parser, code-owned deployment and non-root runtime identities,
exact parser executable, parser configuration, and sandbox image digests, fixed output schema and
transport, and an immutable read-only no-exec evidence mount at `/pajin/input/evidence`. Require a
read-only root filesystem, no-new-privileges, disabled core dumps, disabled network and DNS,
provenance preservation, and pre/post no-mutation evidence. Forbid host filesystem access,
credentials and secrets, inherited environment, symlink traversal, devices, plugins, shell
commands, source read/mount/copy or mutation authority, lateral movement, target execution, raw
result echo, Worker materialization, and runtime or conformance assertions.

Bind positive ceilings for artifact bytes, output bytes, runtime, memory, process count, parser
work units, recursion depth, decompression ratio, and absolute decompressed bytes. Define one
parser work unit as one source or expanded byte processed; repeated processing consumes another
unit. Artifact coordinates may declare zero bytes, while a sandbox's admitted capacity remains
positive. Fix network, DNS, host reads, source writes, evidence mutations,
source copies, credential reads and uses, secret reads, device sessions, plugin loads, lateral
movement attempts, target process executions, and shell commands to zero.

Require one exact non-routable Surface/parser Scope token:

`https://forensics-scope.pajin.invalid/surfaces/<surface-id>/parsers/<parser>`

The current Campaign must explicitly allow that exact canonical token and `GET`; wildcard coverage
is insufficient and any matching deny rule overrides the allow. The token identifies policy scope
only and is never resolved or requested over a network.

Stop at state `prepared-not-authorized`. Preparation does not satisfy approval, issue a Permit,
authorize Gateway dispatch, reserve a budget, select a sandbox or Worker, materialize a mount or
job, resolve or read source bytes, verify custody or provenance, execute a parser, mutate evidence,
or produce a result, Observation, Evidence, Graph admission, Hypothesis, Finding, or further
authority.

At public boundaries, recursively reject unmodeled nested Pydantic state, serialize exact model
instances to canonical alias JSON, revalidate exact types, and compare the result before deriving
content identity. Public cached registrations return deep copies.

Use a local exact Forensics Capability classification and do not change the fixed DOMAIN-003
global inventory. Inventory publication remains a separate versioned decision.

## Consequences

- Each FORENSICS-001A class has one unambiguous input, operation, and parser contract.
- Root, record, provenance, artifact, byte-count, class, parser, image, configuration, and budget
  drift invalidates the request or preparation.
- A custody or authorization digest remains an unverified external coordinate.
- Parser identity and objectively countable byte/work safety ceilings are reviewable without
  claiming runtime availability.
- Zero live-channel budgets prevent the preparation contract from requesting credentials,
  mutation, target execution, lateral movement, network access, shell commands, or plugins.
- FORENSICS-001C must verify immutable-member resolution, source-root and record linkage,
  digest/size, runtime attestation, parser conformance, pre/post no-mutation evidence, and a sealed
  result before admitting neutral knowledge.
- FORENSICS-001D must define deterministic re-parse or independent parser comparison and seeded
  fixtures without inheriting truth or execution authority from this contract.

## Rejected alternatives

### Treat a Surface reference or artifact digest as read authority

Rejected because both identify claims but prove neither custody nor authorization. Exact use
requires the complete revalidated Surface and a separately verified deployment boundary.

### Let callers select parsers, rules, plugins, or commands

Rejected because execution behavior and result semantics could drift from the reviewed Surface
class and signed code identity.

### Embed a path, URI, object key, filename, credential, or secret

Rejected because those values create unresolved acquisition and privilege paths. A future
deployment must resolve an opaque authorized custody coordinate under a separate contract.

### Claim DOMAIN-004 conformance during preparation

Rejected because the profile is a minimum requirement, not a live attestation. Worker admission,
mount properties, process identity, image admission, and no-mutation evidence require runtime
proof.

### Admit parser output or a forensic hypothesis directly

Rejected because preparation contains no execution result. Result custody and neutral knowledge
admission belong to FORENSICS-001C.

## Compatibility and rollback

FORENSICS-001B is additive. It changes no FORENSICS-001A wire format, existing Capability or Tool
registry, DOMAIN-003 inventory, DOMAIN-004 profile, Artifact reader, Scope, Worker, Graph, or
runtime wire.

Rollback removes the additive module, tests, contract, ADR, and documentation links. New source
classes, parsers, operations, signals, output fields, runtime behavior, or authority require a
versioned contract rather than silent expansion.

## Related documents

- [FORENSICS-001B contract](../capability/FORENSICS-001B-immutable-source-read-only-parser-analysis-capability.md)
- [FORENSICS-001A](../discovery/FORENSICS-001A-disk-memory-log-artifact-provenance-surface-model.md)
- [DOMAIN-003](../capability/DOMAIN-003-domain-aware-capability-inventory-projection.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0204](0204-separate-security-domain-from-profile-and-authority.md)
- [ADR-0244](0244-type-forensic-evidence-surfaces-without-source-access-or-evidence-mutation-authority.md)
