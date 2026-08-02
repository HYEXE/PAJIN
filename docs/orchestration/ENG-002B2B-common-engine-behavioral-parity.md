# ENG-002B2B: Common Engine Behavioral Parity Admission

- Status: Implemented
- Contract versions:
  - `pajin.dev/common-engine-normalized-behavior/v1alpha1`
  - `pajin.dev/common-engine-behavioral-parity/v1alpha1`
- Decision: [ADR-0107](../adr/0107-admit-parity-only-from-sealed-semantic-behavior.md)

## Scope

ENG-002B2B consumes one complete ENG-002B2A result and proves behavioral parity between the
legacy-direct and Profile-adapter arms. It re-verifies both exact B2A source roots, runs the current
Mode post-processor against each sealed source, loads the resulting sealed artifacts in fresh
snapshots, and compares Scope, Capability attenuation, ToolRequest, Policy and Worker receipt,
Outcome, and Mode-specific output semantics.

Successful parity admits the Profile adapter as behaviorally equivalent for this exact fixture and
runtime coordinate. It does not compile a `MissionEnvelope`, issue an `ActionPermit`, select the
adapter as a default, or authorize Common execution.

## Source and Mode authority

Parity starts only when each Run's current root is exactly the root recorded by B2A. A source that
was mutated, resealed, or already post-processed is rejected. Mode processing then uses:

- AI assessment: the B1-bound KISA thresholds, complete code-owned KISA catalog, and
  `KISAModePack`;
- Bug Hunt: the exact `BugBountyProgramManifest`, validated against both Campaigns, and
  `BugBountyReportService`; or
- CTF: the exact `CTFChallengeManifest`, recompiled to the Campaign, and `CTFModePack`.

The generated Mode artifacts must extend the exact B2A root in the Run seal chain. Their final root
must be different from the source root. A partially completed pair creates no parity authority.
Because the first Run may already be extended when the second processor fails, retry requires a
fresh B2A pair; the extended Run is never rolled back or treated as parity evidence.

## Explicit normalization

Fresh values remain different in the sealed source Runs. ENG-002B2B replaces only values whose
semantic correspondence is established from typed structure:

- Plan-ordered step and ToolRequest IDs;
- one Agent per non-Specialist role and one Specialist per Plan request;
- each Agent's Capability grant and each role/request-bound Task;
- one Worker execution and evidence path per Plan request;
- validation Candidate, Finding, and Decision IDs in typed validation order;
- audit event IDs by contiguous event sequence;
- the Bug Hunt report ID; and
- execution-generated timestamps in the explicit allowlist: issuance, start/finish, Candidate
  creation, validation decision, event, seal, and Mode result generation times.

Schema fields whose type is an unordered set, such as Task dependencies, Capability tools/targets,
threat classes, and KISA catalog sets, are sorted by canonical JSON. Every other list retains order.
No value is normalized merely because it resembles an ID or timestamp.
Structured JSON replaces only an entire key or value that exactly equals a registered fresh
identity. Substring replacement is limited to Mode-owned UTF-8 report and writeup artifacts, where
those identities are rendered into prose.

## Compared evidence

`CommonEngineNormalizedBehaviorObservation` binds the B2A execution record, source and final roots,
Mode source, complete normalized payload, and separate digests for:

- Scope: Campaign digest and complete B1-normalized Plan;
- Capability: Agent topology, TaskGraph, and complete `capabilities.json` attenuation state;
- ToolRequest: measured Plan requests and sealed dispatch requests;
- receipt: exact Policy decision, Tool result, Worker job, Worker result, network trust flag, raw
  stdout, and host-observed network log;
- Outcome: status, Plan, Agents, TaskGraph, ToolResults, Findings, atomic validation, cancellation,
  and evidence; and
- Mode processing: all required typed JSON and UTF-8 report/writeup artifacts.

Mode processing also binds the exact sealed artifact inventory added after the B2A source root and
the complete semantic audit-event suffix. Event chain hashes are independently verified by the Run
reader and omitted from cross-Run comparison because they inherit different source roots; relative
order, type, payload, identity, and time semantics are compared. An undeclared extra artifact is
drift even when every required artifact is present.

Receipt fields and Mode-specific artifact roles are structurally required. Equal omission is not
parity. Request, receipt, Outcome, and evidence cardinalities must match the measured Plan.

`CommonEngineBehavioralParityAuthority` requires exact equality of all normalized payloads and
semantic digests, fixes the measured and proven dimensions to `scope`, `capability`, `tool-request`,
and `outcome`, and records receipt and Mode post-processing parity as proven.

## Negative cases

Admission fails closed for:

- missing, mutated, extended, foreign, or non-B2A source Runs;
- wrong Bug Hunt Program or CTF Challenge source;
- incomplete Mode post-processing or a final root that does not extend the B2A root;
- request/evidence cardinality drift or unknown Task/Agent/Capability lineage;
- missing Policy, Worker job/result, network trust, Tool result, or Mode artifact roles;
- different Scope, attenuation, request, receipt, Outcome, or post-processing semantics;
- cross-Mode/source substitution and digest drift; and
- measured/proven dimension, parity, Envelope, or Common-execution flag forgery.

## Compatibility, migration, and rollback

The API is additive, direct-call, and opt-in. It appends existing Mode artifacts to the two fixture
Runs but does not change legacy CLI/API defaults, existing runtime schemas, Mode readers, or public
Campaign wire formats. Rollback removes the B2B observation and admission API while retaining B2A,
B1, ENG-002A, and every legacy path.

ENG-002C1 may compile an existing non-expanding `MissionEnvelope` only from an exact PROF-002
compilation and this complete parity authority. Until then, `missionEnvelopeCompiled=false` and
`commonExecutionAuthorized=false` remain mandatory.
