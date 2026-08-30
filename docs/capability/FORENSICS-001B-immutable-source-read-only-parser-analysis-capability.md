# FORENSICS-001B: Immutable-source Read-only Parser Analysis Capability

- Status: Implemented, signed preparation and request adaptation only
- Capability: `pajin.forensics.read-only-evidence-analysis@1.0.0`
- Tool: `forensics.read-only-evidence-analysis@1.0.0`
- Binding API: `pajin.dev/forensic-evidence-analysis-binding/v1alpha1`
- Activation API: `pajin.dev/forensic-evidence-analysis-capability-activation-set/v1alpha1`
- Preparation API: `pajin.dev/forensic-evidence-analysis-preparation/v1alpha1`
- Custody API: `pajin.dev/forensic-evidence-custody-binding/v1alpha1`
- Sandbox API: `pajin.dev/forensic-evidence-analysis-sandbox-binding/v1alpha1`
- Request API: `pajin.dev/forensic-evidence-analysis-request/v1alpha1`
- Rule-set API: `pajin.dev/forensic-parser-rule-set/v1alpha1`
- Output schema: `pajin.forensics.read-only-evidence-analysis-result.v1`
- Authority: `src/pajin/capabilities/forensic_evidence_analysis.py`
- Decision: [ADR-0245](../adr/0245-bind-forensic-parser-preparation-without-source-read-or-evidence-mutation-authority.md)

## Purpose

FORENSICS-001B binds one complete FORENSICS-001A typed immutable-artifact Surface to a current
signed CAP-002 release, exact Campaign Scope, code-owned class/operation/parser mapping, opaque
custody and authorization coordinates, the exact DOMAIN-004 Forensics profile, and a bounded
configuration-only parser sandbox. It stops at `PreparedCapabilityAction` with state
`prepared-not-authorized`.

The adapter resolves, reads, mounts, copies, or mutates no source; verifies no source root, record,
provenance, seal, authenticity, immutability, membership, custody, digest, size, class, or format;
selects or executes no parser, sandbox, or Worker; and produces no result, Observation, Evidence,
Graph admission, Hypothesis, or Finding.

## Capability and activation

The Capability is experimental, T2, `READ_ONLY`, network-disabled, approval-required, and costs
one request unit. It registers materializer, action compiler, executor adapter, result normalizer,
success Oracle, Replay strategy, and cleanup handler roles. Activation accepts only an externally
signed current Range release from the existing lifecycle registry.

Materialization validates the exact request schema. Worker materialization and result
normalization fail closed because the slice contains no runtime. The Oracle is `INCONCLUSIVE`, and
Replay and cleanup return no plan.

The static binding pins the four FORENSICS-001A locators, complete CAP-001/CAP-002 identity, local
exact Forensics classification, exact DOMAIN-004 profile, complete mapping and parser rule set,
fixed output schema, current activation and Scope requirements, one-use Permit and Gateway
re-entry requirements, immutable read-only no-exec handling, provenance preservation, bounded
resources, and zero live channels. It does not modify the fixed DOMAIN-003 inventory.

## Surface-owned mapping

The caller supplies the complete Surface and requested operation. The operation is accepted only
when it is the class-owned value; input kind and parser cannot be selected independently.

| Surface class | Locator | Input kind | Operation | Logical parser | Digest |
| --- | --- | --- | --- | --- | --- |
| `disk` | `forensics-disk` | `disk-evidence` | `disk-evidence-parse` | `disk-evidence-parser` | provenance artifact SHA-256 |
| `memory` | `forensics-memory` | `memory-evidence` | `memory-evidence-parse` | `memory-evidence-parser` | provenance artifact SHA-256 |
| `log` | `forensics-log` | `log-evidence` | `log-evidence-parse` | `log-evidence-parser` | provenance artifact SHA-256 |
| `artifact` | `forensics-artifact` | `artifact-evidence` | `artifact-evidence-parse` | `artifact-evidence-parser` | provenance artifact SHA-256 |

The logical parser is a signed request identity, not an executable implementation, parser
conformance claim, or result-truth claim.

## Code-owned parser rule set

`pajin.forensics.parser-rules.baseline@1.0.0` content-addresses the complete sorted Surface mapping
and exactly four future neutral signals:

- `forensics.disk-analysis`;
- `forensics.memory-analysis`;
- `forensics.log-analysis`; and
- `forensics.artifact-analysis`.

The caller cannot inject or select a rule, parser mapping, signal order, plugin, or runtime. The
rule set fixes parser runtime availability, analysis truth, Finding authority, and execution
authority to false.

## Custody and authorization coordinate

`ForensicEvidenceCustodyBinding` includes the complete canonical Surface, derived input kind,
Surface provenance artifact digest and byte count, the fixed
`pajin.forensics.unverified-immutable-evidence-custody-coordinate` class, an object identifier
derived from the complete Surface digest, and an authorization identifier derived from the
supplied authorization SHA-256.

The object identifier therefore changes when the Surface root, artifact record, provenance
record, artifact digest, byte count, class, or any other Surface identity changes. The public
custody reference carries enough claims to recompute its binding digest but keeps the Surface
reference opaque.

The authorization digest is not proof of signature, freshness, Scope, applicability, or secret
redaction. The binding embeds no raw source or provenance, path, URI, object key, filename,
credential, secret, or parser output. Zero-byte source declarations remain valid because
FORENSICS-001A models the strict `0..2^63-1` byte-count coordinate.

## Configuration-only parser sandbox

`ForensicEvidenceAnalysisSandboxBinding` pins:

- the complete Surface and code-owned rule set;
- the class-owned operation and logical parser;
- `deployment:forensic-evidence-analysis`;
- `svc:pajin-forensic-parser`;
- exact parser executable, parser configuration, and sandbox image SHA-256 digests;
- the fixed `pajin.forensics.read-only-evidence-analysis-result.v1` schema and
  `bounded-json-stdout` transport;
- `/pajin/input/evidence` as an immutable read-only no-exec mount requirement; and
- artifact, output, runtime, memory, process, parser-work, recursion, decompression-ratio, and
  absolute decompressed-byte ceilings.

`parserWorkUnit` is fixed to `one-source-or-expanded-byte-processed`: every source or expanded byte
processed consumes one unit, and repeated processing consumes another unit. The absolute
`maxDecompressedBytes` ceiling prevents a high ratio from authorizing unbounded expansion; the
ratio and absolute ceilings both apply.

It also pins the DOMAIN-004 Forensics minimum profile:

- network: `disabled-by-default`;
- filesystem: `immutable-evidence`;
- credentials: `none`;
- runtime: `provenance-preserving-parser`;
- identity dimensions: `evidence-source`, `parser`;
- budget dimensions: `artifact-bytes`, `runtime`; and
- provenance preservation: required.

Required deployment properties include disabled network and DNS, read-only root filesystem,
non-root execution, no-new-privileges, disabled core dumps, exact digests, provenance
preservation, and pre/post no-mutation evidence. Host filesystem access, credential and secret
injection, inherited environment, symlink traversal, devices, plugins, shell commands, source
read/mount/copy or mutation authority, lateral movement, target execution, raw result echo,
runtime conformance, Worker selection, mount materialization, and execution remain false.

The binding is a requirement set. It does not attest that any deployment implements it.

## Request and budget

`BoundedForensicEvidenceParserAdapter.prepare_request` revalidates custody and sandbox objects,
rebinds their opaque references to the same complete Surface, and requires exact agreement on
input kind, operation, parser, rule set, output schema, artifact digest and byte count, and every
resource ceiling.

The request budget binds one request, declared artifact bytes, and the sandbox's output, runtime,
memory, process, parser-work, recursion, decompression-ratio, and absolute decompressed-byte
ceilings. These dimensions are literal zero:

- network requests and DNS queries;
- host filesystem reads, source writes, source copies, and evidence mutations;
- credential reads and uses and secret-material reads;
- device sessions, plugin loads, and lateral-movement attempts; and
- target-process executions and shell commands.

The budget is attenuation-only and unreserved. Unknown fields, boolean-to-integer coercion, and
attempts to raise a zero dimension fail closed.

## Campaign Scope and preparation

The exact policy token is:

`https://forensics-scope.pajin.invalid/surfaces/<surface-id>/parsers/<parser>`

It is non-routable and exists only for Scope evaluation. The current Campaign must list the exact
canonical token in `allow`, include `GET` in Rules of Engagement, and have no matching deny rule.
Wildcard allow coverage is insufficient. The Campaign private-network flag cannot enable network
or DNS access.

`prepare_forensic_evidence_analysis` revalidates the activation, release, registered binding,
Campaign, complete Surface, exact parser-bound Scope, custody, sandbox, request, normalized
parameters, and prepared-action digests. Its result remains `prepared-not-authorized`.

Preparation does not satisfy approval, issue a Permit, authorize Gateway dispatch, reserve a
budget, resolve or read a source, verify custody or provenance, attest or select a sandbox, select
or materialize a Worker, execute a parser, mutate evidence, or admit knowledge.

## Fail-closed behavior

All definitions, references, classifications, mappings, rule sets, custody, sandbox, Campaign,
request, activation, and preparation values are exact or content-addressed. Public boundaries
recursively reject unmodeled Pydantic state, require exact instance types, canonicalize alias JSON,
and revalidate nested objects. Public cached accessors return deep copies.

Preparation rejects Surface root, record, provenance, digest, bytes, class, registry, Domain, or
type-set drift; operation/parser/rule substitution; custody or authorization-coordinate drift;
executable/configuration/image/deployment/runtime identity substitution; profile or ceiling drift;
missing exact Scope, wildcard-only allow, deny overlap, or missing GET; stale or forged signed
release data; target, method, Tool, request, normalized-parameter, or prepared-action digest drift;
authority-marker escalation; unknown sensitive fields; and boolean or integer coercion.

## Admission and benchmark boundary

FORENSICS-001C must separately verify immutable-member resolution, source-root and record linkage,
artifact digest and size, custody authorization, live sandbox attestation, parser conformance,
pre/post no-mutation evidence, and a sealed result before admitting neutral Observation/Evidence
or a bounded Hypothesis. Credential use, lateral movement, evidence mutation, and Findings remain
separate authorities.

FORENSICS-001D owns deterministic re-parse or independent parser comparison, disposable seeded
fixtures, corruption Controls, metrics, and validation floors. FORENSICS-001B creates no result,
Ground Truth, Control, benchmark Result, or measurement.

## Compatibility and rollback

The implementation is additive. FORENSICS-001A, existing registries, DOMAIN-003, DOMAIN-004,
Scope, Artifact readers, Workers, Graph, and runtime wire formats are unchanged. No source reader,
parser executable, sandbox deployment, Worker, credential broker, network route, data migration,
or external resource is added.

Rollback removes the additive module, tests, contract, ADR, and documentation links. New classes,
operations, parsers, signals, output fields, runtime behavior, or authority require a versioned
contract.

## Verification

`tests/test_forensic_evidence_analysis.py` covers all four Surface mappings, complete Surface and
opaque-reference rebinding, root/record/provenance/digest/byte/class drift, custody coordinates,
parser executable/configuration/image identity, DOMAIN-004 profile binding, parser-work and
decompression safety ceilings, zero-byte sources, zero live channels, exact parser-bound Scope and deny behavior,
all seven CAP-002 roles, current signed activation, preparation identity, fail-closed runtime roles,
forged nested model rejection, and boolean/integer coercion.
