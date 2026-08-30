# ADR-0241: Bind Offline Cryptographic Misuse Analysis without Key-use or Artifact-access Authority

## Status

Accepted

## Context

CRYPTO-001A provides exact protocol, key-usage, ciphertext-digest, and sanitized-configuration
Surface identities. It intentionally performs no artifact access or cryptographic analysis. The
next slice needs a reviewed read-only Capability boundary that can describe one future offline
analysis without turning a Surface declaration, ciphertext digest, or Cryptography Domain label
into permission to read bytes, use a key, invoke an Oracle, or execute a Worker.

The existing CTF single-byte XOR path cannot be generalized safely. It accepts one bounded
synthetic inline ciphertext, executes a fixed finite key search, returns recovered key/plaintext
data, and uses a host recomputation Oracle. Those behaviors are appropriate only for that exact
lab contract. Reusing its Tool, request, Worker command, or result vocabulary for general
analysis would import key-search, plaintext-output, execution, and Oracle authority.

The existing DOMAIN-004 Cryptography profile is a useful minimum boundary: offline sandbox,
read-only artifact filesystem, no credentials, disabled network, and exact analyzer/artifact
identity and byte/runtime budget dimensions. A profile is still policy metadata rather than a
selected, admitted, or attested deployment. CRYPTO-001B must preserve that distinction.

Cryptographic inputs also require stronger separation than a generic file pointer. Protocol,
key-usage, and configuration Surfaces carry caller-supplied declaration digests whose preimages
are external. A ciphertext Surface carries an artifact digest. None proves custody, bytes,
sanitization, authorization, or safe parsing. Embedding paths, endpoints, key identifiers,
credentials, parameters, raw content, commands, or caller-selected plugins would merge identity,
secret access, runtime selection, and analysis authority.

## Decision

Add an experimental, T2, read-only, network-disabled, approval-required Capability and Tool:

- `pajin.cryptography.offline-misuse-analysis@1.0.0`; and
- `cryptography.offline-misuse-analysis@1.0.0`.

Register all seven CAP-002 authority roles and require an externally signed current Range
release. Materialization and action compilation may produce only an exact secret-free prepared
request. Executor and result-normalizer roles fail closed, the Oracle remains inconclusive, and
Replay and cleanup produce no plans because this slice implements no analyzer runtime.

Bind the complete CRYPTO-001A Surface at every custody, sandbox, request, and preparation
boundary. Derive one exact input kind, operation, analyzer, and artifact digest meaning from each
Surface class. Do not allow the caller to select them independently. In particular, a declared
key-use kind never becomes key identity or permission to perform that cryptographic operation.

Register one exact content-addressed code-owned rule identity,
`pajin.cryptography.misuse-rules.baseline@1.0.0`, with a four-member neutral future signal
vocabulary and the exact Surface class, locator kind, input kind, digest source, operation, and
analyzer mapping. Reject caller-supplied rules, plugins, commands, alternate signal order,
runtime availability, misuse confirmation, Finding authority, and execution authority. Bind this
complete mapping into the rule-set digest and therefore into the Tool and signed code-backed
Capability identity.

Represent custody as content-addressed configuration containing the complete Surface,
class-derived input kind and digest, a code-owned immutable-analysis-artifact custody authority
class, artifact and authorization reference identifiers derived exactly from their corresponding
digests, the externally supplied authorization-document SHA-256, and declared byte count. Accept
no caller-controlled custody authority, object ID, or authorization ID, so those fields cannot
smuggle a key alias, KMS/HSM/PKCS#11 coordinate, credential, JWT, path, or URL. Carry no raw
declaration, configuration, ciphertext, plaintext, key, key reference, certificate, JWK,
password, PIN, seed, credential, parameter, endpoint, or command.
Record authorization verification, sanitization verification, object resolution, byte
verification, artifact read, mount, and execution as false.

Bind one configuration-only sandbox to the exact DOMAIN-004 Cryptography profile, complete
Surface, rule set, operation and analyzer, code-owned exact deployment coordinate, executable and
image digests, code-owned exact non-root service identity, fixed output schema and transport,
read-only no-exec artifact mount, and bounded artifact, output, runtime, memory, and process
ceilings. Accept no caller-controlled deployment or runtime-identity text, so those fields cannot
smuggle secrets, key references, credentials, endpoints, paths, or privileged identities. Require
disabled network and DNS,
read-only root filesystem, no-new-privileges, disabled core dumps, and exact digests. Forbid host
filesystem access, credential and key injection, ambient environment, symlink traversal, device
access, plugins, shell commands, raw result echo, key or credential use, cryptographic operations,
key search, protocol negotiation, Oracle invocation, and runtime or execution assertions.

Use one attenuation-only request budget. Fix network, DNS, host reads, artifact writes, credential
and key reads, key-store sessions, cryptographic operations, key searches, protocol negotiations,
Oracle invocations, plaintext/key outputs, target execution, and shell commands to zero.

Require one exact non-routable Surface Scope token under
`https://cryptography-scope.pajin.invalid`, reviewed `GET`, and no matching deny rule. Wildcard
allow coverage is insufficient. Preserve the Campaign private-network flag as input state but do
not let it change disabled network/DNS requirements or zero budgets.

Stop preparation at a content-addressed `PreparedCapabilityAction` with state
`prepared-not-authorized`. Keep approval, Permit issuance, Gateway dispatch, Worker and sandbox
selection, budget reservation, artifact access, authorization or sanitization verification,
analysis, key/credential use, cryptographic operation, Oracle, mutation, Observation, Evidence,
Graph, Hypothesis, Finding, and execution false.

Use a local exact Cryptography Capability classification and leave the established fixed
DOMAIN-003 global inventory unchanged. Adding this Capability to that inventory is a separate
versioned decision. Reuse the existing exact DOMAIN-004 Cryptography profile as a minimum
requirement, but do not claim conformance, runtime availability, or Worker admission from the
reference alone.

At public boundaries, recursively reject unmodeled nested Pydantic state, serialize exact model
instances to canonical alias JSON, revalidate their exact types, and compare the result before
deriving content identity. Public references must carry enough claims to recompute their source
binding digest and reject drift. Keep cached canonical rule, Definition, local classification,
and binding objects private; public accessors return deep copies so bypassing a frozen-model setter
cannot poison later registry reads in the same process.

Do not import or call the CTF XOR Tool, inline input schema, key-search implementation, Worker
command, recovered output fields, or Oracle. The CTF Tool ID, request, runtime, and results remain
independent.

## Consequences

- A caller can prepare one exact future offline analysis while Policy, approval, Permit, Gateway,
  deployment custody verification, sandbox admission, Worker dispatch, result custody, and Graph
  admission remain separate authorities.
- Each CRYPTO-001A Surface has one unambiguous input/operation/analyzer mapping, preventing a
  protocol or key-use declaration from being relabeled as ciphertext analysis or vice versa.
- The exact Cryptography profile becomes an auditable minimum configuration without proving that
  any deployment conforms to it.
- A supplied authorization digest and digest-derived object/reference coordinates are traceable
  but are not proof that the authorization is authentic, current, in Scope, or applicable to
  retained bytes. The authorization digest is not secret redaction.
- Declaration digests remain unverified external sanitized-input coordinates; preparation cannot
  inspect their preimages or establish safe redaction.
- The code-owned signal vocabulary constrains future result admission but cannot confirm misuse,
  produce a Finding, or authorize execution.
- Zero budgets make key access, cryptographic operations, Oracle calls, network use, plaintext/key
  output, commands, and mutation impossible to request through this contract.
- CRYPTO-001C must add a separate sealed result, independent recomputation or Oracle provenance,
  neutral Observation/Evidence, and bounded Hypothesis admission boundary.
- CRYPTO-001D must add independent replay and seeded vectors without inheriting runtime or truth
  from this preparation contract.

## Rejected alternatives

### Generalize the fixed single-byte XOR CTF Capability

Rejected because its inline synthetic artifact, fixed key search, recovered plaintext/key output,
Worker command, and Oracle are deliberate scenario-specific powers. General analysis must not
inherit them.

### Treat the Surface reference or artifact digest as read authority

Rejected because a reference proves only content identity and a digest proves neither custody nor
authorization. The complete Surface is revalidated, and artifact custody is a separate unverified
deployment input whose runtime checks remain outstanding.

### Let callers select analyzers, rules, or plugins

Rejected because that would allow execution behavior and result semantics to drift independently
of the reviewed Surface class and code identity. Version 1 uses one class-owned mapping and one
code-owned rule vocabulary.

### Include key identifiers, KMS or HSM handles, credentials, or parameters

Rejected because those values create resolution, secret-use, and cryptographic-operation paths.
Key identity and key access require separately reviewed contracts and cannot be inferred from a
key-usage declaration.

### Model decryption, verification, key search, or protocol negotiation as read-only analysis

Rejected because those are cryptographic or target-interaction operations, not static metadata
inspection. Their inputs, outputs, side effects, authorization, and Oracle requirements differ.

### Select a Worker or claim runtime conformance during preparation

Rejected because DOMAIN-004 describes a minimum boundary but does not attest a deployment.
Selection, image/executable admission, non-root confinement, mount materialization, and result
custody require fresh runtime evidence.

### Admit signals or Findings directly from the prepared request

Rejected because preparation contains no result. CRYPTO-001C must bind an authorized sealed
execution and independent recomputation or Oracle evidence before any neutral knowledge is
admitted.

## Compatibility and rollback

CRYPTO-001B is additive and requires no migration. Existing CRYPTO-001A Surfaces, CTF XOR
Capability and runtime, Capability and Tool registries, global DOMAIN-003 inventory, DOMAIN-004
profiles, Artifact readers, Scope, Graph, Worker, and runtime wire formats remain unchanged.

Rollback removes the new Capability module, tests, contract, ADR, and documentation links. New
input kinds, operations, analyzers, signals, result fields, runtime paths, key/credential access,
cryptographic operations, or Oracle behavior require explicit versioned contracts rather than
silent expansion.

## Related documents

- [CRYPTO-001B contract](../capability/CRYPTO-001B-offline-cryptographic-misuse-analysis-capability.md)
- [CRYPTO-001A](../discovery/CRYPTO-001A-protocol-key-usage-ciphertext-configuration-surface-model.md)
- [DOMAIN-003](../capability/DOMAIN-003-domain-aware-capability-inventory-projection.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0018](0018-bounded-ctf-crypto-artifacts.md)
- [ADR-0204](0204-separate-security-domain-from-profile-and-authority.md)
- [ADR-0240](0240-type-cryptographic-analysis-surfaces-without-key-use-authority.md)
