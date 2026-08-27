# APP-001B: Read-only Application Static-analysis Capability

- Status: Implemented, signed preparation and request adaptation only
- Capability: `pajin.application.read-only-static-analysis@1.0.0`
- Tool: `application.read-only-static-analysis@1.0.0`
- Binding API: `pajin.dev/application-static-analysis-binding/v1alpha1`
- Preparation API: `pajin.dev/application-static-analysis-preparation/v1alpha1`
- Custody API: `pajin.dev/application-artifact-custody-binding/v1alpha1`
- Sandbox API: `pajin.dev/application-static-analysis-sandbox-binding/v1alpha1`
- Request API: `pajin.dev/application-static-analysis-request/v1alpha1`
- Output schema: `pajin.application.static-analysis-result.v1`
- Authority: `src/pajin/capabilities/application_static_analysis.py`
- Decision: [ADR-0233](../adr/0233-bind-application-static-analysis-without-artifact-access-authority.md)

## Purpose

APP-001B binds one exact APP-001A typed Surface to a complete signed read-only CAP-002
Capability, the current Campaign Scope, an externally supplied immutable Artifact custody and
authorization reference, one exact logical parser, explicit resource ceilings, and the DOMAIN-004 minimum
Application Worker boundary. It stops at `PreparedCapabilityAction`.

The bounded adapter creates only a secret-free request description. It does not resolve or read
artifact bytes, verify the supplied digest or custody authorization, create a mount, select or
attest a sandbox, materialize a Worker job, invoke a parser, perform a network request, execute the
target, attach a debugger, normalize a result, or produce an Observation, Evidence, Graph
admission, Hypothesis, or Finding.

## Capability, operation, and parser binding

The Capability is experimental, T2, `READ_ONLY`, network-disabled, approval-required, and costs
one request unit. Its complete CAP-002 set binds materializer, action compiler, executor adapter,
result normalizer, success Oracle, Replay strategy, and cleanup handler roles. Worker
materialization and result interpretation fail closed, Replay and cleanup return no plan, and the
Oracle returns `INCONCLUSIVE` because APP-001B creates no runtime result.

Activation accepts only an externally signed current Range release resolved through the existing
Capability lifecycle registry. The static binding pins the complete APP-001A locator registry,
the complete code-backed CAP-002 identity, a local content-addressed Application classification,
the fixed output schema, and `pajin.worker-boundary.application.minimum`. The established global
DOMAIN-003 inventory is unchanged.

Each Surface class has exactly one structure-only operation and parser contract:

| Surface class | Operation | Parser |
| --- | --- | --- |
| `binary` | `binary-metadata-read` | `binary-metadata-parser` |
| `configuration` | `configuration-structure-read` | `configuration-structure-parser` |
| `runtime` | `runtime-metadata-read` | `runtime-metadata-parser` |
| `library` | `library-metadata-read` | `library-metadata-parser` |

The mapping is code-owned. One class cannot use another class's operation or parser. The parser
names identify request contracts only; they do not assert that a parser executable, binary format,
configuration grammar, runtime, dependency graph, or vulnerability detector has been implemented
or successfully invoked.

## Authorized custody reference boundary

`ApplicationArtifactCustodyBinding` is an explicitly supplied, content-addressed configuration
value. It binds:

- the complete exact APP-001A Surface and its caller-supplied artifact SHA-256;
- one bounded deployment custody-authority identifier and opaque object identifier;
- one opaque authorization identifier and lowercase SHA-256 authorization-document digest; and
- the declared artifact-byte count, bounded from 1 through 536,870,912 bytes.

The object identifier cannot be a filesystem path or URL. The binding contains no artifact bytes,
filename, mutable path, repository URL, token, password, credential reference, or private key.
Its authorization reference is deployment input: APP-001B binds it but does not verify the
document issuer, signature, freshness, object existence, content digest, or byte count. Those
checks remain mandatory at a later authorized custody-resolution boundary.

The serialized binding records `authorizationVerifiedByPreparation`, `custodyRuntimeVerified`,
`artifactResolved`, `artifactBytesVerified`, `artifactReadAuthorized`, `mountMaterialized`, and
`executionAuthorized` as false. It is not a replacement for the existing sealed Run
`ArtifactRef`, whose media type and repository semantics describe a different artifact class.

## Network-disabled sandbox boundary

`ApplicationStaticAnalysisSandboxBinding` is also configuration-only and content-addressed. It
binds:

- one deployment ID and the exact DOMAIN-004 Application Worker profile;
- one class-specific operation and logical parser;
- exact parser-executable and sandbox-image SHA-256 digests;
- an explicit run-as identity that rejects root, Administrator, LocalSystem, SYSTEM, UID 0, and
  common qualified variants;
- the fixed sandbox-internal `/pajin/input/artifact` mount target and
  `bounded-json-stdout` output transport;
- the fixed `pajin.application.static-analysis-result.v1` output schema; and
- artifact bytes, output bytes, runtime seconds, memory MiB, and process-count ceilings.

The binding requires a disabled network, read-only root filesystem, read-only no-exec artifact
mount, no-new-privileges, non-root runtime, and exact executable/image digests. Host filesystem
access, credential injection, ambient environment inheritance, symlink traversal, target dynamic
execution, debugger attach, and network access are forbidden.

These values are deployment requirements, not live attestation. `runtimeAttested`,
`sandboxSelected`, `artifactMountMaterialized`, `artifactReadAuthorized`, Worker selection,
runtime-support assertion, and execution remain false. APP-001B defines no container runtime,
sandbox service, executable registry, image registry, or Worker deployment.

## Request and budget boundary

`BoundedApplicationStaticAnalyzerAdapter.prepare_request` requires the custody Surface to equal
the requested Surface, the class-specific operation to equal the sandbox operation, the logical
parser to match the operation, and the declared artifact size to fit the sandbox ceiling. It
creates one `ApplicationStaticAnalysisRequest` with the complete secret-free Surface, exact custody
and sandbox references, non-routable Surface target, `GET`, and the fixed output schema.

The request budget binds one request, the exact declared artifact bytes, and the sandbox's output,
runtime, memory, and process ceilings. It fixes network requests, dynamic target executions,
debugger attaches, artifact writes, host-filesystem reads, and credential reads to zero. The
budget is attenuation-only and unreserved.

No raw artifact content, mutable path, credential material, artifact resolution/read, mount,
sandbox invocation, network access, dynamic execution, or debugger authority can be embedded in
the request. Unknown fields and boolean or integer coercion fail closed.

## Campaign Scope and preparation

Preparation requires the exact non-routable token
`https://application-scope.pajin.invalid/surfaces/<surface-id>` in the current Campaign allow
rules. The token is an identity coordinate in the existing HTTPS Scope wire and is never an
endpoint. Wildcard coverage is insufficient, any matching deny rule rejects preparation, and
`GET` must be present in Rules of Engagement. The Campaign private-network flag is preserved but
cannot enable network access because the Tool, Worker profile, sandbox, request, and budget all
remain network-disabled.

`prepare_application_static_analysis` revalidates the current signed activation, registered
binding, current Campaign projection, exact Surface Scope rule, Surface/custody identity, parser
selection, sandbox configuration, and resource ceilings. It creates a content-addressed
`ApplicationStaticAnalysisPreparation` whose normalized parameters contain only the secret-free
request description.

The preparation records custody verification, authorization verification, artifact resolution,
byte verification and read, sandbox runtime availability and attestation, sandbox and Worker
selection, mount materialization, budget reservation, Worker-job materialization, network
activity, dynamic target execution, debugger attach, artifact mutation, Observation production,
Evidence sealing, Graph admission, Finding production, approval satisfaction, Permit issuance,
Gateway dispatch, and execution as false.

Actual analysis still requires current Policy and Approval, one-use ActionPermit, Gateway policy
re-entry, deployment-owned authorization verification, immutable byte resolution and digest
verification, exact image/executable admission, live non-root sandbox attestation, read-only mount
materialization, bounded output custody, and a sealed result-admission contract. None is supplied
by APP-001B.

## Fail-closed behavior

Definitions, references, activation, Domain classification, static binding, custody, sandbox,
Campaign projection, request, and preparation are exact or content-addressed values. Resolution
and preparation reject Surface/custody substitution, artifact-digest drift, class/operation/parser
substitution, image or executable substitution, root/admin identities, artifact or resource
overflow and integer coercion, missing exact Scope, matching deny rules, absent GET, stale release,
target or method drift, secret/path/runtime-admission field injection, authority-marker escalation,
and boolean coercion.

## Observation, Replay, and benchmark boundary

A prepared request proves neither that custody exists nor that analysis occurred. APP-001C must
separately verify one sealed, authorized, exact-artifact sandbox result before admitting neutral
resource/configuration/runtime/library Observation and Evidence or a bounded Hypothesis.
APP-001D owns deterministic re-analysis, seeded binary/configuration Ground Truth, disposable
sandbox fixtures, metrics, and validation floors. APP-001B creates none of them.

Dynamic target execution, debugger attach, and network access remain outside APP-001 authority.
A later feature requiring any of them needs a separate reviewed Capability and Worker boundary.

## Compatibility and rollback

The implementation is additive. Existing APP-001A, sealed Run Artifact repositories, discovery,
Scope, Capability, Tool, Worker, Graph, and runtime schemas remain unchanged. No file reader,
artifact repository, parser process, sandbox deployment, credential store, or data migration is
added. Rollback removes the additive module, tests, contract, ADR, and consumers; existing typed
Application Surfaces retain their original validity.

## Verification

`tests/test_application_static_analysis.py` covers all seven CAP-002 roles, current signed release
activation, exact APP-001A/Application Worker binding, all four operation/parser mappings,
Surface/custody/operation/parser substitution, custody authorization and artifact digest drift,
network-disabled non-root sandbox requirements, mount/output/resource ceilings, exact Scope,
deny and GET behavior, private-network non-authority, preparation non-authority markers, runtime
fail-closed behavior, inconclusive Oracle, stale release, target/method/digest substitution,
path/secret/runtime-admission injection, authority escalation, and boolean/integer coercion.
