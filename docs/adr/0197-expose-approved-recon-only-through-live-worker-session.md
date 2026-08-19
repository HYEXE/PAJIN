# ADR-0197: Expose Approved Recon Only through a Live Worker Session

## Status

Accepted

## Context

PENTEST-004A gives operators a strict, content-addressed compilation artifact, while PENTEST-001C2
already performs one approved GET under current activation, Graph, approval, Permit, Worker mTLS,
egress, receipt, and Run-audit authority. The remaining gap is operational: C2 is direct-call only.

A local CLI cannot safely turn certificate JSON or a serialized `WorkerMTLSAdmission` into the live
direct-mTLS evidence required by C2. A generic queued Job also cannot carry the original ASGI TLS
scope into a later Worker process without defining a new transport-bound delegation authority.

## Decision

### Add a digest-pinned deployment loader

Define one strict deployment inventory that names the exact 004A artifact and raw evidence paths,
current authorization trust anchor and subject, signed lifecycle inventory and activation, Graph
Decision, proposal, external approval, Worker mTLS policy, Graph database, Run root, Worker image,
and Permit TTL. Require an external file SHA-256 at Control Plane startup and require the embedded
Worker policy to equal the separately configured server policy.

The loader reconstructs code-owned CAP-002 adapters and verifies external signed releases. It opens
the existing Graph Permit store and pins the provided approval as input authority. It does not
generate a lifecycle key, release, Decision, proposal, approval, or certificate.

### Rebuild the 004A authority before creating the gate

Strict-load the artifact, reread the raw evidence, and compile again with the deployment's current
trust anchor and independently selected expected subject at the original approved timestamp. The
whole authority must equal the artifact. Then let PENTEST-001C2 repeat its normal reconstruction at
both sides of Permit consumption.

### Invoke C2 only inside the authenticated Worker route

Add a Worker-only route whose request contains only deployment, compilation, intent, and approval
identifiers. Reuse the Control Plane Bearer dependency and live direct-mTLS authentication, then
pass the actual ASGI TLS scope and authenticated Worker Principal into C2. Do not accept a Principal,
certificate, TLS admission, target, Decision, approval, or release from the request body.

Add an HTTPS/mTLS CLI client that strict-loads the local 004A artifact before sending its digest.
Read the Worker Bearer secret from a named environment variable. The command runs from the separated
Worker/Gateway environment; the human operator's authority remains the external approval pinned in
the deployment.

### Seal terminal attempts without enabling retry

Seal successful terminal evidence. If an attempted callback writes a failure or cancellation audit,
seal that terminal attempt before returning failure. Exact retries return the existing durable
receipt with no callback and verify the existing seal.

## Consequences

- Operators gain an installed path from a 004A artifact to one actual C2 dispatch.
- The CLI and HTTP request remain non-authoritative selectors; startup deployment, current trust,
  Graph, approval, Permit store, and live Worker session remain present.
- Missing deployment configuration leaves the route closed with 503.
- Exact retry and failed first attempts cannot produce a second network request.
- The current process hosts the Docker Gateway. Generic distributed Worker execution is unchanged
  and does not receive a serializable substitute for live mTLS.
- This milestone still provides only HTTP GET Recon, not an automated LLM/Web/System pentest suite.

## Rejected alternatives

### Accept certificate or Worker admission JSON in the CLI

Rejected because serialized certificate material does not prove a live TLS connection and C2
explicitly treats `WorkerMTLSAdmission` as non-bearer audit evidence.

### Generate lifecycle, Graph, or approval authority during CLI execution

Rejected because the executor would become its own authorization and approval issuer.

### Put the C2 intent into an ordinary queued Campaign Job

Rejected for this slice because the generic Worker executes after the claim request has ended and
cannot receive the original live TLS scope without a new one-use, transport-bound delegation
contract. That distributed protocol requires a separate ADR.

### Trust the 004A artifact without raw evidence and current trust

Rejected because revocation, evidence, subject, and trust-anchor drift must fail before Permit
consumption.

## Compatibility and rollback

All changes are additive and opt-in. Unconfigured deployments preserve existing Control Plane and
Worker behavior. The PENTEST-004A and PENTEST-001C2 wires and the Graph database schema are
unchanged. Removing the route and deployment loader restores the direct-call boundary without
invalidating existing artifacts.

## Follow-up work

- PENTEST-004C composes independently authorized Replay, Controls, Finding projection, and report.
- REDTEAM-001 adds registered executable LLM, Web, RAG, MCP, browser, and system Capabilities.
- A distributed Worker design must define a transport-bound, single-use delegation instead of
  serializing mTLS admission.

## Related documents

- [PENTEST-004B contract](../orchestration/PENTEST-004B-approved-recon-operator-entrypoint.md)
- [ADR-0196 compilation entrypoint](0196-expose-pentest-compilation-without-execution-authority.md)
- [ADR-0174 approved one-shot Recon](0174-compose-approved-pentest-recon-without-legacy-campaign.md)
