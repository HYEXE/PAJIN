# ADR-0299: Bind Governed Local Browser Execution to Independent Evidence

- Status: Accepted and locally implemented
- Date: 2026-09-14
- Scope: WEB-005 governed authenticated browser execution for an approved local lab

## Context

WEB-003 established a deliberately narrow browser assessment of an exact numeric-loopback OWASP
Juice Shop origin. WEB-004 added passive discovery, extra diagnostics, strict sealed-source loading,
local comparison, and Graph proposals, but intentionally stopped before a core Campaign,
deployment-pinned Capability activation, ActionPermit consumption, Gateway dispatch, Graph
admission, Finding promotion, SARIF export, or external delivery.

Those boundaries cannot be completed by changing WEB-004's false authority markers to true. Its
`pajin.bug-bounty.web-browser-assessment` version `1.0.0` release is registration-only,
`irreversible-write`, cleanup-required, and inert. Its local comparison says only
`local-corroborated`; a second Run by the same ungoverned caller is not independent replay evidence.

The local target also creates a routing constraint. A numeric host-loopback service is not the same
network endpoint from inside a Docker container. Invoking a host browser outside the Gateway would
solve reachability by bypassing the execution authority. Treating a host subprocess as a normal
Docker Worker or claiming a trusted egress-proxy receipt would instead overstate the isolation and
network evidence that actually exist.

WEB-005 therefore needs an additive execution path that preserves the existing Campaign,
Capability, approval, Permit, Gateway, Run, Graph, validation, and reporting authorities while
stating exactly what the local host backend can and cannot prove.

## Decision

### Add a new executable authority identity

WEB-005 uses a distinct signed Capability release, activation, Tool binding, ID, and digest. It does
not activate, reinterpret, or migrate the WEB-004 version `1.0.0` registration-only object. Older
Run and draft readers retain their current meaning, and no historical false authority marker is
upgraded in place.

The executable release remains scoped to one exact canonical numeric-loopback origin and one
deployment-installed code implementation. The first installed implementation is the code-owned
OWASP Juice Shop recipe. A versioned adapter schema may describe other exact HTTP or HTTPS origins,
but schema generality is not evidence that an arbitrary application is supported.

### Bind execution to signed deployment inventory

A deployment publisher signs an immutable `WebAssessmentAdapterManifest`. The manifest binds the
adapter identity and version, exact origin, implementation and recipe digests, exact method set,
authentication-state class, side-effect class, expiry, and negative authority flags. The registry
accepts only installed, current, correctly signed adapters whose implementation and recipe digests
match code present in the deployment.

Links, forms, routes, selectors, field names, response content, model output, CLI input, and Run
artifacts cannot create or widen adapter authority. Discovery remains observation. Any future form
submission needs a separately reviewed code-owned recipe, correct side-effect classification, and
fresh governed authority.

### Provision the disposable account outside the read-only Capability

Account creation occurs before Capability execution under its own exact local-lab authorizations.
An account issuer signs a short-lived, content-addressed `ProvisionedWebAccountReceipt` that binds
the adapter, origin, account-reference digest, provisioning-evidence digest, target-identity digest,
and two distinct authorization IDs. The receipt says that the account already exists and that
account creation is not authorized by the browser Capability.

The receipt is secret-free. Account identity, proof material, and Worker signing material remain in
deployment-owned secret storage and reach a prepared Worker only through one-use SecretBroker
leases and an ephemeral stdin pipe. They are forbidden in Tool arguments, command-line arguments,
environment variables, Run artifacts, Graph nodes, reports, SARIF, PoC files, stdout, and stderr.

### Require the full Campaign, lifecycle, approval, Permit, and Gateway path

The executable Tool accepts only a deployment-resolved adapter reference and account-receipt
reference already bound to the core `CampaignManifest`, exact Campaign Scope, signed active
Capability release, and current Capability Grant. Caller-authored routes, selectors, payloads,
headers, credentials, and artifact paths are not Tool parameters.

Source and validation are separately authorized legs. Each leg has one current one-use Gateway
dispatch binding, and its specialized backend runs a separate target-observer job followed by a
separate executor job. Source and validation therefore use two Gateway dispatches and four fresh
subprocess jobs. Each leg has fresh approval consumption, ActionPermit, Tool request, Gateway
request, and Worker request identities; an authority or binding consumed by either leg cannot be
replayed by the other.

The Gateway re-enters policy, resolves the registered Tool, materializes bounded secret leases, and
dispatches only the exact prepared Worker job. A successful Worker exit without the matching
Campaign, release, activation, Grant, approval, consumed Permit, Gateway outcome, and dispatch
binding is not governed execution evidence.

### Use a truthful host-loopback Worker boundary

The specialized `host-loopback-browser` backend exists only because the approved target is bound to
the host's numeric loopback interface. It launches each observer or executor as a fresh, no-shell,
code-owned Python subprocess with a sanitized environment, bounded stdin/stdout/stderr, a deadline,
an exact output root, and exact-origin application-layer request gates. The parent observes and
checks the process ID and lifecycle before accepting its signed output.

This backend is Gateway-dispatched, but it is not a Docker or OCI isolation boundary. It does not
provide a host-observed egress-proxy log, so an empty network log is not a trusted proxy receipt.
Its effective network control is the reviewed application-layer gate plus the exact Gateway policy.
Production or non-loopback use still requires an appropriate isolated Worker and independently
observable network enforcement.

### Require independently signed source, replay, and target evidence

Deployment-owned Ed25519 trust inventory separates target-observer, source-executor, and
validation-executor signing roles. The source and validation observer jobs use distinct keys even
though they have the same observer role. The target identity is a deployment-observer statement
over a bounded live fingerprint response; it is not a claim signed by the target application.

Finding promotion requires four distinct subprocess IDs, signing key IDs, and execution IDs: a
source observer and executor plus a validation observer and executor. The two assessment legs also
have distinct authorization IDs, approval and Permit identities, Gateway and Worker requests,
sealed Run IDs, Run roots, Result digests, and execution-attestation digests. Each leg carries its
own target-observer attestation; the two attestation digests are distinct while both bind the same
exact approved target-identity digest. Reusing one target attestation may support execution
provenance, but it cannot satisfy independent Finding promotion.

Every signature, key role, key lifecycle, authority binding, timestamp order, target fingerprint,
and sealed Run pin is verified before the evidence can claim `verified-independent-replay`.
Distinct local processes and keys reduce accidental evidence reuse; they do not prove different
machines, organizations, operators, kernels, or failure domains.

### Promote only positive, code-owned semantics

Both sealed Runs are independently reloaded by caller-pinned Run ID and root digest. Their plan,
authorization, origin, target version, Result digest, screenshot references, artifact inventory,
events, and seal are verified before typed semantic reconciliation.

The reconciliation label `local-corroborated` is necessary but not sufficient. An issue can become a
Finding only when both source and validation statuses are exactly `locally-reproduced`. An attack
path can become a confirmed path only when both path statuses are exactly `locally-validated`, each
diagnostic stage references a known issue, and the issue and stage states agree. A code-owned
observed-context stage may omit an issue reference. `not-reproduced`, `locally-not-validated`,
`inconclusive`, missing, unlinked diagnostic, or internally inconsistent material never becomes a
Finding or confirmed path.

Finding titles, severity, CWE, observed impact, potential impact, root cause, remediation, and path
narratives are derived from, or checked against, code-owned metadata for the exact diagnostic.
Matching free-form strings in two Runs are not independent semantic evidence. Negative outcomes
cannot carry caller-authored success language into a promoted Finding or report; WEB-005 ignores
that prose and rebuilds every promoted narrative from code-owned semantics.

### Admit Graph facts and export only after verified promotion

Only verified promotion material can be submitted to the existing Graph admission authority.
Admission records the exact ActionPermit-bound Action, Surface, Hypotheses, Observation, Evidence,
and confirmed Finding campaign facts through registered producer and trusted lineage identities.
Producing a proposal is not admission, and a rejected admission cannot be reported as success.

The validation Run uses the existing two-seal `validation/v1alpha1` contract and
`verified-independent-replay` semantics. Deterministic Markdown, local SARIF 2.1.0, and a redacted
executable PoC bundle are downstream projections of that verified snapshot. The PoC contains the
exact origin, adapter reference, and governed CLI invocation, but no credential, token, cookie,
private key, destination, raw response body, or target mutation.

External delivery remains a separate authenticated and explicitly authorized coordinator action.
The local command accepts no destination and produces only a delivery-readiness manifest with
`externalDeliveryPerformed=false` when no distinct delivery record is supplied.

## Consequences and limitations

- The implemented adapter protocol is versioned, but the initial runnable inventory supports only
  the exact local OWASP Juice Shop recipe. It is not a universal authenticated web scanner.
- The supported target remains canonical numeric loopback. `localhost`, IPv6 loopback, other private
  networks, arbitrary Internet origins, redirects, and caller-selected ports are outside this slice.
- The host-subprocess backend does not claim container, VM, user-namespace, kernel, or trusted
  egress-proxy isolation. Its network log is not authoritative.
- Browser credentials and signing keys are not persisted, and each browser is closed. The target's
  server-side session may remain valid until its own expiry because WEB-005 does not add target
  session revocation.
- Disposable accounts are retained. Account deletion and cleanup are different mutating actions and
  are not authorized by this read-only assessment Capability.
- Distinct local keys and subprocesses establish contract-level separation, not organizational or
  host-failure-domain independence.
- Preflight and postflight compare an exact bounded fingerprint, but cannot exclude a transient
  same-origin target swap that restores the same fingerprint before postflight. A stable process or
  TLS identity is required before extending this design beyond the approved local lab.
- The PAJIN coordinator process is a trusted control boundary. In-process arbitrary-code execution,
  module-global monkeypatching, debugger access, or reflective extraction of private signing
  material is controller compromise, not an untrusted adapter or artifact input supported here.
- No external report submission, disclosure-platform mutation, ticket creation, email, upload, or
  publication is authorized by this decision.
- The Graph and Grant checkpoints are enrolled only in the caller-owned host-local output root. If
  the same UID deletes or rolls back that root and its enrollment markers together, a separately
  retained OPS-005 witness is still required to prove or reconstruct the loss.
- A crash after a database-checkpoint event append but before its dedicated parent seal fails
  closed, but the current torn prefix cannot be extended with a verified terminal failure journal
  and is never automatically redispatched.

## Compatibility, migration, and rollback

This decision is additive. WEB-003 Run artifacts, WEB-004 local drafts and observations, the
registration-only version `1.0.0` Capability, existing Graph wires, public Finding models,
`validation/v1alpha1`, and SARIF readers keep their existing meanings.

Migration consists of installing the new signed adapter, issuer and Worker trust registries,
executable Capability release and activation, Tool binding, and CLI coordinator. No historical Run
or authority object is rewritten. Consumers must select the new API versions explicitly.

Rollback removes the WEB-005 CLI entry point and its deployment inventory and disables the new
release. Existing sealed Runs, consumed approvals and Permits, Graph admission events, validation
snapshots, SARIF files, and PoC bundles remain immutable evidence. Rollback never reclassifies them
as WEB-004 local-only output or restores consumed authority.

## Rejected alternatives

- Activating or weakening the WEB-004 version `1.0.0` registration-only Capability.
- Letting the CLI, browser discovery, an LLM, or a Run supply executable routes, selectors, or
  payloads.
- Supplying credentials directly to a Tool, Worker job, artifact, environment, or report.
- Using one approval, Permit, dispatch binding, observer or executor process, signing key, sealed
  Run, or target attestation for both source and validation promotion.
- Treating equal `local-corroborated` results, including equal negative results, as confirmed
  Findings.
- Trusting matching free-form impact or remediation prose without code-owned re-derivation.
- Treating a target self-description as deployment-observed target identity.
- Calling the host subprocess a Docker Worker or its empty network log a trusted proxy receipt.
- Sending SARIF or a report externally without a separate destination-bound delivery authorization
  and receipt.

## Local verification evidence

The complete exact-origin CLI ran against the explicitly authorized OWASP Juice Shop `19.2.1`
target. Parent Run `run_20260915T053508Z_00f5d91c` binds two distinct Gateway Runs, source Run
`run_20260915T053508Z_dc97107d`, validation Run `run_20260915T053508Z_da341040`, four distinct
observer/executor process, key, and execution identities, and validation projection Run
`run_20260915T053508Z_c274888d`. All four signatures verified, both UI login phases emitted exactly
one login POST, and both browser Runs closed without persisting credentials or reusable session
material.

Promotion admitted nine Graph events, three Finding facts, three confirmed Findings, and two
confirmed attack paths under `verified-independent-replay`. A fresh process strictly reloaded the
parent and all referenced Runs, databases, validation artifacts, report, canonical SARIF, exact PoC
inventory and permissions, and delivery-readiness manifest. The redacted PoC script then reproduced
the full flow in a new root and its parent Run `run_20260915T054048Z_8111d682` also strictly
reloaded with the same counts. No external delivery occurred; disposable accounts and target-side
sessions remain because cleanup was not authorized.

Exact identities, roots, digests, artifact paths, limits, and repository verification commands are
recorded in [WEB-005](../orchestration/WEB-005-governed-local-authenticated-browser-campaign.md) and
the current `HANDOFF.md` checkpoint.
