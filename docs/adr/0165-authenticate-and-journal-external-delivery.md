# ADR-0165: Authenticate and Journal External Delivery

## Status

Accepted

## Context

UX-006A creates deterministic, minimized SARIF bytes from independently replay-confirmed Findings,
but intentionally grants no external side-effect or receipt authority. Sending those bytes directly
from a CLI or request handler would let untrusted request data choose a sink, mix secret access with
serialization, and make a timeout indistinguishable from safe non-delivery. Retrying such an unknown
outcome could create duplicate issues or alerts even when an idempotency key is present.

PAJIN therefore needs a separate boundary that binds exact payload authority, deployment-owned sink
identity, external authorization, one-use secret release, a pre-dispatch durable claim,
authenticated acknowledgement, and bounded reconciliation before it can claim external delivery.

## Decision

### Keep sink and authorization authority outside request data

A content-addressed `ExternalDeliverySink` is supplied through a deployment-owned registry. Its
mutating and reconciliation endpoints are exact credential-free HTTPS URLs on one origin. HTTP,
redirects, ambient proxies, endpoint queries, userinfo, fragments, and cross-origin reconciliation
are rejected by the provided transport and model boundary.

An `ExternalDeliveryIntent` binds the exact UX-006A source Run/root/Finding set, SARIF digest and byte
count, and sink digest. Its domain-separated digest determines both the intent ID and stable
idempotency key. A separate `ExternalDeliveryAuthorizationAuthority` must authenticate an exact,
time-bounded authorization for that intent, payload, sink, idempotency key, two-attempt ceiling, and
reconciliation policy. The included registry is only a process-local allowlist adapter; it is not a
new approval issuer.

### Release secrets only through exact one-use leases

The coordinator accepts only a live `SecretBroker` lease with the registered sink as audience, the
source Run as scope, one remaining use, and a binding over the intent digest, operation, and attempt
ordinal. Lease metadata is checked before the journal claim; secret material is materialized only
after the mutating attempt is durably recorded. Secret values never enter persistent delivery
models or journal rows.

The first connector contract uses the same brokered value for bearer request authentication and
HMAC-SHA256 response authentication. Splitting request and response keys is a compatible future
contract version, not an implicit behavior of this version.

### Record intent before side effects and attempts before dispatch

A dedicated SQLite journal stores canonical immutable intent and authorization bytes. Append-only
triggers reject update and delete operations, and every event participates in a verified digest
chain. Schema identity, database metadata, file identity, sidecars, canonical model bytes, event
order, and state transitions are revalidated on each operation.

The state begins at `ready-initial`. `dispatch_once` changes it durably to
`dispatch-started-outcome-unknown` before releasing a secret or invoking the transport. Any failure
after that claim remains unknown and never causes automatic retransmission.

### Reconcile unknown outcomes before one bounded retry

Reconciliation is read-only at the sink and uses the same idempotency key. A canonical JSON response
must bind the intent, sink, payload, key, and attempt, and its domain-separated content digest must
have a valid HMAC-SHA256 signature. Authenticated acceptance creates a durable local receipt without
redispatch. Authenticated `not-received` after attempt 1 permits one explicit second dispatch using
the same key. Authenticated `not-received` after attempt 2 is terminal. No third attempt exists.

An accepted receipt proves endpoint acceptance of the exact payload. It explicitly keeps
`downstreamActionAttested=false`; vendor-specific issue creation, SIEM indexing, or SOAR execution
requires separate semantic evidence.

## Consequences

- Payload, sink, authorization, secret, attempt, response, and receipt identities cannot be swapped
  independently without failing closed.
- A crash or network ambiguity cannot trigger automatic duplicate delivery.
- A successful authenticated reconciliation can recover an accepted outcome without retransmission.
- Operators receive a bounded, inspectable state machine with an explicit terminal outcome.
- The host-local journal and process-local registries do not provide distributed exactly-once
  delivery, failover, registry refresh, or backup.
- The journal hash chain is not an external transparency anchor and cannot resist replacement by a
  privileged host administrator.
- Authorization expiry can prevent reconciliation of an unknown outcome and requires deployment
  intervention.
- DNS/IP egress policy and private-network blocking remain deployment responsibilities beyond the
  HTTPS origin checks in this slice.
- No caller-facing CLI or Control Plane mutation endpoint is added until deployment wiring can keep
  registries, secrets, and journal ownership outside untrusted request data.

## Rejected alternatives

### Treat HTTP success as a delivery receipt

Rejected because transport status alone is not authenticated application acknowledgement and is not
bound to the exact intent or idempotency key.

### Retry automatically after timeout

Rejected because the first attempt may have succeeded remotely even when its response was lost.
Automatic retry would turn an unknown outcome into a possible duplicate side effect.

### Let callers provide arbitrary sink URLs and secret references

Rejected because that would create SSRF and secret-confusion authority in request data. Sinks and
authorizations must be registered deployment inputs.

### Store delivery state inside the source Run

Rejected because the sealed source Run is immutable and its root digest is Finding authority.
Delivery is derivative host-local operational state with a distinct lifecycle.

### Claim downstream issue, SIEM, or SOAR success from endpoint acceptance

Rejected because generic acceptance cannot attest vendor-specific semantic effects.

## Compatibility and rollback

The change is additive and uses a separate journal. Existing Run, SARIF, validation, benchmark,
Control Plane, and database contracts do not change. Rollback removes the connector module, tests,
and documentation. An existing delivery journal must be retained for audit and reconciliation; it
must not be silently discarded merely because the code is rolled back.

## Related documents

- [UX-006B contract](../orchestration/UX-006B-authenticated-external-delivery.md)
- [UX-006A contract](../orchestration/UX-006A-verified-finding-sarif-export.md)
- [ADR-0164](0164-export-confirmed-findings-before-external-delivery.md)
- [ADR-0008](0008-provider-gateway-and-secret-leases.md)
