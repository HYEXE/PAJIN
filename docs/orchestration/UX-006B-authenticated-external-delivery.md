# UX-006B: Authenticated External Delivery

- Status: Implemented and verified
- Decision: [ADR-0165](../adr/0165-authenticate-and-journal-external-delivery.md)
- Sink contract: `pajin.dev/external-delivery-sink/v1alpha1`
- Intent contract: `pajin.dev/external-delivery-intent/v1alpha1`
- Authorization contract: `pajin.dev/external-delivery-authorization/v1alpha1`
- Receipt contract: `pajin.dev/external-delivery-receipt/v1alpha1`
- Record contract: `pajin.dev/external-delivery-record/v1alpha1`

## Scope

UX-006B delivers the exact bytes produced and reverified by UX-006A to one deployment-registered
Issue Tracker, SIEM, or SOAR HTTPS endpoint. It adds a programmatic connector boundary; it does not
add a caller-configurable CLI or Control Plane mutation endpoint. Deployment code must provide the
sink registry, authorization verifier, `SecretBroker`, durable journal path, and transport.

A request is accepted only when all of these exact values agree:

- source Run ID, final root digest, and confirmed-Finding-set digest;
- SARIF SHA-256 and byte count;
- content-addressed sink ID and digest;
- deterministic intent ID and `pajin-delivery-<intent-digest>` idempotency key;
- separately registered authorization ID and active validity interval;
- one-use secret lease audience, source-Run scope, operation, and attempt ordinal.

The source Run and SARIF projection are reverified before registration, dispatch, and
reconciliation. Stale roots, changed exports, unregistered sinks or authorizations, cross-sink
substitution, and mismatched leases fail before an outbound side effect.

## Sink and network policy

A sink is deployment-owned and content-addressed. Delivery and reconciliation endpoints must be
credential-free ASCII HTTPS URLs on the same exact scheme, host, and port. Userinfo, query strings,
fragments, HTTP, and cross-origin reconciliation are rejected. The provided production transport
disables ambient proxies and redirects, sends `Connection: close`, applies a bounded timeout, and
limits authenticated JSON responses to 64 KiB.

The sink declares bearer request authentication and HMAC-SHA256 response authentication. The
`SecretBroker` releases the bearer/HMAC value only through a live one-use lease bound to the exact
intent operation and attempt. Secret values are never written to the journal, intent, receipt, or
request log structures owned by this module.

## Durable state machine

The host-local SQLite journal stores immutable canonical intent and authorization bytes plus an
append-only, hash-chained event sequence. Triggers reject update or delete operations. Every
mutating dispatch is durably claimed before the secret is materialized and before the network call.

```text
ready-initial
  -> dispatch-started-outcome-unknown
     -> delivered
     -> ready-retry                (authenticated not-received, attempt 1 only)
        -> dispatch-started-outcome-unknown
           -> delivered
           -> terminal-not-delivered
```

A timeout, connection failure, invalid HTTP status, malformed response, mismatched response, or bad
signature after a dispatch claim leaves the state as `dispatch-started-outcome-unknown`. The
coordinator never retransmits automatically. The operator must reconcile the same idempotency key.
Only an authenticated `not-received` response for attempt 1 creates one explicit retry opportunity;
attempt 2 is terminal when also authenticated as not received. The idempotency key never changes.

## Response and receipt authority

The sink response must be canonical JSON bound to the exact intent ID, sink ID, payload digest,
idempotency key, and attempt ordinal. Its content digest is authenticated with HMAC-SHA256. An
`accepted` response also carries a bounded external receipt ID and timezone-aware acceptance time.

A local delivery receipt is created only from that authenticated acceptance and binds the exact
intent, authorization, sink, source Run/root/Finding set, payload, idempotency key, attempt, and
response digest. It sets:

- `externalDeliveryPerformed=true`;
- `deliveryReceiptAuthority=true`;
- `downstreamActionAttested=false`.

The receipt proves that the configured endpoint authenticated acceptance of the exact payload. It
does not prove issue creation semantics, SIEM indexing, SOAR execution, notification delivery, or
any other downstream action.

## Failure behavior

| Condition | Result |
| --- | --- |
| Stale source, payload, sink, intent, or authorization | fail before dispatch |
| Invalid, expired, wrong-audience, reused, or wrong-binding lease | fail before dispatch claim |
| Failure after durable attempt claim | outcome unknown; reconciliation required |
| Forged, malformed, oversized, or cross-intent sink response | fail closed; no receipt |
| Authenticated accepted reconciliation | durable delivered receipt; no redispatch |
| Authenticated not-received after attempt 1 | one explicit retry permitted |
| Authenticated not-received after attempt 2 | terminal not delivered |
| Journal schema, chain, canonical bytes, or file identity differs | fail closed |

## Known limits

- Sink and authorization registries are process-local deployment inputs, not distributed registries.
- The SQLite journal is single-host authority and does not provide multi-host exactly-once delivery,
  replication, backup, or disaster recovery.
- The hash chain detects invalid state transitions but is not an external transparency anchor and cannot
  prevent replacement by a privileged host administrator.
- Request bearer authentication and response HMAC currently share one brokered secret value.
- HTTPS validates the platform trust chain, but DNS/IP allowlisting and private-network egress policy
  remain deployment responsibilities.
- Authorization must remain active for dispatch and reconciliation; expiry can leave an unknown
  outcome requiring deployment intervention.
- There is no generic CLI, Control Plane write API, scheduled retry worker, or vendor-specific
  Issue/SIEM/SOAR semantic adapter in this slice.

## Compatibility and completion

The module is additive. It changes no existing Run, validation, SARIF, Control Plane, or benchmark
schema. Completion requires accepted, outcome-unknown, authenticated reconciliation, single retry,
terminal second failure, forged response, wrong lease, stale/cross-sink substitution, unsafe URL,
journal tamper, and unregistered authorization tests; focused Ruff, format, strict mypy, adjacent
regressions, and documentation consistency checks.
