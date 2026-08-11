# ADR-0164: Export Confirmed Findings before External Delivery

## Status

Accepted

## Context

PAJIN has two different SARIF-shaped concerns. Benchmark Scanner Runs retain raw third-party SARIF
as measurement evidence, while product users need a portable projection of PAJIN Findings. Raw
Scanner output is not product Finding authority, and a report or a legacy semantic confirmation is
not equivalent to an independently replay-confirmed Finding. Sending either directly to an Issue
Tracker, SIEM, or SOAR would also combine serialization, secret handling, network mutation,
idempotency, and delivery acknowledgement in one unsafe boundary.

## Decision

### Add a local, deterministic SARIF projection first

UX-006A adds `pajin sarif-export`. The caller must provide one Run directory plus its exact Run ID
and final root digest. The exporter opens the sealed Run, loads the existing versioned validation
projection through its integrity verifier, and accepts only `verified-independent-replay`
semantics. Legacy flat confirmations and `verified-replay-evidence` projections fail closed.

The result is SARIF 2.1.0 with one PAJIN run. Results are ordered by Finding ID; reporting rules are
derived from a domain-separated SHA-256 of the exact threat class and ordered by rule ID. Severity
maps explicitly: `critical` and `high` to `error`, `medium` to `warning`, and `low` and `safe` to
`note`. No generation time is added, so the same exact authority produces identical bytes.

### Bind the projection without granting delivery authority

The SARIF run properties carry the source Run ID, source root digest, canonical confirmed-Finding
set digest, confirmation semantics, and export contract version. Each result carries a digest of
the exact full Finding and a digest of its target. All Issue mutation, SIEM ingest, SOAR action, and
delivery-receipt authority markers are fixed to `false`, and `externalDeliveryPerformed` is false.

This local file is not a delivery receipt. A later connector must separately define a configured
sink identity, secret lease, payload digest, idempotency key, network policy, response
authentication, durable delivery receipt, retry rules, and reconciliation state.

### Minimize sensitive source fields

The result includes reviewed title, summary, severity, threat class, confidence, affected
component, impact, and remediation. It excludes raw target, root cause, reproduction steps, and
evidence paths/content. The target is represented only by a digest. Display text is NFC-normalized,
bounded, and rejects unsafe Unicode control/format characters. Finding IDs must be portable.

The exporter accepts at most 1,000 Findings, limits the canonical Finding set and final SARIF to 16
MiB, and applies per-field and remediation-count bounds. It writes a private file atomically,
rejects symbolic-link destinations, rereads the exact bytes, checks the output digest, and refuses
to write inside the immutable source Run.

## Consequences

- Product SARIF cannot be confused with raw Scanner measurement evidence.
- An exact verified source can be exported repeatedly without duplicate network effects.
- Consumers receive a useful but intentionally minimized Finding projection; evidence and precise
  target disclosure require a separate approved policy.
- The local file remains sensitive security-report material and must be protected by the operator.
- No external delivery, issue creation, alert ingestion, automation action, retry, or receipt is
  implemented in this slice.

## Rejected alternatives

### Export raw Scanner SARIF

Rejected because Scanner evidence has benchmark-provider semantics and is not the canonical PAJIN
Finding/validation authority.

### Export legacy confirmed Findings

Rejected because legacy semantic validation and replay evidence without independent execution
attestation do not satisfy the product confirmation boundary.

### Send directly to an external service

Rejected for this slice because serialization success does not prove authenticated, idempotent
delivery. A connector needs its own durable authority and secret/network trust boundary.

### Write the export into the source Run

Rejected because a standalone derivative would mutate the immutable Run layout and invalidate the
meaning of its existing root digest.

## Compatibility and rollback

The module and CLI command are additive. Existing Run, validation, report, Scanner SARIF, Control
Plane API, and database schemas do not change; no migration is required. Rollback removes the
command, module, tests, and documentation. Already created standalone SARIF files remain ordinary
operator-owned files and carry no PAJIN delivery state.

## Related documents

- [UX-006A contract](../orchestration/UX-006A-verified-finding-sarif-export.md)
- [ADR-0027](0027-independent-reproduction-confirmation-boundary.md)
- [ADR-0097](0097-run-concrete-zap-baseline-with-raw-sarif.md)
