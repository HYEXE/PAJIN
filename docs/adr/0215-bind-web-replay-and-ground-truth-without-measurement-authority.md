# ADR-0215: Bind Web Replay and Ground Truth without Measurement Authority

## Status

Accepted

## Context

WEB-001C admits one neutral GET Recon Observation through the existing PENTEST-002A producer and
Canonical Graph writer. It intentionally cannot authorize Replay. PENTEST-002B already implements
the required fresh approval, one-use ActionPermit, dedicated Worker session, sealed source/replay
verification, and body-free comparison. Reimplementing that path for the Web Domain would create a
parallel authority model.

PAJIN also already has a Traditional Web/API P0-D1 Target catalog and private code-owned Boolean
SQLi Ground Truth. That matcher is specific to receipt-bound Docker benchmark evidence. A generic
GET response match cannot truthfully satisfy that Ground Truth or become a benchmark score.

## Decision

Add two content-addressed WEB-001D projections.

The first reopens a sealed PENTEST-002B comparison and exact-binds it to the complete WEB-001C
admission, concrete URL and GET method, and DOMAIN-006 Web `independent-replay` plan. It records
whether the response coordinates matched, but creates no new execution authority and does not
claim Ground Truth, measurement, Finding, or Profile-floor satisfaction.

The second reconstructs the exact P0-D1 private Ground Truth, catalog, and public registration from
one provisioned Docker profile and binds them to the DOMAIN-006 Web plan. It remains
`registered-ground-truth-not-measured`; no Manifest, Target selection, provider execution,
measurement, Replay-to-case match, or Finding authority is created.

Do not combine the two projections into a synthetic benchmark result. A future measurement
consumer must bind the exact Target coordinate, matcher-specific raw observation, sealed evidence,
and metric admission independently.

## Consequences

- The Web first slice reuses the existing independent Replay and Ground Truth abstractions rather
  than creating another executor, ledger, matcher, or benchmark engine.
- The source ActionPermit and Graph admission remain provenance only. Replay retains its separate
  approval, Permit, receipt, Run, and Worker identities.
- Replay drift is represented honestly as a completed independent Replay with a changed response,
  not hidden or promoted to a Finding.
- P0-D1 Ground Truth gains an exact DOMAIN-006 Web projection without becoming public or runnable.
- WEB-001D does not publish detection recall, false-positive, precision, cost, evidence, policy, or
  replay-success benchmark values.

## Rejected alternatives

### Let WEB-001C authorize its own Replay

Rejected because discovery and Graph admission cannot create action authority. Replay requires a
fresh current Decision, approval, one-use Permit, and dedicated Worker session.

### Treat a matching GET response as the SQLi Ground Truth result

Rejected because the P0-D1 matcher requires exact Docker provider evidence and registered
Finding/Surface/count semantics. Response stability alone has no vulnerability meaning.

### Extend BENCH-001 or DOMAIN-006 wire formats

Rejected because both are compatibility boundaries. DOMAIN-006 registers requirements only, and
BENCH-001 measurement still requires admitted raw evidence and Target lifecycle authority.

## Compatibility and rollback

The new models and builders are additive. Existing WEB, PENTEST, BENCH, P0-D1, DOMAIN, Graph,
Permit, Worker, Replay, validation, and Finding objects remain unchanged. Rollback stops producing
the projections and preserves historical sealed and content-addressed sources.

## Related documents

- [WEB-001D contract](../benchmark/WEB-001D-independent-web-replay-ground-truth.md)
- [WEB-001C contract](../graph/WEB-001C-sealed-web-discovery-graph-admission.md)
- [PENTEST-002B contract](../orchestration/PENTEST-002B-independently-authorized-recon-replay.md)
- [P0-D1 contract](../benchmark/P0-D1-traditional-web-api-target-catalog.md)
- [DOMAIN-006 contract](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
- [ADR-0176](0176-replay-pentest-recon-under-independent-action-authority.md)
- [ADR-0211](0211-register-domain-metrics-without-measurement-authority.md)
- [ADR-0214](0214-compose-web-knowledge-through-existing-graph-writer.md)
