# ADR-0283: Verify OPS and System on Separate Clean Linux Workflows

Status: Accepted; exact-commit remote execution requires separate approval and observed results.

## Decision

Create independent manual OPS-003 and SYS-002 workflows around the existing actual Linux probes.
Require the approved full SHA, clean checkout, hosted Ubuntu 24.04 runner, locked dependencies,
source-built Linux/amd64 image IDs and an empty owned-resource inventory before execution.

A private marker binds cleanup admission to the boundary, commit, source digest, workflow Run and
attempt. Failed execution still runs cleanup and a separate read-only residue audit. Preexisting
resources prevent admission; discovery cannot grant cleanup authority on a shared/local host.
Fallback removal does not convert a native cleanup failure into success. Verify actual probe
checks, not workflow registration or a skipped pytest. Upload only explicit public summaries.

Keep existing Web/Network/AI selection requirements intact and add separate operational fields.
Broad common changes select all five workflows. Selection does not authorize remote execution.
Record every attempt and require the same new commit for ordinary CI and each selected boundary.

## Limits

Disposable-container shutdown and recovery do not model physical host failure, power loss,
production failover or arbitrary System support. Secrets, database dumps and deployment inventories
are private evidence. New workflow definitions alone are not successful remote conformance.

## Linux fixture portability addendum (2026-09-11)

The first hosted OPS probe failed while its cleanup checks passed. The retained bounded diagnostic
cannot identify its exact internal cause. A separate Linux reproduction demonstrated that the
fixture's private bind-mount UID and group-zero Docker socket assumptions are not portable.
Transfer the three owned PostgreSQL TLS/HBA inputs through a bounded-name stdin archive rather than
relaxing their permissions. Observe the daemon-side socket GID only for the already trusted fixture
controllers; target Workers never receive that socket or group authority. Reject malformed GIDs.
Preserve an allowlisted failed phase and completed-check count without publishing command logs,
credentials or fixture data. The corrected local rehearsal passed; hosted revalidation is pending.
