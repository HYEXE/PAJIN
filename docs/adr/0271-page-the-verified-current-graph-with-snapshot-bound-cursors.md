# ADR-0271: Page the Verified Current Graph with Snapshot-Bound Cursors

- Status: Accepted
- Date: 2026-09-08
- Extends: [ADR-0158](0158-project-current-canonical-graph-without-read-authority-expansion.md)

## Context

The original Graph inspector rejects more than 500 nodes or 1,000 edges. A larger valid current
Snapshot should remain inspectable without truncation or increasing the browser's retained DOM.

## Decision

Add an Operator-only `/pages` endpoint under the exact current Snapshot route. Each request
repeats the existing complete read-only store verification before returning one slice of the
sorted node and edge projections. A canonical cursor binds the Campaign, Snapshot ID/digest,
Projection digest, page size, and common offset. It grants no authority and need not be signed:
an authenticated reader may select any valid aligned position in the same verified Snapshot.

Pages contain at most 500 nodes and 500 edges each, with a default size of 100. Total bounds are
100,000 nodes and 200,000 edges. Edges may refer to nodes on another page; endpoint kinds and
relationship directions remain checked. All original redaction and non-authority markers remain.
The original full-view endpoint and its rejection limits remain unchanged.

The Console replaces the current page rather than accumulating content. It binds navigation to
the verified identity and total counts, discards responses after input or authentication changes,
and clears content on failure. A newly published Snapshot makes prior navigation stale; clients
must submit its exact ID and start a new traversal.

## Consequences and validation

This bounds responses and browser memory, not server verification work. Every page still scans
and verifies the complete retained history. Historical pagination, export, multi-Campaign routing,
and content authorization remain separate work; no schema migration or cursor persistence exists.

Regression tests traverse 503 nodes and 1,001 edges, check authentication, mixed cursors, stale
Snapshots, redaction, no writes, and late-response disposal. A real local Control Plane serving a
verified 504-node SQLite Graph was inspected in Chromium at desktop and mobile widths: six pages,
keyboard next/previous, no horizontal overflow, no browser errors, and lock clearing passed.
The focused Graph/API/Console suite passed 47 tests.
