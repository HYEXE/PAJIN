# ADR-0058: Immutable Graph Backup Repository and Anti-Rollback Inventory

- Status: Accepted
- Date: 2026-07-28

## Context

ADR-0057 defines an authenticated and encrypted retained Graph backup, but a storage integration
still needs a precise contract for non-replacing publication, retention evidence, version-pinned
reads, and rollback detection. Treating a successful generic upload as proof of object lock would
overstate the repository's guarantees. A signed latest-inventory file stored beside the backups
would also be insufficient because an attacker able to roll back that repository could roll back
the inventory with it.

The core repository must stay transport-neutral. Cloud credentials, KMS/HSM keys, account policy,
and the independently persisted latest anchor remain deployment responsibilities.

## Decision

1. `SQLiteGraphBackupRetentionBackend` is the narrow integration boundary. It exposes a stable
   repository identity, `put_if_absent()` for an exact request and byte string, and `read_exact()`
   for the object version named in a receipt.
2. Each put request binds Campaign, retained-backup identity, object kind and key, SHA-256, byte
   length, requested object-lock mode, retention deadline, and request time.
3. A backend receipt must echo the exact request authority and add an immutable object version,
   store time, and a digest of provider-specific evidence. Publication rejects a shortened
   retention deadline or any other mismatch.
4. Ciphertext and canonical signed manifest use content-derived, Campaign-scoped keys and are
   created separately with put-if-absent semantics. A failed second write can leave an orphaned
   first object, but it cannot publish an inventory entry or overwrite existing material.
5. The two verified receipts form a content-addressed publication. Cumulative inventory revisions
   append exactly one publication, bind the previous signed-manifest digest, advance time and
   sequence, and are signed with an externally supplied Ed25519 key.
6. Restore requires a complete valid inventory chain and an external anchor. The anchor pins a
   minimum sequence, inventory identity, and signed-manifest digest. Older histories, forks,
   reorderings, duplicate publications, invalid signatures, and foreign Campaigns fail closed.
7. Restore reads exact backend versions, verifies each receipt digest and length, then applies the
   ADR-0057 signature, AEAD, plaintext, logical-state, and no-overwrite checks.
8. The local locked-memory backend exists only as a conformance fixture. It proves the adapter
   contract and failure behavior, not an actual provider's off-host durability or object lock.

## Consequences

- A provider adapter cannot silently reduce the requested retention policy or substitute another
  object version without failing publication or restore.
- The signed cumulative inventory makes ordering and append-only history verifiable. Rollback
  resistance depends on preserving the latest anchor outside the repository being verified.
- Backend-specific evidence is digest-bound but not interpreted by the core. Deployment review
  must validate that the adapter derives it from the provider's authoritative response.
- Partial publication is intentionally recoverable by exact retry or operational orphan cleanup
  after retention expiry; the core never deletes an immutable object as compensation.
- The cumulative inventory is bounded to 1,024 publications and 8 MiB. A future compaction or
  checkpoint design requires a separate decision and must preserve anchored history.
- Actual cloud/object-store adapters, scheduled off-host transfer, independent-host restore
  drills, KMS/HSM integration, and independently operated anchor storage remain open.

## Compatibility and rollback

The protocol, receipts, publications, and inventory are additive. Existing local plaintext and
ADR-0057 retained backup APIs remain valid. Before a backend is operationally authoritative,
rollback is to stop publishing new inventory revisions while preserving all retained objects,
signed inventory manifests, external anchors, and key history. Rewriting or truncating an anchored
inventory is not an allowed rollback.

## Related documents

- [ADR-0049: Durable Single-Campaign SQLite Graph Store](0049-durable-single-campaign-sqlite-graph-store.md)
- [ADR-0057: Signed and Encrypted Graph Backup Retention Objects](0057-signed-encrypted-graph-backup-retention.md)
- [GRAPH-005: Durable Single-Campaign SQLite Graph Store](../graph/GRAPH-005-durable-sqlite-graph-store.md)
- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
