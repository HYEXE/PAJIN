# ADR-0057: Signed and Encrypted Graph Backup Retention Objects

- Status: Accepted
- Date: 2026-07-28

## Context

ADR-0049 created a bounded, content-addressed SQLite Graph backup and verified restore path. That
pair protects local consistency, but a party able to replace both files can manufacture another
pair, and the database remains plaintext. Moving that pair to another storage system would not
provide external authenticity or confidentiality.

The repository must not become a key store, and a filesystem adapter cannot truthfully claim that
an object was transported off-host or retained according to an organizational schedule.

## Decision

1. `SQLiteGraphStore.create_retained_backup()` first creates and fully verifies the ADR-0049
   backup inside a private temporary workspace.
2. It encrypts the bounded database with AES-256-GCM and a fresh 96-bit nonce. Authenticated
   metadata binds the original backup ID, Campaign, algorithm, external encryption-key ID, and
   nonce.
3. A content-addressed statement binds the complete original backup manifest and the exact
   ciphertext digest and length.
4. An externally supplied Ed25519 signer signs domain-separated canonical statement bytes. The
   retained object stores only key IDs, the public statement, and the detached signature. Neither
   private signing material nor the encryption key is serialized.
5. Ciphertext and signed manifest publish exclusively and never replace an existing leaf. An
   incomplete pair is not restorable.
6. `restore_retained_backup()` requires the caller to supply the expected encryption-key ID and
   key plus an out-of-band set of trusted Ed25519 public keys. It verifies canonical bytes,
   content identity, signature, ciphertext digest, AEAD authentication, plaintext digest, and the
   complete logical Graph state before publishing a previously absent destination.
7. Tests copy the pair into a detached directory and restore it in a fresh process without access
   to the source store. This is an independent local restore drill, not evidence of another host.

## Consequences

- A retained backup can be transported through an untrusted object channel without exposing the
  SQLite plaintext or trusting that channel for authenticity.
- Restore depends on external preservation and rotation of both encryption keys and trusted
  signing keys. Loss of the encryption key makes the object intentionally unrecoverable.
- Encryption is bounded to the existing 256 MiB database limit and currently operates in memory.
- Random nonce generation makes retained object identities intentionally non-deterministic even
  when the source state is unchanged.
- Actual remote transport, object-lock/retention policy, independent-host scheduling, key
  management service integration, and external anti-rollback inventory remain deployment work.

## Compatibility and rollback

The retained format and APIs are additive. Existing plaintext backup/restore and all Graph wire
models remain valid. Operators may stop creating retained objects without changing the canonical
database. Once plaintext has been deleted from an external location, rollback still requires the
matching external decryption key and trusted historical signing key.

## Related documents

- [ADR-0049: Durable Single-Campaign SQLite Graph Store](0049-durable-single-campaign-sqlite-graph-store.md)
- [GRAPH-005: Durable Single-Campaign SQLite Graph Store](../graph/GRAPH-005-durable-sqlite-graph-store.md)
- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
