# ADR-0263: Pin Checkpoint Key Identities Before Serving after Restart

- Status: Accepted
- Date: 2026-09-08

## Context

The Control Plane signs approval checkpoints with an HMAC key ID and verifies the signature when
the checkpoint is read or resumed. Previously the server could restart with replacement bytes under
the same key ID, or with missing previous verification keys, and admit new work before discovering
that existing checkpoints could no longer be verified. The environment entry point configured only
one key, although the signer already supported a keyring.

## Decision

Add an append-only key-ID commitment ledger through schema v16. Bind each configured key ID to a
domain-separated HMAC commitment after verifying all existing checkpoints in the same transaction.
Run this admission during the default application lifespan, including when startup migrations are
disabled, before yielding the serving application. Serialize first admission across repository
instances. Recheck key commitments before signing; embedded checkpoint writers also perform full
admission when they have not run the startup hook.

Preserve the existing active key and key-ID environment variables. Add a bounded, strict JSON map
of previous verification keys. New checkpoints use only the active key; required previous keys
must remain available. Omission of an unreferenced key does not erase its permanent ID binding.
Initial schema migration creates no inferred key authority from stored IDs or signatures.

## Consequences

A mismatched key ID, a missing required verification key, or a damaged existing checkpoint prevents
startup. This intentionally replaces delayed failure with a fail-closed recovery boundary. Valid
rotation preserves old checkpoint signatures and existing one-use approval semantics. Configuration
errors omit secret details; stored commitments cannot sign checkpoints.

Rotation requires a quiescent restart of the trusted deployment. This does not remotely revoke
keys in an already running process, pin Graph verifier code or policy inventory, restore budgets,
or prove that a complete host/database has not been rolled back. Those separate OPS-001 obligations
remain open. See [OPS-001](../orchestration/OPS-001-single-host-recovery-and-urgent-stop.md) for the
executable contract, compatibility boundary, and remaining work.
