# ADR-0291: Require a Separate Witness Before Publishing Recovery Heads

- Status: Accepted
- Date: 2026-09-12
- Contract: [OPS-005](../orchestration/OPS-005-separately-retained-recovery-witness.md)

## Context

OPS-004 detects stale application checkpoints only while its anchor remains current.
A correctly signed prefix of the anchor is internally valid after suffix deletion.

## Decision

An explicit anchor v2 enrollment pins a distinct witness genesis and signing key.
Checkpoint publication locks anchor then witness, validates both complete chains,
fsyncs a signed witness intent containing the signed anchor entry, then appends and
fsyncs the anchor. Readers require exact agreement. Interrupted publication blocks
recovery until an operator explicitly reconstructs the anchor into a new directory
from the independently retained witness. The damaged original is preserved.

Application writers receive neither store. Recovery controllers receive both stores
read only and receive neither publisher key. Enrollment starts with an empty anchor;
the v1 serialized binding is unchanged and cannot silently acquire v2 protection.

## Consequences

Availability is sacrificed when only one record is durable. Reads never repair,
roll back or resume execution. An attacker who can restore both stores to the same
old state defeats this local comparison; external freshness requires another trust
boundary. Same-engine Linux containers prove neither physical separation nor storage
power-loss durability, production failover or long-running availability.
