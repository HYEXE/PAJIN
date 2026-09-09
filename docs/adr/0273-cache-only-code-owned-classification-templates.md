# ADR-0273: Cache Only Code-Owned Classification Templates

- Status: Accepted
- Date: 2026-09-09
- Extends: [ADR-0204](0204-separate-security-domain-from-profile-and-authority.md)

## Context

A recorded profile of the Forensics Replay integration test spent most cumulative time repeatedly
constructing and hashing the same registered Security Domain taxonomy through Graph classification.
Caching arbitrary validated models would weaken the checks on mutable external artifacts and could
allow one caller to poison another caller's view.

## Decision

Cache one private template for the code-owned taxonomy and one for the code-owned multi-domain
Graph semantics registry. Cache a bounded set of classification references by the fixed Security
Domain enum. Public registry and resolver functions return deep copies; no caller receives a cached
model or a nested cached member. Catalog bytes, content-addressed IDs, classification markers,
public imports, and resolver errors retain their prior meaning.

External input validation, artifact reconstruction, authority checks, source digests, mutable
Graph state, permits, and evidence are never cached by this change. A process restart loads the
templates from its deployed code. Runtime inventory continues to bind that code version.

## Validation and consequences

Compare the canonical catalogs before and after, reprofile the same integration test, and retain
negative tests for malformed classifications and authority markers. Mutation tests intentionally
bypass a returned model's frozen assignment guard and alter nested members, then prove that later
calls remain unchanged and the corrupted external model is rejected on revalidation.

Deep copies retain some construction cost, but bounded process memory avoids repeated code-owned
digest generation without relying on caller discipline. The measured integration test and full
regression suite remain required; pure-model speed does not establish real Docker conformance or
CI elapsed-time improvement. Timing-based test placement changes scheduling only and cannot change
which collected tests run; its operator procedure is documented in the root README.
