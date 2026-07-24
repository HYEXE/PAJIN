# ADR 0040: Target-issued challenge-bound Replay receipts

- Status: Accepted
- Date: 2026-07-24

## Context

The executor signature in ADR 0039 proves that a separate workload observed the exact permits and
sealed output. It does not prove where the target response relayed by that executor originated. A
Worker or executor could fabricate both response JSON and proxy-receipt fields, so that proof alone
must not lift a Finding to `VERIFIED_INDEPENDENT_REPLAY`.

A Target signature over a bare nonce is also insufficient. It can be replayed across permits,
requests, or responses and is not tied to the exchange observed by the host. The required chain
must follow the same exact Claim from one-time Control Plane authority through Target response,
host proxy observation, executor result, and final projection.

## Decision

1. B2.8b issues `pajin.kisa-target-attestation:v4` only when a Claim-projection batch explicitly
   requests `target_attestation=true`. It requires B2.8a `portable_attestation=true` and a separate
   executor trust anchor. Existing v1-v3 requests and signature serialization remain unchanged.
2. The Control Plane derives a deterministic challenge with at most a 30-second lifetime from each
   durable Tool permit digest, Replay request ID, batch/item/ticket, fencing value, call ordinal,
   target digest, method, compiled-argument digest, and issue/expiry times. A Worker nonce or
   caller-supplied challenge is never authority.
3. The Target signs the challenge digest, exact request JSON digest, response-payload digest
   excluding the receipt, HTTP status, exchange ordinal, and Target issuer/trust-domain/profile
   with a separate Ed25519 workload key. The Control Plane validates `active`, `retired`, and
   `revoked` lifecycle against an out-of-band keyring and never trusts Artifact-supplied keys.
4. The Target receipt is included as `targetReceipt` in the response JSON. The existing host
   egress proxy records the canonical digest of that complete JSON. The executor binds the Target
   receipt digest to the matching proxy request/response receipt in `target_execution_proofs`,
   covered by its existing executor statement signature.
5. Before copying external Artifact bytes, the Control Plane verifies the executor signature and
   proof shape. After managed import and seal reverification, it re-derives the challenge from the
   permit and checks the exact transcript request, response without the receipt, Target receipt
   signature/lifecycle, host proxy request/response digests, and executor binding. Missing,
   duplicate, reordered, or cross-permit/target/exchange receipts fail closed.
6. The Target verification summary, proof-set digest, and trust-anchor digest enter the
   finalization-result digest. Only an exact Claim whose existing semantic and contradiction Gate
   succeeds and whose independent-execution proof is valid advances to `confirmed /
   VERIFIED_INDEPENDENT_REPLAY / INDEPENDENT_REPRODUCTION_CONFIRMED`. A Target signature cannot
   bypass contradiction, inconclusive, or negative-retest rules.

## Trust boundary and limits

This decision creates three separated authorities from the Control Plane permit through the
Target-issued receipt, host proxy observation, executor signature, and sealed projection. A Worker
or executor self-assertion cannot create independent-execution state.

The first vertical slice has these limits:

- The current host proxy canonically observes plaintext HTTP response JSON. It cannot bind the
  inner response of a generic HTTPS `CONNECT` tunnel to a proxy receipt.
- One Control Plane configuration accepts one Target issuer/trust-domain/profile anchor.
  Multi-Target registries, target-identity routing, HSM/KMS, and transparency logs are follow-up.
- Challenge and key lifecycle checks assume UTC clock synchronization across hosts. The design
  keeps short expiry and fail-closed checks instead of widening the acceptance window.
- A Target receipt proves execution origin, not organizational impact, remediation ownership, or
  production telemetry.
- The 2 MiB portable Artifact ceiling and large object-store/multipart transfer remain separate
  follow-up scope from ADR 0039.

## Consequences

- Registered exact KISA M03/M06/A04 positive Replay can reach
  `VERIFIED_INDEPENDENT_REPLAY` for the first time when Target-issued proof is present.
- A v4 request without a Target signer or configured anchor is rejected during issuance or
  execution.
- Key rotation retains retired keys for old-receipt verification and rejects revoked keys
  regardless of issue time.
- The next improvement is an attested transport that preserves host observation for HTTPS plus a
  multi-Target trust registry, followed by large Artifact transport on the same
  content-addressed contract.
