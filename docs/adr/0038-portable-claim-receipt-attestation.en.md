# ADR 0038: Portable Public-Key Attestation for Claim Receipts

- Status: Accepted
- Date: 2026-07-24

## Context

Through ADR 0037, the Control Plane executes exact KISA M03/M06/A04 validity, impact, and severity
Claims separately and preserves their ticket, compilation, Replay Run, output Artifact, and receipt
seal root in projection input authority v3. Its final trust anchor is still the Control Plane
database plus the Artifact repository's OS account and ACL. An off-host verifier cannot authenticate
those receipts without a server secret, and the internal HMAC checkpoint key is unsuitable for
public verification.

Signing the completed projection Artifact digest from a file contained by that same Artifact would
create a digest cycle. The public-key proof must therefore sign the immutable projection input
authority and every Claim receipt root rather than the containing Artifact itself.

## Decision

1. Add an explicit `CreateReplayBatchRequest.portable_attestation` opt-in. It is valid only with
   `claim_projection: true` for confirmation. This path uses the
   `pajin.kisa-claim-attestation:v3` policy and fails closed at batch creation when no Ed25519 signer
   is configured. Existing v1/v2 policies and projection input authority v1/v2/v3 remain unchanged.
2. The signed statement contains the trust domain, issuer, policy, batch ID, issue time, complete
   `ReplayClaimProjectionInputAuthority`, its canonical digest, and the receipt count. One signature
   therefore binds every validity/impact/severity Claim identity, finalization, Replay Run, output
   Artifact, artifact-set digest, receipt seal root, gate digest, and result digest.
3. Ed25519 signs canonical JSON bytes under a distinct domain prefix. The bundle carries the
   statement SHA-256, key ID, algorithm, and base64url signature.
4. Add the bundle to the confirmation projection transaction as
   `validation/v1alpha1/portable-replay-attestation.json`. The transaction records its digest, and
   the Run seal covers both transaction and bundle. The issue time comes from the immutable batch
   snapshot, so crash recovery and response-loss retries reproduce identical bytes.
5. Model the trust anchor as a separate JSON contract containing issuer, trust domain, and a sorted
   public-key lifecycle. Exactly one key is `active`; previous keys are `retired` or `revoked`.
   Historical bundles from a `retired` key verify within its validity window. A `revoked` key always
   fails closed, regardless of issue time. The active private key must match the anchored public key
   and remains separate from the internal HMAC checkpoint key.
6. The verifier never trusts key material from the bundle and requires an explicitly supplied,
   out-of-band trust anchor. `GET /v1/replay/batches/{batch_id}/attestation` and
   `GET /v1/replay/attestation/trust-anchor` are transport conveniences, not trust establishment.
   `pajin replay-attestation-verify <bundle> --trust-anchor <anchor>` performs the same verification
   without a server secret and reports the anchor digest.

## Security boundary

This slice lets another host verify that a key from the selected Control Plane trust domain signed
the exact Claim receipt set and that the statement has not changed. Pinning the anchor through a
separate channel prevents a verifier from implicitly trusting a key merely because the same server
returned it.

The signature does not prove that a Worker from another organization executed the workload, that
the target independently authored its response, physical isolation or quiescence, completed
remediation, or transparency-log inclusion. The current validity result therefore retains the
`needs-review` ceiling and `independent-execution-attestation-missing` boundary. Independent
executor/target issuers, HSM or external key custody, multi-host/object-store Artifact transfer, and
a transparency log remain follow-on scope.

## Consequences

- Claim receipt authority becomes verifiable off-host without sharing a server secret.
- Rotation preserves old bundles by retaining previous public keys as `retired`; compromise can
  reject a key and all of its bundles through `revoked`.
- The signature bundle remains inside the existing sealed projection transaction, preserving the
  append-only model without a new database schema or mutable backfill.
- Operators must distribute and pin the trust anchor across a channel and ownership boundary
  separate from the Control Plane.
