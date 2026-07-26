# ADR 0042: Worker-observed TLS leaf SPKI binding

- Status: accepted
- Date: 2026-07-24

## Context

The HTTPS transport proof in ADR 0041 exactly joins the opaque CONNECT route observed by the proxy
to the Target-signed application exchange, but it does not bind the server certificate received by
the Worker during the TLS handshake to the Target identity in the registry. PAJIN must separately
reject an unexpected TLS endpoint key even when the DNS route and Target application key match.

A full certificate DER fingerprint changes when a certificate is reissued with the same public
key. A SubjectPublicKeyInfo (SPKI) digest permits that certificate replacement while still
detecting an unexpected endpoint key. This slice does not prove the full TLS channel or operational
fitness of the certificate chain. It adds the leaf key observed after standard HTTPS validation to
the exact registry route.

## Decision

1. Add `pajin.replay.target-attestation-trust-registry/v2`. Every HTTPS exact-URL entry in v2 must
   contain a lowercase SHA-256 `tls_leaf_spki_sha256`. HTTP entries cannot carry that field. The v1
   registry and legacy single-anchor configuration retain their serialization and verification
   compatibility and cannot carry certificate pins.
2. The Worker retains the default Python HTTPS PKIX chain and hostname validation. It reads the
   leaf certificate DER from the verified socket through public
   `SSLSocket.getpeercert(binary_form=True)` and hashes its DER-encoded SubjectPublicKeyInfo.
   Missing or undecodable certificates and missing observations fail the HTTPS AI exchange closed.
3. The Worker records the observation as `tlsPeerLeafSpkiSha256` on each HTTPS transcript turn. The
   Executor rechecks raw/typed transcript equality and signs it with the existing CONNECT and Target
   receipts in `pajin.replay.target-tls-binding/v2`.
4. When the Control Plane verifies a registry v2 HTTPS entry, it requires a TLS binding v2 with an
   exact registry SPKI match. A pin mismatch or TLS binding v1 downgrade is rejected. Registry v1
   and single-anchor routes may continue to accept TLS binding v1.
5. The successful verification summary binds the sorted, unique set of SPKI digests actually used.
   The new field is omitted on v1 paths so existing canonical digests remain unchanged.

## Trust boundary and limitations

This decision proves, under the Executor signature, that the peer leaf public key observed by the
Worker after standard PKIX and hostname validation matches the exact Control Plane registry route.
An SPKI pin does not prove:

- equality of the full certificate DER, issuer, or chain;
- revocation, Certificate Transparency, organizational policy, or CA operational fitness;
- cryptographic channel binding to one TLS session's handshake transcript, negotiated protocol,
  cipher, or application bytes; or
- independent Worker or Executor workload identity or HSM/KMS key custody.

Pin rotation currently requires the operator to coordinate certificate/key deployment and registry
environment configuration atomically. Signed remote registry distribution, monotonic
anti-rollback, old/new pin overlap, transparency, and automatic rotation are not provided. The
Python HTTPS connection hook depends on the standard-library contract of the current Worker
runtime. Until a runtime and protocol with a usable TLS exporter API are introduced, this is
endpoint-key binding rather than session binding. The portable Artifact 2 MiB limit also remains.

## Consequences

- HTTPS target-attested Replay using registry v2 fails closed on an unexpected leaf public key or a
  TLS binding v1 downgrade.
- A reissued certificate may retain the pin when it uses the same key, while key rotation requires
  an explicit registry change.
- The next slice is signed registry distribution, monotonic anti-rollback, and old/new pin overlap
  rotation. TLS exporter or equivalent session binding follows, then object-store/multipart
  portable Artifact transport.
