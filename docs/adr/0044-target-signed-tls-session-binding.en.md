# ADR 0044: Target-signed TLS session binding

- Status: Accepted
- Date: 2026-07-24

## Context

ADR 0042 and ADR 0043 bind the Worker-observed HTTPS leaf SPKI, exact CONNECT route, and signed
registry authority. They cannot distinguish a Target receipt and Executor proof assembled from
different TLS sessions that use the same certificate key. Both endpoints must attest that the
application exchange used the exact TLS session observed by the Worker.

Python 3.12's standard `ssl` API exposes only the RFC 5929 `tls-unique` channel binding and does not
expose a TLS exporter API. RFC 9266 `tls-exporter` support for TLS 1.3 remains a follow-up boundary.

## Decision

1. A session-binding signed registry uses
   `pajin.replay.target-attestation-trust-registry/v4`. Every v4 HTTPS exact-URL entry declares
   `tls_session_binding: tls-unique-sha256` in addition to its existing leaf-SPKI pin. HTTP entries
   cannot carry this field.
2. The PAJIN lab Target enables the mode only when
   `PAJIN_TARGET_TLS_SESSION_BINDING=tls-unique-sha256` is explicit. It requires TLS certificate
   configuration, restricts the protocol to TLS 1.2, reads server-side
   `SSLSocket.get_channel_binding("tls-unique")`, and hashes it with the
   `pajin.replay.target-tls-unique-binding/v1` domain.
3. After normal PKIX and hostname verification, the Worker reads the leaf SPKI and TLS 1.2
   `tls-unique` value from the same socket before the response can release it. It records the same
   domain-separated SHA-256 in the transcript. TLS 1.3 or a runtime without channel-binding data
   produces no session digest.
4. Target receipt statement v2 signs `TLSv1.2`, `tls-unique-sha256`, and the Target-side session
   digest together with the exact request and response. Executor TLS binding v3 separately signs
   the CONNECT route, Worker-observed SPKI, and Worker-side session digest with the workload key.
5. For a registry-v4 route, the Control Plane requires receipt v2 and TLS binding v3, then exactly
   compares the Target and Worker session digests, binding type, TLS version, and SPKI pin. Receipt
   v1, binding v1/v2, digest mismatch, and cross-session proof assembly fail closed. Successful
   summaries preserve the session digests actually verified.
6. The legacy single anchor, registry v1-v3, receipt v1, and TLS binding v1/v2 retain their existing
   read and verification behavior. Like v3, registry v4 is invalid outside a signed distribution
   bundle.

## Trust boundary and limitations

This decision proves that the Target-signed application exchange and Worker-observed HTTPS
connection share the same `tls-unique` channel binding in the PAJIN TLS 1.2 lab profile. It does
not prove:

- TLS 1.3 `tls-exporter` channel binding. Because the Python standard API does not expose an
  exporter, registry v4 rejects TLS 1.3 instead of silently weakening.
- separate attestation of TLS 1.2 extended-master-secret negotiation. The current lab relies on
  modern OpenSSL at both endpoints and one non-renegotiated request connection.
- the full handshake transcript, cipher or ALPN, resumption policy, client workload identity, or
  mTLS
- CA revocation, Certificate Transparency, HSM/KMS custody, background registry refresh, or
  external transparency/federation

## Consequences

Even when two connections share the same certificate key, a Target receipt from one connection
cannot be combined with the Worker proof from another because their session digests differ.
Production TLS 1.3 support remains follow-up work requiring a runtime and client/server adapter
that exposes RFC 9266 `tls-exporter`. The next product priority is object-store/multipart portable
Artifact transfer beyond the current 2 MiB limit.
