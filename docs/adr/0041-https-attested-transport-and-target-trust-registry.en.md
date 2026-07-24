# ADR 0041: HTTPS-aware attested transport and Target trust registry

- Status: accepted
- Date: 2026-07-24

## Context

ADR 0040 B2.8b joined Target-signed receipts to host-proxy plaintext HTTP request and response
digests. Reusing that contract for HTTPS would falsely claim that the proxy observed application
bytes inside TLS. A single global Target anchor also cannot safely route independent Target issuers
and makes accidental trust fallback difficult to detect.

## Decision

1. The existing `pajin.kisa-target-attestation:v4` policy, HTTP proxy binding v1, and legacy
   single-anchor configuration remain compatible. HTTPS uses a distinct transport binding under
   the same explicit `target_attestation=true` policy.
2. The egress proxy records `pajin.dev/egress-https-connect-receipt/v1` for each established HTTPS
   tunnel. It contains the canonical `host:port`, its SHA-256, the selected DNS address, contiguous
   sequence, and `applicationVisibility=opaque`. It does not claim to observe the request path,
   method, body, or response.
3. The Executor joins each CONNECT receipt to the exact Target-signed application exchange and
   signs `pajin.replay.target-tls-binding/v1`. The Control Plane rechecks the permit-derived Target
   digest, CONNECT authority and sequence, transcript digests, Target signature, and key lifecycle.
4. General AI Tool and Retest execution still require complete plaintext HTTP receipts. Only
   target-attested Replay, where a Target receipt is mandatory, may accept opaque CONNECT evidence.
5. `pajin.replay.target-attestation-trust-registry/v1` maps up to 128 canonical exact Target URLs
   to public trust anchors. Routes are sorted and unique; wildcards, origin fallback, and
   unknown-target fallback are forbidden.
6. `PAJIN_CP_TARGET_ATTESTATION_TRUST_REGISTRY` is mutually exclusive with the legacy
   `PAJIN_CP_TARGET_ATTESTATION_TRUST_ANCHOR`. A registry-backed verification summary and
   finalization authority bind the registry ID/digest and the selected anchor digest.
7. The development AI Target starts a TLS 1.2-or-newer listener when
   `PAJIN_TARGET_TLS_CERTIFICATE` and `PAJIN_TARGET_TLS_PRIVATE_KEY` are both supplied. It refuses
   startup when only one is present.

## Trust boundary and limitations

This slice proves which authority and IP the proxy connected a TCP tunnel to, then joins that route
to an application exchange signed by a Target key. It does not mean the proxy observed TLS
plaintext, the certificate chain, negotiated protocol, or server-certificate fingerprint. Standard
HTTPS certificate validation remains in the Worker client. Certificate pinning, TLS exporter
binding, mTLS workload identity, and HSM/KMS key custody remain follow-up boundaries.

The registry supplies exact routing and a version digest, but not dynamic discovery, transparency
logs, cross-organization federation, or automatic key rotation. A Replay proof set spanning
multiple anchors currently fails closed.

## Consequences

- HTTPS target-attested Replay can verify CONNECT routing plus a Target-signed application exchange
  without misrepresenting it as plaintext proxy observation.
- Multiple Target issuers can be operated through one versioned registry while wrong Targets and
  fallback routes are rejected.
- The next slice is certificate/exporter binding and registry distribution/rotation automation,
  followed by object-store/multipart portable Artifact transport.
