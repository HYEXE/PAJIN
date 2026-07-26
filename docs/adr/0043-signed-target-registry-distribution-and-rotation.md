# ADR 0043: Signed Target registry distribution and monotonic rotation

- Status: Accepted
- Date: 2026-07-24

## Context

ADR 0042 registry v2 binds an HTTPS endpoint key to an exact Target URL, but does not prove the
origin, freshness, or distribution order of the registry JSON itself. Replaying an older registry
could restore a retired key, while replacing a pin atomically would interrupt legitimate
certificate rotation.

## Decision

1. Signed distribution uses `pajin.replay.target-attestation-trust-registry/v3`. Each HTTPS entry
   has one current `tls_leaf_spki_sha256` and at most one optional
   `retiring_tls_leaf_spki_sha256`. The retiring pin requires
   `retiring_tls_leaf_spki_not_after` and remains valid for at most 24 hours from bundle issuance
   and never beyond bundle expiry.
2. A separate `TargetAttestationRegistryTrustAnchor` Ed25519 key signs the registry with domain
   separation. The statement binds trust domain, issuer, a contiguous sequence starting at one,
   predecessor bundle SHA-256, issued/not-before/expiry timestamps, and the complete registry.
   Bundle lifetime is at most seven days. Target application receipt keys are not distribution
   keys.
3. At startup the Control Plane reads either an inline bundle or at most 512 KiB from an absolute
   HTTPS URL with normal certificate and hostname verification and no redirects. The distribution
   trust anchor is configured out of band. The registry is unusable until signature, key
   lifecycle, and current validity verification succeeds.
4. Schema v14 adds append-only
   `cp_target_attestation_registry_versions`, recording activation sequence and
   bundle/predecessor/registry digests per trust domain. Bootstrap accepts only sequence one.
   Restarts and multiple replicas reject rollback, gaps, predecessor mismatch, and different
   content at the same sequence (equivocation).
5. A receipt issued before the retiring-pin deadline may match either current or retiring pin.
   At and after the deadline only the current pin is accepted. Verification summaries preserve
   the SPKI digest actually observed and verified by the Worker, not merely the expected pin.
6. The legacy single anchor and inline registry v1/v2 remain compatible. Registry v3 is rejected
   outside a signed bundle.

## Trust boundary and limitations

This decision proves registry distribution origin and order plus bounded pin rotation. It does not
prove TLS-exporter or handshake-transcript session binding, CA revocation or Certificate
Transparency, online rotation of the distribution trust anchor, or anti-rollback after loss of the
database and all backups. The current implementation refreshes only at startup and fails Replay
closed after bundle expiry.

## Consequences

A normal rotation publishes the new pin as current and the old pin as retiring for at most 24
hours, then removes the retiring pin in the next version. The Control Plane does not start if the
signed sequence and predecessor digest do not continue its durable ledger. TLS exporter or
equivalent session binding is next, followed by object-store/multipart Artifact transport.
