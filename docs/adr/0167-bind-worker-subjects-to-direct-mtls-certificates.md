# ADR-0167: Bind Worker Subjects to Direct mTLS Certificates

## Status

Accepted

## Context

The Control Plane already maps opaque bearer credentials to separated generic and Replay Worker
subjects. That proves possession of a shared secret, but it does not prove that the caller also
holds a deployment-issued workload private key. Human OIDC admission deliberately excludes Worker
authority, and the existing Target-to-Worker TLS 1.2 session binding protects a different trust
boundary.

Accepting a forwarded certificate header would make a proxy configuration part of authentication
without an authenticated forwarding contract. Requiring client certificates for every TLS
connection would also break certificate-free Human OIDC and opaque Operator access. UX-007B needs
an opt-in, direct-termination boundary that strengthens only Worker principals.

## Decision

### Pin one certificate public key to every Worker subject

`pajin.control-plane.worker-mtls-trust-policy/v1` is a bounded strict-JSON deployment policy. Each
binding maps one exact local Worker subject to a lowercase SHA-256 digest of its DER
SubjectPublicKeyInfo. Subjects are unique, and startup requires the policy to bind every and only
the Worker subjects configured by bearer credentials. Human principals cannot enter this map.

The TLS stack first verifies certificate chain, validity, and proof of private-key possession
against `PAJIN_CP_WORKER_MTLS_CA_FILE`. The application then compares the verified leaf SPKI digest
with the bearer-authenticated subject. A CA-valid certificate for another Worker therefore fails
with the same generic `401` as a missing, malformed, or mismatched credential.

### Terminate Worker TLS directly in the PAJIN Uvicorn process

The PAJIN server uses a dedicated Uvicorn H11 protocol adapter. It reads the peer certificate from
the direct asyncio TLS transport and exposes it through the standard ASGI `tls` extension. The
application never reads `X-Forwarded-Client-Cert`, `X-SSL-Cert`, or another request header as
certificate authority. Uvicorn proxy headers remain disabled.

The server uses `CERT_OPTIONAL`: a certificate that is presented must verify against the Worker CA,
while Human routes may omit it. Once a bearer maps to `PrincipalRole.WORKER`, the application
requires verified TLS evidence and the exact subject binding. `PAJIN_CP_WORKER_MTLS_CA_FILE` and
`PAJIN_CP_WORKER_MTLS_TRUST_POLICY` must be configured together, and they require the direct server
certificate and key settings.

### Give each Worker daemon an HTTPS-only client identity

Generic and Replay Worker clients accept the same four deployment inputs: Control Plane CA bundle,
client certificate, client key, and optional key password. CA, certificate, and key are all-or-none.
They cannot be combined with the plaintext lab exception. The client uses one bounded
`PROTOCOL_TLS_CLIENT` context, TLS 1.2 or newer, no environment proxy, no redirect, and the existing
bearer credential.

Loading the deployment CA as bounded PEM `cadata` avoids platform default-store authority and the
Windows OpenSSL FILE boundary. Certificate and key paths remain service-account-owned deployment
inputs, not request data.

## Consequences

- A Worker request requires possession of both its bearer secret and its deployment-pinned private
  key when the policy is enabled.
- A Replay Worker certificate cannot authenticate the generic Worker subject, or vice versa, even
  when both chain to the same CA.
- Human OIDC and opaque Human routes remain certificate-optional.
- Existing deployments without the Worker mTLS policy retain their previous behavior.
- SPKI pinning permits certificate renewal with the same public key. Public-key rotation requires a
  policy update and coordinated daemon rollout.
- This slice does not add certificate revocation distribution, automated rotation, HSM keys,
  proxy-terminated mTLS, TLS exporters, or ABAC execution attributes.
- The boundary is distinct from B2.8f Target TLS session binding and does not reuse its evidence as
  Control Plane workload identity.

## Rejected alternatives

### Trust a client-certificate HTTP header

Rejected because an untrusted direct client could forge the header and no authenticated proxy
forwarding contract exists.

### Require a client certificate on every Control Plane connection

Rejected because Human OIDC and separated Human opaque credentials have a different identity
lifecycle and must remain usable without a workload certificate.

### Treat any certificate from the Worker CA as the bearer subject

Rejected because CA membership alone does not bind generic and Replay Worker authority to one
canonical local subject.

### Replace bearer credentials with certificates in this slice

Rejected because bearer removal changes the existing HTTP authentication, secret-rotation, audit,
and compatibility contracts. UX-007B composes two factors instead.

## Compatibility and rollback

The change is additive and opt-in. It does not change routes, request or response schemas, database
schema, audit-event schema, lease semantics, or Worker result authority. Rollback first removes the
Worker mTLS policy and CA setting, then removes daemon client-certificate settings, while retaining
the existing bearer credentials. No data migration is required.

## Related documents

- [UX-007B contract](../orchestration/UX-007B-worker-mtls-subject-binding.md)
- [ASGI TLS extension](https://asgi.readthedocs.io/en/latest/specs/tls.html)
- [ADR-0166 Human OIDC identity](0166-bind-mfa-oidc-identity-without-token-role-authority.md)
