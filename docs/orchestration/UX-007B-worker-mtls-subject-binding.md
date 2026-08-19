# UX-007B: Worker mTLS Subject Binding

## Goal

Bind each bearer-authenticated generic or Replay Worker subject to one deployment-pinned client
certificate public key without granting certificate headers, Human OIDC claims, or Target TLS
evidence any Worker authority.

## Deployment contract

The Control Plane configures these values together:

- `PAJIN_CP_TLS_CERT_FILE`
- `PAJIN_CP_TLS_KEY_FILE`
- optional `PAJIN_CP_TLS_KEY_PASSWORD`
- `PAJIN_CP_WORKER_MTLS_CA_FILE`
- `PAJIN_CP_WORKER_MTLS_TRUST_POLICY`

The strict policy has API version `pajin.control-plane.worker-mtls-trust-policy/v1`, a stable
`worker-mtls-policy_<32 hex>` ID, and one `{principal_subject, certificate_spki_sha256}` binding for
every configured Worker subject.

Each generic and Replay Worker configures:

- `PAJIN_CP_TLS_CA_FILE`
- `PAJIN_CP_MTLS_CERT_FILE`
- `PAJIN_CP_MTLS_KEY_FILE`
- optional `PAJIN_CP_MTLS_KEY_PASSWORD`

The daemon settings are all-or-none and valid only with an HTTPS `PAJIN_CP_URL`.

## Admission sequence

1. Direct Uvicorn TLS verifies any presented client certificate against the deployment Worker CA.
2. The PAJIN H11 adapter exports the verified leaf certificate in the ASGI `tls` extension.
3. Existing bearer authentication resolves one canonical `Principal`.
4. Human principals continue through existing role checks without a client-certificate requirement.
5. A Worker principal must have an exact policy binding and a verified leaf certificate.
6. The application hashes the leaf DER SubjectPublicKeyInfo and compares it with the subject pin.
7. Existing generic-versus-Replay Worker route separation runs on the same principal.

## Fail-closed cases

- Policy and Worker CA are not configured together.
- Direct server certificate or key is absent when Worker mTLS is enabled.
- Policy omits a configured Worker or names a non-Worker subject.
- Daemon CA, certificate, or key is partially configured.
- Daemon attempts to send mTLS credentials over plaintext HTTP.
- TLS is absent, the ASGI TLS extension is absent, or the certificate chain is empty or malformed.
- Certificate verification reports an error.
- Leaf SPKI digest does not match the bearer-authenticated subject.
- A forwarded certificate header is supplied without direct TLS evidence.

All request-time Worker identity failures use the existing generic bearer `401` response and do not
disclose which credential factor failed.

## Authority exclusions

- The certificate does not grant roles, executor profiles, Capabilities, Permits, leases, or result
  authority.
- Human OIDC mappings cannot receive Worker authority.
- Target TLS session binding cannot authenticate a Control Plane Worker.
- `worker_id` request fields remain status/lease inputs, not authentication identity.
- Proxy-terminated mTLS and certificate-forwarding headers are unsupported.

## Validation

- Windows configuration and fail-closed tests cover incomplete server/client settings, protocol
  wiring, and environment policy parsing.
- Linux loopback tests perform real TLS handshakes for the correct certificate, a different
  CA-valid certificate, missing client certificate, and certificate-free Human access.
- Existing Control Plane bearer/OIDC and Worker daemon regression tests run unchanged.
