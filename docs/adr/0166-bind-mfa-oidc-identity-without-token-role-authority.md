# ADR-0166: Bind MFA OIDC Identity without Token Role Authority

## Status

Accepted

## Context

The Control Plane authenticates opaque bearer credentials and maps each credential directly to a
local `Principal`. This preserves role separation, but it requires long-lived human secrets and
does not bind a human request to an external login, authentication context, or MFA method. Worker
credentials use the same HTTP scheme and must remain compatible while Worker Identity and mTLS are
designed separately.

Accepting an arbitrary JWT would be unsafe. An OpenID Connect ID Token is issued to a client, not to
the Control Plane resource server. Token-selected algorithms, key URLs, audiences, roles, or groups
could create algorithm confusion, cross-JWT substitution, SSRF, or a duplicate authorization
authority. Dynamic discovery and JWKS refresh also need their own rollback and availability
contract before they can be trusted at runtime.

UX-007A therefore needs the smallest resource-server boundary that can consume the output of an
external OIDC login without implementing the login redirect flow, expanding Worker authority, or
treating provider role claims as PAJIN roles.

## Decision

### Accept only an explicitly typed access-token profile

The Control Plane accepts a compact signed JWT only through
`pajin.control-plane.oidc-human-trust-policy/v1`. The token must carry `typ=at+jwt` or
`application/at+jwt`, case-insensitively as a media type, and must use the policy-pinned `RS256`
key selected by an exact `kid`. ID-token and untyped JWT values fail closed.

The verifier uses bounded canonical base64url, strict UTF-8 JSON, duplicate-key rejection, a closed
protected-header shape, a 16 KiB token ceiling, a 2 KiB header ceiling, and a 12 KiB claims ceiling.
It never reads `jku`, `x5u`, embedded `jwk`, or another token-selected key location. RSA keys are
deployment-pinned DER SubjectPublicKeyInfo values with at least 2048 bits and explicit
active/retired/revoked lifecycle state.

### Bind the token to one deployment-owned resource and login context

The verifier requires exact `iss`, one exact `aud`, exact `client_id`, a required scope, `sub`,
`iat`, `exp`, `jti`, `auth_time`, `acr`, and `amr`. It enforces a deployment-bounded token lifetime,
authentication age, clock skew, optional `nbf`, key not-before time, retirement time, and immediate
revocation. Multiple audiences are rejected in v1 to avoid ambiguous multi-resource authority.

`required_acr` and every `required_amr` value are deployment policy, not global interpretations of
provider-specific strings. A deployment must configure values whose semantics it has verified with
its issuer. Missing, stale, or mismatched MFA evidence fails authentication.

### Derive roles only from an out-of-band identity map

The policy maps one exact provider `sub` to one canonical local principal subject and a separated
set of Operator, Approver, or Auditor roles. Worker role is forbidden. Operator and Approver cannot
be combined. Token `roles`, `groups`, `entitlements`, and other authorization claims are ignored.

Provider subjects and local principal subjects are unique within a policy. OIDC and opaque bearer
authorities cannot share a local principal subject. The combined settings validator rechecks
separation of duties across all configured authorities. If two authenticators nevertheless accept
the same presented bearer value, the chained authenticator rejects it as ambiguous.

### Preserve the existing API and audit authority

All protected routes continue to use the existing HTTP Bearer dependency and existing
`PrincipalRole` checks. A successfully mapped OIDC principal flows through the existing service
actor parameter, so durable Run audit events retain its canonical local subject. No token, claims,
signature, or public key is written into Run events.

`PAJIN_CP_OIDC_HUMAN_TRUST_POLICY` accepts one inline bounded strict-JSON policy. When present, the
environment may omit static Operator and Approver tokens, but it must still provide separated
effective Operator and Approver authorities. The generic Worker token and checkpoint key remain
required. Existing deployments with no OIDC policy retain their former required secrets and
behavior.

## Consequences

- A provider-authenticated, MFA-bound human access token can reach existing Control Plane routes
  without granting token claims local role authority.
- ID-token substitution, `alg=none`, wrong-key signatures, unknown or revoked keys, issuer,
  audience, client, scope, time, subject, ACR, and AMR mismatches fail as the same generic `401`.
- Existing opaque bearer authentication and Worker routes remain compatible.
- RSA verification adds per-request CPU cost. This slice does not change PAJIN benchmark targets,
  denominators, or scores, and no performance claim is made.
- The policy is loaded once at process startup. Dynamic discovery, JWKS refresh, issuer metadata
  validation, and live key rollover are unavailable.
- This is a resource-server admission boundary after an external login. It does not implement an
  authorization-code redirect, PKCE, browser session, logout, token issuance, or refresh.
- `jti` is structurally required but not stored as a one-use nonce; access tokens retain normal
  bearer-token replay semantics within their short configured validity window.
- ABAC, Worker workload identity, mTLS, proxy certificate forwarding, and TLS 1.3 exporter binding
  remain separate follow-up trust boundaries.

## Rejected alternatives

### Accept OpenID Connect ID Tokens as API bearer tokens

Rejected because an ID Token is audience-bound to the OIDC client and can be confused with a
resource-server access token.

### Trust provider `roles` or `groups` claims directly

Rejected because issuer-side vocabulary would become PAJIN authorization policy and could combine
Operator, Approver, or Worker authority without the deployment-owned separation check.

### Fetch discovery or JWKS URLs from the token or request path

Rejected because untrusted network resolution would add SSRF, availability, refresh, and rollback
authority that this slice does not specify.

### Replace Worker credentials with the same human policy

Rejected because human login identity and workload identity have different lifecycle, possession,
transport, and attestation requirements. Worker mTLS remains a later slice.

## Compatibility and rollback

The change is additive. It does not change HTTP routes, request or response schemas, database
schema, audit-event schema, opaque credential format, or Worker client behavior. Existing settings
constructors gain one optional field with a `None` default.

Rollback removes the OIDC policy and restores separated static Operator and Approver tokens before
starting the old binary. Existing audit events remain readable because they store only the
canonical local principal subject. No database or artifact migration is required.

## Related documents

- [UX-007A contract](../orchestration/UX-007A-oidc-mfa-human-identity.md)
- [RFC 9068: JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068.html)
- [RFC 8725: JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0-18.html)
