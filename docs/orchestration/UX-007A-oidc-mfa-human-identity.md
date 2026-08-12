# UX-007A: OIDC MFA Human Identity Admission

- Status: Implemented and verified
- Decision: [ADR-0166](../adr/0166-bind-mfa-oidc-identity-without-token-role-authority.md)
- Task ID: `UX-007A`
- Policy contract: `pajin.control-plane.oidc-human-trust-policy/v1`
- HTTP API version: existing `/v1` routes, unchanged
- Database schema: unchanged

## Goal

Admit a human principal to existing Control Plane routes from an externally completed OIDC login
without accepting an ID Token as a resource-server credential, granting token claims PAJIN roles,
changing Worker authentication, or creating a second route authorization model.

The slice consumes one RFC 9068-shaped JWT access token through the existing Bearer header. It does
not run an OIDC redirect flow or contact an issuer at request time.

## Threat model

The boundary assumes the deployment controls one strict-JSON trust policy and keeps the
authorization server's private signing key outside PAJIN. It defends against:

- unsigned or `alg=none` tokens and algorithm/key-type confusion;
- ID Token or generic JWT substitution for a resource-server access token;
- token-controlled key URLs, embedded keys, and unknown or revoked key IDs;
- wrong issuer, resource audience, OIDC client, scope, provider subject, or key lifecycle;
- expired, not-yet-valid, excessively long-lived, or stale-authentication tokens;
- missing or wrong provider-specific ACR/AMR MFA evidence;
- duplicate JSON keys, non-canonical base64url, non-finite JSON, oversized tokens, and deep claims;
- token `roles`, `groups`, or `entitlements` escalating local authority;
- one local principal subject being owned by both OIDC and opaque bearer authorities;
- one bearer value being accepted by more than one configured authenticator.

It does not defend against issuer private-key compromise, a malicious policy administrator, bearer
token theft and replay inside the token window, host compromise, or an issuer falsely asserting the
configured MFA semantics.

## Trust boundary

```text
external OIDC login / authorization server
  -> signed RFC 9068-shaped access token
  -> existing HTTP Bearer header
  -> bounded strict JWS parser
  -> deployment-pinned RS256 key and key lifecycle
  -> exact iss/aud/client/scope/time/MFA checks
  -> deployment-owned provider-subject to local-Principal map
  -> existing PrincipalRole route dependency
  -> existing service actor and append-only Run audit event
```

The token is authentication evidence only. The local mapping remains authorization authority.
Worker credentials do not enter this mapping.

## Policy schema

`PAJIN_CP_OIDC_HUMAN_TRUST_POLICY` contains one bounded strict-JSON object:

```json
{
  "api_version": "pajin.control-plane.oidc-human-trust-policy/v1",
  "policy_id": "oidc-human-policy_0123456789abcdef0123456789abcdef",
  "issuer": "https://identity.example.invalid/tenant",
  "audience": "https://control-plane.example.invalid",
  "client_id": "pajin-console",
  "required_scope": "pajin.control-plane",
  "required_acr": "urn:deployment:authentication:mfa",
  "required_amr": ["pwd", "otp"],
  "maximum_token_lifetime_seconds": 300,
  "maximum_authentication_age_seconds": 600,
  "clock_skew_seconds": 30,
  "keys": [
    {
      "key_id": "issuer-key-2026-08",
      "algorithm": "RS256",
      "public_key_spki_base64url": "<canonical DER SubjectPublicKeyInfo>",
      "state": "active",
      "not_before": "2026-08-01T00:00:00Z",
      "not_after": null,
      "revoked_at": null
    }
  ],
  "identities": [
    {
      "provider_subject": "provider-alice",
      "principal_subject": "oidc:alice@example.com",
      "roles": ["operator", "auditor"]
    },
    {
      "provider_subject": "provider-bob",
      "principal_subject": "oidc:bob@example.com",
      "roles": ["approver", "auditor"]
    }
  ]
}
```

The serialized field names above are exact. Unknown and duplicate members are rejected. The inline
policy is limited to 256 KiB, depth 24, 8,192 JSON nodes, 32 keys, and 256 identities.

### Key rules

- `algorithm` is exactly `RS256` in v1.
- Public material is canonical unpadded base64url DER SubjectPublicKeyInfo.
- RSA modulus size is at least 2048 bits.
- Key IDs are unique and token `kid` selects exactly one policy key.
- `revoked` rejects every token immediately.
- `retired` requires `not_after` and accepts only tokens issued before that boundary.
- Token issuance cannot predate key `not_before`.
- No request-time discovery, JWKS fetch, `jku`, `x5u`, or embedded `jwk` exists.

### Identity and role rules

- Provider and local principal subjects are each unique.
- OIDC identities may receive Operator, Approver, or Auditor only.
- Operator and Approver cannot be combined in one identity or one local subject.
- Worker cannot be combined with or derived from OIDC human identity.
- A local subject cannot appear in both OIDC policy and opaque bearer credentials.
- Token authorization claims are ignored even when cryptographically valid.

## Access-token validation

The compact token is limited to 16 KiB and exactly three non-empty canonical base64url segments.
The protected header is a closed object containing only `alg`, `kid`, and `typ`. `typ` accepts the
media types `at+jwt` and `application/at+jwt` case-insensitively. The claims object is strict UTF-8
JSON with a 12 KiB, depth-8, 512-node ceiling.

The token must contain and satisfy:

| Claim | v1 rule |
| --- | --- |
| `iss` | exact policy issuer |
| `sub` | exact registered provider subject |
| `aud` | exact string or one-element array containing only the policy audience |
| `client_id` | exact configured OIDC client |
| `scope` | unique space-delimited values containing the required scope |
| `iat`, `exp` | bounded integer NumericDate and policy-bounded lifetime |
| `nbf` | optional bounded integer NumericDate, not in the future beyond skew |
| `jti` | required bounded visible-ASCII token ID; not treated as a one-use nonce |
| `auth_time` | bounded integer NumericDate, no later than issuance and within max age |
| `acr` | exact deployment-configured MFA context |
| `amr` | unique string array containing every deployment-required method |

Signature verification uses only the policy-selected RSA public key and PKCS#1 v1.5 SHA-256. Any
failure becomes the existing generic `invalid bearer credential` response; claims and failure
detail are not reflected to the caller.

## API, audit, and compatibility

The route surface, Bearer scheme, `Principal`, `PrincipalRole`, role dependencies, response models,
and database schema are unchanged. Existing service methods continue to record
`principal.subject` as their actor. A Run submitted by the example identity records
`oidc:alice@example.com` in the existing append-only `run.submitted` audit event.

With no OIDC policy, `PAJIN_CP_OPERATOR_TOKEN`, `PAJIN_CP_APPROVER_TOKEN`,
`PAJIN_CP_WORKER_TOKEN`, and `PAJIN_CP_CHECKPOINT_KEY` remain required exactly as before. With a
valid OIDC policy, static human tokens may be omitted, but the combined configured authorities must
still contain separated Operator and Approver roles. The Worker token and checkpoint key remain
required.

## Failure behavior

| Condition | Result |
| --- | --- |
| Missing or non-Bearer credential | `401 bearer credential required` |
| Invalid JWS, claims, MFA, key, mapping, or ambiguous authenticator result | generic `401` |
| Authenticated principal lacks the route role | existing generic `403` |
| OIDC and opaque credentials share a local subject | startup failure |
| Policy lacks separated effective Operator and Approver authority | startup failure |
| OIDC mapping contains Worker or combined Operator/Approver roles | policy validation failure |
| Dynamic discovery or unknown key | fail closed; no network request |

## Positive and adversarial verification

`tests/test_control_plane_identity.py` covers:

- `at+jwt`, `application/at+jwt`, and media-type case handling;
- deployment role mapping while a forged token `roles` claim is ignored;
- wrong issuer, audience, client, scope, subject, times, ACR, and AMR;
- ID-token types, `alg=none`, unknown key, wrong signature, revoked key, and duplicate JSON;
- weak RSA keys, Worker mapping, and combined Operator/Approver mapping;
- duplicate bearer authority rejection and cross-authority subject rejection;
- OIDC-only human environment configuration;
- API submission, existing durable actor audit, OIDC Approver read, static Worker route access, and
  unregistered-subject `401`.

The existing `tests/test_control_plane.py` suite verifies compatibility with static credentials and
all prior Control Plane route behavior.

## Benchmark impact

This slice changes no benchmark Target, policy arm, metric name, denominator, Result, comparison,
or activation eligibility. Every OIDC request adds one RS256 verification plus bounded JSON and
mapping checks. No throughput or latency claim is made; an operational authentication benchmark is
follow-up work if deployment SLOs require one.

## Migration and rollback

Migration is configuration-only:

1. obtain issuer metadata out of band and pin the exact issuer, resource audience, client ID,
   required scope, provider-specific MFA semantics, and RSA public key lifecycle;
2. register distinct local Operator and Approver subjects;
3. start with the policy and, if desired, temporary distinct legacy human credentials;
4. verify OIDC route access and audit actors; and
5. remove legacy human tokens once the deployment rollback window closes.

Rollback removes the policy and restores separated static Operator and Approver tokens before
process start. No database or artifact migration is required, and existing audit actors remain
readable.

## Deferred scope

- authorization-code redirect, PKCE, browser session, logout, refresh, and token issuance;
- discovery metadata, remote JWKS, live key refresh, and multi-issuer routing;
- access-token revocation/introspection and `jti` replay storage;
- ABAC decisions or direct role/group/entitlement claim authority;
- Worker workload identity, mTLS, proxy certificate forwarding, and certificate rotation;
- TLS 1.3 exporter and external transparency anchoring.
