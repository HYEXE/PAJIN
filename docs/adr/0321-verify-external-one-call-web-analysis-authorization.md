# ADR-0321: Verify External One-call Web-analysis Authorization Before Durable Claim

- Status: Accepted
- Date: 2026-09-22
- Scope: WEB-007 prepared compact live-call Gate C
- Implementation status: the external Ed25519 trust anchor, narrow one-call statement, strict
  parsers, exact admission/request/model/transport verifier, and Gate B nonce-identity composition
  are implemented and test-verified. Gate D runtime and receipt integration and every actual model,
  Provider, or target dispatch remain pending.

## Context

[ADR-0319](0319-separate-prepared-compact-admission-from-live-call-authority.md) requires an
authorization supplied outside the execution code path before a prepared compact request may be
claimed or dispatched. The authorization must identify exactly one admitted completion, expire
quickly, resist replay, and grant no target or downstream assessment authority.

The prepared admission is intentionally non-authoritative. Likewise, the identity coordinate in
[ADR-0320](0320-durably-claim-prepared-compact-web-analysis-and-recover-cleanup.md) is only an
unverified input to the durable uniqueness domain. Neither object proves that an external issuer
approved the call.

Existing authorization types cannot be reused as this wire. The Pentest authorization contract
grants assessment targets, scope, and request budgets. Web Campaign approval, ActionApproval,
Capability, Permit, and proxy-route authority belong to different trust boundaries and carry
target-side meanings that this model-only authorization must not acquire. Reinterpreting any of
them would both widen authority and violate ADR-0319's external-issuer requirement.

## Decision

### 1. Add an adjacent verification-only contract

Add a Web-specific `analysis_live_authorization` module containing only:

- an externally provisioned Ed25519 verification-key lifecycle and trust anchor;
- a signed one-call statement and detached signature bundle;
- bounded, duplicate-key-rejecting parsers;
- a pure verifier configured with an independently retained trust-anchor digest and trusted clock;
  and
- an auditable verified result that is not dispatch-ready.

The production module has no private key, signer, issuer, approval compiler, Provider client,
model endpoint, worker, target client, or process-local replay cache. Test code may construct
signatures to prove the verifier, but execution code cannot synthesize an accepted authorization.

The trust anchor is supplied independently from the signed bundle and must match a separately
retained digest. A bundle cannot introduce or select an attacker-controlled trust root. The keyring
is uniquely sorted, has exactly one active key, and records explicit active, retired, or revoked
lifecycle states. A live authorization accepts only its exact active key.

### 2. Bind the external grant to one exact prepared completion

The signed statement binds all of the following:

- issuer, trust domain, signed key ID, and a 16-to-256-character nonce;
- admission ID and digest;
- preparation Run ID, Run root, preparation identity, and Index digest;
- exact live-request, Provider registration, Provider chat request, compact projection, and
  response-schema digests;
- Provider ID and selected model ID;
- Capacity v2 Pin, registered model Pin, model SHA-256, model size, model image, and platform
  manifest;
- transport Pin, transport version, worker action, Worker image, and proxy image; and
- exact attempt one, maximum dispatch count one, and one model-completion grant.

The verifier canonicalizes and revalidates the exact concrete admission, live request, Capacity v2
Pin, and transport Pin before comparing every signed value. A valid signature over a mismatched
request, model, Capacity Pin, or transport still fails closed.

The statement also requires tools and streaming to remain disabled. Target request, Tool,
Capability, Permit, Finding, Graph admission, report, delivery, retry, scope expansion, general
execution, and automatic redispatch authority are all required literal `false`. A
`campaignApprovalReinterpreted` marker is also required literal `false`; a code-generated Campaign
approval or another approval type is rejected by the exact input type before signature checking.

### 3. Limit validity to 180 seconds

Issue, not-before, expiry, key-lifecycle, and evaluation timestamps must be timezone-aware. The
statement must satisfy `issuedAt <= notBefore < expiresAt`, and `expiresAt - issuedAt` may not exceed
180 seconds. Evaluation uses `notBefore <= now < expiresAt`; the exact expiry instant is invalid.
The entire authorization window must fit inside the signing key's validity.

The 180-second ceiling matches the pinned Web transport's Worker-open, proxy-exchange, and job
timeouts. It is a validity ceiling, not permission to retry for 180 seconds. Gate D must verify the
authorization again immediately before consuming the durable dispatch marker.

### 4. Compose replay resistance with the Gate B durable journal

After signature and exact-binding verification, the verifier creates the existing Gate B
authorization coordinate itself. The coordinate binds the exact canonical bundle digest and derives
its authorization identity from the verified issuer, bundle key ID, and nonce.

Gate C remains stateless. Verifying the same still-valid bundle twice may return the same result;
that does not consume it. The first Gate B atomic reservation consumes the authorization identity.
Any later exact replay or a differently signed statement using the same issuer, key, and nonce has
the same identity and loses the journal's independent authorization `UNIQUE` constraint, including
when paired with a new preparation. This avoids a process-local pre-check and the resulting
time-of-check/time-of-use race or second replay authority.

### 5. Keep the verified result non-bearer until Gate D composes all gates

The verified result records successful signature, admission, preparation, request, model,
transport, validity, and nonce binding and the single external completion grant. It also fixes
`authorizationConsumed=false`, `durableClaimPresent=false`, `liveMaterializationAttested=false`,
`dispatchReady=false`, and `dispatchCount=0`, with every downstream authority false.

Gate C does not strict-reload the sealed source, Skill, Capacity, preparation, or admission files,
reserve the journal, materialize the model, invoke a Provider, or create a receipt. Gate D must
strict-reload the immutable inputs first, run this verifier, reserve the verified coordinate,
materialize and attest Gate A resources, and re-run authorization verification immediately before
its one possible dispatch. A serialized verified result alone is never accepted as renewed
authority.

## Consequences

### Positive

- A valid signature cannot authorize a substituted request, model, transport, or preparation.
- The execution code path contains no private signing material or local authorization issuer.
- Replay resistance remains one durable authority with independent preparation and authorization
  uniqueness rather than an in-memory cache plus a database.
- Campaign, target, Tool, Finding, Graph, report, delivery, and retry authority stay outside the
  one-completion grant.
- Gate D receives a verified coordinate that it did not accept from an untrusted caller.

### Cost and remaining work

- Deployment must provision an external public-key trust anchor, retain its expected digest, and
  define key rotation outside the execution process.
- A single-host Gate B journal remains the replay authority; multi-host operation would require a
  different consensus-backed uniqueness boundary.
- Gate D must still compose strict reload, verification, atomic claim, Gate A materialization,
  pre-dispatch revalidation, one dispatch, cleanup, and the terminal receipt in ADR-0319 order.
- Model output, Provider behavior, proposal quality, latency, memory, stability, and every target
  action remain unverified. No model, Provider, or target call is made by this decision.

## Rejected alternatives

- Reinterpret a local Campaign approval, ActionApproval, Capability, Permit, Pentest authorization,
  or proxy-route authority as this model-only external grant.
- Put a signer or private key in the production verifier.
- Let the signed bundle supply its own trusted key without an independently retained anchor digest.
- Treat a valid signature as sufficient without exact admission, request, model, Capacity, and
  transport matching.
- Add a process-local nonce set or a second replay database before Gate B.
- Mark the verified result dispatch-ready or accept it without current-time revalidation in Gate D.
- Extend validity beyond 180 seconds or treat expiry as retry authority.

## Compatibility and rollback

This decision is additive. Existing admission, preparation, Capacity, transport, Campaign approval,
Pentest authorization, ActionApproval, Permit, proxy-route authority, and Gate B journal wires keep
their original meanings. None is migrated into the new authorization type.

Rollback removes or disables Gate C and therefore leaves prepared compact live dispatch disabled.
It does not permit a local approval fallback, reuse an unverified Gate B coordinate, reopen a
consumed nonce, widen validity, use a legacy runtime, or skip any other ADR-0319 gate.
