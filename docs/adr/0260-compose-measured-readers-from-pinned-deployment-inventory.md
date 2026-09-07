# ADR-0260: Compose Measured Readers from Pinned Deployment Inventory

- Status: Accepted
- Date: 2026-09-07
- Owners: PAJIN architecture and security boundary maintainers
- Scope: UX-010 startup composition and read-only Console consumption

## Context

The Web, Network, and AI product APIs already reopen sealed predecessor evidence, but the default
Control Plane application does not construct their deployment-owned readers. An application author
must currently supply live Python objects. Directly serving the product JSON would lose the
independent source, Replay, approval, lifecycle, and cleanup checks.

## Decision

Use one private, bounded, SHA-256-pinned JSON deployment inventory. The server operator selects
its path and digest out of band. It contains explicit typed evidence coordinates and verification
material, never Python import paths, pickles, callables, or measurement signing keys. The loader
constructs the existing fixed providers, registries, and readers and verifies every configured
result before creating the Control Plane database or accepting requests.

Network lifecycle reconstruction uses retained public policy, review keys, and signed releases.
Graph, activation, route claim, and Worker evidence reconstruction opens existing state without
creation, schema repair, or migration. Web reconstruction
uses a provider without an attestor; this provider rejects lifecycle execution and signing before
operation claims. Retained Web terminal approval tuples are historical verification material,
not an approval issuer or a substitute for a live dispatch authority. Existing sealed source,
route claims, target journal, and Worker evidence are still independently reopened.

The deployment inventory is host trust configuration. Its digest is not a signature from an
independent authority, and the inventory must not come from HTTP inputs or discovered metadata.
Replacing policy or trust keys requires a reviewed inventory and process restart. Startup loading
does not implement hot revocation, distributed recovery, or rollback-resistant backup restoration.

## Consequences

- Default server startup and a configuration-only CLI share the same reconstruction and preflight.
- Unconfigured domains preserve the existing authenticated 503 behavior. Invalid configured
  domains fail startup with a safe stage diagnostic.
- Every GET still invokes the contextful reader. Startup validation is not a response cache.
- Network and AI Console panels disclose the synthetic benchmark ceiling, validate exact public
  schemas, and clear results on credential replacement, lock, and failed refresh.
- Browser constants are generated from the public model registrations and checked for drift.
- The private inventory can contain Ground Truth and retained request evidence. Keep it out of
  Git, public artifacts, logs, HTTP responses, and browser storage.
- Real Docker conformance remains a separate gate; simulated command-runner tests do not satisfy it.

## Alternatives

Direct JSON serving removes required verification. Dynamic Python factory configuration expands
the executable deployment surface and still leaves durable context recovery unspecified. A new
generic reader abstraction would duplicate the existing domain verifiers. Explicit data recipes
keep the transport contract additive and the existing verification boundaries reviewable.

## References

- [UX-010 deployment and Console contract](../orchestration/UX-010-measured-product-deployment-and-console.md)
- [ADR-0257 read-only Web product flow](0257-project-web-002d-through-a-read-only-operator-product-flow.md)
- [ADR-0258 measured Network](0258-select-governed-measured-network-service-identification-after-phase-23.md)
- [ADR-0259 measured AI](0259-select-governed-measured-ai-system-prompt-disclosure-after-phase-24.md)
