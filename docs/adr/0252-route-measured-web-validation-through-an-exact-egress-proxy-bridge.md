# ADR-0252: Route Measured Web Validation through an Exact Egress Proxy Bridge

- Status: Accepted
- Date: 2026-08-28
- Owners: PAJIN architecture and security boundary maintainers
- Scope: WEB-002A through WEB-002D
- Supersedes: ADR-0251 direct Worker-to-Target attachment details; all other ADR-0251 decisions remain accepted

## Context

[ADR-0251](0251-require-additive-target-routing-and-validation-policy-for-measured-web.md)
correctly requires additive WEB-002 Profile and Capability identities, an operation-fenced route,
a versioned validation-floor policy, and a distinct Finding projection. It also correctly preserves
the internal-only P0-D1/P0-E2B Target and the existing REDTEAM identities.

One deployment detail in ADR-0251 does not match the current trusted runtime. The Docker Worker
backend gives an egress-enabled Worker a per-execution internal network containing only that Worker
and its proxy. The proxy, not the Worker, joins the selected external network. The Worker can reach
only the proxy through injected proxy variables, while the host reads the proxy log after execution.
Attaching the Worker directly to the Target network would bypass this existing isolation and make
the route receipts described by ADR-0251 ambiguous.

## Decision

Retain Phase 22 and every additive identity, policy, Ground Truth, and Finding decision in ADR-0251.
Replace only its direct Worker-to-Target attachment model with an exact egress-proxy bridge.

WEB-002A must define a deployment-signed, operation-scoped proxy-route authority. In addition to the
bindings required by ADR-0251, it binds the exact Worker action, isolated Worker-proxy network
identity, proxy image and deployment identity, Target Factory network, internal service alias,
scheme, port, method, path, request budget, response ceiling, Target operation fence, expiry,
single-use consumption, and cleanup invalidation. Caller input cannot select any network, route,
proxy, image, service coordinate, or Docker operation.

WEB-002B and WEB-002D may materialize that authority only through a deployment-owned adapter:

1. create the normal per-execution internal Worker-proxy network;
2. start the exact egress proxy on the authorized Target Factory network;
3. connect that proxy to the internal network under its fixed `egress-proxy` alias;
4. start the Worker only on the internal network with `NetworkMode.EGRESS_PROXY` and the exact
   WEB-002 egress policy;
5. permit only the three fixed plaintext HTTP `GET` requests to
   `http://target:8080/v1/users/lookup`, with no arbitrary CONNECT, DNS, method, path, body, or
   caller-authored payload;
6. collect host-observed proxy route/request/response receipts and Worker result Evidence; and
7. remove the Worker, proxy, and internal network, reconcile the Target operation, and invalidate
   the route before Target cleanup completes.

The Worker never joins the Target Factory network and never receives its identity. The Target has
no published host port. The proxy is the only component present on both the Target network and the
ephemeral internal network. A route is not satisfied by a generic `external_network_routes`
configuration entry: the adapter must reconstruct and consume the exact signed authority for the
current operation and must fail closed on any runtime drift.

The route Evidence must distinguish proxy attachment to and detachment from the Target network from
Worker attachment to the internal network. Missing, reordered, duplicate, stale, or untrusted
receipts prevent measurement, validation-floor satisfaction, and Finding projection. The separate
WEB-002B source measurement and WEB-002D controlled validation continue to require fresh Target
operations, fences, routes, approvals, Permits, Worker sessions, results, and Evidence.

## Consequences

- The existing Worker isolation and host-observed egress semantics remain authoritative.
- P0-D1/P0-E2B remains internal-only, and no host port or direct Worker-to-Target path is added.
- WEB-002A must version a proxy-route schema rather than a Worker attachment schema.
- The additive floor policy and Finding projection from ADR-0251 are unchanged.
- Phase 22 still introduces no execution authority until the later materialization slices.

## Rejected alternatives

### Attach the Worker directly to the Target network

Rejected because it bypasses the proxy-only Worker boundary, exposes Target-network membership to
the Worker, and conflicts with the current Docker Worker backend.

### Publish the Target on the host

Rejected because it weakens P0-E2B isolation and changes the measured deployment surface.

### Treat a configured external-network route as signed operation authority

Rejected because a process configuration mapping is not bound to a Target Run, operation fence,
Campaign, Scope, Permit, expiry, single-use consumption, or cleanup state.

### Reuse the benchmark scanner container as the controlled validation Worker

Rejected because Scanner measurement and controlled validation require distinct execution,
authority, and Evidence identities.

## Security and authority impact

This ADR corrects a planned deployment boundary and executes nothing. WEB-002A keeps proxy-route
materialization, Docker operations, Target access, Worker execution, Graph admission, measurement,
floor satisfaction, Finding projection, product activation, and report delivery false.

Future materialization grants the deployment adapter only the exact proxy bridge needed for one
current Target operation. It grants neither the Worker nor the caller a Docker socket, Target
network membership, arbitrary egress, credential, host port, image selection, or reusable route.
Any cleanup ambiguity or fence advancement fails closed and invalidates the route.

## Compatibility and rollback

The correction is additive and precedes WEB-002 implementation. Existing Worker, proxy, REDTEAM,
P0-D1, P0-E2B, WEB-001, Capability, Permit, Result, Evidence, and Finding identities remain
unchanged. Rollback stops registering or issuing WEB-002 proxy-route authorities. Historical sealed
artifacts remain readable.

## Verification requirements

Tests must prove that the Worker is only on the internal network, the proxy alone bridges to the
exact Target network, the Target publishes no port, the fixed three-request policy is reconstructed,
and host-observed receipts cover attachment, every request/response, detachment, reconciliation, and
cleanup. They must reject direct Worker attachment, caller-selected networks, generic route-map
substitution, foreign or stale operations, fence drift, replay, double consumption, proxy/image
drift, arbitrary CONNECT/DNS/method/path/body, missing receipts, and cleanup failure.

WEB-002B and WEB-002D require opt-in real-Docker conformance. Fake Docker runners validate command
construction and fail-closed logic but do not prove live network isolation or cleanup.

## Related contracts and decisions

- [ADR-0251](0251-require-additive-target-routing-and-validation-policy-for-measured-web.md)
- [ADR-0250](0250-prioritize-governed-measured-web-validation-before-new-domain-runtimes.md)
- [ADR-0003](0003-egress-proxy-and-mcp-boundary.md)
- [P0-D1](../benchmark/P0-D1-traditional-web-api-target-catalog.md)
- [P0-E2B](../benchmark/P0-E2B-zap-scanner-baseline-measurement.md)
- [DOMAIN-006](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
