# NET-001A: Host, Service, Protocol, and Port Surface Model

- Status: Implemented, typed registry only
- API versions:
  - `pajin.dev/network-host-service-locator/v1alpha1`
  - `pajin.dev/network-host-service-locator-registry/v1alpha1`
  - `pajin.dev/network-host-service-surface/v1alpha1`
- Authority: `src/pajin/discovery/network_surfaces.py`
- Decision: [ADR-0220](../adr/0220-type-network-services-without-scan-authority.md)

## Purpose

NET-001A implements the locator schema reserved by DOMAIN-002 for `network.host-service`. It binds
the exact DOMAIN-001 Network classification and DOMAIN-002 Network type-set to secret-free host,
port, and service locators. It also provides a content-addressed typed Surface whose initial state
is `registered-not-authorized`.

This contract represents knowledge only. It does not resolve a DNS name, enumerate ports, infer or
probe a service, create a socket, inspect a banner, select a scanner, access a credential, send a
packet, expand Scope, or authorize execution.

## Locator classes

| Class | Locator kind | Exact fields | Meaning |
| --- | --- | --- | --- |
| `host` | `network-host` | address family and canonical host | One DNS name, IPv4 literal, or IPv6 literal; a DNS name remains unresolved |
| `port` | `network-port` | host, transport protocol, and integer port | One candidate coordinate with no service inference |
| `service` | `network-service` | host, transport protocol, integer port, and explicit service name | One declared service identity; the declaration is not an Observation or verification result |

The registry contains exactly these three mappings in code-owned order. TCP and UDP are the only
v1 transport identifiers. This is a representation boundary, not a claim that a Worker supports
both transports. Raw IP protocols, ICMP, SCTP, port ranges, wildcards, CIDRs, and scanner presets
are deliberately outside the v1 schema.

An unknown service is represented by a `network-port` locator, not a mutable or inferred service
alias. `network-service` rejects `unknown`, `auto`, and `default` names. It does not store product,
version, banner, certificate, request, response, or credential content; those require the later
Observation/Evidence boundary.

## Canonical host identity

Each host explicitly selects `dns-name`, `ipv4`, or `ipv6`:

- DNS names are IDNA-encoded, lower-cased, de-rooted, and validated label by label without making a
  resolver call;
- IPv4 and IPv6 literals are validated against the declared family and serialized in compressed
  canonical form; and
- URL syntax, user information, wildcard hosts, scoped IPv6 zone identifiers, cross-family
  literals, ambiguous roots, and control or surrounding whitespace fail closed.

The address family is part of content identity. A DNS name is never replaced with a resolved IP,
so constructing a locator cannot change the target or create time-dependent identity.

## Typed Surface identity

`NetworkHostServiceSurface` binds:

- the exact Network classification reference;
- the exact `network.host-service` DOMAIN-002 type-set reference;
- the complete locator-registry reference;
- one discriminated host, port, or service locator;
- the code-owned class for that locator; and
- a content-addressed Surface ID and digest.

The value is pre-Observation knowledge and is not the established evidence-bound `AttackSurface`.
It contains no Campaign, Scope, Capability, approval, Permit, scanner, Tool, Worker, request,
credential, secret, banner, Observation, or Evidence field. The existing discovery `SurfaceLocator`
union and `AttackSurface` wire remain unchanged.

## Threat model and fail-closed behavior

The primary threats are treating host or port metadata as authorized Scope, resolving a DNS name
into a different target, using a service label to select a scanner or privileged protocol path,
embedding credentials or banner evidence in classification metadata, and relabeling another
Domain's knowledge as Network authority.

Definitions, references, the complete registry, and typed Surfaces are content-addressed. Exact
resolution rejects locator class or model substitution, registry reordering, Domain relabeling,
address-family mismatch, protocol or port coercion, invalid service aliases, digest drift, extra
authority metadata, true authority markers, and non-boolean marker coercion.

## Trust boundary and non-authority guarantees

NET-001A adds only in-process typed values and exact registry resolution. It creates no new
publisher, durable store, audit event, network process, Worker, resolver, scanner, or execution
boundary. In particular, all of these remain false:

- DNS resolution, port enumeration, service probing, raw-socket use, and network access;
- Scope expansion, Capability activation, approval satisfaction, and Permit issuance;
- scanner, Tool, or Worker selection;
- credential access, Graph admission, runtime-support assertion, and execution.

NET-001B now separately binds an exact IP-literal TCP `network-port` Surface to a reviewed
read-only service-identification Capability, current Campaign Scope, fixed protocol budget, and
the DOMAIN-004 Network Worker boundary while stopping preparation before Policy/Approval,
ActionPermit, Gateway dispatch, or deployment-owned Worker selection. Its exact boundary is
[NET-001B](../capability/NET-001B-passive-service-identification-capability.md). NET-001C now
separately verifies one approved sealed NET-001B Run and admits only neutral protocol
Observation/Evidence and an optional open Hypothesis through the existing Graph writer.

## Audit and benchmark impact

The registry and Surface references are deterministic content-addressed values suitable for later
audit binding, but NET-001A emits no audit Artifact or Event. It registers no metric, Ground Truth,
Replay, validation-floor evidence, or benchmark Result. NET-001D owns the first isolated-service
benchmark and fresh-handshake Replay contract.

## Compatibility, migration, and rollback

The implementation is additive. Existing discovery locators, `SurfaceLocator`,
`SurfaceObservation`, `AttackSurface`, DOMAIN-002 semantics, Scope, egress, Capability, Worker,
Graph, and artifact readers remain unchanged. There is no data migration.

Rollback removes the additive module, public exports, contract, ADR, and consumers. Existing
serialized artifacts retain their exact wire and identity. New locator kinds or transport
identifiers require a versioned registry/schema change rather than silent membership expansion.

## Verification

`tests/test_network_host_service_surfaces.py` covers exact Domain/type-set/class membership,
content-addressed resolution, DNS/IPv4/IPv6 canonicalization, host/port/service identity,
non-inference between port and service, strict transport and port validation, discovery-wire
compatibility, authority escalation, metadata injection, identity/order/Domain substitution,
digest drift, and boolean coercion.
