# NET-001B: Passive TCP Service-identification Capability

- Status: Implemented, preparation and bounded Tool/Worker/Gateway adapters
- Capability: `pajin.network.tcp-passive-service-identification@1.0.0`
- Tool: `network.service-identify@1.0.0`
- Binding API: `pajin.dev/network-service-identification-binding/v1alpha1`
- Preparation API: `pajin.dev/network-service-identification-preparation/v1alpha1`
- Authority: `src/pajin/capabilities/network_service.py`
- Tool and Worker path: `src/pajin/tools/network.py`, `containers/worker/worker_entry.py`
- Decision: [ADR-0221](../adr/0221-bind-passive-service-identification-without-network-authority.md)

## Purpose

NET-001B binds one NET-001A `network-port` Surface to an exact read-only CAP-002 service-
identification Capability, the current Campaign Scope, a fixed passive TCP protocol budget, and
the DOMAIN-004 minimum Network Worker boundary. The preparation boundary produces a
`PreparedCapabilityAction` only. It does not issue a Permit, select or materialize a Worker,
grant egress, open a connection, produce an Observation, seal Evidence, or admit Graph knowledge.

The bounded Tool, Worker action, and Gateway attenuation adapters exist only for use inside the
ordinary Policy, Approval, ActionPermit, deployment-owned Worker identity, and trusted network-
receipt path. This contract does not compose an end-to-end deployment or bypass or satisfy any of
those downstream authorities.

## Exact supported coordinate

The v1 Capability accepts exactly one canonical IPv4 or IPv6 literal, TCP, and one port from 1
through 65535. DNS names are rejected rather than resolved. UDP, ranges, CIDRs, wildcard hosts,
raw IP protocols, application-protocol requests, credentials, and port enumeration are outside
the Capability.

The fixed `tcp-passive-banner-v1` budget is:

| Dimension | Value |
| --- | --- |
| Connection units | 1 |
| Application-protocol write bytes | 0 |
| Maximum passive banner | 1,024 bytes |
| Connect timeout | 5,000 ms |
| Banner-read timeout | 2,000 ms |

The only bytes written by the Network Worker are the HTTP `CONNECT` request to the PAJIN egress
proxy. After the proxy establishes the exact target tunnel, the Worker sends no bytes to the
target service and reads at most one bounded passive banner. The deterministic v1 classifier may
label only `ftp`, `imap`, `pop3`, `smtp`, or `ssh`; an absent label is not a negative conclusion.

## Capability and authority binding

The Capability is experimental, T2, `READ_ONLY`, network-enabled, approval-required, and costs
one request unit. Its complete CAP-002 authority set binds all seven required roles:

- materializer;
- action compiler;
- executor adapter;
- result normalizer;
- success Oracle;
- Replay strategy, explicitly unavailable; and
- cleanup handler, explicitly unavailable because this read-only action creates no managed Target.

Activation accepts only an externally signed, current Range release resolved by the existing
Capability lifecycle registry. The binding pins the complete code-backed Capability identity,
the NET-001A `network-port` locator registration, the exact Network classification, and
`pajin.worker-boundary.network.minimum`. The Worker profile requires exact
address-family/host/port/protocol identity, probe-count/response-bytes/runtime budgets, no host
filesystem, no credential, isolated non-root runtime, and reviewed protocol privileges.

The global DOMAIN-003 inventory is intentionally unchanged because its established code-owned
bundle set does not contain this additive Capability. NET-001B instead exposes a resolvable,
content-addressed local classification containing the full code-backed authority reference and
the exact Network Domain reference. That projection is not activation, Worker selection, or
execution authority.

## Campaign Scope projection

Preparation derives the canonical HTTPS `CONNECT` target for the exact IP/port and requires the
Campaign allow list to contain the matching host-wide rule, such as
`https://192.0.2.10:2222/**`. `CONNECT` must be present in Rules of Engagement. Any deny rule with
the same authority rejects preparation, even if its path would not normally overlap, because a
CONNECT tunnel has no enforceable application path after establishment.

Private, loopback, link-local, reserved, and other non-global addresses additionally require
`allowPrivateNetworks=true`. The content-addressed Campaign projection preserves Campaign digest,
Scope, allowed methods, and the private-network flag, but is not a canonical Network Surface and
grants no approval or execution authority.

At Gateway re-entry, CONNECT egress is attenuated to the one exact host-wide allow rule and the
Tool-specific 1,024-byte response ceiling. The Tool trusts a successful result only when the host
records exactly one matching HTTPS CONNECT receipt. Tool output, Worker self-report, and Network
Domain metadata cannot substitute for that receipt.

## Preparation output and non-authority guarantees

`prepare_network_service_identification` revalidates the signed activation, Campaign, typed
Surface, exact Scope rule, RoE method, private-network flag, protocol budget, and compiled request.
It returns a content-addressed `NetworkServiceIdentificationPreparation` in
`prepared-not-authorized` state.

The preparation explicitly records that no Worker job or egress policy was materialized, no DNS
lookup or connection occurred, no Observation or Evidence was produced, no Graph admission
occurred, and no approval, Permit, Gateway dispatch, Worker selection, or execution was granted.
Runtime use must still follow the existing Policy/Approval, one-use ActionPermit, Gateway,
deployment Worker, direct mTLS, and trusted receipt boundaries.

## Fail-closed behavior

Definition, authority set, activation, Domain classification, binding, Campaign projection,
protocol budget, and preparation are content-addressed or exact code-owned values. Resolution and
preparation reject DNS or cross-family hosts, UDP, service-declared Surfaces, missing exact Scope,
same-authority deny rules, absent CONNECT RoE, unauthorized non-global addresses, stale or
substituted releases, Tool or role drift, altered budgets or requests, digest drift, extra fields,
authority-marker escalation, and boolean/integer coercion.

Worker input is validated again before any socket is created. The Worker connects only to its
configured HTTP egress proxy, validates the CONNECT response with bounded header storage, sends no
target application bytes, and bounds banner reads. Malformed or relabeled output fails Tool
interpretation, and missing or mismatched trusted network receipts fail execution validation.

## Observation, Replay, and benchmark boundary

The service label and banner bytes returned by this Tool are execution output, not admitted
`network.host-service` Observation/Evidence. NET-001C separately verifies a sealed approved Run
and admits neutral protocol knowledge through the existing Graph writer. NET-001D owns fresh
handshake Replay and isolated-service measurement. NET-001B creates no Finding, confirmation,
negative conclusion, Ground Truth, Replay result, or benchmark metric.

## Compatibility and rollback

The Capability, Tool, Worker action, Tool response-budget hook, and CONNECT-specific Gateway
attenuation are additive. Existing non-CONNECT Tool behavior and existing discovery, Graph, Scope,
artifact, and Capability wires retain their versions. Rollback removes these additive components,
exports, tests, contract, and ADR. Serialized NET-001A Surfaces remain valid and inert.

## Verification

`tests/test_network_service_identification.py` covers the complete CAP-002 role set, signed release
activation, exact Domain/Worker/Surface/Scope binding, preparation non-authority markers, private
network and deny behavior, DNS/UDP/service-Surface rejection, digest and marker tampering,
Gateway attenuation, strict Tool interpretation, host-observed CONNECT receipts, and a fake-socket
Worker proof that only the proxy CONNECT is written and the passive banner is bounded.
