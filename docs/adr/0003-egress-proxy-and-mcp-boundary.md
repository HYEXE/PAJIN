# ADR-0003: Egress proxy and registered MCP execution boundary

- Status: Accepted
- Date: 2026-07-12

## Context

PAJIN tools need controlled access to authorized targets, while a compromised agent, prompt, Tool
Adapter, or MCP server must not gain general network or process execution. Docker's `--network none`
is a safe default but cannot support real target validation. Giving the Worker the ordinary bridge
network would make the campaign scope an application convention instead of a network control.

MCP adds a second boundary problem. If an agent can provide a server command, executable path, or
arbitrary stdio arguments, an apparently valid MCP call becomes unrestricted process execution.

## Decision

### Network egress

1. A Tool Adapter always prepares a network-disabled `WorkerJob`. The Tool Gateway rejects any
   adapter that attempts to self-grant a network mode or egress policy.
2. For a registered `ToolSpec` with `network_access=true`, the Tool Gateway creates an `EgressPolicy`
   from the authorized campaign allow scope, deny scope, allowed methods, and private-network rule.
3. Every network execution receives a new Docker `--internal` network. The Worker joins only that
   network and receives HTTP(S) proxy environment variables.
4. A dedicated, non-root, read-only, capability-free proxy container joins both the internal
   network and the configured external Docker network. It is removed with the internal network when
   the execution ends.
5. The proxy parses the requested URL, applies deny-before-allow rules, resolves DNS, rejects the
   entire result if any address is prohibited, and connects to the validated literal address.
6. Private, loopback, link-local, multicast, unspecified, and reserved addresses are denied by
   default. Private destinations require explicit campaign rules of engagement.
7. Proxy allow, deny, and typed error events are attached to Worker evidence. Query values and raw
   exception text are not persisted.
8. Plain HTTP requests receive full method, authority, path, query-policy, and destination-IP checks.
   HTTPS remains end-to-end encrypted: the proxy can enforce only the CONNECT authority, accepts
   only a host-wide `/*` or `/**` allow rule, and denies the whole authority when any deny rule
   targets it. Exact HTTPS method and path come from the Gateway-bound fixed Worker action, not from
   proxy inspection. CONNECT events are explicitly `receiptEligible=false` and record
   `methodEnforcement=trusted-worker-only` plus `pathEnforcement=authority-only`; they are not
   request or response receipts. PAJIN does not intercept TLS.

### MCP execution

1. Host-side MCP tools are registered as canonical `ToolSpec` entries and still pass through the
   ordinary Policy Engine and Tool Gateway.
2. A registered adapter can send only `serverId`, `toolName`, and `arguments` to the Worker action
   `mcp-call`. It cannot send an executable path or server arguments.
3. The Worker owns a separate fixed server catalog mapping IDs to commands and allowlisted tool
   names. Unknown servers and tools fail closed.
4. The Worker bridge uses the official MCP Python SDK v1, initializes a stdio session, checks
   `list_tools`, and calls the registered tool only if the server advertises it.
5. The MCP SDK is resolved for Python 3.12, pinned below v2, and hash-locked with its transitive
   dependencies and platform markers. The Docker build downloads binary wheels from the configured
   package index (or cache), requires every selected distribution hash to match, and does not disable
   TLS verification. It is reproducible with respect to the lock, but is not an offline build.
6. The Worker drains bridge stdout and stderr concurrently while retaining only fixed-size prefixes.
   Either stream exceeding its limit fails closed, and timeout or cancellation kills the bridge's
   process group before the action returns.
7. The host adapter accepts only the strict bridge envelope: `isError` is a real boolean, content is
   bounded and typed, duplicate JSON keys and reserved identity fields are rejected, and target,
   server, and tool identity come only from the request plus the sealed registration.

## Consequences

### Positive

- Destination authority, DNS result, and plain HTTP scope are enforced at both the Tool Gateway and
  the network boundary. Exact HTTPS requests remain bound to trusted fixed Worker actions.
- Direct sockets from the Worker cannot bypass the proxy through the internal Docker network.
- DNS rebinding toward a prohibited address is rejected before connection.
- Agents cannot turn MCP registration into arbitrary process execution.
- Every actual network decision and MCP result is reproducible from campaign evidence.

### Trade-offs and residual risks

- HTTPS method and path details are invisible to the proxy. Host-wide authorization is therefore
  required, path-specific HTTPS deny rules fail closed for the whole authority, and a CONNECT event
  cannot attest which encrypted request was sent. Compromise of the trusted fixed Worker action is
  outside this proxy's method/path enforcement boundary.
- Proxy policy JSON, response buffering, and JSON receipt parsing are bounded. The fixed 64 MiB proxy
  container admits at most an 8 MiB response; larger configured limits fail validation rather than
  relying on an eventual out-of-memory kill.
- The local Docker daemon and external Docker network remain trusted infrastructure. Production
  deployment needs a hardened remote worker plane, image digests and signatures, and host firewall
  controls.
- The host and Worker MCP catalogs can drift. Runtime `list_tools` verification catches missing
  tools, but a future signed registry should generate both catalogs from one reviewed source.
- The development proxy supports bounded HTTP/1.1 and CONNECT; it is not a general-purpose forward
  proxy and intentionally omits protocols such as UDP and arbitrary TCP.

## Verification

The following checks form the acceptance evidence for this decision:

```powershell
.venv\Scripts\pajin egress-check
.venv\Scripts\pajin run examples\egress-proxy.yaml --worker docker
.venv\Scripts\pajin run examples\mcp-tool.yaml --worker docker
.venv\Scripts\pajin mcp-check
.venv\Scripts\pytest -q
```

The Docker verification must show an allowlisted request succeeding, a denied authority being
rejected, a direct socket bypass being blocked, CONNECT evidence remaining explicitly ineligible as
a request receipt, the registered MCP tool producing one validated finding, and no residual PAJIN
containers or per-execution networks.
