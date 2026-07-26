# ADR-0002: Tool Gateway and Docker Worker Isolation

- Status: Accepted
- Date: 2026-07-12

> Historical scope note: the fully network-disabled Worker described here was the state when this
> ADR was accepted. [ADR-0003](0003-egress-proxy-and-mcp-boundary.md) subsequently extended it
> with policy-controlled egress through a dedicated proxy while preserving Worker isolation.

## Context

PAJIN agents may use MCP, security CLIs, browsers, and code runners in the future. Allowing agents
or individual Tool Adapters to run processes and containers directly could bypass Scope,
Capability, budget, and evidence-collection controls. Tool names, arguments, and images generated
by a model are also untrusted input.

## Decision

1. Every Tool Invocation passes through a single `ToolGateway`.
2. A Tool Adapter does not execute anything directly; it prepares a `WorkerJob` and interprets a
   `WorkerResult`.
3. Before execution, the Tool Gateway checks Authorization, Scope, Capability, Risk, Method, and
   Budget policies.
4. Unregistered tools and images outside the allowlist are rejected before Worker dispatch.
5. The Docker Worker applies the following fixed controls:
   - `--network none`
   - `--read-only`
   - `--cap-drop ALL`
   - `--security-opt no-new-privileges`
   - Non-root UID/GID `65532`
   - CPU, memory, PID, and execution-time limits
   - Size-limited `/workspace` and `/tmp` tmpfs
   - Collection-size limits for stdout and stderr
   - `--pull never` and an image allowlist
6. On Timeout, the Docker client process and container are forcibly terminated.
7. The policy decision, safely reduced WorkerJob metadata, WorkerResult, and ToolResult are linked
   in a single evidence file.
8. The Simulated Worker is for development and unit testing only and is not considered a security
   isolation boundary.
9. General `pajin run` and `pajin multi-run` commands default to the Docker Worker. Selecting the
   Simulated Worker requires an explicit `--worker simulated` option.
10. Every Local and Multi-Agent Run derives its Worker identity from the actual backend instance,
    seals it in `execution-context.json`, duplicates its key fields in `run.json` and the
    `campaign.started` event, and renders it in the report. A simulated Run is always labeled
    `SIMULATED / NOT REAL TARGET EVIDENCE`; a CLI completion line alone is not its authority.
11. A Tool Adapter interprets successful Worker stdout only as one complete strict JSON object.
    Truncated stdout or stderr, duplicate object keys, non-finite numbers, and excessive tree depth
    or node count fail closed, preventing last-wins differences between raw evidence and the
    normalized ToolResult.

## Verification

`pajin worker-check` verifies the following through observations from inside the container:

- Non-root user
- Network blocking
- Read-only root filesystem
- Ability to write only to the restricted workspace
- Removal of Linux capabilities
- `no-new-privileges`
- Observed cgroup memory, PID, and CPU limits
- Forced termination on timeout
- Docker defaults for the general Run commands and explicit simulated opt-in
- Matching backend identity in the sealed execution context, Run summary, start event, and report
- Unmistakable development-only warnings on simulated CLI and report output
- Common Adapter decoder rejection of duplicate keys, truncated transcripts, and excessive JSON trees

## Consequences

### Positive

- Agents and Tool Adapters cannot bypass policy checks.
- Docker commands are built as argument arrays, reducing the risk of shell-string injection.
- External tool failures and policy denials remain in the same audit and evidence flow.
- Future remote Workers other than Docker can implement the same `WorkerBackend` contract.

### Negative

- The current Docker mode blocks the network completely, so it cannot test real targets.
- Target-specific egress control requires a separate network proxy or network-policy layer.
- Development images use the `pajin-worker:dev` tag; deployment additionally requires digest
  pinning and signature verification.
- The Docker daemon itself has elevated privileges, so a dedicated Worker host or hardened runtime
  is required.

## Next

The next step is to implement an egress proxy that enforces the target allowlist and an MCP
Adapter. MCP servers will not be exposed directly to agents and will be callable only behind the
Tool Gateway.
