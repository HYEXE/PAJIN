# ADR 0288: Isolate an approved kernel ASLR read from OS-release authority

Status: Accepted

## Context

The next executable feature was selected as another System read using existing
owned Linux assets. SYS-002 already binds OS-release execution and sealed result
readers to exact code, schema, release, approval, image and target coordinates.
Extending its existing input or host parser would change authority commitments
used by retained evidence.

## Decision

Add SYS-004 as an explicit `system.aslr-read` capability and `pajin.system_aslr`
entry point. Read only `/proc/sys/kernel/randomize_va_space` through one fixed
`/v1/aslr` mTLS endpoint. Accept exactly `0`, `1` or `2` followed by a newline.
The agent bounds actual reads rather than relying on procfs `st_size`, and
requires two matching observations. It performs no sysctl write or process scan.

Reuse the existing Capability lifecycle, Policy, Graph approval/Permit,
ToolGateway, Docker Worker, egress proxy, Secret Lease and sealed Run engines.
Keep the small profile-specific authority composition and evidence reader in a
new namespace with distinct signature domains, Tool/Capability IDs, reservation
names and receipt versions. Preserve the existing SYS-002 source bytes and
artifact behavior. A general profile registry is deferred: introducing it here
would unnecessarily migrate already signed historical authority contexts.

Preparation remains unsigned. A separately pinned operator approves exact
intent; current release and Scope are checked before a durable one-use Permit
dispatches the fixed Worker. Read-only result reconstruction uses independently
pinned trust and Run roots and needs no agent credentials. Re-execution requires
new request, approval, Permit, Run and Worker coordinates. The fixture compares
actual bytes with GNU coreutils `od`, independently of the PAJIN parser.

## Limits

The value configures the kernel visible to the agent. It does not establish the
effective ASLR of each process, executable build properties, a vulnerability or
physical-host identity. Linux containers in the selected environment share a
guest kernel. Agent nonce history remains bounded and process-local; Graph
Permit consumption is the durable execution boundary. Target, TLS deployment and
image pins remain trusted infrastructure.

The new result is available through its explicit product CLI. SYS-003's existing
OS-release API and Console remain their own versioned reader. This slice does
not add arbitrary paths, commands, Cloud execution or default activation.
