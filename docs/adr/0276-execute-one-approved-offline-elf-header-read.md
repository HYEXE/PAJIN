# ADR-0276: Execute One Approved Offline ELF Header Read

- Status: Accepted
- Date: 2026-09-10

## Context

The next-domain task requires an actual execution and verification slice. Cloud/System retain
provider-credential and authenticated-host-agent prerequisites without configured live deployments.
Application can use the available offline Docker boundary and an independent LLVM fixture reader.
The existing APP-001 family deliberately remains preparation/admission contracts, including broader
artifact-mount and parser requirements. Turning those markers into execution authority would be an
incompatible trust-boundary change.

## Decision

Add the opt-in APP-002 `pajin.application.elf-header-read@1.0.0` Capability. It is experimental,
T2, read-only, approval-required and network-disabled. Its seven CAP-002 roles bind exact Tool,
image, parser, input and resource limits. Only a current signed Range release can activate it.
Keep existing APP-001 identities, false runtime markers, public imports and wire formats unchanged.

An unsigned intent names one immutable digest/size and an exact non-routable Campaign Scope
coordinate. A create-only reservation allows one intent per Run. The deployment's separately
pinned Ed25519 operator key signs the exact approval, including Campaign, release, Graph Snapshot,
proposal and request. The SQLite Graph store atomically consumes approval and ActionPermit before
the dedicated Gateway re-enters Policy and reads custody. Failed/uncertain dispatch remains charged;
retries do not redispatch. Another execution requires a fresh Run, grant, approval and Permit.

The deployment-owned POSIX custody reader accepts only an authorized digest filename in its private
directory. It rejects symlinks, hard links, non-regular files, mutable bytes and wrong digests/sizes.
Non-blocking open prevents FIFO substitution from hanging before the regular-file check. The fixed
Worker receives at most 256 KiB as an immutable stdin copy, never a mount, path or command supplied
by the proposal. It checks the copy's SHA-256 and reads bounded ELF64 little-endian header fields.
It never executes the artifact, loads its libraries or resolves its declared dependencies.

Use the existing real Docker backend with an exact local image ID, UID 65532, network=none,
read-only root, cap-drop-all, no-new-privileges and fixed resource limits. The trusted entrypoint
also observes its effective capabilities, privilege flag, root/tmpfs modes, active interfaces and
non-loopback routes. Administrative-down kernel links may exist; their names are not an isolation
decision. Any non-loopback active interface or route rejects the execution. Docker owns process
cleanup; a separate host query observes exact execution-label absence afterward. Unknown observation
never becomes verified cleanup.

Seal the request, signed approval, consumed Permit/receipt, detached Gateway/Worker result and cleanup
observation. The product reader requires independently supplied Run roots and deployment trust,
rechecks signatures/authority/timing/resource/input bindings and reinterprets the result. A fresh
authorized re-execution compares structural fields. The disposable fixture suite also uses LLVM to
check class, architecture, entry address and section count; compilation with `-c` supplies the known
relocatable type. Do not label this as independent verification of every ELF field or vulnerability.

## Consequences

APP-002 completes one bounded local read/report flow, not general Application support. It adds no
default activation, API/Console route, Discovery execution, Graph Finding, target write or remote
deployment. The explicit fixture harness uses disposable operator/reviewer/publisher identities;
those are fixture authorization, not production releases or approval of other artifacts.

The support floor is POSIX custody plus a trusted Linux Docker host and configured image/release/
operator pins. Distributed Campaign scheduling, Windows custody, cross-host attestation, whole-host
recovery, ELF32, big-endian/extended-numbering inputs and broader parser semantics remain outside
this feature. See [APP-002](../orchestration/APP-002-bounded-offline-elf-header-execution.md) for
execution evidence, reproduction and exact limitations.
