# ADR-0281: Execute One Authenticated System OS-release Read

Status: Accepted for a bounded additive implementation; live verification pending.

## Context and selection

Cloud credentials and production host access are outside the authorized scope. An owned disposable
Linux container can expose real operating-system metadata through an authenticated host agent,
with an independent Python standard-library result. Select System rather than repeat APP-002.
The target represents that container's userspace distribution, not the host kernel or physical host.

## Decision

Add opt-in SYS-002: one GET of OS-release through a fixed mTLS agent. The agent reads only the
regular bounded `/usr/lib/os-release` file; no caller-selected file, command, write or enumeration
exists. Pin agent instance, certificates, client identity, implementation and exact Worker/proxy
images independently of evidence. Lease client credentials once to an isolated Docker Worker.
Require an explicit host-wide HTTPS Scope for CONNECT plus an exact reviewed endpoint, current
Capability release and Policy, separate signed operator approval and durable one-use Action Permit.
The proxy observes the TLS route; fixed trusted Worker code enforces method/path and peer identity.

Preserve the existing APP-002 and SYS-001 contracts/readers. Register a separate experimental System
Capability with all code-backed roles; do not assert SYS-001's broader replay/attestation requirements
are satisfied. Plan/replay/report metadata grants no execution or Finding authority.

Seal the exact request, approval/Permit, gateway/Worker evidence and normalized file result in RunStore.
Recompute from an independently pinned Run root and external deployment trust. A fresh separately
approved Run and a standard-library read inside the owned agent container provide additional checks.
Transport ambiguity and duplicate reads never produce synthetic success or automatic retry.

## Limits and consequences

The deployment, Docker controller, exact images, CA and pinned client/agent keys remain trusted.
One request per Permit is durable; the agent's bounded nonce ledger is process-local and does not
claim rollback resistance. Fixed-file access is read-only. Container/Worker/proxy cleanup is observed
outside the Worker; physical failure, arbitrary hosts, external rollback and whole-System support
remain outside scope. Secrets, raw private bytes and inventories remain private.

## Local validation checkpoint

The bounded implementation completed actual mTLS source/re-execution, independent standard-library
comparison, fresh-process sealed reporting and explicit negative/failure/cleanup cases. The final
fixture runner separately observed all four Worker/proxy lifecycles and both agent containers absent.
This closes the local validation item above; remote same-commit conformance and broader System
support remain separate. See SYS-002 for the measured scope and corrected fixture/reader failures.
