# ADR-0268: Exclude Checkpoint Operations from Enrolled Host Activity

- Status: Accepted
- Scope: OPS-001 local activity exclusion before cross-store checkpointing
- Builds on: ADR-0266 and ADR-0267

## Context

Startup fingerprints and durable budgets do not establish a quiet point for copying multiple
stores. Checking process IDs or writing an idle flag can race with a new claim, and stale flags
survive process failure. Supervisor and urgent-observation producers can also write outside the
default HTTP and Worker loops. A checkpoint operation needs exclusion that lasts for its entire
operation and participates in actual execution paths.

## Decision

Add an opt-in POSIX local host gate. Runtime inventory v2 binds one absolute host-root digest in
addition to the existing component code/configuration fingerprints. Every component using v2 must
configure that exact root. V1 serialization and unenrolled behavior remain unchanged, while v1
cannot enroll a gate. Old inventory readers reject v2.

Enrollment creates one private, exclusively created, fsynced `runtime-gate.json` binding a new gate
ID, the complete inventory digest/ID and the root digest. It never repairs or replaces an existing
gate. A participating activity holds a shared nonblocking kernel `flock`; a checkpoint operation
requires an exclusive nonblocking lock on that same file. Missing, noncanonical, substituted,
linked, nonprivate or relocated gates are rejected. Kernel locks disappear when all owning file
descriptors close, including on abrupt process exit. Gate files remain retained identities.

Hold activity across default CP construction and its serving lifespan, closing the CP repository
before releasing the serving lock. Default generic and Replay Workers retain their lock from
startup admission through shutdown/drain. Enrolled embedded Supervisor invocation and urgent-stop
admission require an admitted runtime context and retain their own shared descriptors through
completion. Invocation journal initialization and transactions enforce that same context. A child
operation cannot be mistaken for idle merely because its parent's context has ended.

Expose a context-managed quiescence API for the forthcoming checkpoint coordinator. Its live,
process-local handle is not a serializable idle claim or execution authority. The CLI can enroll a
new gate and check whether it can acquire exclusion at that instant; checking idle does not retain
exclusion after the command returns.

## Consequences and limits

This gate excludes only enrolled local activities obeying the supported entry points. Operators
must enroll all writers, keep launch configuration and code stable while running, and prevent
unenrolled programs from writing participating stores. POSIX local filesystem locking is the
supported boundary; Windows and network/distributed filesystem semantics are not established.

Kernel exclusion does not prove physical Worker cleanup, absence of orphan external resources,
complete participant/store inventory, consistent histories, or a correct backup. Unknown outcomes
still need their existing reconciliation authority. Complete OPS-001 requires explicit source/Run
and store bindings, consistent checkpoint contents/heads, encrypted retention and independently
expected restore verification before new execution.

Gate identity is location-specific. Code/configuration/key rotation needs a newly reviewed v2
inventory and a newly enrolled root after quiescing the old deployment. Retain the old gate and
state, and prevent old launch configurations from returning through the trusted process manager.
There is no in-place gate rewrite, hot revocation or independent detection of whole-host rollback.
