# OPS-001: Single-Host Recovery and Urgent Stop

- Status: Implemented and locally verified for explicitly enrolled POSIX local SQLite deployments.
  First-use inventory, default and embedded producer binding, conservative budgets, key continuity,
  closed encrypted checkpoints, independently pinned restore and urgent cancellation/alerts are
  connected. Automatic deployment relocation/reactivation and distributed operation remain outside
  this version. Current-commit Docker and live PostgreSQL verification are separate pending gates.
- Scope: Sequential improvement 5, following UX-011.
- Existing authorities: APPROVAL-001C3, SUP-004B1/B3, HANDOFF-001 through HANDOFF-004,
  and ADR-0023/0024. ADR-0263 through ADR-0270 add the bounded slices below.

## Implemented checkpoint-key recovery slice

The default `create_app` lifespan verifies the schema, admits the complete configured checkpoint
keyring, and verifies every stored checkpoint before serving requests. This still runs with
`PAJIN_CP_INITIALIZE_SCHEMA=false`. Startup failure closes the repository. The `--check-config`
command validates configuration syntax without opening or creating the database; it does not
replace the serving startup's database continuity check.

Schema v16 adds `cp_checkpoint_key_identities`. It stores each key ID, first-seen time, and a
domain-separated HMAC-SHA256 commitment to the key bytes and ID. Commitments are neither signing
keys nor API output. Existing append-only update/delete/replace guards apply. SQLite writer
serialization and a PostgreSQL transaction advisory lock prevent conflicting first admissions.
The entire keyring is pinned only after all historical checkpoint signatures verify. Failed
verification or transaction interruption does not leave a partly pinned keyring. Creating a
checkpoint rechecks the stored commitments before signing. Embedded `ControlPlaneService` callers
must call `activate_checkpoint_keyring()` before admitting work; their checkpoint writer also
performs full admission if the startup hook has not completed.

The compatible rotation procedure is:

1. Quiesce the trusted deployment and retain its current database and required secrets under the
   existing access controls. Do not run old and new signing configurations concurrently.
2. Choose a new, unique `PAJIN_CP_CHECKPOINT_KEY_ID` and its `PAJIN_CP_CHECKPOINT_KEY`.
3. Set `PAJIN_CP_CHECKPOINT_VERIFICATION_KEYS` to a strict JSON object mapping previous key IDs to
   their original UTF-8 secret strings. This optional map allows at most 31 previous keys and
   64 KiB of JSON. Duplicate IDs, inclusion of the active ID, nested/non-string values, invalid IDs,
   and keys shorter than 32 bytes are rejected without secret details. IDs use 1-100 visible ASCII
   characters. The active key remains required, preserving the previous environment contract.
4. Start the server. Existing checkpoints must still verify, and new checkpoints use the selected
   active key. Previously consumed approvals remain consumed across new processes.
5. Omit a previous key only when no retained checkpoint needs it. Removing a required key blocks
   startup. Omission does not remove its permanent ID commitment or authorize reuse with new bytes.

The forward migration preserves existing Runs, checkpoints, approvals, signatures, and review
history. It adds an empty key ledger, then runtime admission authenticates existing checkpoints
before populating it. A missing v16 table with v16 history is rejected rather than re-created.
Rolling back executable code requires a separately retained, compatible database checkpoint; do
not delete the migration or key bindings in place. No automatic key retirement, remote revocation,
whole-host rollback detection, Graph verifier identity pin, or cross-store consistency is claimed.

Local checks cover actual default-API checkpoint creation and key rotation, fresh-process approval
resume and duplicate rejection, wrong/missing keys, corrupt checkpoints, an exact v15 upgrade,
two-repository conflicting admission, transaction interruption, append-only guards, missing-schema
rejection, and strict secret configuration. These are bounded CP recovery checks, not completion of
the full fault matrix below. PostgreSQL SQL construction is covered by migration tests; live
PostgreSQL behavior remains unverified at this checkpoint because the local Docker API was
unavailable. The final focused run passed 434 tests across checkpoint recovery, migrations,
Control Plane/service/identity, measured review models/API, Console, and packaging. Ruff and Linux
strict mypy passed (405 source files). This is local evidence for the current uncommitted worktree.

## Implemented journal-bound budget recovery slice

`SupervisorInvocationJournal.bind_budgets()` binds one Campaign controller and its distinct
Supervisor controller to that journal. The trusted caller supplies the exact Campaign and dedicated
policy digests; limits come from the two code-owned controllers. A role has one identity per
Campaign, so changing policy or limits cannot create a new allowance under the same Campaign.

`SupervisorCheckpointInvoker.invoke()` verifies the current schedule and Provider runtime, then
binds or restores both ledgers before claiming a new or unstarted invocation. Exact retries of
terminal or already-started history remain inspection/recovery operations; they do not dispatch.
For complete Campaign coverage, the trusted deployment must bind both controllers before its first
work and pass the same Campaign controller to the existing runners. Initial adoption includes all
already-accounted live usage, but cannot reconstruct a crash before the first binding. Complete
startup inventory admission is supplied by the first-use enrollment composition below.

Schema v2 adds `supervisor_budget_checkpoints` to the invocation database. Each append-only record
contains versioned canonical JSON, a domain-separated digest, predecessor, revision, owner,
original UTC duration origin, UTC recording time, full budget limits and all counters. A dual
reservation or release updates both histories in the same existing `BEGIN IMMEDIATE`, FULL
synchronous transaction. Direct Campaign mutations serialize through the same ledger. A failed
second write rolls the database back; an ambiguous commit fences the live controllers. Restart
reads the committed state, without inferring whether an unacknowledged commit succeeded.

Recovery verifies both complete histories, exact limits/policy and the current schema. It requires
fresh controllers, rejects clock rollback or expired duration, and restores elapsed time as at
least both the saved elapsed value and time since the original origin. New owner checkpoints fence
old owners before further mutation. Rebinding the same live pair reads and verifies its current
heads without appending. Bound controllers cannot accept caller-supplied replacement usage.

All active reservations are already charged before execution; recovery recreates no old handles
and provides no automatic refund for a dead process. Existing verified model settlement may reduce
its own live reservation to actual usage. Unknown model calls keep both upper bounds. Ordinary
Recon, Hypothesis, Local, Multi-agent, Tool Loop and AI validation-Control Tool calls now reserve
before awaiting the existing Gateway. Proven `executed=false` refunds; executed results, exceptions
and cancellation retain one call. Replay already charged its attempt before dispatch and preserves
that contract. No Capability or Permit check is replaced. If recording the end of an uncertain Tool
call fails, the original error/cancellation propagates with a generic accounting note, the charge
remains and the controller stays fenced; cancellation cleanup can still be reported. The Provider
failure path preserves this behavior for both single and dual durable model budgets.

An exact schema-v1 journal is verified and upgraded in one transaction. Its existing intents,
events and receipts are unchanged. A Campaign with legacy invocation history but no complete budget
history cannot bootstrap a zero balance. Historical terminal/unknown receipts remain readable and
unknown requests still cannot redispatch. Missing current-schema objects and corrupt legacy rows
are rejected without repair. Older executable versions cannot open schema v2; rollback requires a
separately retained compatible checkpoint and the complete deployment recovery contract. Removing
history, changing the Campaign or choosing another journal is not a supported recovery procedure.

Focused tests cover complete non-Supervisor consumption, uncertain dual and ordinary calls,
cross-process abrupt termination, stale-owner fencing, dual denial and mixed-journal rejection,
transaction/acknowledgement interruptions, partial restore failure, drift/expiry, immutable guards,
history corruption, legacy migration, actual cancelled Local execution and a replacement Supervisor
invoker attempting a different checkpoint after its budget was consumed. The combined run passed
313 tests in 50.08 seconds. This establishes local accounting, not complete-host rollback detection
or cross-store consistency.

## Implemented urgent-stop slice

`control_plane.urgent_stop_runtime.UrgentStopRuntime` is an explicit trusted-host producer. Its
constructor owns a `UrgentStopBinding`, the fast-gate and terminal authorities, an exact terminal
result and collaboration Snapshot, the Graph store, and sealed artifact sources. These are trusted
runtime configuration, never HTTP input or model-selected verifier/path/Run metadata. Bind the exact
CP Run and immutable submission digest, canonical Campaign digest, source Run and root, result
artifact and terminal handoff identities/digests, fast-gate identity/digest and cancellation actor.
The initial producer targets a CP submission containing its exact `input.manifest`; a Replay Run
or other input shape is not inferred as an equivalent target. Existing explicit Replay cancellation
and its new Worker reporting remain independently available.
The existing deployment Run-cancellation ABAC must authorize that actor and submission; no policy
or rule is inferred from a decision.

`runtime.admit(observation=..., decided_at=...)` verifies the source Campaign and root, resolves
the terminal authority, performs the existing fast-gate admission and complete verification, then
calls `ControlPlaneService.urgent_stops`. A separate `pajin.dev/urgent-stop-application/v1` records
the application. The original decision retains `admitted-not-applied` and its false authority flags.
Calling `UrgentObservationFastGateAuthority.admit` alone retains its existing metadata-only behavior.
There is no endpoint that converts a posted decision or Campaign display name into a stop action.

The consumer reuses `cancel_run_in_transaction`, preserving cancellation ABAC and the existing
Job/Approval/Run lock order. Run/Job cancellation, approval revocation and `urgent-stop.applied`
commit together in the existing append-only `cp_events` journal. An exact handoff is unique across
targets; SQLite writer serialization and a purpose-separated PostgreSQL transaction advisory lock
serialize application. Exact current-authority retries reuse the recorded application. A rebuilt
runtime uses the original durable decision time and still verifies the complete source inputs.
Failed source or target checks and injected post-flush write failures leave no partial cancellation
or alert. Schema v16 is unchanged.

Cancelling a leased Job first appends `job.stop-fenced` with a purpose-separated commitment to
the existing lease hash, Job, Run and owner. The active lease is then erased normally. No raw lease
or reusable lease hash is stored in the public journal. The two authenticated routes are:

- `POST /v1/worker/jobs/{job_id}/stop-observations`
- `POST /v1/worker/replay/jobs/{job_id}/stop-observations`

Both accept `pajin.dev/worker-stop-report/v1` with `workerId` and the original `leaseToken`, require
a cancelled Run and Job, and retain generic/Replay identity and route separation. Current generic
leases remain principal-bound; legacy unbound lease compatibility is unchanged. The report cannot
heartbeat, renew, finalize or authorize a resume. It contains only cancellation kind, timestamps,
bounded engine identity and cleanup status. `resourceCleanupVerified`, `executionAuthorized` and
`resumeAuthorized` must be literal false. Contradictory reports and impossible clock windows are
rejected. Exact duplicates return the same durable observation after a fresh CP process starts.
Legacy cancelled Jobs with no commitment do not acquire retrospective proof.

Both default daemon entry points inject the existing `ControlPlaneClient` as their stop reporter.
After bounded task draining they submit the original cancellation snapshot on their route family.
Delivery has a five-second timeout and does not replace the original cancellation/quiescence error.
The local status adds `stop_reporting_status` (`not-requested`, `recorded`, `failed`). Custom daemon
embedders opt in through `stop_reporter`; a missing report never proves a stop. A Replay parent may
report `executor-drained` while its child Run separately seals `quiesced`; these scopes remain
distinct. No Worker report attests external resources or side-effect rollback.

`GET /v1/urgent-stops` returns bounded pages with an event cursor and aggregate cancelled-lease,
reported, drained, locally quiesced and incomplete counts. Operator/Approver/Auditor reads are
allowed; Workers are excluded. `POST /v1/urgent-stops/{alert_id}/acknowledgment` requires an Operator
and the exact application digest. The append-only acknowledgment has no effect on Run state,
approvals, permits or budgets. The default Console loads alerts on connection and refresh, exposes
role-bound acknowledgment and older pages, clears unavailable/stale responses, and clears all data
on lock or credential replacement. No email or chat transmission is performed.

Local verification covers running Campaign cancellation through the actual CP client and registered
executor, sealed local cleanup, Replay forced fallback with separately scoped child evidence,
fresh-process duplicate reports, role/lease/target drift, concurrent application, atomic rollback,
historical acknowledgment and Console browser interactions. Live PostgreSQL and a complete restored
host are not verified by these tests. Runtime inventory must still install the exact producer before
supported Campaign work; this slice does not automatically enable urgent observations everywhere.

## Required operating outcome

A supported single-host deployment must preserve the authority and conservative accounting that
existed before restart. It must reject an incompatible verifier/configuration, an older or incomplete
backup, a duplicate executable request, and an unverified reconciliation of an uncertain operation.
An admitted urgent observation must reach a durable execution fence and a visible human alert.
The product must distinguish requesting cancellation from observing Worker cleanup or quiescence.

The supported boundary is one trusted host, its explicitly registered local stores and runtime
composition, and its existing authenticated Control Plane/Worker channels. Arbitrary alternate
databases, replacement runtime code, dishonest host administrators, distributed exactly-once
execution, and complete-host rollback without an independently retained expectation are outside
this boundary. A local hash or MAC is not evidence that an entire host has not been rolled back.

## Implemented default-startup inventory gate

The trusted process owner can configure `PAJIN_RUNTIME_INVENTORY_PATH` (absolute path) together
with `PAJIN_RUNTIME_INVENTORY_SHA256` (SHA-256 of its exact bytes). The optional
`PAJIN_RUNTIME_COMPONENT_ID` selects a component within that inventory; its default is the
daemon role (`control-plane`, `worker`, or `replay-worker`). The role must match as well as the ID.
The process never obtains an expected pin from a Job, HTTP payload or copied database. Keeping the
pin beside the inventory does not supply independent anti-rollback evidence.

The strict `pajin.dev/runtime-inventory/v1` JSON has `apiVersion`, `inventoryId`, and 1-64 unique
`components`. Each component contains `componentId`, `role`, `packageSha256`, and
`configurationSha256`. IDs are lowercase ASCII slugs up to 64 characters. Input is bounded to
64 KiB; duplicate JSON keys, unknown fields, invalid roles/digests, symlinks and multiply-linked
inventory files fail closed. SHA-256 verification precedes model admission.

The package digest covers current files under the PAJIN package, including source and Console
assets, excluding Python bytecode caches. It also binds Python version/implementation/platform
and installed distribution metadata/version/RECORD. File reads are bounded and reject symlinks;
the package has 4,096-file and 128 MiB bounds, with 16 MiB per file. This is a source/deployment
fingerprint, not proof against modified imported third-party code or a compromised interpreter.

The configuration digest includes complete effective `ControlPlaneSettings`, every inherited
environment variable except the three inventory selectors and shell bookkeeping (`_`, `SHLVL`,
`OLDPWD`), current directory/hostname, and Python executable/prefix/search path after the invocation
slot. Those inputs conservatively cover implicit daemon defaults and environment-selected
credentials. Direct CP/Worker deployment JSON files and configured TLS/CA files are read and hashed
using the same bounded no-follow discipline. Injected CP settings' deployment paths are included.
The private encoding is structural, finite and bounded; unsupported objects/callables are rejected.
Only the final digest leaves the private configuration computation. No raw values, filenames or
per-secret commitments are exported. Mutable stores/output directories are bound by location;
their contents belong to a future quiescent checkpoint, not this startup fingerprint.

`create_app()` compares before measured-reader loading and CP repository construction. It refuses
injected CP runtimes/readers in inventory mode because the default factory cannot establish their
complete implementation/configuration. Both default Worker entry points compare before the
stateful deployment loader/backend/client, and therefore before a claim. CP `--check-config`
also compares without creating stores. Both variables absent preserve existing startup; a
partial/blank pair or orphan component selector fails. An unconfigured process is not an enrolled
recovery deployment, and this optional gate alone does not enforce whole-host enrollment.

Use the exact environment and Python installation intended for each process. Fingerprint output
contains only digests; retain each output as a new private component JSON file. The commands print
to stdout and do not create/overwrite an approved pin or initialize any store:

```sh
python -m pajin.runtime.inventory fingerprint --role control-plane
python -m pajin.runtime.inventory fingerprint --role worker
python -m pajin.runtime.inventory fingerprint --role replay-worker
python -m pajin.runtime.inventory compose --inventory-id lab-host component-cp.json component-worker.json component-replay.json
```

Review the deployment, retain the composed output privately, and provision its exact SHA-256 and
absolute path independently through the trusted process configuration. Then run:

```sh
python -m pajin.runtime.inventory verify --role control-plane
python -m pajin.control_plane --check-config
```

Fingerprint/compose output is not execution approval, valid credentials, live Docker conformance,
or proof that a backup is complete. A code/configuration/key change requires a newly reviewed pin;
the existing key history, policy and deployment checks still apply. Source/configuration must stay
unchanged while the process is running. This initial fingerprint is location-specific: it does not
rewrite paths or automatically admit a new restore destination. External services, OS trust stores,
third-party file bytes, mutable image tags and arbitrary embedded runtimes remain outside this
comparison. The first-use composition and closed checkpoint sections below add the supported
first-work and restore paths; this fingerprint alone cannot replace them.

## Implemented default-Worker first-work budget binding

Both default Worker entry points compose `RunBudgetRegistry` after the startup inventory gate.
The generic Worker uses `PAJIN_DAEMON_BUDGET_ROOT`, defaulting to `_control-plane-budgets` under
its output root. The Replay Worker uses `PAJIN_REPLAY_BUDGET_ROOT`, defaulting to the same directory
name under its staging root. These are private trusted process settings; their values are included
in the configuration fingerprint. Creating the registry performs no I/O. The first authenticated
claim derives a filename as SHA-256 of the ASCII CP Run ID plus `.sqlite3`; no Job-supplied path is
accepted. Keep these journals with the deployment's other state.

The journal stores a canonical `pajin.dev/supervisor-journal-run-binding/v1` object with
`controlPlaneRunId`, `campaignDigest`, `inputDigest` and `budgetMode`. The input digest covers the
Job kind and original typed input; Tool Loop continuation uses its sealed original input and Replay
uses its execution context. Display names, retries and changed payloads cannot select a fresh
allowance for the same Run. Two CP Runs using the same Campaign have independent accounts.

Run-bound journals use schema v3 and the existing v2 SQL objects plus immutable binding metadata.
Every instance read/write validates that exact binding. Unbound callers retain schema v2. Only an
empty journal may be enrolled under an explicit binding, and only first claimed attempts may create
one. Retry and approval continuation require an existing journal, including after process restart.
Reopens and later write transactions use SQLite `mode=rw`; removal between the filesystem check
and connection open fails without creating an empty replacement database.
Nonempty v1/v2 histories cannot be relabeled as fresh Runs. Wrong Campaign/input/Run/mode, replaced
stores, changed limits and incomplete accounting fail closed. No in-place downgrade is supported;
older executables must not execute retained v3 Runs without their accounting.

The default Local, Tool Loop, General Attack, Capability Graph and exact Replay paths use
`campaign-only`. They do not invoke a Supervisor and do not invent a dedicated model allowance.
A trusted embedded Supervisor may instead bind `campaign-and-supervisor` before first work and use
the existing atomic dual ledger. Changing between modes or attaching another Campaign is rejected.

Local and Tool Loop receive the same bound controller before Run creation. Tool Loop resume first
verifies the sealed checkpoint and then requires complete durable counters at least as large as
all checkpoint usage, including elapsed duration, before claiming the continuation. Conservative
extra consumption stays charged. General Attack and Capability Graph reserve before their existing
dispatch boundaries; verified `dispatched=false` releases that live reservation. Exceptions,
cancellation and unknown outcomes retain it. Exact Replay uses the bound controller for each
existing attempt charge; its durable Permit and finalization rules remain authoritative.

Journal binding and initial accounting are complete before any such work, but are separate
transactions from the CP claim and other stores. Unenrolled legacy retries/resumes cannot bootstrap
zero usage. Binding cannot reconstruct execution that occurred before adoption. A newer owner
fences future mutations by an older budget controller; it does not prove an already dispatched
operation stopped. Full host enrollment, Supervisor/urgent-producer composition, cross-store
quiescence and an independently expected backup checkpoint remain required below.

Local integration checks exercise default inventory verification, real CP authentication, claim,
registered Local executor dispatch and completion using in-process HTTP transport; the Tool charge
is already durable when the simulated backend is entered. Further checks cover Tool Loop approval
continuation through a replacement executor, an under-accounted resume before claim, Capability
Graph duplicate dispatch, General Attack and exact Replay permits/finalization, Worker cancellation,
and abrupt process exit after reservation. These are local accounting and execution-boundary
checks, not live Docker, current full CI or PostgreSQL evidence.
The broad local regression passed 438 tests; after the final write-open race fix, the focused Run
budget, dual budget, journal/scheduler, Tool Loop, generic Worker and inventory regression passed
264 tests. Ruff, Linux strict mypy (416 source files), documentation and whitespace checks passed.

## Implemented enrolled-host activity exclusion

`runtime/host_gate.py` supplies an opt-in POSIX local gate. Configure the same absolute
`PAJIN_HOST_RUNTIME_ROOT` for every participating process before generating its existing runtime
fingerprint. This variable remains part of the private configuration digest. Compose a v2
inventory with the root digest, preserving the exact environment intended for each component:

```sh
python -m pajin.runtime.inventory fingerprint --role control-plane
python -m pajin.runtime.inventory fingerprint --role worker
python -m pajin.runtime.inventory fingerprint --role replay-worker
python -m pajin.runtime.inventory compose --inventory-id lab-host --host-root "$PAJIN_HOST_RUNTIME_ROOT" component-cp.json component-worker.json component-replay.json
```

Fingerprint and compose still print to stdout; save their outputs to new private files and review
the complete configuration. V2 adds `hostRootSha256`, the domain-separated digest of the absolute
root, to the v1 component inventory. V1 has no new serialized field, cannot select a host root or
enroll a gate, and remains an unenrolled startup check. A v2 process missing its root or selecting
another root fails before stateful startup. Old v1 readers reject the v2 version.

Provision the inventory path/SHA-256 through trusted configuration, then enroll a new gate:

```sh
python -m pajin.runtime.host_gate enroll --root "$PAJIN_HOST_RUNTIME_ROOT" --inventory "$PAJIN_RUNTIME_INVENTORY_PATH" --sha256 "$PAJIN_RUNTIME_INVENTORY_SHA256"
```

Enrollment creates a private root and an exclusive-create `runtime-gate.json`, fsyncing the file
and directory. Its strict canonical JSON binds a random gate ID, complete inventory ID/digest and
root digest. Existing or interrupted enrollment is never overwritten, repaired or unlinked by
this command. Gate and root permissions must be private; file ownership and single-link, regular
file/path identities are checked. Copying a gate to another root cannot establish quiescence for
the original deployment. A compromised local administrator or a rolled-back complete host remains
outside this proof.

`runtime_activity(role, configuration=...)` repeats the existing code/configuration verification
and holds a shared nonblocking kernel lock for the entire activity. Default `create_app` protects
factory construction; the lifespan reacquires before initialization and holds the lock through
repository close. `--check-config` protects its reader work without creating a CP database. Both
default Workers hold activity from startup through claim, dispatch, accounting and complete
shutdown/drain. An exclusive checkpoint prevents all these participating starts; an active process
prevents the exclusive operation. Busy gates fail immediately rather than blocking the event loop.

An embedded producer must enter `runtime_activity` using its enrolled component and complete
trusted configuration before constructing/writing a Supervisor journal, invoking the Supervisor
or applying an urgent decision. `host_work()` checks that live, same-process context and keeps a
separate shared descriptor for the nested operation. Detached context reuse after release and
removing/changing its configured gate are rejected. A still-draining child keeps its own lock even
after the outer activity ends. Existing budget, source, fast-gate, cancellation ABAC, Permit and
receipt validation still determine authority; the host context cannot supply or replace them.

`host_quiescence(root, inventory_path=..., inventory_sha256=...)` provides exclusive exclusion for
the complete scope of a checkpoint coordinator. The live handle can require exclusive mode and
revalidate its identity, but must not be serialized or treated as a stored idle assertion. The
following diagnostic releases its lock before returning; it is not permission to copy afterward:

```sh
python -m pajin.runtime.host_gate check-idle --root "$PAJIN_HOST_RUNTIME_ROOT" --inventory "$PAJIN_RUNTIME_INVENTORY_PATH" --sha256 "$PAJIN_RUNTIME_INVENTORY_SHA256"
```

The operating system releases activity when owning descriptors close, including abrupt process
exit. No PID-file deletion or stale-lock override exists. This proves participating local activity
exclusion, not physical cleanup or safe redispatch. Out-of-process side effects, unregistered
writers and Windows/network filesystem locking are unverified. The trusted process owner must
enroll every writer and keep configuration stable; optional legacy programs are not automatically
incorporated into a supported recovery deployment.

Changing source/configuration/keys requires a reviewed new inventory and newly enrolled root while
the old deployment is quiescent. Retain its old gate and state and prevent old launch configurations
from restarting. There is no gate rewrite or hot migration. The recovery-set API below adds
encrypted checkpoints with independently expected restore identity. The first-use section below
adds complete source/Run and participant enrollment for the supported stores. Automatic deployment
relocation or reactivation remains outside the recovery contract.

Local tests cover shared/exclusive contention, private/file/root substitution, missing enrollment,
exception and abrupt-process release, child drain, default CP startup/restart/close, both default
Worker claim paths, authenticated Local execution with durable budget, actual Supervisor two-seal
receipt and duplicate non-dispatch, and the verified urgent producer's idempotent CP cancellation.
Transport/backend fixtures remain distinct from live Docker and remote CI evidence.
The local integration regression passed 352 tests; final host/inventory/Run-budget checks passed
85 tests after handle property hardening. Ruff, Linux strict mypy (417 source files), documentation
and whitespace checks passed. Current full CI, live Docker and PostgreSQL remain unexecuted.

## Implemented closed SQLite recovery-set slice

`runtime/host_checkpoint_models.py`, `host_checkpoint_stores.py` and `host_checkpoint.py` expose
`create_host_checkpoint` and `restore_host_checkpoint` as trusted local maintenance APIs. The owner
provides a reviewed `HostCheckpointPlan` and independently configured SHA-256. It binds the exact
gate identity and a sorted, closed partition under the enrolled root's `state/` directory.

| Member kind | Required verification |
| --- | --- |
| `control-plane-sqlite` | Exactly one current CP database; schema, SQLite integrity/foreign keys, stored key commitments and all checkpoint signatures |
| `graph-sqlite` | Exact Campaign ID; existing retained Graph backup and independent restore, including complete Graph history/heads |
| `supervisor-sqlite` | Exact v3 Run binding; complete Campaign-only or dual budgets, invocation chains and CP Run membership |
| `artifact` | Separately expected SHA-256; copied as opaque private data without becoming sealed evidence or source authority |

Every previously attempted CP Run needs its budget journal. Omitting both a file and its plan entry
cannot reset accounting. Unbound journals, missing structures and incomplete budget histories are
rejected without migration or repair. Plan v1 retains the declared-set contract. Inventory v3 and
plan v2 add actual first-use registration and producer/source checks described below.

Creation retains the live exclusive `host_quiescence` lease through copying, verification,
encryption and publication. Missing/unlisted files, symbolic/hard links and hot `-journal` files
are rejected. Known SQLite `-wal`/`-shm` belong only to their declared database; SQLite backup
incorporates committed WAL state. An opaque artifact cannot hide a SQLite database. Limits are
4,096 members, 256 MiB of source/object contents, a 4 MiB manifest and bounded SQLite backup time.

CP/journal snapshots use SQLite backup. Graph reuses `create_retained_sqlite_graph_backup` and
`restore_retained_sqlite_graph_backup`. Source inode identities and SQLite `data_version` are
compared across collection. This supplements the gate without claiming exclusion of unenrolled
writers. Verification does not initialize schema, register a key, reconcile a claim, reset a budget,
consume an approval or append an invocation.

Active CP Runs/leases, previously attempted Jobs that did not succeed, claimed/abandoned Replay
tickets, running/retry-pending Replay items and unknown Supervisor dispatch prevent this checkpoint.
Succeeded Jobs retain historical lease fields for idempotency and are not active merely because
those fields remain. Graphs with reversible-write cleanup reservations need their separate physical
reconciliation contract; neither inactivity nor a cleanup Permit removes that limitation.

All objects, including evidence and nested Graph manifests, enter one AES-256-GCM encrypted file.
Its canonical manifest binds the plan, ordered object digests/sizes, creation time, encryption key
ID/nonce and ciphertext under a separate-domain Ed25519 signature. Existing Graph signer/key types
are reused; the signature domains are distinct. Private key material is absent from the manifest.
Publication creates one private fsynced file outside the source host root without overwriting.

Retain the returned `manifest.digest` independently alongside the expected plan digest. Restore
requires both external values, the intended encryption key ID/key and unique trusted public keys.
It authenticates the complete envelope and repeats domain checks in a private workspace. Old valid
backups, wrong keys, incomplete/trailing ciphertext and mismatched objects fail closed. This is
pin-based rollback rejection, not a managed remote monotonic authority or enforced retention policy.

Restore exclusively reserves a new directory, moves verified `state/` contents there and writes
`restored-checkpoint.json` last. Failure before publication leaves the destination absent; an
interruption after reservation can retain a private incomplete destination without a marker.
Retry cannot overwrite it. Source stores, evidence and retained checkpoints remain untouched.

No runtime gate is copied or enrolled. Historical paths and authority references remain unchanged;
reviewed source-path/configuration/key bindings and new enrollment are required before execution.
Restore never rewrites those references or starts a server/Worker. PostgreSQL, network filesystems,
remote retention enforcement, automatic relocation and whole-host
rollback without independent expectations remain outside this slice. Existing Graph repository
retention/anchor APIs keep their separate authority.

Local validation passed 31 checkpoint tests and a 197-test integration regression covering host
activity/inventory, Run accounting, Supervisor/budget histories, CP key recovery, Graph backup
repository/v2 compatibility and documentation. An actual new process restored under a keyring
retaining the old verification key; restored approval consumption stayed single-use across CP
restart. Tampering, missing state, source mutation, unknown dispatch and interrupted publication
were rejected while preserving source state. Ruff, Linux strict mypy (420 source files) and final
documentation/whitespace checks passed. Current full CI, live Docker and PostgreSQL are unexecuted.

## Implemented first-use enrollment and producer checks

The supported recovery deployment is POSIX local storage with one CP SQLite database, SQLite
Graph stores, Run-bound budget journals and sealed Runs under a common private `state/` directory.
It supports normal restarts at the same location and verified offline restore to a new directory.
It does not automatically relocate or reactivate execution. Other mutable provider stores need
their own recovery contracts; an unlisted file prevents checkpoint publication.

Compose inventory v3 by adding `--enroll-recovery` to the existing inventory compose command. It
requires `--host-root` and emits `recoveryPolicy: closed-local-sqlite-v1`. Enroll the gate once,
before creating stores. Enrollment creates the private state directory and `recovery-index.sqlite3`
outside it. The index retains exact original inventory bytes, gate identity, actual admitted
components and first-use store identities. V1/v2 keep their previous wire and behavior.

Default CP registers its database after successful schema/key checks and before serving. Both
Workers check output/budget roots before claim; RunStore, Graph and journal constructors register
before first use. Journal records include exact CP Run, Campaign, original input and budget mode.
Existing unregistered files, missing registered files, conflicting identities, index tampering,
links and interrupted enrollment are rejected without recreating or adopting state.

Supervisor invocation requires its enrolled SQLite Graph/journal, original CP input and exact
sealed schedule/shared-source Runs before budget binding, claim or dispatch. Canonical typed inputs
cover the default Campaign, Tool Loop, Capability/General Attack profiles and the original Replay
execution context. The existing Supervisor profile-compilation Campaign digest and Campaign-only
Worker component digest are checked according to their existing budget modes. A changed input,
Campaign or source cannot redirect retained accounting. Urgent admission verifies registered
Graph/source Runs and its actual enrolled CP repository, then applies the existing exact source,
Campaign, submission and cancellation checks. It does not gain authority from registration.

For checkpoint creation, hold `host_quiescence` and call `inspect_recovery_inventory` with
`require_complete=True`. Retain/review its digest through trusted maintenance configuration and
pass it as `expected_enrollment_sha256` to `build_registered_checkpoint_plan`, together with the
original runtime inventory path and recovery set ID. Every declared component must have actually
entered its verified runtime. The builder derives plan v2 from all registered stores and all files
of each verified sealed Run. Creation compares the live index again; copied/restored verification
rechecks Run seals, exact membership and original CP inputs. V3 rejects a declared-only v1 plan.

Use the existing encrypted checkpoint API and retain its returned manifest and plan digests
independently. Together they pin every included store head and source file at that checkpoint.
This rejects restoration of another valid historical checkpoint; it does not detect an arbitrary
rollback of the entire active host together with all locally held expected values. Restore keeps
references and source state unchanged, creates no gate and cannot restart a Worker. New deployment
paths and execution authorities require a separate reviewed composition.

Local validation passed 418 regression tests, including real CLI/new-process CP restart, both
default daemon claims, authenticated default Worker execution/accounting, complete registered
checkpoint restore, original-input rejection, SQLite-backed Supervisor two-seal invocation and
urgent cancellation. Ruff and Linux strict mypy (424 source files) passed. These are bounded local
tests; current dirty-tree full CI, live Docker and PostgreSQL remain unexecuted.

## Current evidence and deployment limits

| Concern | Verified current behavior | Required implementation or validation |
| --- | --- | --- |
| Approval consumption | Graph approval, Permit and receipt consumption is atomic; unknown batch outcomes cannot redispatch | Preserve the exact verifier and policy inventory across supported restart; reject drift before another claim |
| Supervisor invocation and default Workers | First-use enrollment, original CP input/source checks and complete budget histories precede calls | Preserve the trusted embedded producer composition when changing a deployment |
| Multiple stores | Complete v3 registration derives a closed, verified, encrypted checkpoint under exclusive host exclusion | Retain the expected checkpoint independently; unsupported provider stores need separate recovery contracts |
| Backups and keys | Recovery sets reuse Graph retention, verify CP keys and require independently expected checkpoint/plan digests | Compose deployment relocation and retention policy without promoting a restored receipt to runtime authority |
| Urgent observation | The producer checks enrolled Graph/source/CP state and full lineage, then atomically cancels and records an alert | Metadata alone stays non-authoritative; external notifications require separate authorization |
| Cancellation | Default generic/Replay daemons report their local stop observation using the original cancelled lease | Preserve pending/failed delivery as unknown and validate live PostgreSQL deployment behavior |
| Physical outcome | Console distinguishes committed cancellation, reported execution drain and local cleanup; Replay child evidence remains separate | Independent external resource cleanup and side-effect rollback require their own existing authorities |
| Human attention | Default Console reads durable alerts and permits idempotent operator acknowledgment | Complete host recovery must retain the journal; acknowledgment never resumes execution |

## Admission and recovery requirements

1. **Explicit host inventory.** Supported recovery must identify the stores, Campaign/runtime
   bindings, verifier implementations, complete policy inventory, and public key identities before
   execution resumes. A Job, HTTP payload, model output or copied database cannot choose a verifier,
   authorizer, source directory, key, or replacement budget.
2. **Conservative accounting.** Persist or reconstruct a complete budget checkpoint from verified
   invocation evidence. In-flight and uncertain requests retain their upper-bound charges. Recovery
   must not release reservations merely because a process died, reset elapsed duration, or charge
   only one side of a dual budget. Any incomplete accounting blocks further dispatch in that scope.
   The journal-bound slice above supplies pre-dispatch accounting. Complete deployment composition
   must bind it before any Campaign work and reject recovery from incomplete inventory.
3. **Quiescent checkpoint.** Cross-store backups require a supported, explicit quiescent boundary
   and exact store identities/heads. An uncertain write, active execution, changed head or omitted
   store prevents a complete checkpoint. A collection of individually readable files is insufficient.
4. **Pinned restore.** Restore to a new destination using a separately retained expected checkpoint
   identity and the intended key. Do not overwrite active stores, delete source evidence, silently
   downgrade schemas, or reinitialize missing structures. Preserve sensitive evidence through the
   existing appropriate encryption and access controls. Keys and credentials must not enter reports.
5. **Key lifecycle.** Document which old keys remain verification-only during rotation, which key
   creates new records, and how retirement affects recovery. Removing or substituting a required key
   must produce an explicit failure, not acceptance under a different key with the same identifier.

## Urgent stop requirements

The downstream integration must bind the exact admitted decision and its verified source lineage
to the intended Control Plane Run through trusted deployment/runtime state. Campaign display names
or caller-supplied Run IDs alone are not sufficient bindings. It must preserve the existing
cancellation authorization boundary and reject cross-Run, cross-Campaign, stale, fabricated or
equivocating inputs.

A live trusted producer must invoke the consumer when it admits the urgent decision. A helper
that remains unused by a runtime does not satisfy this requirement. Consumption must commit the
durable stop/alert state consistently with the existing Run fence and approval revocation, or
retain a recoverable pending state that cannot authorize more work. Retrying the same decision
must return its existing application state without producing duplicate effects or alerts.

Workers must observe the existing cancellation fence through their authenticated lifecycle. Tests
must exercise an actual running Worker/registered executor, cooperative stop, forced fallback,
late finalization denial, and missing or incomplete cleanup evidence. A committed `cancelled` Run
alone must not be shown as verified physical quiescence or external side-effect rollback.

The Console must show a durable alert with the bounded reason, affected Run, application state,
and available stop observations. Human acknowledgement must not undo the fence or authorize
resume. Alert content must exclude raw observation material and secrets. External email, chat,
notifications, and automatic remediation are not part of the authorized implementation.

## Completion evidence

Use isolated local test stores and bounded executors. Never exercise recovery by altering user or
production data. Record actual commands, results and remaining limitations in HANDOFF and this
contract. The minimum fault matrix is:

| Scenario | Required observation |
| --- | --- |
| Clean restart with the same inventory | Exact authority, history and remaining budget are retained |
| Verifier, policy inventory or key substitution | Rejected before a new claim or execution |
| Duplicate request before and after restart | One durable consumption; no extra execution |
| Crash around claim/dispatch/terminal persistence | Conservative charge and unknown state retained; no automatic redispatch |
| Partial or stale cross-store backup | Restore/admission rejected without overwriting or repairing sources |
| Valid checkpoint restored to a new location | Verified identities and expected heads match; sensitive data remains protected |
| Authorized key rotation and retired key | New records use the active key; required old verification works only while explicitly retained |
| Urgent observation during a running Job | Exact decision produces a fence, Worker stop observation and human-visible alert |
| Duplicate stop, interrupted application, or missing cleanup | Application is recoverable and idempotent; uncertainty remains visible |

Focused regression, existing cancellation/backup/budget checks, Ruff, Linux strict mypy and the
actual Console flow must pass. Completion also requires a reviewed default/deployment composition
path; isolated model or helper tests alone are insufficient.
