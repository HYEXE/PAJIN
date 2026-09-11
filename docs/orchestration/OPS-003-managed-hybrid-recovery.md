# OPS-003: Managed Linux Hybrid Operator Recovery

Status: Implemented; isolated Linux recovery and approved continuation verified locally.

## Supported boundary

This additive operator command supports a deliberately limited single Linux/Docker host:
PostgreSQL 17 Control Plane, local SQLite Graph and manifest-bound campaign-only execution journals,
and sealed host-local Runs. All participating application writers must be listed by exact container
ID, image ID and an operator-pinned ownership selector, with restart disabled. Exactly one is the
control-only API; execution Workers are separate. PostgreSQL is a separately pinned container.
The recovery controller has administrative Docker/DB access and is part of the trusted deployment.
Its credentials and socket are never given to target Workers.

`python -m pajin.operations` implements preflight, stop, checkpoint, restore, verify and resume.
It does not expose the OPS-002 test helper as a production API. The new versioned deployment,
encrypted checkpoint, verification receipt and signed resume authorization are independent of
OPS-001's registered local-SQLite API. No existing schema, import, wire format or reader is migrated.

The operator must establish the complete participant inventory before using this command. A label
only locates candidates; the independent plan pin authorizes the exact IDs/images. Unknown writers,
external supervisors, mutable provider stores, distributed fencing and arbitrary production hosts
are unsupported. Preflight is not a discovery-to-permission conversion. New or replaced participants,
running execution Workers, missing state, unverifiable evidence and unsupported budgets fail closed.

## Contract and custody

The private `pajin-hybrid-deployment-v1` document binds:

- exact participant IDs, images, roles, owner selectors and PostgreSQL database/user;
- canonical state-root commitment, declared Graph paths/Campaigns, journal paths/original Run bindings
  and sealed Run directories;
- original checkpoint-key commitments, current product source digest and separate recovery approver
  public keys/subjects;
- the target's local HTTPS Operator API origin and independently pinned CA.

Keep the document and its SHA-256 outside application state. Generate the code commitment with
`python -m pajin.operations code-digest`. Preserve the private original CP keyring as
`{"active_key_id":"...","keys":{"...":"hexadecimal key bytes"}}` and the 32-byte encryption key
separately. Never put keys, environment files, model data or raw evidence in public artifacts.
`PAJIN_RECOVERY_DATABASE_URL` must use PostgreSQL and `sslmode=verify-full`. The verified TLS connection
must resolve to the same database identity observed through the pinned administrative container.

The encrypted `pajin-hybrid-cold-checkpoint-v1` includes the complete PG custom-format dump and exact
local file set, source inventory and database identity, Graph heads, original key identities,
budget history and sealed Run roots. Retain its expected SHA-256 independently from the archive and
source/target volumes. AES-GCM encryption is purpose-separated from OPS-002. The initial bound is
64 MiB logical PG content, 64 MiB total local files and 4,096 local files; larger deployments reject.
These limits are not production capacity measurements.

This first contract rejects databases with managed artifact repository admissions or Replay items:
their external blob/credential authorities are not part of this host-local inventory. A database dump
alone cannot make that deployment complete. Every attempted supported Run must retain its original
manifest-bound journal. Process loss after an unacknowledged reservation preserves the full charge;
absence of an outcome never creates a refund or a successful result.

## Operator sequence

All paths below are operator-selected private paths. Replace placeholders with reviewed, independently
pinned configuration. Stop/checkpoint deliberately stop only the listed source containers. Do not run
them against a service without explicit authorization for its interruption.

1. Run `preflight --deployment <source.json> --deployment-pin <sha256> --state-root <absolute-state>
   --output <new-report>`. Confirm every participant, code/image identity, state count and actual PG17
   database identity. No process is stopped by preflight.
2. Run `stop` with the same pinned arguments and a new output. Every listed application container is
   inspected, stopped and observed with PID zero. New/replaced participants reject the operation.
3. Run `checkpoint` with those arguments plus `--cp-keyring <private-json> --encryption-key <key>
   --checkpoint <new-archive>`. No other PG client may remain. Verify schema, original checkpoint keys
   and signatures, original CP/journal/Campaign bindings, conservative budgets, Graph histories and
   Run seals. Capture the dump and all local files, repeat the state checks, then stop the source PG
   and observe all source writers absent from execution before publishing the checkpoint. The source
   remains stopped after completion or a publication failure. Retain the returned archive pin independently.
4. Provision an independently authorized separate empty PG database and new state destination with
   compatible code/keys/member contracts. Create its future API/Worker containers stopped. Supply a new
   pinned target deployment; never change source identities in the archive. `restore` adds
   `--checkpoint-pin <independent-sha256>` and uses the target's verified TLS DB credentials. It refuses
   an alias of the source DB, nonempty DB, conflicting files or a changed member/verifier contract.
5. `verify` repeats the passive checks and compares all logical PG rows and local evidence with the
   independently pinned checkpoint. Only a successful receipt has `verified=true`; it always has
   `execution_authorized=false`. The original deployment remains stopped.
6. After independent review, start only the target's control-only API. Record a fresh CP approval
   through its existing authenticated Approver route. Obtain a separate Ed25519 recovery authorization
   binding the archive pin, successful verification-receipt digest, target DB/state identities, exact
   CP checkpoint/approval, operator subject, key ID and UTC expiry. The signature domain is
   `pajin.hybrid-resume/v1` plus NUL, followed by canonical sorted JSON excluding `signature_hex`.
7. Run `resume` with target/checkpoint/key arguments plus `--verification <receipt>
   --resume-authorization <signed-json> --operator-ca <pinned-ca> --attempt <new-private-intent>`.
   `PAJIN_RECOVERY_OPERATOR_TOKEN` supplies the current Operator credential. The command checks the
   independently pinned recovery signer, live target identity, unchanged local evidence/budgets,
   current UTC duration, unknown invocations and unclaimed checkpoint. It sends one authenticated
   HTTPS resume request. The CP rechecks its current roles/ABAC, original signed intent, current
   approval, expiry and single-use claim. It queues that approved continuation; it never starts a Worker.
8. Activate execution Workers only under the current deployment's separate authorization. Existing
   Capability/Policy/Approval/Permit and durable budget gates still apply. A copied Run or successful
   recovery receipt cannot supply any of these authorities.

## Failure, retry and rollback

- Stop failure leaves the observed state explicit; checkpoint refuses any still-running participant.
  This is not proof of external side-effect cleanup. External rollback remains `unknown`.
- A failed copy or restore stays quarantined. Source bytes are never deleted or overwritten. A fully
  materialized exact local set may retry a PG restore only while the separate target DB remains empty.
  Partial/conflicting local state requires a new empty destination. `pg_restore` uses one transaction.
  A completed target is inspected with `verify`, not overwritten with another restore.
- Missing signatures, altered rows, wrong keys, changed Graph/current heads, missing journals, mixed
  evidence and size limits deny verification. Expired budgets and uncertain invocations deny the
  affected resume; no charge or elapsed time is reset. Unsupported producer modes remain unsupported.
- Before the HTTPS mutation a create-only `outcome-unknown` intent is persisted. Transport failure
  does not trigger an automatic retry or refund. Inspect the current CP checkpoint/approval and audit
  trail before a new explicit attempt. The CP's single-use transaction remains the final duplicate fence.
- Rollback selects the retained original stopped deployment after separate authority review. Do not
  bring both source and target execution online. Changing code, supported schema or member layout
  requires an explicit compatible checkpoint/contract; do not rewrite existing archives.

This is a managed cold procedure. It does not validate physical host/storage failure, power loss,
live backup, cross-host failover, network storage durability, unknown external rollback or production
deployment. Actual isolated Linux results must be recorded separately from unit tests and remote CI.

See [ADR-0279](../adr/0279-separate-managed-hybrid-recovery-from-execution-activation.md).

## Observed local validation

The isolated Linux arm64 rehearsal completed in 186.57 seconds. Eleven named contract checks covered
real PostgreSQL 17 TLS, separate HTTPS Control Plane and authenticated mTLS Worker, abrupt loss after
a durable call reservation, cold capture, a separate empty destination, a mid-restore failure and exact
retry, fresh-process passive verification, correctly rejected expiry/unapproved resume, current role
checks, separate recovery authorization, approved continuation and duplicate rejection. Two Run seals
verified; the unacknowledged call retained its full charge of one. The payload was a deterministic
simulated model/mock Tool fixture, not a model-quality or target-effectiveness evaluation.

A fresh observer confirmed all exact owned container/volume selectors and recovery controllers absent.
Earlier fixture/readiness failures and a duration-field serialization bug were retained, diagnosed and
corrected; the final success is not a first-attempt claim. Unit coverage accepts both public alias and
internal budget serialization. These recovery results are local. Commit
`3c66c2e3824d86c0a38bb82fbe69e8cb52ce320a` passed ordinary remote CI and the existing
Web/Network/AI Docker workflows; those workflows did not execute the OPS-003 recovery procedure.
A dedicated `ops-003-conformance.yml` workflow is now implemented; its new remote run still
requires explicit approval and observed results for the same new commit.

A final integration image containing the completed Graph and System modules repeated all eleven
checks in 71.07 seconds, with two valid Run seals and the unknown call charge still one. A separate
observer again verified the eight exact container/volume selectors and recovery-controller absence.
The fixture is invoked as `python -m scripts.hybrid_operations_rehearsal`; direct script invocation
without the repository package path is unsupported. Runtime timing is a local observation, not a
recovery-time objective or physical-failure estimate. Serialized bounds do not measure peak RSS.

The 2026-09-11 follow-up repeated the actual eleven checks on Linux arm64 with current local
product digest `4f9f9fcbaf0fbad134f172b5ad88ae7a39930e9a1f9ccdb76e988cfd3f629ce3` and runtime image
`sha256:d5a104f4a5fff0b3ecb6751e3900e1454835cdaa2a24b8f39ace8b67b1da65ad`.
Its final integration repetition completed in 114.33 seconds while other local verification was active.
Source inventory was
unchanged during execution. The new CI wrapper's report verifier accepted all eleven checks;
a separate read-only Docker observer found no resources under the three OPS ownership labels.
This validates the reused local probe and report projection, not the new clean Linux amd64 remote gate.
