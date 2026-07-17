> Languages: [English](0011-durable-control-plane.en.md) | [한국어](0011-durable-control-plane.ko.md)

# ADR 0011: PostgreSQL durable Control Plane

- Status: Accepted
- Date: 2026-07-12
- Extended by: [ADR 0023](0023-fenced-control-plane-actions.en.md)

## Context

The file-backed runtime is useful for a single authorized local campaign, but it cannot safely
coordinate multiple Supervisor or Worker processes. In particular, a production approval cannot
be represented by a CLI string, a filesystem checkpoint claim is host-local, and a crashed Worker
can leave work without a durable owner or recovery deadline.

## Decision

PAJIN adds an optional FastAPI Control Plane backed by PostgreSQL. The existing file-backed CLI and
run artifacts remain supported. The Control Plane is an orchestration and authorization boundary;
it does not execute offensive tools itself.

The storage model contains five tables:

| Table | Purpose | Critical invariant |
|---|---|---|
| `cp_runs` | Canonical campaign lifecycle | submission key is idempotent |
| `cp_jobs` | Durable Worker queue | one hashed lease token and bounded attempt count |
| `cp_checkpoints` | Resumable state | canonical payload hash plus HMAC signature |
| `cp_approvals` | T3/T4 human decision | exact checkpoint, call, Tool, target, tier, and expiry |
| `cp_events` | Audit history | database trigger rejects update and delete |

PostgreSQL claims the next available Job in a short transaction with
`SELECT ... FOR UPDATE SKIP LOCKED`. A claim increments the attempt count and returns a random lease
token once. Only its SHA-256 digest is stored. Heartbeats extend an active lease; completion and
failure require the exact Worker ID and token. Expired leases are atomically requeued while attempts
remain and otherwise dead-lettered.

Checkpoint payloads are canonicalized JSON. The signature envelope binds the checkpoint ID, Run ID,
sequence, schema version, payload digest, and signing-key ID. The database stores the key ID but not
the key. Resume verifies both the payload digest and HMAC before checking approval state. An approved
T3/T4 decision must exactly match the signed pending intent. Resume atomically claims the checkpoint,
consumes the approval, and enqueues one idempotent continuation Job. A second resume is rejected.

Opaque bearer credentials are configured outside the database and retained only as SHA-256 digests
in the API process. Roles are separated into Operator, Approver, Worker, and Auditor. The lab uses
public fixture credentials; production must source distinct credentials and signing keys from a
secret manager, terminate TLS before the API, and restrict database and API networks.

SQLite implements the same repository contract for local development and API unit tests. Foreign
keys and append-only triggers are explicitly enabled. SQLite does not provide PostgreSQL's
multi-consumer `SKIP LOCKED` semantics and is not a production queue backend.

## API flow

1. An Operator submits an idempotent Run; the transaction creates its first queued Job and event.
2. A Worker claims the Job and heartbeats until it completes or creates an approval checkpoint.
3. Checkpoint creation completes that Job and puts the Run in `awaiting-approval`.
4. An Approver approves or denies the exact signed T3/T4 intent.
5. An Operator resumes an approved checkpoint, consuming it once and creating a continuation Job.
6. A Worker claims and completes the continuation Job; the Run becomes `completed`.
7. A maintenance call or any subsequent claim sweeps expired leases for crash recovery.

## Consequences

- Multiple Worker processes can claim work without a central in-memory broker.
- Approval identity and one-time consumption are durable and auditable.
- Database compromise by a role capable of changing both rows and signing keys remains outside this
  boundary; production signing keys must not share database custody.
- `create_all` is sufficient for this vertical slice. A later schema change must introduce managed,
  forward-only migrations before production upgrade support is claimed.
- Durable storage does not replace policy, Capability, scope, egress, Worker isolation, or Secret
  Lease enforcement. A Worker still has to re-enter those existing boundaries when executing a Job.

## References

- [PostgreSQL `SELECT` locking clauses](https://www.postgresql.org/docs/17/sql-select.html)
- [SQLAlchemy `with_for_update(skip_locked=True)`](https://docs.sqlalchemy.org/en/20/core/selectable.html)
- [FastAPI security dependencies](https://fastapi.tiangolo.com/reference/security/)
