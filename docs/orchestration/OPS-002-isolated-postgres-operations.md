# OPS-002: Isolated PostgreSQL Operational Drill

Status: Local real-server/Worker/crash/restore drill verified. Production DB/host
selection is unresolved. No deployment or production data changes are part of this command.

## Configuration and scope

The repository's `containers/compose.control-plane.yaml` is explicitly a lab, with ephemeral
PostgreSQL storage and local credentials. It does not select a production host or database. The
operator has been asked to select the deployment scope. Meanwhile this separate drill uses a real
PostgreSQL 17.11 Linux container and the current local Python Control Plane implementation.
The host executing Python must be reported separately from the DB container's Linux platform.

The [official 17.11 release](https://www.postgresql.org/docs/release/17.11/) contains security fixes.
The drill pins the official multi-platform image digest rather than changing a deployed server:
`postgres:17.11-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73`.
An explicit locally built Worker image ID is required; tags cannot silently choose another build.

`scripts/operational_postgres.py` creates a new private output directory, random fixture credentials,
short-lived certificate, loopback-only dynamic port, owned container and persistent named volume.
The server runs as UID 70 with a read-only root, dropped capabilities, no privilege escalation and
CPU/memory/PID limits. Only its brief network-disabled volume initializer has CHOWN capability.
TCP clients use `verify-full`; `hostssl`/SCRAM reject plaintext and the wrong certificate hostname.
The Docker bridge is not an attested production egress policy. No existing database URL is accepted.

## Live scenarios

The runner explicitly invokes the existing PostgreSQL suites plus
`tests/operational_postgres_probe.py`. The latter is an explicit live probe, with no new skip marker.
It reuses checkpoint contract assertions by changing only the database configuration; SQL, locking,
repository, migration and key verification execute against PostgreSQL.

- Legacy v2/v3/v4/v9 migrations, exact schema and append-only fences, retained rows, JSON guards,
  late writers, simultaneous initialization, claim/duplicate/conflict and shared budget races.
- v15-to-current migration retaining checkpoint payload/signature, concurrent conflicting first key
  admission, rejected rebound/missing key, rotation and fresh-process single-use approval/resume.
- Atomic urgent cancellation and operator-visible alerts, concurrent retries and durable acknowledgment.
- A real network-disabled Docker Worker runs the bounded sleep action. The probe observes that exact
  execution's running container and immutable image before urgent cancellation. The normal Worker
  daemon reports stop/quiescence and seals its Run; Docker absence is checked separately afterward.
  This is a process-stop test, not a scanner-quality or external-side-effect restoration claim.
- A committed checkpoint and issued Replay tool permit are retained without a completion receipt.
  The owned DB container is killed and restarted. A fresh Python process checks the complete logical
  table fingerprint, verifier identity and conservative consumed-call charge.
- A custom-format dump is streamed under the non-root DB user, pinned outside both DBs, and restored
  from the exact rechecked byte stream
  transactionally into another newly created empty database. A fresh process compares all logical rows,
  the checkpoint and unrefunded uncertain permit. Archive or expected-row substitution is rejected.

Resource mutations require the original container ID and ownership label. Cleanup removes only the
new resources and inventories their labels afterward. Failed or unobserved cleanup remains unknown.
Private logs may contain disposable credentials and source fixture details; do not publish them.

## Reproduction

Build the Worker from the current allowed Docker context, resolve its immutable ID, and ensure the
fixed PostgreSQL image is available. Run from the repository root in an environment permitted to use
Docker and loopback TCP. The output directory must not already exist.

```sh
.venv/bin/python scripts/operational_postgres.py \
  --worker-image "$OPS_WORKER_IMAGE_ID" --output .pajin/ops002-new-drill
```

The output includes a minimized report, private pytest/DB logs, archive, row commitment and independent
checkpoint. This is an operator-run local probe, not automatic migration, remote workflow dispatch or
deployment admission. Keep the independently expected checkpoint in separate custody for any real
recovery; returning both the DB and expected pin to an older state is outside this local drill.

## Recovery boundary

[OPS-001](OPS-001-single-host-recovery-and-urgent-stop.md) still admits only registered POSIX local
SQLite CP/Graph/journal/RunStore closed checkpoints. This PostgreSQL dump is one DB snapshot, as
described by [pg_dump](https://www.postgresql.org/docs/17/app-pgdump.html); it is not an atomic capture
of Graph, budget journals, Run artifacts, provider stores or cluster roles.

A PostgreSQL/SQLite hybrid deployment needs a separately reviewed closed-set recovery/fencing contract.
The Worker-to-Control-Plane API hop in this drill uses an in-process ASGI transport with the normal
bearer authentication and authorization code. It does not verify deployed TCP ingress, API TLS/mTLS,
or API-network disconnect behavior. PostgreSQL connections use actual certificate-verified TLS, and
the Worker execution and container observation use the actual Docker daemon; those are separate facts.
Multi-host failover, host loss, production storage/TLS/role configuration and real host restart remain
unverified. A successful DB or Worker drill cannot admit that deployment. Worker reports retain
`resourceCleanupVerified=false`; the separate observer covers only the owned local container.

## Validation results

The initial real-server run exposed three existing v9 fixture failures: it incorrectly required
post-v10 tables and an outdated terminal schema version. The new v15 probe also retained a PostgreSQL
v16 trigger function while removing its table. Fixtures were corrected to represent their claimed
historical layouts, while current-schema and data-retention assertions remain enforced.
Post-change SQLite checkpoint/runner regressions: 31 passed. The actual PostgreSQL/Worker suite
passed 71 cases, including observed running-container cancellation and absence. The first crash
verification found Docker may change an ephemeral published port; the runner now rechecks the owned
endpoint. A later run verified crash recovery and retained uncertain-call charges, but Docker archive
copy failed. A narrower non-root dump/restore stream probe passed with observed cleanup; the runner
uses that path without changing the security profile. The integrated source was verified again on
2026-09-10: **71 live tests / 94.03 seconds**, actual server
crash recovery, fresh-process verifier/row/budget checks and restore into a separate empty DB. All
owned container/volume labels were observed absent. The source inventory remained unchanged during
the 109.26-second drill. Five runner boundary tests and four documentation tests also passed.

Source manifest SHA-256: `b9dbba2a3b2922ad7fa63a1fbded91154cc7c491e2d376fe32da3f91f74b0c1e`.
Archive SHA-256: `27f2e90ec0c718a4c76665013226d17e33594e731d94f208461009218c7c22bb`.
Independent row-state file SHA-256: `aaebb08ae828bd5e2f7e08eee35e579c08312a17db263bc1cc79b629ee59ef87`.
The private checkpoint and logs are retained under `.pajin/ops002-live-07/`.
The measured Python host was macOS arm64 / Python 3.12.13; PostgreSQL was Linux arm64 17.11.

The minimized report records the local Python host, DB version, exact Worker image, before/after
source inventory binding and final observed cleanup. Python on macOS plus a Linux DB is not evidence
of an all-Linux deployment. Old fixture/runtime failures remain distinct from product regressions.
