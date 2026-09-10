# OPS-002: Isolated PostgreSQL Operational Drill

Status: The initial real-server/Worker/crash/DB-restore drill is verified. The operator selected
the Linux hybrid configuration below; its full-state local rehearsal is verified.
The additional change is published at `215d4fc`; its same-commit CI and three Docker conformance runs passed. No deployment or
production data changes are part of either command.

## Configuration and scope

The repository's `containers/compose.control-plane.yaml` is explicitly a lab, with ephemeral
PostgreSQL storage and local credentials. It does not select a production host or database. The
operator subsequently selected a single Linux host with PostgreSQL 17 Control Plane, local SQLite
Graph/execution journals and host-local RunStore. The initial separate drill uses a real
PostgreSQL 17.11 Linux container and the local Python Control Plane implementation.
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

A PostgreSQL/SQLite hybrid deployment needs a separately reviewed recovery/fencing procedure.
The Worker-to-Control-Plane API hop in the initial drill uses an in-process ASGI transport with the normal
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

## Selected Linux hybrid rehearsal

[ADR-0277](../adr/0277-rehearse-passive-cold-recovery-of-the-selected-linux-hybrid-host.md) defines
the additive manual cold-recovery scope. `scripts/operational_linux.py` creates dedicated Linux
controller, state/config/evidence volumes and PostgreSQL containers. It accepts exact local image
IDs and a new output directory, never an existing deployment's URL or state. The controller image
uses the runtime hash lock plus a small test-only lock derived from `uv.lock`. It compares its copied
source files against the current source inventory before running the probes.

The selected API and actual Worker daemon both execute on Linux. The API runs in a separate process
with direct TLS and the existing `WorkerMTLSH11Protocol`. A short-lived fixture CA and separate
client key bind Worker certificate SPKI to authenticated Worker subjects. Missing certificates,
wrong server hostname, untrusted CA, plaintext and missing bearer credentials are rejected.
The trusted urgent producer remains local to the Control Plane database; its admission is not
replaced by a new public endpoint. Its Graph uses the actual SQLite admission/projection stores.

The running network-disabled Docker Worker is observed before cancellation. Its normal daemon,
durable Run budget registry, stop report, sealed Run and operator alert are checked. Container
absence remains a separate observation; `resourceCleanupVerified` and external rollback are not
upgraded from that report. A second retained Replay permit deliberately has no completion receipt.
Checkpoint key rotation retains the original verifier; rebound and missing keys reject actual
server startup.

A serving Linux API container and the owned PostgreSQL process are forcibly terminated. A fresh
Linux process checks all logical DB rows, original key identity, retained uncertain-call charge,
current Graph Snapshot/history, Run seals, Run-bound budget history and durable stop alert.
Budget verification checks the saved hash chain and exact limits independently. If the existing
30-second fixture budget expires during downtime, restoring execution must fail with the duration
budget error; the elapsed wall time must independently justify that error and the journal copy
must remain unchanged. Otherwise the restored Tool count must equal the saved count. Neither case
refunds the uncertain call. The restored API also rejects resuming the retained checkpoint with
its still-unapproved approval record.
The runner then stops and inspects all owned application containers and checks that no application
DB sessions remain. Under this manual exclusion it combines a PostgreSQL custom dump and every
local state file into one bounded AES-256-GCM archive. Its expected digest, state commitments and
original configuration remain outside both application state volumes. These are independent
rehearsal inputs, not an off-host custody service.

Restore requires the exact encrypted archive pin and key, a newly created PostgreSQL container and
a new empty local volume. Validated file paths cannot escape the destination or overwrite existing
state. The normal domain readers run in a fresh Linux process against both restored stores. The
original application and DB remain stopped. Only a temporary API is opened for read verification;
no restored Worker is launched and unresolved calls are neither refunded nor redispatched.

```sh
docker build -f containers/operations/Dockerfile -t pajin-ops002-linux:local .
OPS_RUNTIME_IMAGE_ID="$(docker image inspect --format '{{.Id}}' pajin-ops002-linux:local)"
.venv/bin/python -m scripts.operational_linux \
  --runtime-image "$OPS_RUNTIME_IMAGE_ID" --worker-image "$OPS_WORKER_IMAGE_ID" \
  --output .pajin/ops002-linux-new-drill
```

The controller can access the local Docker daemon and must run only as trusted maintenance code;
this access is not passed to its target Worker. Volume initialization briefly uses UID 0 with only
CHOWN and DAC_OVERRIDE in a network-disabled container. The application controller runs as UID 10001,
with read-only root, dropped capabilities, no privilege escalation, bounded CPU/memory/PIDs and
private temporary storage. Every mutation checks its generated owner label and original container
ID. The cold-file collector has neither networking nor Docker socket access. Failed cleanup stays
unknown. Linux server logs are copied into a bounded private evidence archive before volume removal;
missing log retention prevents a complete report. Test reports and unencrypted intermediate fixture
files are private. The private cold format allows at most 4,096 local files, 64 MiB of local bytes,
64 MiB per dump and a 192 MiB encoded envelope; it is not a general backup utility.

This evidence covers a passive manual recovery procedure for the selected isolated configuration.
It does not enable the SQLite-only OPS-001 enrolled recovery API for PostgreSQL, provide an atomic
live backup, fence unrelated writers, restore external side effects or automatically resume execution.
Container/process loss on the local Linux Docker host is not a physical machine reboot or storage
failure. Production storage, key custody, ingress, multi-host fencing, external resources and a
reviewed activation procedure still need deployment-specific verification.

## Selected Linux validation result

On 2026-09-10, the final unchanged 1,513-file source inventory passed the selected Linux rehearsal:
**84 PostgreSQL/journal tests in 69.38 seconds; 134.55 seconds for the complete drill**. The API,
producer and Worker daemon ran under Linux aarch64 / Python 3.12.13, with PostgreSQL 17.11. Actual
mTLS and all listed negative transport/key cases passed. The separately observed Worker container
was absent after urgent cancellation, while its report retained `resourceCleanupVerified=false`.

The checkpoint covered 18 local files, including two sealed Runs, plus the PostgreSQL dump in an
888,828-byte encrypted archive. Fresh-process restart restored exactly one charged Tool call.
Fresh-process restore retained that charge and denied execution because the original 30-second
Campaign budget had expired. Independent elapsed time and the unchanged verified journal justified
that rejection. The API rejected the unapproved checkpoint resume with HTTP 409. Graph and Run
verification, full logical DB equality, original verifier and durable alert comparison passed.
All owned application and database containers/volumes were observed absent after cleanup; private
Linux log retention also succeeded. `complete=true` describes this local rehearsal only.

- Runtime image: `sha256:490d592c0c17097754e0efdc72d9b763cef7b8f34628186bdafcc1dd81d33ac5`.
- Worker image: `sha256:144b961e48a3a71b360f011471416e261f0cc86e3237f18f72d07a0291d968b3`.
- Source manifest SHA-256: `91ed1c43a3ca7650444c17ae83be66412127eb8f1bcc74327d29afa1f3a9bc05`.
- Of the 1,513 local inventory files, all 840 repository files match the published commit. The
  remaining 673 are ignored vendor files unused by either image; the Worker installs dependencies
  inside its image from the committed hash lock. Copied controller sources were compared inside
  the actual Linux container before the live tests.
- Independently pinned encrypted checkpoint: `3594fbd66133af32a0670af0816804be81e97678f34df303bcfc71ec066b3276`.
- Expected state SHA-256: `6fb1f318314d19ab35f038120656b5acc8ed34872a324f4fef52091003c9d15c`.
- Private evidence: `.pajin/ops002-linux-live-07/`, including `private-linux-evidence.json`.

The local focused regression passed 125 cases, including 22 new cold-archive/controller boundary
cases. Repository-wide Ruff and Linux strict mypy passed (447 existing sources and two new scripts;
the namespace scripts use a separate `--explicit-package-bases` invocation). The earlier full suite
and remote results at `72bdbd9` are historical evidence, not results for this additional change.
The additional change was published at `215d4fc03e1385c64ccc1e4e7fe70efd0ea4add2`. Its
[CI run](https://github.com/HYEXE/PAJIN/actions/runs/34466459329) passed Quality and all 24 shards:
8,260 passed and 76 existing opt-in skips. All 8,336 test IDs were unique across the 24 clean,
same-SHA duration artifacts; the earlier test set was retained and 22 boundary cases were added.
The required [Web](https://github.com/HYEXE/PAJIN/actions/runs/34466552572) (136.13 seconds),
[Network](https://github.com/HYEXE/PAJIN/actions/runs/34466556691) (270.42 seconds) and
[AI](https://github.com/HYEXE/PAJIN/actions/runs/34466560216) (91.39 seconds) Docker tests each
passed once on Ubuntu 24.04 / Linux amd64. Each first attempt passed its exact clean-commit gate,
recorded image IDs, actual conformance test and unconditional residue audit. These remote product
checks are separate from the selected Linux aarch64 operational rehearsal above.

Initial rehearsal failures were confined to controller setup/verification: source file ownership,
volume initialization scope/order, an incorrect Snapshot accessor, and checking termination before
it completed. These were fixed without increasing application privilege or changing product code.
The duration-budget rejection was preserved as a required negative result; the budget was not
extended or reset. Earlier failed reports remain separate from the successful final run.
