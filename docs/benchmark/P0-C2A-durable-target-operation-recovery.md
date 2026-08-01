# P0-C2A: Durable Target Operation Fencing and Cleanup Recovery

- Status: Implemented contract and Harness
- Operation contract: `pajin.dev/benchmark-target-operation/v1alpha1`
- Recovery authority: `pajin.dev/benchmark-target-recovery-authority/v1alpha1`
- Decision: [ADR-0082](../adr/0082-durable-target-operation-recovery.md)
- Predecessor: [P0-C1](P0-C1-provider-neutral-target-factory-lifecycle.md)

## Scope

P0-C2A adds a durable provider-operation boundary in front of P0-C1 without changing its wire
formats. A recoverable adapter receives an exact operation object for every reset, isolation,
execution, and cleanup call. The operation binds the abandoned attempt, adapter, coordinate, stage,
ordinal, idempotency operation ID, and monotonically issued fence.

The provider contract requires the adapter to make the operation ID idempotent and reject an older
fence after observing a newer one. The core records an intent in a local SQLite journal before each
provider call and records only validated receipts or a stable `provider-exception` code afterward.
Exception messages and secrets are not persisted.

## Journal and recovery ordering

The journal uses `BEGIN IMMEDIATE`, `synchronous=FULL`, and `journal_mode=DELETE`. Fence increments,
attempt creation, record appends, and terminal state changes are separate durable transactions.
Each record is content-addressed and chained to the previous record. The journal path rejects
symbolic-link or junction ancestors and non-regular database paths.

Before a new coordinate starts, the Runner loads every open attempt for the same exact adapter and:

1. accepts a previously journaled successful cleanup without calling the provider again;
2. otherwise atomically claims a newer recovery fence;
3. passes the abandoned attempt, a fresh cleanup operation, and any known isolation receipt to
   `reconcile_cleanup`;
4. retries cleanup up to the configured bound with distinct idempotency IDs under the same fence;
5. blocks all new reset work when no successful cleanup receipt is obtained; and
6. marks the attempt reconciled only after a sealed recovery authority exists.

A P0-C1 completed measurement with `cleanupSucceeded=false` is preserved as the measured fact, but
the recoverable Runner does not return it or close the journal attempt until a separately fenced
cleanup reconciliation succeeds. If reconciliation remains unresolved, the call fails and new work
stays blocked.

The recovery method must discover resources from the attempt and operation identities even when a
process exits after a provider side effect but before its receipt is journaled.

## Sealed failure authority

Every reconciliation attempt emits a separate sealed Run containing
`benchmark-target-recovery-authority.json`. The authority binds the exact adapter, coordinate,
abandoned attempt, complete journal chain, resolution fence, optional successful cleanup receipt,
and one of these terminal states:

- `cleanup-reconciled`: an exact successful cleanup receipt is present; or
- `cleanup-unresolved`: cleanup exhausted its retry bound and new work remains fenced.

The authority always has `measurementAdmissionEligible=false`. It proves what the local recovery
coordinator observed; it is not a Benchmark metric Observation and cannot replace the P0-C1
external measurement signature. Its failure reason is `attempt-not-journaled-complete`, which also
covers a process loss after provider cleanup but before the journal's completed transition.

## Negative boundaries

The implementation fails closed on a different adapter, attempt/coordinate drift, stale journal
writer, reused operation intent, receipt without an exact prior intent, receipt/operation mismatch,
foreign recovery environment or isolation identity, non-monotonic original lifecycle stages,
incorrect resolution fence, malformed chain, unsafe journal path, changed sealed artifact, or
changed audit event.

The hard-exit regression test uses a spawned process that writes an execution intent and terminates
with `os._exit(23)`. No Python exception or cleanup handler runs. A new Runner must issue a higher
fence, reconcile cleanup, seal a measurement-ineligible authority, and only then allow another
coordinate.

## Compatibility and remaining P0-C2 work

P0-C1 models, artifacts, events, readers, and the existing provider-neutral adapter remain
unchanged. `RecoverableBenchmarkTargetFactoryRunner` adapts the new durable provider contract into
the existing P0-C1 Runner, so completed Runs remain BENCH-003B1-compatible.

P0-C2A does not claim a real Docker or cloud implementation. P0-C2B1 now adds the separate
measurement-key registry with rotation/revocation. Provider evidence retrieval, enforced network
policy, signed registry distribution, mandatory admission, and a live provider conformance run
remain P0-C2B2. The local journal coordinates cooperating processes on one filesystem; durable
cross-host ownership still depends on the provider enforcing the supplied fence.
The journal assumes the local host and filesystem remain in the operator's trust boundary. Its
content-addressed records detect accidental inconsistency during model reconstruction but are not a
signature against an attacker who can rewrite the entire live database. The sealed Recovery
Authority becomes the immutable audit boundary after reconciliation.

## Related documents

- [P0-C1 contract](P0-C1-provider-neutral-target-factory-lifecycle.md)
- [BENCH-003B1 contract](BENCH-003B1-walking-measurement-admission.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
