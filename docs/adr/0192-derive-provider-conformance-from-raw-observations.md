# ADR-0192: Derive Provider Conformance from Raw Black-box Observations

## Status

Accepted

## Context

ADR-0191 activates one exact deployment-supplied Object Storage provider and records the guarantees
that its native idempotency, fence, signature, redirect, encryption, consistency, cleanup, and
logging behavior must provide. Those fields are necessary for fail-closed runtime composition but
are declarations. The repository has no common executable rule for deciding whether a selected
provider actually exhibits them.

No provider family, SDK, credential inventory, signer, encryption configuration, emulator, or
isolated live environment has been selected. A provider-specific implementation cannot be added
truthfully until deployment makes those choices. The common portion can still be fixed now so each
provider is evaluated against the same cases and cannot define its own success criteria.

## Decision

### Compile one exact, non-authoritative suite

Introduce content-addressed conformance plan, case-plan, normalized observation, case-result, and
report models. Bind a run to the exact UX-007O activation, UX-007M checkpoint, adapter, deployment
profile, transport binding, local conformance profile, bounded fresh challenge digest, and time.

The plan fixes eight cases: high-water fence, multipart idempotency, redirect refusal, server-side
encryption receipt, strong read-after-write, idempotent prefix cleanup, exact PUT/key/expiry
signature coverage, and adapter/SDK/HTTP log non-disclosure. Operation IDs have the UX-007O fence
shape. Fence 2 is observed before stale fence 1, then every other operation has a unique contiguous
higher fence.

### Keep pass criteria in the common runner

A provider-specific `ObjectStorageProviderConformanceTarget` executes cases in its isolated
environment and returns typed raw observations. It does not return a pass flag. The common runner
checks exact operation IDs, attempt and native mutation counts, response classes, content digests,
policy receipt, immediate-read count, remaining remote inventory, cleanup dispositions, timestamps,
and captured log material.

Before and after every target call, require the binding authority to remain the durable head, the
target identity to remain the latest concrete activation, the endpoint to remain exact, and the
attempt journal to have no pending work. Any failure prevents report construction.

### Retain auditable facts without credentials

Keep raw log bytes, signed URLs, and additional credential values in a redacted runtime-only
capture. Search the full URL, query, decoded values, percent encoding, standard base64, and URL-safe
base64 across adapter, provider-SDK, and HTTP-transport captures. Persist only normalized
observations, tested-value counts, the non-secret log digest, and zero matches; do not retain a URL
or secret-derived digest.

Require the report finish time to be at or after the observed expiry probe. The report and every
component remain transport-only with Artifact admission and finalization fixed false.

## Consequences

- Provider families cannot weaken or omit common cases in their own test implementation.
- A profile declaration can be compared with observable native behavior before deployment enables
  the adapter.
- Exact active identity is rechecked around every black-box call, so a mid-suite head change
  invalidates the run.
- Accepted reports are auditable and content-addressed without retaining bearer-like URLs, raw
  logs, secrets, or remote bytes.
- A real expiry test may last at least the configured upload TTL unless the reviewed isolated
  provider environment supplies an equivalent controllable clock.
- The provider-specific target remains TCB for the truthfulness of its raw observations and remote
  inventory. A live environment and implementation review are still required.
- The common harness alone does not complete UX-007P because no actual provider is selected or
  exercised in this repository state.

## Rejected alternatives

### Accept the deployment profile as conformance evidence

Rejected because it would let configuration assert the same behavior that it is supposed to prove.

### Let each provider return a boolean pass result

Rejected because provider code could change expected counts, status classes, cleanup completeness,
or logging scope without changing the common contract.

### Persist raw HTTP and SDK logs for audit

Rejected because signed URLs, query credentials, authorization material, and runtime secrets can
enter those logs. The harness retains only bounded, secret-free normalized evidence and digests.

### Choose an S3-compatible SDK as the default target

Rejected because no deployment has selected that provider family, endpoint inventory, credential
custody, signing behavior, encryption policy, or test environment.

### Treat a passing report as provider or Artifact authority

Rejected because conformance evidence describes observed transport behavior. It does not activate
a provider, authorize network use, select bytes, admit an Artifact, or satisfy Replay finalization.

## Compatibility and rollback

The decision is additive and internal. It adds no dependency, environment variable, database
migration, public route, Worker wire, Artifact schema, or provider implementation. Existing
transports and UX-007O recovery behavior remain unchanged.

Rollback removes only the common harness and its secret-free reports. It cannot classify remote
state as absent or delete unresolved provider state. Any provider attempt created outside the
suite remains governed by the UX-007O journal and reconciliation contract.

## Follow-up work

- Select and implement one exact provider adapter and target.
- Execute the suite in an isolated live environment and retain reviewed report/configuration
  evidence without credentials.
- Define deployment admission and report freshness for the selected provider.
- Keep public transport, Distributed Workers, KMS/HSM, cross-host fencing, and automatic garbage
  collection in separate decisions.

## Related documents

- [UX-007P provider-common harness](../orchestration/UX-007P-provider-common-conformance-harness.md)
- [ADR-0191 provider attempt recovery](0191-journal-and-reconcile-object-storage-provider-attempts.md)
- [ADR-0190 provider revalidation](0190-revalidate-remote-object-storage-before-managed-admission.md)
