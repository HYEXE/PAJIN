# UX-007P Provider-common Object Storage Conformance Harness

## Status

The provider-common black-box harness is implemented. It compiles and runs one fixed suite against
an exact provider target whose adapter and deployment profile are already active under UX-007O.
UX-007P2 selects one disposable local MinIO target, implements its adapter and target, and retains
passing reports from an isolated live environment. The in-memory target remains the deterministic
unit-test fixture. Neither target nor a passing report grants deployment authority.

## Purpose

UX-007O makes provider guarantees durable, but a profile is still a deployment assertion. The
common harness converts those assertions into fixed observations before a selected provider may be
treated as locally conformant. Provider-specific code performs network and SDK operations in an
isolated environment. The common runner, rather than that code, owns the expected case order,
operation IDs, pass criteria, active-head checks, and secret-free report.

The harness proves only the behavior observed for the exact adapter, profile, authority checkpoint,
binding, challenge, and local conformance environment in its report. It grants no transport use,
Artifact admission, Replay finalization, provider selection, deployment, or production authority.

## Active composition gate

`run_object_storage_provider_conformance()` accepts the durable UX-007M head store, UX-007O attempt
journal, an exact upload-only binding, a deployment-supplied conformance target, bounded challenge
bytes, and a clock. Before planning, before each case, and after each case it requires:

- the binding's complete deployment authority to be the current durable head;
- the target adapter definition and deployment profile to equal the latest concrete activation;
- the adapter endpoint origin to equal the binding endpoint; and
- the provider journal to contain no open attempt.

A head rotation, profile or adapter substitution, pending attempt, or endpoint change fails closed.
The runner never selects the target from a request, URL, response, or report.

## Plan and operation IDs

`ObjectStorageProviderConformancePlan` content-addresses the exact activation, authority checkpoint,
adapter, deployment profile, binding, local conformance profile, challenge digest, start time, and
all case plans. The challenge is 32 to 4,096 runtime bytes; only its SHA-256 is durable.

Every case receives fixed-width UX-007O-shaped operation IDs. The fence case deliberately presents
fence 2 before fence 1. Every later operation uses one unique contiguous fence starting at 3. The
target must use a fresh, isolated namespace for the binding so an earlier test run cannot make a
new lower fence look stale or expose unrelated objects to destructive cleanup.

## Fixed black-box cases

The suite executes these cases in this order:

1. `operation-fence`: a higher operation has exactly one effect; the later lower operation is
   provider-rejected with no effect, and the namespace was initially empty.
2. `multipart-idempotency`: the same part and completion operation IDs are each invoked twice; each
   native mutation occurs once, and the resulting bytes equal the challenge digest.
3. `redirect-refusal`: credential issue, completion, read, cleanup, and reconciliation encounter a
   controlled redirect; all five are rejected, no redirect is followed, and no remote effect occurs.
4. `server-side-encryption`: a successful write has a provider receipt bound to the exact activated
   encryption policy ID and the observed bytes equal the challenge.
5. `strong-read-after-write`: the first immediate read succeeds without polling or retry and returns
   the exact challenge bytes.
6. `prefix-cleanup`: the first exact operation reports `cleaned`, its exact retry reports
   `already-absent`, and neither objects nor native uploads remain under the binding root.
7. `signature-coverage`: a valid exact `PUT` succeeds once; `GET` with the same credential, a changed
   object key, and use at or after the exact expiry each receive 401 or 403 and have no remote effect.
8. `log-non-disclosure`: adapter, provider-SDK, and HTTP-transport captures contain no complete
   credential URL, query, decoded query value, additional runtime-sensitive value, percent encoding,
   standard base64, or URL-safe base64 representation.

The target returns typed raw observations, never a caller-selected `passed` boolean. The common
runner validates every count, operation ID, status, digest, timestamp, disposition, and policy ID.
One invalid or missing observation prevents report construction.

## Signature expiry and report time

The signature case records a valid probe before the binding expiry and an expired probe at or after
that exact expiry. A report cannot finish before the recorded expired probe. A real target must
therefore wait for provider-observed expiry or use an isolated provider-supported clock mechanism
whose behavior is itself part of the reviewed conformance environment. A fabricated future
timestamp with an earlier report finish is rejected.

## Runtime-only credentials and logs

`ObjectStorageProviderLogCapture` is a slots-based runtime dataclass with a redacted representation.
It may hold captured log bytes, ephemeral credential URLs, and optional additional sensitive byte
values only while the runner scans them. It is not a Pydantic or wire model.

The accepted logging observation retains only capture channels, tested-value counts, log byte count,
the non-secret captured-log SHA-256, and a zero match count. It does not retain a credential URL or
secret-derived digest. The report includes normalized secret-free observations and their content
digests; it never includes the challenge bytes, credential URLs, query values, raw provider logs,
SDK secrets, remote bytes, or provider exception text. Provider exceptions are raised as
case-specific generic errors without exception chaining.

## Report and authority ceiling

`ObjectStorageProviderConformanceReport` includes the exact plan and complete normalized observations
so a reviewer can audit why the common runner accepted each case. The report is content-addressed
and binds the active identities, binding, challenge digest, profile ID, and observed time window.

`transportOnly=true`, `artifactAdmissionEligible=false`, and `finalizationEligible=false` remain
fixed on plans, case plans, results, and reports. A passing report does not update the authority
head or provider journal, authorize provider use, choose Artifact bytes, admit a Replay output, or
permit deployment. Deployment composition must separately require and retain the report before
enabling a selected adapter.

## Provider-specific target requirements

A selected-provider target must be reviewed with its adapter and must:

- use a dedicated account, bucket/container inventory, and fresh binding root containing no
  production data;
- disable client redirect following and expose controlled redirect observations for all provider
  entry points;
- distinguish network attempts from native mutation counts and object/upload inventory;
- derive encryption evidence from provider responses or subsequent provider metadata, not a copied
  profile declaration;
- perform the expiry probe against provider-observed time;
- capture the adapter, SDK, and HTTP logger channels at their deployment configuration; and
- clean the exact isolated prefix even after a case fails, without classifying unknown state as
  absent.

The common protocol does not add a cloud SDK, credential environment variable, signer, emulator,
bucket, or cleanup credential. Those are selected-provider inputs and remain deployment TCB.

## Threat model and negative cases

An implementation may replay a previous observation, claim a boolean success, count retries as
independent mutations, follow a redirect, return a policy name copied from configuration, hide an
eventual-consistency retry, omit native uploads during cleanup, fabricate expiry time, or redact
only the complete URL while logging its query token. It may also rotate the authority head during a
case or expose a credential in an exception.

The fixed plan binds observations to one challenge and case-plan digest, validates raw facts rather
than a pass flag, checks the active composition on both sides of each target call, checks report
time against the expiry observation, scans common credential encodings, and sanitizes target
exceptions. A malicious provider-specific target can still fabricate raw observations; target
implementation review and an isolated live environment remain part of the deployment trust base.

## Compatibility, migration, and rollback

The harness is additive. It adds no public route, Worker message, database schema, dependency,
credential setting, provider selection, Artifact wire, or finalization field. Existing inline,
local multipart, UX-007N direct-call, and UX-007O recoverable runtimes are unchanged.

No prior report is migrated. Rollback stops using the harness and discards only secret-free reports;
it must not delete provider state or an unresolved UX-007O attempt. A deployment that has already
used a selected provider must still reconcile and clean that provider under the active journal.

## Validation

- Fixed case order, case-specific operation counts, unique operation IDs, and `(2, 1)` stale-fence
  probe followed by contiguous higher fences.
- Exact active head, adapter, deployment profile, endpoint, binding, and no-pending-attempt checks.
- Positive observations for all eight cases and one adversarial failure for every case.
- Head rotation during a probe and active-profile substitution before a probe.
- Report finish after the expired signature probe.
- Full URL, query, percent-encoded, and base64 sensitive log detection.
- Secret-free exception text, runtime-only capture representation, content-addressed report,
  tamper rejection, strict booleans, and false Artifact/finalization authority.

## Selected-provider follow-up

UX-007P2 closes the selected-provider implementation and live-evidence portion with an exact local,
single-node MinIO inventory. UX-007Q now binds that inventory, activation, and report to a fixed
one-hour, append-only, revocable deployment-admission head. Production provider selection remains
separate.

Public routes, Distributed Workers, KMS/HSM, tenant isolation, cross-host fencing, coordinated
backup/restore, automatic expiry collection, and historical garbage collection remain separate
boundaries.

## Related documents

- [ADR-0192](../adr/0192-derive-provider-conformance-from-raw-observations.md)
- [UX-007P2 selected-provider conformance](UX-007P2-minio-selected-provider-live-conformance.md)
- [UX-007Q selected-provider admission](UX-007Q-selected-provider-deployment-admission.md)
- [ADR-0194 fresh and revocable admission](../adr/0194-require-fresh-revocable-selected-provider-admission.md)
- [ADR-0193 selected local MinIO target](../adr/0193-select-disposable-minio-for-local-provider-conformance.md)
- [UX-007O durable provider recovery](UX-007O-durable-object-storage-provider-recovery.md)
- [UX-007N provider revalidation](UX-007N-object-storage-provider-revalidation.md)
- [ADR-0191 provider attempt recovery](../adr/0191-journal-and-reconcile-object-storage-provider-attempts.md)
