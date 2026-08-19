# UX-007P2 MinIO Selected-provider Live Conformance

## Status

Implemented and exercised on 2026-08-18. The selected provider is a disposable, single-node MinIO
S3 environment used only for local black-box conformance. It is not a production Object Storage
selection and grants no deployment, public-network, Artifact-admission, or finalization authority.

## Exact provider inventory

| Property | Selected value |
| --- | --- |
| Provider family | `minio-s3-single-node` |
| Server image | `minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e` |
| Platform | `linux/amd64` |
| SDK | `boto3==1.43.73` |
| SDK core | `botocore==1.43.73` |
| Endpoint | `https://127.0.0.1:9443` |
| Controlled redirect endpoint | `https://127.0.0.1:9444` |
| Bucket | `pajin-conformance-ux007p2` |
| Region and addressing | `us-east-1`, path style |
| Signer | S3 SigV4 query signing for exact `PUT`, key, signed headers, and expiry |
| Credential custody | Random disposable root credential injected only into the runtime process and container |
| Encryption | SSE-C AES-256 with a random 32-byte runtime-only customer key |
| TLS | Per-run private CA and leaf certificate for `127.0.0.1` and `localhost`; verification is mandatory |
| Isolation | Fresh container, named data volume, bucket, provider journal, and binding prefix per run |

`MinioS3ProviderInventory` content-addresses this non-secret selection together with the per-run TLS
CA digest. `MinioS3RuntimeSecrets` carries the root credential and SSE-C key only in memory and has a
redacted representation. The durable inventory, activation, journal, report, and log observation do
not contain those values, a presigned URL, or a digest derived from a secret.

The MinIO image is the final tagged community release in the archived upstream repository. The
selected image is used only as a disposable single-node test target. The published path-traversal
advisory states that the vulnerable route is registered only in multi-node deployments, so this
contract prohibits multi-node use and does not generalize the result to production.

## Adapter and target

`MinioS3ObjectStorageAdapter` implements the UX-007N and UX-007O provider boundary with the selected
SDK. It verifies the pinned SDK versions, TLS CA digest, exact endpoint and bucket-derived object
keys, applies path-style SigV4, requires SSE-C headers, and maps provider failures to secret-free
fail-closed errors. A local SQLite operation-ID fence gives exact retries one remote effect and
rejects a lower fence before a provider call.

The adapter supports ephemeral part credentials, remote part re-reading, completion, prefix
cleanup, and restart reconciliation. Empty MinIO `ListObjectsV2` and multipart-list responses are
treated as empty inventories only when the corresponding response field is absent; malformed or
oversized inventories are rejected.

`MinioS3ProviderConformanceTarget` drives actual SDK and HTTPS operations and returns only the typed
raw observations required by UX-007P1. It disables redirect following, derives the SSE-C receipt
from the provider response, performs the first read immediately, inventories objects and native
multipart uploads after cleanup, probes method/key/expiry signature failures, and captures the
adapter, SDK, and HTTP log channels for the common non-disclosure check.

## Isolated live runner

Run the selected environment from the repository root:

```powershell
.venv\Scripts\python.exe scripts\run-minio-object-storage-conformance.py
```

The runner creates a fresh CA, runtime secrets, container, named volume, SQLite authority stores,
and binding. Docker lifecycle stays on the Windows host. The actual TLS/S3 suite runs in the WSL
Ubuntu environment because local endpoint security intercepts Windows loopback TLS in this
workstation profile. The runner never disables TLS verification or bypasses endpoint security.

The runner removes the exact container, named volume, runtime secret file, certificates, SQLite
state, and temporary directory in `finally`. Reports are written only after the common runner has
accepted all cases. An existing content-addressed evidence path is reused only if its bytes are
identical; differing bytes at the same path fail closed.

## Retained evidence

The latest reproduced run retained:

- inventory `minio-inventory-3351ef2b8716a5efd9569ef2d6222658b038249132f427fe48998b0cd636610d.json`;
- report `minio-report-57da9bf2da7c96e396e2da3ba9462575a109633a78347fcaf91abf3f1ec9d8db.json`;
- observation window `2026-08-18T13:56:14.644138Z` through
  `2026-08-18T13:57:15.417767Z`; and
- all eight UX-007P1 results passed, with `transportOnly=true`,
  `artifactAdmissionEligible=false`, and `finalizationEligible=false`.

The filename digests are the models' domain-separated canonical digests, not raw file SHA-256
values. The retained JSON files can be reparsed to recompute and verify their embedded digests.
Earlier reports remain separate historical observations with their own per-run CA-bound
inventories. UX-007Q also binds the latest inventory and report to a selected-provider evidence,
one-hour policy, admission, and current-head checkpoint.

After the reproduced run, the exact container, named volume, and `pajin-ux007p2-*` temporary
directory inventories were empty. A repository scan found no access-key prefix, secret-access-key
label, private-key block, SSE-C customer key, or complete SigV4 credential query in retained report
files.

## Authority ceiling

A passing report proves only that the exact selected local test environment produced observations
accepted by the common harness during the report window. It does not:

- activate a production endpoint or permit public network use;
- make the report indefinitely fresh;
- authorize a deployment or select a tenant credential;
- admit remote bytes as an Artifact or finalize a Replay Run;
- provide KMS/HSM custody, tenant isolation, off-host retention, or cross-host fencing; or
- authorize automatic expiry or historical garbage collection.

UX-007Q now defines local selected-provider admission and report freshness. The adapter remains
opt-in test infrastructure: no report or admission can enable public or production composition.

## Compatibility and rollback

The implementation is additive. The SDK is in the optional `object-storage-minio` dependency group;
existing installs, public routes, Worker messages, Artifact formats, and provider-neutral adapters
are unchanged. Removing the optional dependency, selected adapter, runner, and retained reports
rolls back this local target. Rollback must not classify an unresolved provider attempt as absent;
the UX-007O journal and reconciliation rules still govern any attempt created before removal.

## Related documents

- [UX-007P provider-common harness](UX-007P-provider-common-conformance-harness.md)
- [UX-007Q selected-provider admission](UX-007Q-selected-provider-deployment-admission.md)
- [ADR-0194 fresh and revocable admission](../adr/0194-require-fresh-revocable-selected-provider-admission.md)
- [ADR-0193 selected local MinIO target](../adr/0193-select-disposable-minio-for-local-provider-conformance.md)
- [ADR-0192 raw-observation conformance](../adr/0192-derive-provider-conformance-from-raw-observations.md)
- [UX-007O durable provider recovery](UX-007O-durable-object-storage-provider-recovery.md)
- [UX-007N provider revalidation](UX-007N-object-storage-provider-revalidation.md)

## External references

- [boto3 1.43.73 package record](https://pypi.org/project/boto3/1.43.73/)
- [Pinned MinIO linux/amd64 image](https://hub.docker.com/layers/minio/minio/RELEASE.2025-09-07T16-13-09Z/images/sha256-a1a8bd4ac40ad7881a245bab97323e18f971e4d4cba2c2007ec1bedd21cbaba2)
- [MinIO path-traversal advisory](https://github.com/minio/minio/security/advisories/GHSA-xh8f-g2qw-gcm7)
- [MinIO TLS guidance](https://min.io/docs/minio/container/operations/network-encryption.html)
- [MinIO server-side encryption guidance](https://min.io/docs/minio/linux/administration/server-side-encryption.html)
- [Boto3 S3 presigned URL guidance](https://docs.aws.amazon.com/boto3/latest/guide/s3-presigned-urls.html)
