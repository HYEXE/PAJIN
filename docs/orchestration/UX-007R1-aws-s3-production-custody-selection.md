# UX-007R1 AWS S3 Production Custody Selection

## Status

Implemented as a non-executable production selection contract on 2026-08-18. UX-007R1 selects
Amazon S3 in `ap-northeast-2` and the regional endpoint
`https://s3.ap-northeast-2.amazonaws.com`, but it does not claim that an AWS account, bucket, IAM
role, KMS key, VPC endpoint, backup, or restore drill exists. No external resource was created or
changed.

The next slice, UX-007R2, must obtain deployment-owned identifiers and independently observed live
evidence before any production activation can become eligible.

## Why this slice is separate

UX-007Q admits one disposable MinIO environment for at most one hour. Its root credential, SSE-C
key, local CA, single-node target, and destroyed SQLite stores are intentionally unsuitable for
production reuse. A caller-supplied bucket name or a claim that KMS and tenant isolation are
enabled cannot replace deployment authority.

UX-007R1 therefore fixes the provider and the required custody shape while keeping every execution
ceiling false. It creates content-addressed inputs for later observation instead of treating a
configuration file, environment variable, URL, or identity claim as live proof.

## Provider selection

`AwsS3ProductionBucketSelection` fixes:

- provider family `aws-s3`;
- partition `aws`, region `ap-northeast-2`, and regional HTTPS origin
  `https://s3.ap-northeast-2.amazonaws.com`;
- boto3 and botocore `1.43.73`, SigV4, and virtual-hosted addressing;
- one exact AWS account, tenant bucket ARN, and `pajin/tenants/{tenantId}` key prefix;
- one exact S3 VPC gateway endpoint and digests of the bucket, endpoint, and organization
  policies;
- `BucketOwnerEnforced`, ACLs disabled, and all four Block Public Access settings enabled;
- SSE-KMS with one fully qualified tenant KMS key ARN and S3 Bucket Keys disabled; and
- private-network-only transport with live inventory verification still false.

AWS lists `s3.ap-northeast-2.amazonaws.com` as the Seoul regional S3 endpoint and supports SigV4
there. AWS also documents the virtual-hosted request form, recommends Bucket-owner-enforced object
ownership with ACLs disabled, and defines the four independent Block Public Access settings.

The selected bucket is an ephemeral transport staging bucket, not the managed Artifact repository
and not the authority backup repository. It therefore selects `unversioned-ephemeral-transport`
and `objectLockEnabled=false`: version history or Object Lock would leave old transport bytes after
the current prefix cleanup contract reports the visible key absent. Immutable retained backups
must use a separate R2 inventory and restore path.

## Tenant credential custody

`AwsStsTenantCredentialSelection` requires one role per tenant in the selected account. The
deployment credential broker may request only AWS STS `AssumeRole` sessions with:

- the AWS minimum session duration of 900 seconds;
- exact trust, role-permission, and session-policy digests;
- an external-ID digest rather than the external ID value;
- a deterministic secret-free `SourceIdentity` derived from deployment and tenant;
- the exact `pajin:tenant-id` session tag; and
- runtime-only workload identity, with static or persisted credentials prohibited.

AWS documents that AssumeRole returns temporary credentials, supports session policies, external
IDs, source identity, and session tags, and accepts a minimum `DurationSeconds` of 900. UX-007R1
stores none of the returned access key, secret key, or session token.

## KMS custody and revocation

`AwsKmsTenantKeySelection` selects one fully qualified customer-managed symmetric KMS key ARN per
tenant in `ap-northeast-2`. It requires:

- `SYMMETRIC_DEFAULT`, `ENCRYPT_DECRYPT`, AWS-generated key material, and AWS KMS service custody;
- a distinct credential custodian and KMS security custodian;
- exact key-policy and grant-policy digests;
- enabled state, no pending deletion, no cross-tenant grants, and no multi-Region key;
- automatic 365-day rotation; and
- disable-first revocation followed by reviewed deletion with a 30-day waiting period.

AWS recommends a fully qualified customer-managed key ARN when the requester and bucket-owner
context could differ. Customer-managed keys can be controlled, rotated, and disabled. Automatic
rotation is supported for symmetric AWS_KMS-origin customer keys and defaults to approximately
365 days. AWS warns that deletion is destructive, recommends disabling an uncertain key first,
and permits a 7-to-30-day deletion waiting period.

S3 Bucket Keys remain disabled in v1. AWS documents that Bucket Keys change the encryption context
from the object ARN to the bucket ARN; the stricter per-object/tenant policy contract is retained at
the cost of additional KMS requests. The exact cost impact must be reviewed in the deployment cost
policy before R2 admission.

## Tenant isolation and operations

The aggregate selection requires all four subdocuments to share the exact deployment, tenant, AWS
account, region, endpoint, object-key prefix, and KMS key. Credential and KMS custodians must be
different. Operations, security, cost, and external-checkpoint custodians must also be four
distinct identifiers.

`ObjectStorageProductionOperationsSelection` additionally binds exact digests for retention,
backup, restore, expired-upload cleanup, and cost policy; an exact backup region; a five-minute RPO;
a one-hour RTO; off-host immutable backup; external anti-rollback retention; an independent restore
drill; and explicit cost approval. These are required deployment objectives, not claims that a
backup or restore has occurred.

AWS documents native S3 integration with AWS Backup and separately documents Versioning, Object
Lock, and replication as data-protection mechanisms. UX-007R2 must select a separate immutable
backup inventory appropriate for the authority/admission/journal stores and prove a new-path
restore. It must not turn on versioning or Object Lock in the ephemeral transport bucket and then
reuse a current-version listing as proof of byte deletion.

## Compiler and substitution rules

`compile_aws_s3_production_provider_selection()` revalidates every strict input and binds it to the
complete UX-007L `ObjectStorageDeploymentAuthority`. It requires:

- exact deployment and tenant scope across all documents;
- the fixed Seoul endpoint and `pajin/tenants/{tenantId}` prefix;
- a 900-second authority upload TTL;
- one account across bucket, STS role, and KMS key;
- the bucket default KMS ARN to equal the exact tenant key ARN;
- equal Bucket Key settings; and
- separate credential and KMS custodians.

Cross-tenant, cross-account, different-key, different-prefix, different-TTL, pre-authority time,
custodian collapse, digest substitution, JSON boolean/integer coercion, unknown fields, and
secret-bearing field names fail closed.

## Authority ceiling

`AwsS3ProductionProviderSelection` fixes all of the following false:

- `productionActivationEligible`;
- `transportAdmissionEligible`;
- `publicNetworkEligible`;
- `artifactAdmissionEligible`;
- `finalizationEligible`; and
- `externalResourceCreationEligible`.

It simultaneously fixes fresh live inventory, credential-issuer evidence, KMS evidence,
cross-tenant isolation probes, and restore-drill evidence as required. The selection cannot be fed
to the UX-007Q MinIO runtime and creates no URL, credential, KMS operation, AWS call, Artifact, Run
event, or deployment default.

## UX-007R2 completion requirements

UX-007R2 must not be compiled from fixture values. It requires at least:

1. deployment-owned account, bucket, VPC endpoint, IAM role, KMS key, and policy digests;
2. a production AWS adapter and provider-common conformance environment;
3. fresh reads of bucket ownership, Block Public Access, encryption, versioning/Object Lock, bucket
   policy, endpoint policy, role trust/permissions, STS duration/tag/source-identity behavior, KMS
   state/rotation/policy, and CloudTrail audit configuration;
4. positive same-tenant upload/read/cleanup and negative cross-tenant, public-path, wrong-role,
   wrong-prefix, wrong-key, expired-session, and disabled-key probes;
5. an independently retained checkpoint and signed live inventory;
6. off-host backup publication plus an independent new-path restore drill; and
7. deployment security, operations, and cost approvals.

Only a new versioned authority may decide whether that complete evidence can enable production
transport. Artifact admission and finalization remain separate even after transport activation.

## Compatibility and rollback

The change is additive. It introduces one internal module, strict tests, this contract, and an ADR.
It changes no public route, environment variable, SDK call, provider runtime, database, existing
wire, or Artifact reader.

Rollback removes the R1 selection module and documents. Because R1 cannot activate transport or
create resources, rollback has no remote cleanup step. A later R2 rollback must first reconcile
pending provider attempts and preserve all current authority, admission, journal, and external
checkpoint heads.

## Official references

- [Amazon S3 endpoints and quotas](https://docs.aws.amazon.com/general/latest/gr/s3.html)
- [Virtual hosting of S3 buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html)
- [AWS STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [AWS STS session tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html)
- [S3 Object Ownership](https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html)
- [S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [S3 SSE-KMS](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html)
- [S3 Bucket Keys](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-key.html)
- [AWS KMS automatic rotation](https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKeyRotation.html)
- [AWS KMS key deletion](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys-scheduling-key-deletion.html)
- [S3 data protection](https://docs.aws.amazon.com/AmazonS3/latest/userguide/data-protection.html)

## Related documents

- [ADR-0195 AWS S3 production custody selection](../adr/0195-select-aws-s3-seoul-production-custody-boundary.md)
- [UX-007Q selected-provider admission](UX-007Q-selected-provider-deployment-admission.md)
- [UX-007L Object Storage deployment authority](UX-007L-object-storage-deployment-authority.md)
