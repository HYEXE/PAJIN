# ADR-0168: Authorize Approval Decisions from Signed Attributes

## Status

Accepted

## Context

Control Plane routes already separate Operator, Approver, Auditor, and Worker roles. Role checks
answer whether a principal may reach an approval route, but they do not constrain which signed Tool
intent that Approver may decide. OIDC token claims, client-certificate attributes, request metadata,
or a caller-provided reason must not silently become authorization inputs.

The existing T3/T4 checkpoint boundary already signs the exact call fingerprint, Tool ID, target,
risk tier, and expiry. The service verifies that checkpoint and its Approval record before changing
the decision state. Those fields provide a bounded server-verified resource context for the first
ABAC vertical slice.

## Decision

### Add one deployment-owned exact allow policy

`pajin.control-plane.abac-policy/v1` contains a bounded list of exact approval-decision tuple rules.
Every rule fixes one local Approver subject, action `approval.decide`, Tool ID, target, and T3/T4
risk tier. Multiple exact tuples may name the same subject, but the complete tuples must be unique.
Rules cannot contain wildcards, lower risk tiers, unknown subjects, or subjects without
authenticated Approver authority.

The policy is optional for compatibility. When configured, an authenticated Approver without a
matching rule or signed attribute match is denied by default. A listed rule does not grant the
Approver role; RBAC admission remains a prerequisite.

### Evaluate only after checkpoint integrity verification

The application loads and locks the Approval and checkpoint, verifies their relationship, verifies
the signed checkpoint, and reconstructs the exact `ApprovalIntent`. It then evaluates the local
principal subject plus fixed action and signed Tool ID, target, and risk tier before any approval
state, Run state, or audit event is changed.

The decision request's `approve` flag and reason do not select the rule. OIDC claims, HTTP headers,
mTLS certificate fields, Worker identity, Run input, and current time do not add ABAC authority.
Existing separation of duties, expiry, lifecycle, and one-use checkpoint checks still run.

### Keep denial generic and mutation-free

An ABAC mismatch returns a generic HTTP `403` and does not disclose which attribute failed. The
denied request creates no decision event and does not change Approval, checkpoint, Job, or Run
state. Deployment request/access logging remains outside this slice.

## Consequences

- Operators can pin individual Approvers to exact signed Tool, target, and risk-tier combinations.
- A valid Approver token or MFA OIDC token is insufficient for a non-matching approval intent.
- Policy omission preserves the previous role-only approval behavior.
- Policy updates require coordinated deployment configuration but no database migration.
- The policy does not authorize Run submission, cancellation, resume, maintenance, Replay,
  export, read visibility, or Worker operations. Those remain future ABAC slices.
- Exact targets avoid ambiguous prefix, glob, regular-expression, DNS, and URL-normalization
  semantics. A new policy version is required before adding those features.

## Rejected alternatives

### Read roles or entitlements from OIDC claims

Rejected because ADR-0166 makes the deployment mapping, not token-selected claims, the local role
authority. Token claims also do not prove the signed workload resource attributes.

### Authorize from approval request fields

Rejected because the `approve` flag and reason are caller-controlled decision data, not the signed
Tool intent being authorized.

### Match target prefixes or regular expressions

Rejected because normalization and overlap rules would make authorization interpretation broader
and harder to audit than exact deployment-owned values.

### Apply one broad policy to every route in this slice

Rejected because read visibility, Run lifecycle, Replay, and Worker mutations have different
resource authorities. They require separate contracts rather than guessed common attributes.

## Compatibility and rollback

The change is additive and opt-in. Removing `PAJIN_CP_ABAC_POLICY` restores the prior role-only
approval route. Existing routes, request/response schemas, database schema, checkpoint signatures,
and audit-event formats do not change.

## Related documents

- [UX-007C contract](../orchestration/UX-007C-signed-approval-abac.md)
- [ADR-0166 Human OIDC identity](0166-bind-mfa-oidc-identity-without-token-role-authority.md)
- [ADR-0167 Worker mTLS identity](0167-bind-worker-subjects-to-direct-mtls-certificates.md)
