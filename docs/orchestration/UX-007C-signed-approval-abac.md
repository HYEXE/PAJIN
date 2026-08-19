# UX-007C: Signed Approval ABAC

## Goal

Require an Approver's local subject and deployment rule to match the exact Tool ID, target, and
risk tier recovered from a verified signed checkpoint before an approval decision can mutate
Control Plane state.

## Deployment contract

`PAJIN_CP_ABAC_POLICY` contains strict JSON with:

- API version `pajin.control-plane.abac-policy/v1`
- policy ID `abac-policy_<32 lowercase hex>`
- one or more `approval_decision_rules`
- one exact `(principal subject, approval.decide, Tool ID, target, risk tier)` tuple per rule
- unique complete tuples, with multiple distinct tuples allowed for one subject
- only T3 or T4 risk tiers and no wildcard matching

Every listed subject must already be authenticated through an opaque bearer mapping or the
deployment-owned OIDC mapping and must have Approver authority. The policy cannot create a role.
Authenticated Approvers may be intentionally omitted; when the policy is enabled, omission means
their approval decisions are denied.

## Admission sequence

1. Existing bearer/OIDC authentication resolves one canonical local `Principal`.
2. Existing RBAC requires `PrincipalRole.APPROVER`.
3. The service locks the Approval and signed checkpoint and verifies their exact relationship.
4. The checkpoint signature is verified and the `ApprovalIntent` is reconstructed.
5. The ABAC authorizer matches local subject, `approval.decide`, Tool ID, target, and risk tier.
6. Existing self-approval, expiry, lifecycle, and decision transitions run only after ABAC allows.

## Fail-closed cases

- Policy JSON is blank, oversized, malformed, duplicated, or contains unknown fields.
- A rule names an unauthenticated subject or a subject without Approver authority.
- The authenticated Approver has no rule.
- The signed Tool ID, exact target, or risk tier is absent from the subject's rule.
- The action differs from `approval.decide`.
- The Approval/checkpoint relationship or checkpoint signature is invalid.

ABAC denials return generic HTTP `403`, do not identify the failed attribute, and occur before any
Approval, Run, checkpoint, Job, or audit-event mutation.

## Authority exclusions

- Policy entries do not grant authentication or roles.
- OIDC token roles, groups, entitlements, or other claims are not ABAC inputs.
- mTLS certificate fields and Worker/Target TLS evidence are not ABAC inputs.
- The approval reason and `approve` boolean do not select authorization.
- This policy does not cover reads, Run submission/cancellation/resume, maintenance, Replay,
  export, or Worker routes.

## Validation

- Strict policy parsing rejects duplicates, lower risk tiers, and extra fields.
- Startup rejects rules that do not name an authenticated Approver.
- API tests prove exact signed attributes can be decided.
- API tests prove a mismatched signed attribute returns `403` without state or event mutation.
- Existing role-only approval behavior remains covered when the policy is absent.
