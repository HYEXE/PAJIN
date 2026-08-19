# UX-007D: Exact Run Cancellation ABAC

## Goal

Require an Operator's local subject and a separate deployment rule to match one immutable Run
submission authority digest before the Control Plane kill switch can change durable state.

## Deployment contract

`PAJIN_CP_RUN_CANCELLATION_ABAC_POLICY` contains strict JSON with:

- API version `pajin.control-plane.run-cancellation-abac-policy/v1`
- policy ID `run-cancel-policy_<32 lowercase hex>`
- one or more `run_cancellation_rules`
- one exact `(principal subject, run.cancel, submission authority digest)` tuple per rule
- a lowercase 64-hex submission authority digest and no wildcard matching
- unique complete tuples, with multiple distinct tuples allowed for one Operator

Every subject must already resolve through an opaque bearer or deployment-owned OIDC mapping with
Operator authority. The policy cannot create authentication or roles. Operators may be omitted;
when this policy is enabled, omission denies their cancellation requests.

For a public submission, deployment tooling computes the digest with
`pajin.control_plane.models.submission_authority_digest` from the exact submitter, campaign name,
complete input, idempotency key, Job kind, and retry limit. The function uses the repository's
canonical JSON and domain separation. Individual fields, a digest supplied in the cancellation
request, or a locally invented serialization are not accepted.

## Admission sequence

1. Existing bearer/OIDC authentication resolves one canonical local `Principal`.
2. Existing RBAC requires `PrincipalRole.OPERATOR`.
3. The cancellation transaction acquires the existing canonical Job/Approval or Replay lock graph.
4. The Run is locked and its schema-validated, immutable `submission_authority_digest` is read.
5. The authorizer matches local subject, fixed `run.cancel`, and the exact digest.
6. Existing state checks and idempotent response run only after ABAC allows.
7. Existing Job, Approval, Replay, Run, reservation, and audit transitions remain unchanged.

Only the public `cancel_run` entry point performs this Human ABAC check. Internal lifecycle
cancellation caused by approval denial or expiry remains governed by its existing state authority
and cannot be invoked through this policy.

## Fail-closed cases

- Policy JSON is blank, oversized, malformed, duplicated, or contains unknown fields.
- A rule names an unauthenticated subject or a subject without Operator authority.
- The authenticated Operator has no exact rule.
- Any submission-bound field differs and therefore produces a different digest.
- The Run has a missing, malformed, substituted, or unlisted submission authority digest.
- The action differs from `run.cancel`.

Denials return generic HTTP `403` before an idempotent result or any durable mutation. The
cancellation reason does not affect policy selection.

## Authority exclusions

- Policy entries do not grant authentication, Operator role, Run submission, or execution.
- URL Run ID, campaign label, Job kind, and Run input are not independently sufficient authority.
- OIDC token roles, groups, entitlements, HTTP headers, or mTLS certificate fields are not inputs.
- Approval ABAC rules do not authorize cancellation and cancellation rules do not authorize
  approval decisions.
- Resume, maintenance, Replay issuance, reads, export, and Worker routes remain outside this policy.
- The policy does not change cancellation propagation, Replay refund, lease fencing, or cleanup
  semantics.

## Validation

- Strict parsing rejects duplicate tuples, malformed digests, and extra fields.
- Startup rejects rules that do not name authenticated Operators.
- API tests prove an exact precomputed submission digest permits cancellation.
- API tests change campaign, input, idempotency key, Job kind, and retry limit independently and
  prove generic `403` with unchanged Run, Job, and event state.
- API tests prove an unlisted Operator is denied without mutation.
- Existing cancellation tests cover policy omission and preserve RBAC-only compatibility.
