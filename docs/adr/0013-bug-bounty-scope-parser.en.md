> Languages: [English](0013-bug-bounty-scope-parser.en.md) | [한국어](0013-bug-bounty-scope-parser.ko.md)

# ADR 0013: Digest-approved Bug Bounty Scope Parser

- Status: Accepted
- Date: 2026-07-13

## Context

PAJIN's generic Campaign schema can enforce URL scope, methods, risk, and capability grants, but a
Bug Bounty program begins as a changing human policy. Letting an LLM translate that policy directly
into executable scope would make ambiguous or stale interpretation an authorization source. It
would also be unsafe to record rate limits and testing hours in a review while the runtime ignores
them.

The first Bug Bounty vertical slice therefore needs a deterministic trust transition from the
authoritative policy snapshot to an executable Campaign. It must preserve what remains a manual
operator obligation instead of presenting it as automated control.

## Decision

PAJIN introduces a strict `BugBountyProgram` manifest with the source URI, retrieval time, raw policy
text, typed in-scope and out-of-scope assets, concrete entry points, methods, tool categories,
prohibitions, testing windows, request rate, data-handling requirements, reporting requirements, and
budgets.

The workflow has two separate commands:

1. `bug-bounty-review` validates and normalizes the policy, writes JSON and Markdown review
   artifacts, and computes a SHA-256 digest over canonical JSON. Canonicalization sorts set-like
   scalar collections so the digest is stable across Python processes.
2. `bug-bounty-compile` requires the exact digest plus an identified approver, offset-aware approval
   and expiry timestamps, and authorization evidence. A changed or older policy snapshot invalidates
   the approval.

The compiled Campaign receives only concrete entry points that match their own allow rule and no
deny rule. Explicit deny remains dominant. The MVP rejects T3/T4 risk and unsafe data-handling
settings. Mandatory prohibitions are added even when the source omits them.

`RulesOfEngagement` gains two reusable controls:

- `allowedToolCategories` is a positive allowlist; every category declared by a Tool must be
  included when the list is present.
- `testingWindows` is evaluated in an IANA time zone, including overnight windows. A
  `00:00-00:00` window represents a full selected local day.

`maxRequestsPerMinute` is enforced by a Tool Gateway sliding window. Request units are reserved after all
static policy checks and before adapter preparation or Worker dispatch, so failed execution
attempts still consume program traffic allowance. A Tool declares its bounded request cost; the
fixed Boolean SQLi comparison reserves three units for its three HTTP requests. The limit belongs
to one Campaign runner/Gateway instance. Current Control Plane Jobs execute a complete campaign in
one runner, preserving that boundary.

## Safety invariants

- Free-form policy text is evidence bound into the digest but never interpreted as executable
  authority.
- Only HTTP(S) URL patterns supported by the conservative scope matcher are compiled.
- At least one non-wildcard concrete entry point is required.
- Entry points inside an explicit deny rule fail validation.
- Program policy sources require HTTPS and approvals require timezone-aware timestamps.
- Default prohibitions cover denial of service, social engineering, persistence, credential
  stuffing, real-user-data access, and data exfiltration.
- Test accounts and secret redaction are mandatory in this MVP.
- Private-network execution is rejected except for a `local-lab` program whose executable assets
  use the fixed `boolean-sqli-lab` profile and `host.docker.internal` entry points.

## Consequences

The operator can inspect exactly which policy will execute and approvals cannot silently survive a
policy change. Existing AI Red Team campaigns remain compatible because the new category, rate, and
window fields are optional.

This slice does not parse arbitrary vendor HTML, infer scope with an LLM, enforce evidence deletion,
query duplicate-report systems, or generate a final platform-specific submission. The review lists
retention and duplicate checks as manual controls. A future connector may collect policy documents,
but its output must still pass this typed review and digest approval boundary.

## Validation

Tests cover normalization, policy-text digest binding, set-order stability, approval mismatch and
staleness, allow/deny overlap, entry-point escape, mandatory-prohibition conflicts, T3 rejection,
IANA and overnight time windows, tool-category allowlisting, weighted per-minute rate exhaustion,
private-lab restrictions, artifact serialization, Campaign loading, and a real CLI
review/compile/validate round trip.
