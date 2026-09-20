# ADR-0298: Separate Local Web Observation from Governed Execution

- Status: Accepted
- Date: 2026-09-14
- Scope: WEB-004 authenticated browser assessment continuation

## Context

WEB-003 proves one deliberately narrow local path: an explicit operator assertion authorizes the
exact numeric-loopback OWASP Juice Shop recipe, a disposable browser logs in, three controlled
diagnostics run, two local attack paths are derived, and a secret-free Run is sealed. That assertion
is not a core Campaign approval, signed Capability release, ActionPermit, Gateway dispatch, Graph
admission, or Finding decision.

The next slice needs reusable route and form discovery, more diagnostic recipes, strict source
loading, cross-Run comparison, and Graph-ready material. Reinterpreting the existing local assertion
as any of those authorities would bypass the platform's deployment-pinned lifecycle, approval, and
execution boundaries. It would also make two executions by the same host appear independent when
they are only locally corroborating observations.

## Decision

WEB-004 is split into authority-preserving layers.

1. Account provisioning remains outside the registered browser Capability. Credentials stay in
   process memory. Only an opaque, content-addressed, secret-free receipt can cross into a Capability
   plan.
2. A code-backed `web.browser-assessment` Capability registers the exact WEB-003 plan, target,
   methods, risk, side-effect class, and all seven required implementation roles. Its initial Profile
   and Plan classify login conservatively as `irreversible-write` with cleanup required, and remain
   inert: credential delivery, login-state mutation, cleanup authority, lifecycle activation,
   execution authorization, ActionPermit issuance, Gateway dispatch, and Finding authority are all
   false.
3. Passive authenticated discovery uses a fresh hardened browser context. It follows bounded,
   query-free, same-origin links and records only route and form structure. It never submits a
   discovered form, retains values, saves raw DOM, or captures screenshots.
4. Additional diagnostics are code-owned, GET-only recipes with fixed controls and source/replay
   trials. Their results remain local observations and cannot mint Findings.
5. A sealed WEB-003 Run must be reloaded through independently supplied Run ID and root-digest pins,
   then interpreted through code-owned typed semantic oracles. Artifact integrity alone is not
   semantic validation.
6. The local authorization can produce only a content-addressed
   `LocalWebAssessmentCampaignDraft`. The draft previews the exact plan, scope, T2 Capability, and
   every missing governed prerequisite; it is not a core `CampaignManifest` and cannot be consumed by
   the Campaign ledger or Policy engine. A local two-Run comparison accepts only distinct verified
   source references. Matching results are called `local-corroborated`, never independently attested.
7. Canonical Graph material is produced only as neutral Observation and Hypothesis proposals under
   `sealed-source-authority` lineage. It contains no Capability Grant, ActionPermit, approval receipt,
   or execution claim. Pure proposal construction does not perform Graph admission and cannot create
   a Finding or authorize SARIF.
8. Markdown output is local and deterministic. External delivery remains a separate authenticated,
   explicitly authorized action.

Dynamic discovery cannot widen Campaign Scope, register a new Capability, generate a Permit, or turn
a discovered form into an executable action. Any later form submission requires a code-owned recipe,
an appropriate side-effect classification, a new Graph decision, and a fresh Permit.

## Consequences

The local Juice Shop path can gain broader observation coverage without weakening the core authority
model. It can prepare an inert Campaign draft and exact registration-only Capability material before
the production execution path exists, but it cannot compile the draft into a core Campaign.

Full governed execution remains closed until a deployment supplies an authenticated account-receipt
issuer, a signed lifecycle release and activation, an approval input authority, credential delivery,
explicit login-state mutation authority, cleanup capacity and permits, a Gateway/Worker route, and
bounded artifact return. Numeric `127.0.0.1` identifies the host process, but it identifies the worker
container itself inside Docker; a signed target-routing contract is therefore required before worker
dispatch.

The bundled CLI derives the source Run ID and root digest from the Run it just produced, so its
`sourceIdentityPinIndependentlySupplied` marker is false. The strict loader accepts caller-supplied
pins, but neither mode is an independent execution or target attestation.

Independent Finding validation additionally requires a separately authorized executor and target
attestation. A second Run from the same host and trust domain does not satisfy that requirement.

## Rejected alternatives

- Treating `LocalWebAssessmentAuthorization` as a core approval or Permit.
- Downgrading the T2 browser action to use the approval-free T0/T1 Permit path.
- Activating an unsigned Capability or invoking the host browser behind the Gateway's back.
- Persisting credentials in Tool arguments, Run artifacts, Graph nodes, or reports.
- Letting discovered links, forms, selectors, or input names become executable actions automatically.
- Calling same-host repetition independent validation or exporting it as a confirmed Finding.
