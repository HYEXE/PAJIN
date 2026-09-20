# ADR 0297: Bind local browser assessment to an exact loopback origin

Status: Accepted

## Context

PAJIN has bounded Web discovery, synthetic SQL injection measurement, and independently controlled
benchmark paths, but it does not have one operator-facing flow that logs into a real application,
navigates dynamic pages, exercises multiple diagnostics, joins their evidence into attack paths, and
produces a local report. Treating existing discovery metadata as execution authority would widen the
Campaign and Capability boundaries. Accepting arbitrary URLs would also turn a local product slice
into an unbounded scanner before its authorization, identity, rate, and reporting contracts exist.

The first approved target is an operator-provided OWASP Juice Shop instance on numeric loopback. It
is deliberately vulnerable and may retain disposable test state. The desired flow must prove actual
browser behavior without persisting passwords, session tokens, response bodies, or raw DOM content,
and without relabeling local diagnostic results as confirmed PAJIN Findings.

## Decision

Add WEB-003 as a separate opt-in local assessment boundary. A code-owned Juice Shop recipe binds an
exact `http` or `https` numeric loopback origin, registration and login endpoints, browser selectors,
three dynamic routes, three fixed diagnostics, denied paths, duration, request, and response limits.
`localhost`, non-loopback addresses, credentials in URLs, redirects, ambient proxies, ambiguous path
representations, and target-derived scope expansion fail closed.

The CLI requires `--authorized-local-lab`. That assertion creates a content-addressed authorization
valid for at most 30 minutes and bound to the exact plan digest, origin, disposable-account creation,
and the three checks. Network execution binds its monotonic deadline to that expiry and rechecks wall
time at every phase and request reservation, so beginning shortly before expiry cannot extend request
authority. It is not a reusable Campaign approval, Capability Grant, ActionPermit, or authorization for
another host. The implementation may later be adapted behind those wider product authorities; WEB-003
does not infer them now.

One fresh Playwright context blocks service workers, WebSockets, downloads, redirects, non-approved
origins, methods, and POST paths. It creates one random local test account through the fixed recipe,
uses the normal login UI, and waits for concrete components on search, contact, and about routes. The
context is closed before the result can claim browser completion. The account is intentionally not
deleted because deletion is outside the approved methods and paths; this retained local state is
reported explicitly.

The diagnostic set is fixed:

1. A true/false-condition login comparison, repeated twice, proves whether unauthenticated input
   mints a session and whether that session can read the protected user directory.
2. That injected session reads its own basket, the distinct basket created for this run, and a missing
   control identifier, repeated twice. It never selects an unrelated customer's basket as the target.
3. A plain-text search control and an inert-effect DOM marker are each exercised in source and replay
   browser trials. The marker only sets a dedicated same-origin DOM attribute and transmits nothing.

Local issues reference exact trial evidence. Attack paths may connect login injection to cross-account
basket access and a crafted search route to same-origin script execution. Every issue and path carries
literal false Finding authority. A failed prerequisite produces an inconclusive downstream diagnostic
instead of manufacturing a success.

## Evidence and compatibility

The Run stores the plan, short-lived authorization, result, safe Markdown report, browser screenshots,
and chained audit events under owner-private permissions. Screenshot capture masks all form controls and
known rendered credential variants, session tokens, and generated DOM markers before bytes are persisted.
HTTP evidence contains a per-Run keyed
request fingerprint, method, origin-relative path without query data, status, media type, response
hash, and size. Browser evidence contains a redacted route, ready selector, DOM hash and size, and a
screenshot hash and reference. It stores no request or response body, raw DOM, password, or session
token. Result validation binds issue status, identity, and canonical narrative to its controlled trials;
requires every diagnostic path stage to reference a local issue; fixes the ordered issue sequence for both
paths; and binds stage/path state and canonical narrative to those issues. Report rendering revalidates the
serialized model. It also rejects duplicate or dangling issue, path, and Evidence references before the
Run is sealed and independently verified, so negative and inconclusive results cannot retain success-form
observed-impact language.

The feature is additive. Base installations do not import Playwright from ordinary CLI paths; actual
execution requires the `browser` optional dependency and an installed Chromium runtime. Existing Web
Campaign, benchmark, Graph, Finding, SARIF, report-delivery, and Control Plane wires do not change.
There is no external submission, Graph mutation, Finding admission, deployment, or generalized Web
target support in this decision.

Failure Runs omit exception detail and record a fixed failure category, false authority/delivery/credential
markers, and whether account state was retained. The seal may also include plan, authorization, audit events,
and browser evidence created before failure. Removing generated local accounts or Run artifacts is a separate
destructive action and is not implied by retrying or completing an assessment.
