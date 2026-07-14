# ADR 0022: Same-origin Control Plane Web Console

- Status: Accepted
- Date: 2026-07-14

## Context

ADR 0011 and ADR 0012 provide an authenticated durable Control Plane and a lease-aware Worker
daemon, but operation still requires direct API calls. The first product UI must submit registered
Jobs, show durable Run state, and expose the append-only event trail without weakening the existing
role boundary or introducing a second authentication system.

A browser cannot attach an `Authorization` header to normal page navigation. Putting an opaque
Bearer credential in a URL, cookie, server-rendered form, browser storage, or build-time asset would
create new leakage, CSRF, session, and retention risks. A separate frontend origin would also require
CORS and an additional deployment boundary before tenant isolation exists.

Run input may contain sensitive assessment configuration and can be large. Returning it for every
row in a dashboard list would expand both disclosure and database resource cost. The existing
`RunView` is therefore unsuitable as a list DTO.

## Decision

The FastAPI Control Plane serves a dependency-free HTML, CSS, and JavaScript Console at `/ui` from
packaged `importlib.resources`. The public shell contains no Run data, credential, inline script,
inline style, or external resource. All state remains behind the existing same-origin `/v1` API.

The Console keeps a Bearer credential only in a JavaScript module variable. It does not use cookies,
`localStorage`, `sessionStorage`, IndexedDB, a URL, a DOM attribute, or console logging. Lock, page
exit, and HTTP 401 clear the value. Fetch calls use fixed same-origin paths, omit credentials, disable
caching and redirects, and attach the Bearer header only after explicit connection.

`GET /v1/session` returns the authenticated subject and roles to Operator, Approver, or Auditor
credentials. The UI enables submission only for Operators; server-side role checks remain final.
Worker credentials cannot access session, Run list, detail, or event endpoints.

`GET /v1/runs` returns `RunListView` with `RunSummaryView` items, total count, limit, and offset:

- `input`, submission key, Job payload/result, and lease fields are absent;
- SQLAlchemy defers the input column rather than loading and discarding it;
- state filtering is server-defined;
- ordering is fixed to `updated_at DESC, run_id DESC`;
- limit is 1-100 and offset is 0-10,000.

The first UI slice supports idempotent Run submission, bounded listing, selected Run detail, and the
append-only event trail. Polling is explicit or five-second interval based. Approval decision,
checkpoint resume, cancellation, report download, Agent Graph, SSE, and WebSocket are excluded.

HTML responses apply a restrictive CSP with same-origin script, style, and API connections only;
inline attributes, objects, workers, framing, base URLs, and form navigation are denied. UI and API
responses use no-store and no-referrer policies. UI rendering creates DOM nodes and assigns
`textContent`; untrusted response values are never interpreted as HTML.

The assets are declared as setuptools package data so editable installs, wheels, and the read-only
Control Plane container use the same resources. No npm, CDN, template engine, or runtime filesystem
write is required.

## Consequences

- A local Operator can submit and monitor a durable Run without manually constructing API calls.
- Approver and Auditor credentials receive a read-only Console because the UI learns their role.
- The browser holds a plaintext token in memory while unlocked; XSS, a privileged extension, or
  DevTools can still read it. CSP, no external assets, same-origin serving, and HTTPS reduce but do
  not eliminate that risk.
- The shell is intentionally public, while every data operation remains authenticated. Deployments
  must not treat access to `/ui` as authentication.
- Offset pagination is bounded and sufficient for the local preview. Large fleets should move to a
  stable keyset cursor and add managed database indexes.
- The event endpoint still returns the complete Run event list. Incremental sequence pagination is a
  later scaling requirement.
- Current credentials and Run ownership are global RBAC, not tenant scoped. Remote or multi-tenant
  exposure is prohibited until identity, tenant ownership, CSRF/session policy if applicable, TLS,
  and authorization isolation are separately designed and tested.

## Validation

Automated tests verify role separation, stable filtering and pagination, query bounds, summary field
minimization, read-only listing, idempotent submission, CSP and security headers, public-shell versus
authenticated-data separation, absence of persistent credential APIs and unsafe DOM sinks, the
default executor input, and packaged asset loading. Wheel inspection verifies all three static assets
are included. Desktop and compact headless-browser renders verify the responsive shell layout.
