# WEB-003: Exact-Loopback Browser Assessment

- Status: Implemented and locally verified for the bounded Juice Shop profile
- Domain: Web / API
- Entry point: `pajin web-assess-local`
- Decision: [ADR-0297](../adr/0297-bind-local-browser-assessment-to-an-exact-loopback-origin.md)

## Supported vertical slice

WEB-003 is the first complete local path from explicit operator authorization through normal browser
login, dynamic SPA navigation, controlled multi-issue diagnostics, attack-path construction, impact
reporting, and tamper-evident local evidence. It accepts only one exact numeric loopback origin and the
code-owned OWASP Juice Shop recipe. This is a reusable engine/recipe split, not a claim of arbitrary
website support.

The fixed flow is:

```text
explicit local-lab assertion
-> exact plan-bound short-lived authorization
-> target version fingerprint
-> disposable account registration
-> fresh Chromium login through the normal UI
-> search/contact/about component navigation
-> DOM XSS control/probe source and replay
-> SQL login true/false source and replay
-> cross-account basket source and replay
-> local issue and attack-path projection
-> secret-free JSON/Markdown/screenshots
-> Run seal and independent integrity verification
-> browser/network cleanup
```

The registration account supplies the controlled cross-account object. The injected session supplies
the attacking identity. The object diagnostic therefore demonstrates a real authorization boundary
without choosing an unrelated local-lab customer's data. Missing SQL session evidence leaves the
object diagnostic inconclusive. A DOM probe changes only `data-pajin-xss` on the document root and
makes no callback or external request.

## Authority and network boundary

The CLI refuses execution unless `--authorized-local-lab` is present. The resulting authorization is
bound to the exact plan digest and expires within 30 minutes. Its expiry is also bound into the network
deadline and rechecked at every phase and request reservation. The plan rejects `localhost`, public or
private non-loopback addresses, URL credentials, paths on the origin input, missing recipes, extra POST
paths, and duplicate routes. Browser and direct HTTP requests share one mediator with phase-specific
request ceilings, an aggregate 128 MB response ceiling, an assessment deadline, no environment proxy,
no redirects, and no cookie jar shared with direct diagnostics.

Only `GET`, `HEAD`, and fixed login/registration `POST` paths are available. Password reset/change and
Socket.IO paths are denied. Chromium disables background networking, QUIC, non-proxied WebRTC UDP,
service workers, WebSockets, and downloads. Scope or budget rejection is recorded by fixed category,
not by attacker-controlled error text.

WEB-003 authorization is local execution authority for this exact slice only. It is not a Campaign,
Capability, Permit, Graph, Finding, SARIF, report-delivery, deployment, or external target authority.

## Result contract

`LocalWebAssessmentResult` requires the ordered `sql-login`, `object-access`, and `dom-xss` issues and
content-addressed attack paths. Every issue contains ordered source and replay trials, control state,
bounded facts, and known Evidence references. The result rejects dangling or duplicate references and
binds all public-safe content into `result_digest`.

The sealed Run includes:

- `plan.json` and `authorization.json`;
- `result.json` and `report.md`;
- eight browser screenshots for login state, three routes, and four DOM control/probe states;
- `events.jsonl` and `run-integrity.jsonl`.

Raw DOM and HTTP bodies are not artifacts. Runtime query values, generated XSS payloads, generated
passwords, generated test-account identifiers, and session tokens are not written. Screenshots mask form controls and
rendered full or application-masked credential variants, session tokens, and generated DOM markers before
their bytes reach the Run. The code-owned
SQL condition remains visible in the versioned plan. The generated test account remains in the local lab
and that side effect is reported. The report is local only and cannot be interpreted as external delivery
or confirmed PAJIN Finding authority.

Issue status is derived from both controlled trials and cannot contradict their reproduced/control
states. Issue IDs bind the check, CWE, and trial evidence. Every non-observed attack-path stage must bind
one local issue, the two fixed paths must reference the exact ordered issue sequences, and path status is
derived from every diagnostic stage. Issue, stage, and path narratives are canonical for their check,
shape, and status; report rendering revalidates the serialized result before emitting them. Negative and
inconclusive diagnostics therefore cannot retain success-form titles or observed-impact text.

## Local verification evidence

On 2026-09-14, WEB-003 ran against the user-authorized OWASP Juice Shop 19.2.1 instance at numeric
loopback. Run `run_20260914T030956Z_037159c5` completed in a fresh Chromium context with:

- 56 completed browser requests and no unexpected console or request-capture failure;
- eight screenshot/DOM-hash page records covering authenticated search, contact, about, and DOM XSS;
- 70 total HTTP Evidence records;
- two passing true/false SQL login trials, each minting a session and reading 31 protected records;
- two passing cross-account basket trials with own-object and missing-object controls;
- two passing DOM XSS probe trials with non-executing plain-text controls;
- three locally reproduced diagnostic issues and two locally validated attack paths;
- two denied-path requests, with no scope expansion or external delivery;
- one valid seal over 12 artifacts and two events, root digest
  `4348d5216b53e46c84094b84a4ef85b8333f32d47cd305b60bbe77d16bc503a2`.

The same checkout's focused suite passed seven tests covering origin and authorization rejection,
authorization-expiry rechecks, ambiguous/denied path and method enforcement, open-request and
request-budget phase gates, controlled positive/negative/inconclusive diagnostics, result/path status
lineage and digest tampering, sealed-run integrity, secret absence, and CLI confirmation. Ruff and
Linux-target strict mypy passed for the implementation. The final contact and DOM-control screenshots were
also inspected at original resolution and showed opaque masks over the account, form, and runtime marker values.

Before the final review hardening, the repository-wide suite completed with 8,791 passed, 76 skipped, and
11 failed. Ten failures were
`PermissionError` results from the sandbox denying loopback test listeners; the exact ten tests passed in
an environment permitting those listeners. The remaining failure detected a stale generated Control Plane
dependency export after the browser extra changed the root lock's hash set. Regenerating that export made
all 19 deployment tests pass. The complete suite was not repeated after that generated-file correction.
The post-review focused suite passed seven tests. The final source produced a fresh sdist and wheel; direct
wheel import found `pajin.web_assessment`, and metadata contains the `browser` extra with `httpx` and
`playwright`. No remote CI or clean-checkout result is claimed.

Earlier failed attempts were sealed while the real browser exposed two timing/state defects: the
welcome dialog appeared after a non-waiting visibility check, and the optional navigation control could
already be covered by an open drawer. The final implementation waits for and closes login obstructions,
bounds the login click, and treats optional navigation interaction conservatively. Failed attempt Runs
and their generated test accounts remain local; eleven random accounts were created across nine private
repository Runs and two temporary diagnostic Runs. Two pre-mask successful Runs retain a reconstructible
application-masked test-account suffix in screenshots; the final Run masks it and generated DOM markers.
No Run contains a full test password or session token. No automatic cleanup or external mutation is claimed.

## Use and remaining limits

Install the optional browser dependency and Chromium, start an authorized Juice Shop on an exact
numeric loopback origin, then run:

```sh
pajin web-assess-local \
  --origin http://127.0.0.1:3000 \
  --authorized-local-lab
```

Use `--headed` for operator-visible execution or `--output` for another private Run root. The command
does not accept credentials, payloads, additional paths, arbitrary recipes, or an external report
destination from the CLI.

[WEB-004](WEB-004-bounded-authenticated-browser-campaign.md) now adds an inert local Campaign draft,
registration-only Capability preparation, authenticated passive route/form discovery, two additional
GET-only diagnostics, strict source verification, semantic reconciliation contracts, sealed-source neutral
Graph proposals, and a wider sealed local report. Remaining work includes authenticated core Campaign
compilation, signed lifecycle/Permit/Gateway execution, authenticated user-supplied account handling, safe
state cleanup, rate/concurrency policy, anti-CSRF and multi-step form submission, browser crash recovery,
accessibility-aware exploration, Graph admission, independently controlled Finding validation, and report
review/delivery. Those are separate trust boundaries, not implied by WEB-003 or WEB-004.
