# ADR-0326: Preserve the Web Assessment Budget by Suppressing Decorative Images

- Status: Accepted
- Date: 2026-09-23
- Scope: Exact local Juice Shop WEB-006 aggregate browser assessment

## Context

WEB-006 adds authenticated passive discovery between installed route navigation and DOM probing. The
phase changes intentionally retire the active document so background page requests cannot cross into
the narrower discovery policy. A first full governed local attempt consumed its 100-request cumulative
ceiling before SQL login diagnostics. A separate bounded diagnosis measured 53 navigation requests, 19
passive requests, and 25 DOM source requests, plus fingerprint and account provisioning. The failed
attempt remains terminal and is never resumed with its consumed approval or Permit.

The earlier successful fixed assessment requested product and carousel pictures during authenticated
navigation. They are decorative network resources; the structural route/form crawl, authenticated
state, DOM marker, HTTP controls, and independent replay do not depend on their response bodies.

## Decision

Keep the 100-request cumulative ceiling, the 20-request passive ceiling, both document-retirement
boundaries, and the installed route and diagnostic set. In the aggregate browser's network gate, abort
only a code-owned Juice Shop decorative image request when all of these conditions hold:

- the installed adapter implementation ID is the exact Juice Shop ID;
- the current phase is authenticated navigation or a DOM source/replay phase;
- the method is `GET`, Playwright classifies the request as `image`, and the URL has no query delimiter;
- the URL starts with the installed exact origin followed by `/assets/public/images/products/` or
  `/assets/public/images/carousel/`;
- the request is not a redirect, which retains its existing earlier rejection.

Record a fixed `decorative-image-disabled` block reason and abort before a network reservation. Every
other request still enters the existing gate. In particular, passive discovery images retain its
query-free, bodyless request and receipt checks; the DOM probe's `data:` image marker is outside these
network paths. When an installed route exactly equals the already authenticated page URL, reuse that
document while still checking its ready selector and capturing the route evidence. A different URL
continues through normal navigation.

This is an execution-cost change within the existing code-owned adapter and wire contract. It does
not add an executable input, widen Campaign Scope, raise a Permit budget, change a serialized field,
or give discovered content authority.

## Consequences and verification

The product and carousel pictures are absent from browser screenshots; page text, controls, DOM
hashes, screenshots, and the diagnostic marker remain captured. This visual limitation is part of the
evidence, not a claim of full-fidelity page rendering. The rule does not apply to another installed
adapter without a separate code and contract review.

Two separate, fresh governed local Runs (the direct execution and its redacted PoC replay) completed
with separate source and validation Workers. Each assessment recorded 95 completed requests, 16
decorative image blocks, 19 passive requests, four discovered routes, and one form. Both Campaigns
produced nine Graph events, three independently validated Findings, and two attack paths. Their
completed parent Runs passed strict reload in separate processes. The expanded Web regression passed
573 tests; the changed source passed Linux-target mypy and repository Ruff checks. No external
delivery occurred.

The exact local target still has only five requests of headroom. A version or behavior change can
fail closed at the unchanged budget; this evidence does not prove transfer to another target or a
general request-cost estimate.

## Compatibility and rollback

No historical Run or authority artifact is rewritten, and no previously consumed approval is reused.
Rollback restores the prior browser request behavior for future Runs; it cannot retroactively change
sealed observations. Historical completed-Run reader compatibility is tracked separately because
defaulted plan and discovery fields can alter reconstructed legacy digests.
