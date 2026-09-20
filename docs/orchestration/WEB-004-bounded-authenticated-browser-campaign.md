# WEB-004: Bounded Authenticated Browser Campaign

- Status: Bounded local observation implemented and locally verified; governed execution unavailable
- Domain: Web / API
- Entry point: `pajin web-campaign-observe-local`
- Predecessor: [WEB-003](WEB-003-exact-loopback-browser-assessment.md)
- Decision: [ADR-0298](../adr/0298-separate-local-web-observation-from-governed-execution.md)

## Objective

WEB-004 extends the approved local OWASP Juice Shop path without converting local evidence into
production authority. It adds Campaign and Capability preparation, passive authenticated route/form
discovery, two passive diagnostic recipes, strict sealed-source loading, typed semantic comparison,
and neutral Graph proposals.

The supported target remains exactly `http://127.0.0.1:3000`. This contract does not authorize an
arbitrary Internet crawler or another private-network target.

## Layered flow

```text
explicit exact-local authorization
-> disposable account provisioning outside the registered Capability
-> opaque secret-free account receipt
-> inert local Campaign draft (never a core CampaignManifest)
-> code-backed irreversible-write, cleanup-required Capability + inert Profile/Plan
-> local WEB-003 browser execution under its existing local authority
-> sealed Run reload from exact Run ID/root digest
-> source-integrity-only Run reference and sealed-source authority
-> fresh authenticated passive route/form discovery
-> fixed GET-only security-header and FTP-listing diagnostics
-> code-owned semantic interpretation
-> neutral Graph Observation/Hypothesis proposals
-> deterministic local report
```

The current Capability Profile and Plan stop before credential delivery, login-state mutation and
cleanup authority, signed lifecycle activation, ActionPermit issuance, Gateway dispatch, and Worker
execution. The local observation runner does not claim that its host execution passed through those
production gates.

## Authenticated passive discovery

Discovery starts only after the code-owned normal-login recipe succeeds in a fresh browser context.
During authentication, POST is limited to the exact query-free login endpoint. After all login
requests settle, the runtime starts a separate GET/HEAD-only passive phase; account-registration and
other background POST requests are denied. The context reuses the exact-origin network reservation
gate, blocks redirects, service workers, WebSockets, downloads, external origins, denied paths, and
unapproved methods, and is always closed.

The traversal is deterministic and bounded by route, depth, link, form, field, time, request, and
response limits. Only query-free same-origin anchor and area targets are eligible. URL credentials,
external origins, unsafe schemes, ambiguous encodings, query values, numeric object routes, and
sensitive account or administration routes are rejected by fixed categories.

For each retained form, the result records structural metadata such as method, action disposition,
encoding, control tag/type, safe field-name state, autocomplete role, and Boolean attributes. It
does not retain control values, page content, raw DOM, cookies, tokens, credentials, screenshots, or
submitted requests. Discovery output cannot expand Scope or authorize an action.

## Additional diagnostics

Two versioned passive recipes are separate from the WEB-003 three-issue Result contract:

- `security-header-posture`: two exact `GET /` reads inspect code-owned CSP, MIME-sniffing, and frame
  protection predicates.
- `ftp-directory-listing`: two source/replay pairs compare exact `GET /ftp/` with fixed
  `GET /ftp/pajin-web004-control-missing-v1.md` controls and retain only status, media-shape, and
  bounded anchor counts. The listing request permits gzip because Juice Shop 19.2.1's identity
  representation advertises a longer body than it sends. Compressed input and incrementally decoded
  output are bounded separately before retained bytes are materialized.

Both recipes cap responses at 256 KiB, persist no raw body or file names, perform no callback or
target write, and derive status and narrative from their typed facts. Their `findingAuthority` flag is
always false.

## Source verification and reconciliation

The strict loader accepts an independently supplied Run path, Run ID, and root digest. It verifies the
single seal, two-event lifecycle, exact artifact inventory, plan/authorization/result bindings,
deterministic report rendering, and every screenshot's reference, size, and hash. It returns
`source-integrity-only` material.

Typed semantic oracles then re-derive the three WEB-003 outcomes from closed fact schemas. A local Run
reference binds the exact plan, local assertion, result, root digest, and semantic claims while
explicitly denying Permit, independent-execution, and Finding semantics. An optional local-only
comparison requires distinct Run, root, result, and local-authorization identities.

Even when all claim and attack-path semantics match, the outcome is only `local-corroborated` while
the Web executor and target lack independent attestation. Finding and SARIF authority remain false.

## Graph and reporting

Sealed source material can be converted into pure Canonical Graph Observation and Hypothesis
proposals with exact local-draft, Run-reference, source-root, result, plan, target, and semantic
digests. Graph Action status describes successful source materialization only. Lineage uses
`sealed-source-authority`; Capability Grant, ActionPermit, approval receipt, and governed execution
identities are absent. The proposal set contains no Finding node and does not open or mutate a Graph
store. Admission requires the existing producer and lineage authorities in a separate step.

The combined Markdown report is deterministic and local. It distinguishes observed behavior,
potential impact, missing governance authorities, retained disposable account state, and unperformed
external delivery. No destination is accepted by the local command.

## Local verification evidence

On 2026-09-14, the local command ran without browser-runtime warnings against the user-authorized
OWASP Juice Shop 19.2.1 instance at exact `http://127.0.0.1:3000`. Outer Run
`run_20260914T061252Z_7ce5c4cc` binds source WEB-003 Run
`run_20260914T061252Z_c4169751` and records:

- three `locally-reproduced` semantic claims and two `locally-validated` attack paths;
- eight authenticated query-free routes and two value-free forms from 75 HTTP Evidence records;
- `locally-observed` security-header posture and FTP directory listing from six additional Evidence
  records;
- no persisted credentials, query values, raw DOM, extra-diagnostic response bodies, extracted FTP
  listing entries, or absolute paths;
- false lifecycle, ActionPermit, Gateway, independent-attestation, Graph-admission, Finding, SARIF, and
  external-delivery markers.

The outer Run has one seal over 14 artifacts and two events. A strict reload with explicit expected Run
ID and root digest returned valid for root
`d85be14c03b80aa8fa0c334b5ae6a9fe0578dd136686a233630c43cf2e388670` and reproduced Result digest
`1a99aa91392c7cd0e66ac1df184c6018fceb75caacdc93cbfcdb690bebee3d58`. The source Run has one seal
over 13 artifacts and two events, root
`dccfdd008bb324cf463dc1bc0964eaecb3feadb507eb7199243db309ee526cf9` and Result digest
`e2f9096d50c75fcd73cf22cb7a07f7592b15728f9f07c0b1832bb79a16b76b6b`.
The latest DOM-control/probe screenshots were inspected at original resolution and showed opaque masks
over generated runtime markers.

The final authority redesign validation and the warning-free confirmation each created one disposable
account. Earlier WEB-003/WEB-004 validation accounts also remain in the local lab. No account deletion
was authorized or attempted, credentials were not persisted, and this contract does not assert a
current aggregate account count.

The final integrated repository verification collected 9,046 tests and completed with 8,970 passed,
76 environment-gated skips, and no failures. Repository lint, the three CI Linux strict mypy commands,
the WEB-004 format subset, and fresh source and wheel builds also passed. A whole-tree format check is
not an existing CI gate and reported 234 unrelated files that would be reformatted; no bulk formatting
was performed.

## Remaining production boundary

The following are deliberately not implemented or claimed by this slice:

- authenticated issuer authority for the opaque account receipt;
- authenticated compilation of the inert draft into a core Campaign;
- signed Capability release and activation in a deployment inventory;
- operator approval input authority and durable T2 ActionPermit consumption for this Capability;
- Gateway/Worker routing for a host-loopback browser target;
- secret-broker delivery, login-state mutation authority, cleanup capacity/permits, and bounded
  browser artifact return from the Worker;
- independently attested replay and target identity;
- Graph admission, Finding creation, SARIF export, or external report delivery;
- discovered-form submission, account cleanup, arbitrary targets, IPv6/HTTPS, or browser diversity.

These are authority and isolation requirements, not flags that a local caller can opt around.
