# SYS-003: Operator Read of Retained System Evidence

## Scope

Expose already sealed SYS-002 results through the existing authenticated Control Plane and
same-origin Console. The result concerns one `/usr/lib/os-release` read in an isolated Linux
container. Loading it never issues approval, a Secret Lease, an Action Permit, a Worker job or a
new read. Finding authority, execution authority and general System support remain false.

## Deployment and admission

The existing private `MeasuredProductDeployment` inventory accepts an optional `system` recipe.
Its independently pinned SHA256 covers the exact evidence root, external `SystemReportTrust`,
source/replay Run references, Campaign ID and nonempty list of permitted Operator subjects.
Exports without System omit the new field, preserving the existing three-product JSON shape.
Paths must be exact, retained entries under the deployment evidence root; symlinks and multi-link
files are rejected. The existing environment path/digest pair and bounded strict-JSON loader remain
the sole production configuration path. Startup verifies each configured System result. A malformed
or mismatched deployment fails before Control Plane database creation.

`GET /v1/campaigns/{campaign}/products/system-os-release` uses existing bearer authentication and
the Operator role. The requested Campaign must equal the deployment's Campaign, and the principal
subject must occur in that recipe's allowlist. Both checks precede evidence access. Campaign
selection is only a lookup within these fixed permissions; it cannot select a path, trust key,
Run reference, Scope or execution input. Query strings and request bodies are rejected.
An unknown Campaign and a subject without access receive the same 404 response.

Each request reuses `read_system_run` and, when comparable source/replay results exist,
`compare_system_runs`. The additive `expected_campaign` keyword checks each sealed authorization's
Campaign name; old CLI calls and return formats are unchanged. Thus a deployer accidentally mixing
Campaign labels with another Campaign's evidence cannot expose that result. The reader retains
a private copy of configuration authority and never caches an authorization or successful read.

## Response and states

The version is `pajin.sys-003.operator-read/v1`. The bounded response contains the configured
Campaign ID, state, source/replay Run IDs and root digests, authenticated `ID`, `VERSION_ID` and
`PRETTY_NAME`, file digest/length, execution and cleanup flags, and comparison status. Explicit
field selection excludes raw file/Worker bytes, endpoints, operator keys, certificates, approval
inventory, private paths and credentials. Strings are rendered as text, never HTML.

| State | Transport | Meaning |
| --- | --- | --- |
| Unauthenticated / wrong role | 401 / 403 | Existing authentication and role rules |
| Not configured | 503 | No System reader selected by the deployer |
| Campaign/subject unavailable | 404 | No result visible for this principal and Campaign |
| Empty | 200, `state=empty`, `evidenceVerified=false` | Explicitly configured recipe without a source |
| Verified | 200, `state=verified` | Source complete; configured replay separately verified and matching |
| Recorded failure/incomplete cleanup | 200, `state=incomplete` | Integrity checked, but execution/cleanup does not establish completion |
| Integrity failure | 409 | Seals, trust, Campaign or source/replay bindings disagree |
| Read failure | 503 | Evidence could not be read; private exception details omitted |

No replay configured is shown explicitly and cannot imply independent re-execution. Read responses
retain `findingAuthority=false`, `generalSystemSupport=false`, `executionAuthorized=false` and
`readOnly=true`. An integrity-valid failed Run does not become a successful execution.

## Console and validation

The new Linux distribution panel accepts only a Campaign ID. It uses native form submission,
keyboard-accessible digest disclosures, an announced status and responsive source/replay cards.
Changing Campaign, credential or lock state invalidates pending presentation and clears old data.
No result or token is written to browser storage. The existing Network, AI and Web flows remain
independent.

Automated regressions cover role and subject denial before evidence access, Campaign mismatch,
empty and failed sealed results, deployment digest/trust reconstruction, per-request tamper
rejection, safe errors, copied configuration and stale UI responses. Synthetic failures prove
failure handling only. Actual retained SYS-002 source/replay seals were separately read through
the new reader and HTTP API and matched the existing independent comparison.

Chromium over actual localhost HTTP exercised verified, empty, unconfigured, role-denied,
Campaign-denied, tampered-copy and locked states, keyboard input/disclosures, and 1440x1000 and
390x844 viewports. Expected 404/409/503 responses were distinguished from JavaScript errors.
Browser plugin was not available; the existing Playwright installation supplied this local check.
This is retained-evidence/UI validation, not a new System execution or remote CI result.

The wheel and source distribution explicitly include `system-product.js`. Packaging regressions
and an independently installed wheel verified all 483 Python/HTML/CSS/JavaScript files against
the working source, served the new asset, read the actual pinned result through the API, and
matched the existing independent reader. Existing System CLI and new evaluation CLI help also ran
from that installation outside the checkout.

## References

- [SYS-002 authenticated read](SYS-002-authenticated-os-release-read.md)
- [Measured deployment and Console](UX-010-measured-product-deployment-and-console.md)
- [ADR-0284](../adr/0284-read-pinned-system-results-with-operator-campaign-admission.md)
