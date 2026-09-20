# WEB-005: Governed Local Authenticated Browser Campaign

- Status: Implemented and locally verified for the exact Juice Shop adapter
- Domain: Web / API
- Entry point: `pajin web-campaign-run-governed-local`
- Predecessors: [WEB-003](WEB-003-exact-loopback-browser-assessment.md) and
  [WEB-004](WEB-004-bounded-authenticated-browser-campaign.md)
- Decision:
  [ADR-0299](../adr/0299-bind-governed-local-browser-execution-to-independent-evidence.md)

## Objective

WEB-005 connects one explicitly approved local OWASP Juice Shop campaign from account provisioning
through signed deployment inventory, a core Campaign, Capability activation, fresh approvals,
one-use ActionPermits, Gateway-dispatched browser Workers, independently signed source and
validation Runs, strict semantic reconciliation, Graph admission, PAJIN Finding validation, impact
and attack-path reporting, local SARIF, and a redacted executable PoC.

The initial runnable adapter supports exactly the canonical numeric-loopback Juice Shop recipe at
`http://127.0.0.1:3000`. The adapter protocol is reusable, but this implementation is not a generic
arbitrary-site login or crawling engine. Supporting another application requires a separately
implemented, reviewed, signed, and installed code-owned adapter.

## Authority sequence

```text
explicit exact-local-lab operator assertion
-> disposable account provisioning under separate source/validation authorizations
-> signed, secret-free preprovisioned-account receipt
-> signed exact-origin adapter resolution from deployment inventory
-> core CampaignManifest and exact Campaign Scope
-> distinct executable Capability release + signed lifecycle activation + Grant
-> source ActionProposal -> fresh approval -> one-use ActionPermit
-> source one-use Gateway dispatch -> fresh target-observer then executor subprocesses
-> validation ActionProposal -> fresh approval -> one-use ActionPermit
-> validation one-use Gateway dispatch -> fresh target-observer then executor subprocesses
-> signature, role, lifecycle, target, Permit, request, and sealed-Run verification
-> strict typed source/validation semantic reconciliation
-> positive-only governed Finding and attack-path promotion
-> registered-producer Graph proposal submission and actual admission
-> two-seal validation/v1alpha1 verified-independent-replay snapshot
-> deterministic local report, SARIF, and redacted executable PoC
-> delivery-readiness record with no external delivery
```

No arrow may be skipped or inferred from the existence of a later artifact. A report, successful
browser exit, signed statement, sealed Run, matching replay, Graph proposal, or SARIF file is not a
substitute for its missing upstream authority.

## Versioned contracts

| Contract | Required binding or result |
| --- | --- |
| `WebAssessmentAdapterManifest` | Deployment-publisher signature; adapter/version/digest; exact origin; implementation and recipe digests; GET/HEAD/POST method set; read-only, no-account-creation, no-caller-route, and no-caller-payload policy |
| `ProvisionedWebAccountReceipt` | Account-issuer signature; adapter and origin; two distinct local authorization IDs; account, provisioning, and target digests; distinct secret-material references; at most 30-minute validity; no secret values |
| core Campaign and Scope | Exact local target, request ceilings, Capability release, and reporting intent; discovery cannot widen it |
| Capability release, activation, and Grant | A distinct executable capability ID and digest from the inert WEB-004 definition, even though both currently use semantic version `1.0.0`; current deployment-pinned signatures and lifecycle |
| approval and `ActionPermit` | Fresh and distinct for source and validation; exact Campaign, Capability, Tool, target, request, risk, method, budget, and expiry |
| `WebAssessmentDispatchBinding` | One already-approved Permit mapped to one request, role, worker execution, adapter, account receipt, and output-root reference; consumed exactly once during Tool preparation |
| `WebWorkerJobSpec` | Secret-free, code-owned plan and authorization; exact authority binding, role, request ceiling, target evidence, and deployment-selected implementation |
| target identity attestation | Deployment-observer Ed25519 statement over one bounded live target fingerprint and the exact authority binding |
| execution attestation | Source- or validation-executor Ed25519 statement over the exact authority, target attestation, process, sealed Run ID/root, Result digest, and closed/no-persistence markers |
| governed execution evidence | Four distinct observer/executor process, key, and execution identities; distinct source/validation approvals, Permits, requests, attestations, Runs, roots, Results, and target observations over one shared Campaign/Capability/adapter/account/origin identity |
| governed promotion | Only exact positive typed matches become PAJIN Findings or confirmed attack paths; narratives remain code-owned |
| Graph admission | Existing registered producer, trusted lineage, exact ActionPermit-bound Action, Surface, Hypotheses, Observation, Evidence, Finding facts, and admitted events |
| `validation/v1alpha1` | Two sealed snapshots ending in `verified-independent-replay` decisions and a confirmed Finding set |
| local exports | Strictly reloaded SARIF 2.1.0, `delivery-readiness.json`, and secret-free `poc/` bundle |

All serialized inputs use strict versioned schemas, reject unknown fields, and are content-addressed
where the implementation exposes a digest. References are accepted only when the deployment
registry can resolve and re-verify the referenced object.

## Adapter and target rules

The CLI accepts an exact origin and an installed adapter reference. It does not accept login routes,
form selectors, field names, diagnostic paths, request bodies, headers, credentials, cookies,
arbitrary JavaScript, or external destinations. The adapter registry checks the publisher
signature, key lifecycle, expiry, implementation digest, code-owned Juice Shop recipe digest, and
exact origin before Campaign construction.

The signed login recipe also binds how each state-changing control is activated. Login supports
`submit-click` or `password-enter`; the post-login success control supports `click` or `enter`.
Both operations wait for a visible and enabled control within a fixed deadline and then perform one
actual action. A disabled or timed-out control produces no click or key press and fails closed. The
Juice Shop adapter uses `password-enter` for login and `enter` for the success control because its
SPA controls did not provide a stable pointer action in the verified target version. Legacy recipes
without either optional mode retain `submit-click` and `click`, respectively, and retain their prior
digest. Any explicit mode change is bound into the recipe and plan digest. The verified Juice Shop
recipe digest is `3b66877b08648ea82faca13dbda6395d90ac8c13f37db9ca20fd7dea5e57ff96`;
its implementation version is `1.0.2` with implementation digest
`f8bb878928ebf43b0c5e7057563ce322728b943ead179403ba0eb7f6783741f7`.

Only canonical numeric loopback is runnable in this slice. The exact string
`http://127.0.0.1:3000` is not interchangeable with `localhost`, IPv6, another port, a private LAN
address, a container alias, or an Internet host. Redirects, WebSockets, service workers, downloads,
unsafe schemes, URL credentials, and cross-origin requests remain denied. Dynamic links and forms
are retained only as bounded observations and never become execution authority.

The target observer performs only the code-owned bounded fingerprint request, does not authenticate,
and signs a deployment observation. This proves what the deployment observed at the approved
origin; it is not a target-issued identity or a remote organizational attestation.

## Account and secret handling

The coordinator creates a disposable account before the read-only Capability is dispatched. Source
and validation receive distinct local assessment authorizations bound into one short-lived signed
receipt. The account receipt contains only digests and opaque references; it cannot carry a username,
password, session token, cookie, signing private key, or reusable server session.

The SecretBroker supplies role-specific one-use leases after Permit consumption and Tool
preparation. Each target observer receives its own signing key. Each executor receives a different
signing key plus the account identity and proof. Material is passed in a bounded stdin payload to a
fresh subprocess, cleared from the parent projection path, and checked against stdout and stderr.
Worker output asserts that authentication completed, the browser closed, target mutation did not
occur, and credentials or server-session material were not persisted.

The target may keep the authenticated server-side session valid until its normal expiry. The account
itself is retained. Revoking sessions or deleting accounts is a separately classified mutating
operation and is not part of WEB-005.

## Approval, Permit, Gateway, and Worker enforcement

Source and validation cannot share an approval receipt, ActionPermit, Tool request, Gateway request,
dispatch binding, or Worker execution ID. The exact Permit is durably consumed before dispatch, and
the code-owned binding registry makes a second preparation fail closed. Failed, expired, stale,
mismatched, or already-consumed authority cannot be replaced with data copied from a prior Run.

The Gateway resolves the registered Tool and Worker backend and attaches only the exact egress
policy compiled from the code-owned plan: approved origin, denied paths, GET/HEAD/POST methods,
private-network allowance for numeric loopback, maximum response bytes, and request-unit ceiling.
The backend independently compares that complete policy before launching a process.

`host-loopback-browser` is a specialized local backend. It starts a no-shell Python subprocess with
proxy variables removed, private byte-bounded stdin/stdout/stderr, a deadline, a fixed module and
role argument, and an absolute bounded output root. It verifies the subprocess PID, signed lifecycle,
Run path confinement, sealed Run contents, browser-close marker, and credential-persistence marker.

The Gateway path is real, but the backend is not a Docker container and does not expose a
host-observed egress proxy. `containerIsolation` remains false, the isolation statement remains
`fresh-host-subprocess`, and an empty Worker network log is not trusted network evidence.

## Independent evidence and semantic promotion

Source and validation each use a fresh observer and a fresh executor. All four jobs have distinct
subprocess IDs, signing key IDs, and execution IDs. The two legs also use different request IDs,
authorization IDs, approvals, Permits, sealed Runs, roots, Results, execution attestations, and
signature-verified target-observer attestations. The two target observations are distinct while
binding the same approved target-identity digest, Campaign, Capability, adapter, account receipt,
origin, and expected fingerprint.

A single shared target attestation, executor key, PID, approval, Permit, request, Run, root, or Result
can support ordinary provenance but cannot support Finding authority. All Ed25519 signatures are
checked against a deployment-owned role and lifecycle registry. Key-role mismatch, revocation,
expiry, timestamp reversal, foreign authority scope, changed target fingerprint, or a mismatched
Run pin fails closed.

Both Runs are then reloaded independently by exact Run ID and root digest. The loader checks their
seal, artifact inventory, events, plan, authorization, Result, screenshots, deterministic report,
origin, and target version. Typed semantic oracles re-derive the WEB-003 checks and attack paths from
closed facts.

`local-corroborated` alone never authorizes promotion:

- an issue is eligible only when source and validation are both exactly `locally-reproduced`;
- a path is eligible only when source and validation are both exactly `locally-validated`, every
  diagnostic stage links to a known issue with a consistent derived state, and any unlinked stage
  is the code-owned observed-context stage;
- `not-reproduced`, `locally-not-validated`, `inconclusive`, omitted, unlinked, or mismatched outcomes
  produce no Finding or confirmed path.

Titles, severities, CWEs, impacts, remediation, stage labels, and path narratives are code-owned or
re-derived against code-owned metadata. Matching arbitrary prose in two otherwise matching Results
does not make that prose trusted. Positive-looking prose on a negative source Result is ignored and
cannot enter a promoted Finding, confirmed path, validation report, or SARIF result.

## Graph, validation, report, SARIF, and PoC

After promotion, WEB-005 submits registered Surface, Hypothesis, Observation, Evidence, and
Campaign-Fact proposals through the existing Graph admission authority. The Graph Action is bound to
the exact successful Permit and request. Every proposal must produce an admitted event; proposal
construction alone is not reported as Graph admission. Negative and inconclusive checks may inform
contradicted or unresolved hypotheses, but they cannot create Finding facts.

The validation Run writes an immutable source snapshot, seals it, writes the exact
`validation/v1alpha1` decisions, confirmed Finding set, index, and report with
`verified-independent-replay` semantics, and seals again. The strict loader reopens the final root
before export. At minimum, the sealed output retains:

- `governed-web-promotion.json`;
- the legacy candidate and source-decision projection required by current readers;
- `validation/v1alpha1/index.json`, `decisions.json`, `findings.json`, and `report.md`;
- exact source and validation Run, authority, execution-attestation, target-observation, Graph
  admission, and promotion references required to reproduce the decision.

The PoC is published as a separate atomic bundle only after the sealed validation projection has
been strictly reloaded. Its `poc/manifest.json`, `poc/README.md`, and private executable
`poc/reproduce.sh` bind the Campaign, signed adapter, target fingerprint, both assessment Run roots,
Promotion, Graph admission, validation root, and confirmed Finding-set digest. Writing the PoC
inside the sealed validation Run is rejected.

The redacted PoC script invokes only:

```sh
pajin web-campaign-run-governed-local \
  --origin http://127.0.0.1:3000 \
  --adapter-ref <installed-adapter-ref> \
  --authorized-local-lab \
  --output <private-output-directory>
```

It contains no credential, token, cookie, secret reference, private key, raw response, absolute
checkout path, or delivery destination. A rerun requires a fresh explicit local-lab assertion and
fresh account/approval/Permit lifecycle; the script is not bearer authority.

The verified SARIF exporter writes `findings.sarif` outside the sealed validation Run, then reloads
and binds it to the confirmed Finding set and final root. Reporting output is minimized and must not
expose credentials, target-derived raw bodies, runtime query values, private paths, or executable
attack payloads beyond the code-owned redacted reproduction contract.

Without a distinct authenticated external-delivery coordinator record, the adjacent
`delivery-readiness.json` records no destination, no delivery receipt authority, and
`externalDeliveryPerformed=false`. This command never uploads, emails, publishes, opens a ticket,
or submits a disclosure.

## CLI behavior

The public command is `web-campaign-run-governed-local`. Its help text describes it
as running the signed, exact-origin governed browser campaign against an explicitly authorized local
lab. The minimal public options are:

- `--origin`: canonical numeric-loopback origin, initially exactly `http://127.0.0.1:3000`;
- `--adapter-ref`: deployment-installed signed adapter reference;
- `--authorized-local-lab`: mandatory explicit operator assertion;
- `--output`: private output root;
- `--headless` / `--headed`: browser display choice only, with no authority effect.

Credentials, account identifiers, signer keys, trust-registry contents, Campaign IDs, Capability
digests, approval material, Permit fields, routes, payloads, and delivery destinations are
deployment-derived or generated internally and are not public CLI inputs. The command returns a
non-zero status on any incomplete authority chain, Worker failure, evidence mismatch, semantic
inconsistency, Graph rejection, strict reload failure, or export verification failure.

## Failure and negative cases

The end-to-end run fails closed when any of the following occurs:

- the local-lab assertion is absent, expired, or for a different exact origin;
- the adapter or account receipt is unsigned, expired, revoked, uninstalled, foreign, or digest
  mismatched;
- the account was not provisioned beforehand, material references collide, or secret values appear
  in a receipt or persisted output;
- Campaign Scope, release, activation, Grant, approval, Permit, request, adapter, receipt, origin,
  target identity, or output-root bindings differ;
- an approval, Permit, dispatch binding, secret lease, Worker request, executor key, target
  attestation, or sealed Run is reused across source and validation;
- the Gateway policy differs from the fixed plan or the subprocess tries an unapproved request;
- a process times out, exceeds an output limit, emits stderr, emits secret material, returns a
  foreign PID, or leaves an unverifiable Run;
- source and validation signatures, target observations, target versions, typed facts, statuses,
  code-owned narratives, or path structure differ;
- a negative or inconclusive check is presented as a Finding, a path contains an unlinked stage, or
  positive prose is retained for a negative result;
- Graph admission, the two-seal validation reload, SARIF reload, or PoC manifest verification fails;
- output attempts to claim external delivery without a separate exact delivery record and receipt.

Failure does not restore consumed approvals, Permits, dispatch bindings, or leases. A retry requires
fresh authority and produces distinct execution and Run identities.

## Compatibility, migration, and rollback

WEB-005 is additive. It does not change the wire meaning of WEB-003 Runs, WEB-004 local drafts or
observations, the inert browser Capability version `1.0.0`, existing ActionPermit and Graph models,
public Finding models, `validation/v1alpha1`, SARIF, or external delivery records.

Deployments opt in by installing the new signed adapter, account-issuer registry, Worker trust
registry, executable Capability release and activation, Tool binding, and coordinator. Existing
artifacts are not migrated or promoted. A WEB-004 result can be used only as historical local
evidence and must be re-executed through WEB-005 to obtain governed authority.

Rollback removes or disables only the new command and deployment inventory. It does not delete
retained disposable accounts, rewrite sealed Runs, reverse Graph events, remove exported files, or
restore consumed authority. Operators may delete local output separately only under an explicit
destructive-action decision.

## Known limitations

- Only the installed OWASP Juice Shop adapter and its code-owned recipe are runnable; arbitrary
  sites, SSO, MFA, CAPTCHA solving, arbitrary forms, browser extensions, and generic payload
  synthesis are unsupported.
- Only the exact numeric-loopback origin is supported by the initial coordinator. HTTPS, IPv6,
  private-network hosts, container aliases, and Internet targets are outside this slice.
- Host-subprocess separation is weaker than container, VM, or remote-Worker isolation, and no
  trusted host egress-proxy receipt is produced.
- Distinct local signing keys and PIDs do not establish separate organizations, machines, kernels,
  operators, or administrative trust domains.
- Matching preflight and postflight fingerprints do not exclude a transient same-origin target swap
  that restores the expected response before postflight. Non-local use needs a stable process or TLS
  identity in addition to this bounded response fingerprint.
- The PAJIN coordinator process is trusted. Arbitrary code execution, debugger access,
  module-global monkeypatching, or reflective extraction inside that process is controller
  compromise and outside the untrusted CLI/adapter/artifact boundary tested by WEB-005.
- Browser close and non-persistence do not revoke a server-side session. Disposable account and
  target-side audit data remain until separately authorized cleanup occurs.
- The command prepares local reports, SARIF, PoC, and delivery readiness only. External delivery is
  out of scope.
- The enrolled Graph and Grant SQLite checkpoints remain host-local. If the same UID deletes or
  rolls back the entire caller-owned output root together with its enrollment markers, WEB-005 alone
  cannot prove or reconstruct the lost state; a separately retained OPS-005 witness remains
  required.
- A crash after a database checkpoint event is appended but before its dedicated parent seal fails
  closed, but the current implementation cannot append a verified terminal failure journal from
  that torn prefix. It does not automatically recover or redispatch the uncertain action.

## Local verification evidence

The complete command ran against the explicitly authorized OWASP Juice Shop `19.2.1` instance:

```sh
pajin web-campaign-run-governed-local \
  --origin http://127.0.0.1:3000 \
  --adapter-ref juice-shop-local/v1 \
  --authorized-local-lab \
  --output <new-private-output-directory> \
  --headless
```

The primary completed record is under the public-safe relative root
`output/web005-juice-shop-20260915-live13/`:

- parent Run `run_20260915T053508Z_00f5d91c`, campaign plan digest
  `490929551c8d8ef9d234e3a1c793bdab9d19f74d1be6668545471e3820b711c8`, final root
  `d0c9d005ce3667522240379c62e9726cee1a1a33fbe751340ef4e704ce5eef03`, and completed-evidence
  digest `1f279d963631bc2e9021e48c6c62c9111254ad64206327913cb702cec9ca49f6`;
- Campaign digest `8a9fbd9bddeae25d8a005499312c03b7ac302ee202ffb7e11a30b6f3cda49eb5`;
  adapter `pajin.adapter.juice-shop.local` version `1.0.0`, digest
  `d53db88778dbd4b47250116b2edf54bce8ee741701dbbf406664dc784ac42a34`; and signed account-receipt
  digest `77ba1d492a010108a18414d732306aa7f920a30b14fe4dedcaec760e1e45bbfa`;
- executable Capability `pajin.bug-bounty.web-authenticated-read-only-assessment` version `1.0.0`,
  digest `796b120528d8dd16714483b3dbffc61cb4d508d85403516c58dbe8ce48f40151`, release digest
  `59c80cb3bd441aef7d6bbe143ba52fbd48307ebdd63a2521e4fbd082984edadc`, and activation digest
  `4d2d79563b4e2c1a1c3d8c71dc6fc4adaf75f46a37bf2145fc8c87a7956e7a09`;
- root/source/validation Grant digests
  `ca66a52b1ebca1e9d259318b8a5f89f2b080d79663879bbc592aaabd6f163f0c`,
  `2a0fb587da3499a910126d40316df3ad8009b60a67cdf8e24cfb0cfc9f6e68db`, and
  `e752ce65b1ef7aa574eb9d005a6dd5dd02ec67fd2be45296554db3e80b6e4c3c`;
- source and validation Gateway Runs `run_20260915T053508Z_d22a113a` and
  `run_20260915T053508Z_ba15facb`, backed by distinct approvals, Permits, requests, dispatch
  bindings, and one-use consumption receipts;
- source Run `run_20260915T053508Z_dc97107d`, root
  `275bc64eb7f6d2dd989020c9fd2106b0ab5a8474149b6a55c6ae47cf390a1b89`, Result digest
  `aa63719462145e9482b6f5793e1807aa7d9b3e3346ac676278ac785a88efb7cd`; validation Run
  `run_20260915T053508Z_da341040`, root
  `a0d8bcc7aac2603ee04a8b68b0906a4cb948f022da168251f9e6a658d7b8c7c2`, Result digest
  `c8934f69081eba2a0521de6a97c549e4fc6c901b0ef4bd2b98b56a6d824871ef`;
- source observer/executor PIDs `42828`/`42842` and validation observer/executor PIDs
  `42938`/`42953`; four distinct key IDs and execution IDs were verified. All four target/execution
  signatures were valid. Execution-evidence digest:
  `a12e30df2843b94a4bf5f2712831289937f983b3586d8c91ca92613c2d7f0d4d`;
- both browser Runs authenticated and closed, each emitted exactly one
  `browser-authenticated-navigation` POST to `/rest/user/login`, and retained no credential or
  reusable session material. All three issue checks were `locally-reproduced`; both paths were
  `locally-validated`;
- Promotion digest `4ba4162ae456234e7e5579feba1416fa3ab0977879a370a4a724b94f9f52c6ed`
  with `verified-independent-replay`; Graph admission digest
  `41a1a6b8d1cdeb5206b40b96a7b2a62eef4746337c40ff2c6555947fca0d3514`, nine admitted events,
  and three Finding-fact nodes;
- validation projection Run `run_20260915T053508Z_c274888d`, first sealed source root
  `908e3c31837915bddb75314ada9ea7f43445503250492f8211e9e6701ca5421c`, final root
  `3c63045e857364c395fae7b9e963372f33384005f86917a2f50bef19fad8ad73`, three confirmed Findings,
  and two confirmed attack paths;
- report SHA-256 `bb24a375a931f57b6f6e228391cabf457b19840b69fd27549a4e80d747ed6648`,
  SARIF digest `6cc32f9ab15a2bad0280f3b0a07402836cfe37b945c6db69f482557cc5fd17fe`,
  redacted PoC manifest digest `1c5ecc1b9831c0f497bc4d3769afaa2963516e363bd1f0949adfb7c6e01aa3a0`,
  and delivery-readiness digest `8ab0bdc69763a78654eda0be39a73d39a2f5fc1ab79b90943b5ca8c4f62048f9`.

A fresh Python process strictly reloaded the parent and every referenced child Run, pinned Graph and
Grant database, validation projection, report hash, canonical SARIF bytes, exact PoC inventory and
permissions, and delivery manifest. The bundled `poc/reproduce.sh` then ran the whole governed flow
again into `output/web005-juice-shop-20260915-poc1/`; its parent Run
`run_20260915T054048Z_8111d682` also strictly reloaded and independently produced nine Graph events,
three Findings, and two attack paths. Both executions report `credentialsPersisted=false`,
`privateKeysPersisted=false`, and `externalDeliveryPerformed=false`. Their disposable accounts and
server-side sessions remain on the local lab because cleanup was neither authorized nor performed.

The live and PoC-replay records prove the exact installed Juice Shop slice, not arbitrary-site,
production, remote-Worker, or external-delivery support. Repository-wide test, lint, type, format,
and packaging results for this checkpoint are recorded in `HANDOFF.md`.
