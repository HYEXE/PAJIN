# ADR-0256: Bind WEB-002D Independent Controlled Validation to Durable Evidence, Floor, and Finding

- Status: Accepted
- Date: 2026-08-30

## Context

WEB-002B seals one registry-governed ZAP source measurement, and WEB-002C admits only neutral
knowledge and a bounded open Hypothesis. Neither predecessor independently executes the exact
WEB-002A controlled route, evaluates the registered fourteen-metric Profile floor, or projects a
Finding. WEB-002D must perform those actions without allowing Scanner output, a caller-supplied
provider, persisted JSON, or a completed cleanup record to manufacture independent validation.

The controlled path crosses four distinct custody boundaries: the single-use signed proxy route,
the host-observed Docker Target/Worker/proxy lifecycle, durable Worker Evidence, and the private
expected-reference matcher. A success path alone is insufficient. The registered cleanup-before-
route policy denial must also be observed with zero route, provider, and network side effects.

An independent review identified an additional provider trust gap: a structurally compatible
object could return self-consistent Target definition and Evidence claims while bypassing the
production Docker command boundary. Such a substitute must not be able to satisfy cleanup,
Profile-floor, or Finding projection.

## Decision

1. Consume the exact signed WEB-002A controlled-validation route through an append-only SQLite
   compare-and-set ledger before the first Docker side effect. Every attempted route is spent.
   Success records an exact claim receipt; cleanup-before-route records an exact denial tombstone.
2. Execute one fresh Target attempt through the exact Docker adapter and proxy-only topology. Keep
   the Target, Worker, proxy, route, approval, Permit, dispatch, request, result, operation, and
   fence identities disjoint from WEB-002B.
3. Persist Worker Evidence in an exact append-only SQLite store. Existing stores are validated,
   never repaired in place, and fail closed on schema, trigger, journal-mode, integrity,
   canonical-wire, or content drift.
4. Seal the success lifecycle with exactly eight route/Target/Worker/cleanup authority events. Seal
   the denial lifecycle with exactly seven events plus the route tombstone. Rebuild every current
   predecessor before accepting either form.
5. Treat historical cleanup-invalidated route verification only as evidence that the formerly live
   route matched the complete signed predecessor chain. It never revives execution authority.
6. Derive the WEB-002B request-unit observation from the sealed source, independently recompute
   the controlled baseline, negative Control, Boolean probe, Worker/tool claims, host observations,
   cleanup, and all fourteen metric observations, and run the private matcher only inside the
   evaluation gate.
7. Project a Finding only after the exact six source-evidence names, ten controlled-evidence names,
   denial Control, identity separation, cleanup proof, and registered Profile floor all pass. The
   public claim ceiling is `benchmark-ground-truth-match`; impact and severity remain explicitly
   unevaluated.
8. The final build and reload gates accept only the exact source-owned
   `CatalogBoundDockerZAPScannerTargetFactoryAdapter` used by that call, wrapping the exact
   `DockerZAPScannerTargetFactoryAdapter` and `SubprocessDockerCommandRunner`. They reject
   subclasses, delegating lookalikes, a same-config different provider object, instance or class
   method shadowing, `__getattribute__` shadowing, unexpected state, executable or timeout drift,
   artifact-root drift, and wrapper/inner authority-snapshot disagreement.
9. A fresh process may construct a new exact provider object, but its source reopen context and
   final build or load call must share that one object. Durable canonical state and Evidence, not
   Python object identity across processes, provide historical identity.
10. The public cleanup-before-route observation remains non-authoritative. It may record the
    denial tombstone, but only the final source-owned production-provider gate can issue the sealed
    authority, floor evaluation, and Finding.
11. Do not mark WEB-002D complete until the post-fix opt-in real-Docker test passes both the success
    and zero-side-effect denial lifecycles, cleanup, sealing, and fresh-session reopen against the
    exact immutable images.

## Security boundary

The provider guard protects the in-process construction boundary against supported object,
method, and state substitution. It does not claim protection against arbitrary mutation of private
process memory, interpreter compromise, a hostile Docker executable, daemon compromise, host
administrator compromise, or forged operating-system observations. Those remain part of the
deployment and host custody trusted computing base.

The Finding grants no Scope expansion, Graph mutation, report delivery, external delivery, Permit
issuance, additional execution, private Ground Truth disclosure, controlled-query disclosure, or
raw SARIF disclosure authority.

## Compatibility and rollback

The change is additive and introduces only new `v1alpha1` WEB-002D artifacts and stores. Existing
WEB-002A, WEB-002B, WEB-002C, Target, Scanner, Capability, Permit, Graph, and Finding wires remain
unchanged. Deploy readers and writers that understand the new artifacts before retaining them.

Rollback stops issuing and reading WEB-002D artifacts and returns the roadmap item to its
pre-execution state. It must not reinterpret a WEB-002D Finding as a generic product Finding or
reuse an attempted route. Append-only claim, denial, Worker Evidence, Target-operation, and audit
records are not rewritten or deleted as a rollback mechanism. Any live disposable resources must
still complete their receipt-backed reconciliation and cleanup.

## Consequences

- A Scanner result cannot manufacture independent validation or a Finding.
- A caller-compatible provider cannot substitute for the source-owned production Docker custody
  boundary at final build or reload.
- Route denial is measured as a real 1/1 Control with zero side effects rather than inferred from
  policy registration.
- Fresh-session reload depends on exact durable stores and canonical predecessor artifacts; missing
  or modified custody fails closed.
- Implementation and deterministic/static verification do not satisfy the real-Docker exit gate.

## Rejected alternatives

### Trust a Protocol-compatible Evidence provider

Rejected because self-consistent definition and Evidence claims do not prove Target cleanup or
production Docker custody.

### Reuse WEB-002B Scanner output as controlled validation

Rejected because source measurement and independent validation must not share execution or
Evidence identity.

### Treat cleanup-invalidated route verification as live authority

Rejected because cleanup must permanently fence the route. Historical verification is evidence,
not execution authority.

### Project impact or severity from the benchmark match

Rejected because this slice validates one private expected reference, not production exploitability
or business impact.

### Complete the roadmap item with unit tests only

Rejected because the vertical-slice exit gate requires the exact real-Docker topology, images,
side effects, cleanup, and fresh-session reopen.

## Verification requirements

Tests must cover success and cleanup-before-route denial, atomic route consumption, durable-store
tamper resistance, exact event sequences, historical route invalidation, source/validation identity
separation, independent observation and metric recomputation, bounded Finding projection, strict
canonical JSON reopen, exact source-owned provider custody, method and state shadowing, and all
false authority ceilings. The final conformance test must run against the exact Docker Target,
Worker, proxy, and ZAP images.

## Related decisions and contracts

- [ADR-0250](0250-prioritize-governed-measured-web-validation-before-new-domain-runtimes.md)
- [ADR-0251](0251-require-additive-target-routing-and-validation-policy-for-measured-web.md)
- [ADR-0252](0252-route-measured-web-validation-through-an-exact-egress-proxy-bridge.md)
- [ADR-0253](0253-separate-zap-measurement-routing-from-controlled-validation-routing.md)
- [ADR-0254](0254-bind-web-source-measurement-to-a-fresh-registry-governed-zap-target-run.md)
- [ADR-0255](0255-admit-sealed-web-source-measurement-without-execution-authority.md)
- [WEB-002D contract](../benchmark/WEB-002D-independent-controlled-validation-floor-and-finding-projection.md)

## Hardening addendum: signed ledger identity and immutable production binding

This append-only addendum records the production-custody hardening adopted on 2026-08-30 after an
independent review found two additional substitution paths: the same signed route could be paired
with a second SQLite claim ledger, and critical adapter state could be replaced after construction
but before the production custody check.

The following requirements supplement Decisions 1, 8, 9, and 11:

1. The signed `WebProxyRouteRuntimePolicy` requires `claimLedgerIdentityDigest`, an opaque,
   domain-separated digest of the deployment ID and the claim ledger's canonical absolute path.
   Only the digest is serialized; the raw path is not exposed in route or runtime-policy artifacts.
2. Before any Docker side effect, the production adapter recomputes the digest from its actual
   ledger and deployment ID and requires exact equality with the signed runtime policy. The same
   signed route cannot be rebound to a different SQLite ledger.
3. Production construction captures an immutable binding to the exact live route-authority object,
   claim-ledger object and identity digest, code-owned UTC clock, runtime-policy digest, deployment
   ID, Gateway policy ID/version, and Worker backend ID/version. The production custody guard
   revalidates the binding and rejects replacement or drift before backend dispatch or final use.
4. A pre-hardening `pajin.dev/web-proxy-route-runtime-policy/v1alpha1` artifact does not contain the
   newly required field and therefore fails closed under current canonical readers. Because the raw
   path is intentionally absent, the identity cannot be inferred or patched into a persisted
   artifact. Operators must issue a new runtime policy and re-sign the route for the intended
   deployment and ledger; no in-place artifact migration is permitted.

Regression coverage includes rejection of a second production adapter backed by a split claim
ledger and eight post-construction state-drift cases covering route authority, claim ledger,
code-owned UTC clock, deployment identity, Gateway policy ID/version, and Worker backend ID/version.
These deterministic tests do not satisfy Decision 11's exit gate. Current-tree opt-in real-Docker
conformance remains pending and is not claimed by this addendum.
