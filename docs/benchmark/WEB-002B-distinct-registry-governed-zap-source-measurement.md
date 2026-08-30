# WEB-002B: Distinct Registry-Governed ZAP Source Measurement

- Status: Implementation, deterministic provider verification, and post-audit exact-commit
  real-Docker conformance are complete
- Accepted conformance evidence: Ubuntu 24.04 run `33310558350`, job `99254722600`, passed the exact combined WEB-002D test at commit `975bf7876a186cefae66c289d09f530f3e0fe7aa`
- The covered WEB runtime, Docker test, and conformance workflow paths remain unchanged at the current checkpoint
- Prior conformance: the 2026-08-29 run predates receipt-bound request-unit custody and is retained
  only as historical evidence
- Lineage API: `pajin.dev/web-zap-source-lineage/v1alpha1`
- Authority API: `pajin.dev/web-zap-source-measurement/v1alpha1`
- Implementation: `src/pajin/workflow/web_source_measurement_authority.py`
- Decision: [ADR-0254](../adr/0254-bind-web-source-measurement-to-a-fresh-registry-governed-zap-target-run.md)

## Purpose and boundary

WEB-002B is the bounded source-measurement entrypoint for the exact WEB-002A measured case. It
reconstructs that case from its signed Capability release, private P0-D1 Ground Truth profile,
Target adapter, Scanner plan, and ZAP registration. The caller cannot choose a Target coordinate,
route, approval, Permit, Worker action, request, or response. The runner executes only the single
Scanner coordinate already committed by the exact plan.

This lifecycle uses the existing P0-E2B Scanner route into the isolated Target network. It does not
import, consume, or materialize the WEB-002A `controlled-validation` proxy route, which remains a
separate WEB-002D contract.

## Constructor-owned execution context

`WebZAPSourceMeasurementRunner` receives deployment context only through its constructor:

- the catalog-bound Docker ZAP provider;
- the P0-D1 measurement Trust Anchor;
- the append-only Target operation journal;
- the durable measurement-registry activation store;
- the signed registry distribution bundle; and
- the out-of-band distribution Trust Anchor.

Before provider reset, the runner contextfully reloads WEB-002A, verifies current distribution
validity, and requires the provider definition, target selection, Scanner registration,
measurement authority, registry authority, and active registry key to match exactly. It then runs a
fresh `RecoverableBenchmarkTargetFactoryRunner` through the registry-governed Harness for each
plan-owned coordinate and seals the existing P0-E2B Scanner measurement.

## Completed Target lineage

One `WebZAPSourceLineage` binds only public-safe identity and digest material:

- the Scanner and Target coordinates, seed, and repetition;
- Harness Run/root/authority, registry activation/bundle/admission, and completed Target
  Run/root/authority/attestation identities;
- the fresh Target attempt and fence;
- immutable Target, benchmark-Worker, and ZAP image IDs;
- execution and cleanup operation, receipt, and provider-evidence digests;
- raw SARIF SHA-256 and byte size, strict normalization digest, and Scanner source-binding digest;
  and
- literal proof markers for a completed journal and absent cleanup resources.

The completed journal must contain exactly eight canonical, hash-chained records in this order:

1. reset intent and receipt;
2. isolation intent and receipt;
3. execution intent and receipt; and
4. cleanup intent and receipt.

All four operations must be stage-local ordinal one and share the exact attempt, adapter,
coordinate, and fence. Every journal receipt must equal the corresponding signed Target Run
receipt. Attempt, intent, provider receipt, and record timestamps must form one causal,
nondecreasing lifecycle. A reconciled, open, incomplete, reordered, duplicated, foreign, or
noncanonical journal is not WEB-002B source authority.

## Evidence custody and cleanup

Before the generic Scanner measurement is sealed, WEB-002B requires the completed Target Run to
report succeeded cleanup and reloads both execution and cleanup evidence from the provider by exact
receipt. Execution evidence must prove the immutable images, internal network, zero published
ports, exact Scanner plan and registration, raw SARIF hash and size, and normalization digest.
Cleanup evidence must bind the exact cleanup operation and receipt and report
`resourcesAbsent=true`.

Provider SQLite evidence and cached results, including idempotent operation replay, the Target
journal, Scanner source bindings, Scanner observation bundles, and the outer authority artifact
are accepted only in their canonical JSON wire form. Semantically equivalent coercions such as
string integers or numeric booleans fail closed.

## Sealed authority and contextful reload

`WebZAPSourceMeasurementAuthority` binds the exact measured-case reference, Capability release,
Scanner plan and registration, Target selection, Scanner measurement Run/root/artifact identity,
baseline Result digest, and all completed source lineages. The outer Run has exactly three audit
events: start, `benchmark.web-zap-source-measurement.sealed`, and completion.

`load_web_zap_source_measurement_authority` does not trust the outer JSON or its digest alone. It
reopens WEB-002A, the Scanner measurement, every Harness and Target Run, registry activation and
admission, provider execution evidence and raw SARIF, cleanup evidence, strict normalization, and
the exact completed journal. Every Harness must contain the exact caller-supplied signed
distribution bundle and out-of-band Trust Anchor; an independently valid bundle with the same
registry contents is still foreign lineage. The loader rebuilds the complete outer authority and
requires exact equality with both the sealed artifact and supplied outcome. Historical reload
verifies registry authority at the nested sealed time and therefore does not make an immutable
historical result unreadable merely because the distribution later expires. All three outer audit
events and their complete payloads must equal the code-owned start, seal, and completion contract.

## Public-safe negative authority

The outer authority contains no raw SARIF body or path, private Ground Truth contents, matcher,
Docker container or network ID, private key, route, approval, Permit, request, or response. Its
literal markers keep all of the following false:

- controlled route use and controlled validation execution;
- private Ground Truth disclosure, metric-floor evaluation, and floor satisfaction;
- Graph admission/write, Finding projection/authority, candidate comparison, and Supervisor
  eligibility;
- product activation, report delivery, and additional execution.

The source and future controlled-validation identities are explicitly separated. WEB-002B cannot
claim an independent Replay or Control, evaluate the DOMAIN-006 floor, project a Finding, mutate
Graph, or authorize a downstream product action.

## Rejection requirements

Execution and reload fail closed on a foreign or stale measured case, plan, registration,
selection, provider, Trust Anchor, signed distribution bundle, registry, activation, Target Run,
coordinate, attempt, fence, operation, receipt, evidence digest, image, network fact, raw SARIF
artifact, normalization, cleanup observation, or completed-journal record. Missing, empty,
multi-link, substituted, or modified raw SARIF and noncanonical or type-coerced stored wire are
also rejected. Rehashed and resealed outer events with changed payloads are rejected. Security
markers accept literal booleans only.

## Verification status

Deterministic fake-Docker tests execute the complete WEB-002A to WEB-002B path and verify immediate
and repeated contextful reload, public-safe projection, completed cleanup, absent resources, raw
SARIF custody, strict normalization, journal/fence tampering, raw-artifact tampering, and provider,
Scanner-source, and observation wire coercion. The opt-in test exercises the same outer runner and
loader with real Docker; standard test runs continue to skip it unless
`PAJIN_TEST_DOCKER_ZAP=1`.

The combined exact-commit WEB-002D conformance at commit
`975bf7876a186cefae66c289d09f530f3e0fe7aa` passed on Ubuntu 24.04 in run `33310558350`, job
`99254722600`. The exact node completed in `666.82s (0:11:06)` and verified source and controlled
lifecycle cleanup, sealing, and fresh-session reopen; six independent container/network label/name
queries returned zero matching resources.

As earlier development evidence, on 2026-08-29,
`test_real_docker_web_zap_source_measurement_conformance` passed against Docker Engine 29.7.2
with Target image
`sha256:a6387af2d56e4d41fd208985227dc73099a3dc140ffa24abf08fe59550c7f2e0`, Worker image
`sha256:047fb728394c4c363b371deb736aeb81fdddefd6f99088b99f0501f9fa6f8a9d`, and ZAP image
`sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef`.
The run passed in 69.27 seconds, verified cleanup through the outer loader, and an independent
post-run Docker inspection found no remaining `pajin-bench-` container or network.

## Compatibility and rollback

WEB-002B is additive. It does not change the existing P0-D1, P0-E2B, WEB-002A, Scanner source
binding, Target Run, registry, raw SARIF, Result, route, Finding, or Graph wire identities.
Rollback stops issuing the new outer authority and removes the bounded runner/loader; already
sealed authorities remain historical artifacts and must not be reinterpreted as WEB-002C or
WEB-002D evidence.

## Related contracts

- [WEB-002A exact measured case, route, floor, and Finding policy](WEB-002A-exact-measured-case-route-floor-finding.md)
- [P0-E2B ZAP Scanner baseline measurement](P0-E2B-zap-scanner-baseline-measurement.md)
- [P0-D1 traditional Web/API Target catalog](P0-D1-traditional-web-api-target-catalog.md)
- [DOMAIN-006 domain-aware validation](DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
