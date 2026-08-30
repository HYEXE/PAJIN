# P0-E2B OWASP ZAP Scanner Baseline Measurement

## Status

Implemented as a runnable `v1alpha1` local-Docker baseline. It specializes the P0-E2A generic
Scanner plan with OWASP ZAP 2.17.0, retains exact raw SARIF 2.1.0 evidence, and emits a completed
registry-governed `BenchmarkResult`. Candidate comparison and Supervisor activation remain false.

## Goal and trust boundary

P0-E2B measures one concrete traditional Web/API Scanner without treating a fake adapter or
synthetic report as execution. A code-owned registration binds the reviewed ZAP product/version,
the exact runtime image ID, the automation-plan digest, and the P0-E2A parser-contract digest. The
provider resolves the mutable distribution reference only to verify that it still names the
registered image, then creates the Scanner container by the immutable image ID.

The measurement remains a host-local deterministic lab result for the exact P0-D1 target. It does
not claim general Web Scanner quality, production supply-chain distribution, a single-agent
baseline, comparison eligibility, or autonomous activation.

## Versioned authorities

| Authority | API version | Role |
| --- | --- | --- |
| `ZAPScannerRegistration` | `pajin.dev/zap-scanner-registration/v1alpha1` | ZAP 2.17.0 image, automation configuration, output format, and parser identity |
| `ZAPSarifNormalization` | `pajin.dev/zap-sarif-normalization/v1alpha1` | Bounded projection of one separately retained raw SARIF file |
| `ScannerBaselineSourceBinding` | `pajin.dev/scanner-baseline-source-binding/v1alpha1` | Registry-governed Harness/Target source, execution evidence, raw SARIF, normalization, and Observation |
| `ScannerBaselineMeasurementAuthority` | `pajin.dev/scanner-baseline-measurement/v1alpha1` | Exact P0-E2A plan, registration, catalog selection, complete sources, and completed Result |

Every authority rejects unknown fields and uses bounded domain-separated canonical digests.

## Execution boundary

1. The existing fenced P0-D1 Docker lifecycle performs reset and creates one internal bridge
   network with no published port.
2. The registered target starts in that isolation before ZAP is invoked.
3. ZAP runs in a separate container with a read-only root filesystem, all capabilities dropped,
   `no-new-privileges`, fixed user, memory/CPU/PID limits, and bounded tmpfs mounts.
4. Only a fresh operation-specific host directory is bind-mounted at `/zap/wrk`; the repository is
   never mounted. The provider writes the code-owned automation plan there before container start.
5. The fixed plan seeds the exact lookup endpoint with the Automation Framework requestor, runs a
   bounded active scan, and writes `sarif-json` output.
6. The provider snapshots the Target stdout before and after ZAP and accepts only canonical LF
   JSONL response records with the bounded GET or POST method set and query-free absolute paths.
   Both methods count as request units only on the exact lookup path. All other methods and all
   query-bearing records fail closed.
7. The provider requires successful container exit, exact image/command/hardening/mount state,
   unchanged plan bytes, a regular bounded SARIF file, and the post-execution target isolation.
8. Cleanup removes the Scanner, target, and network before the final Observation becomes
   measurement-eligible. Startup recovery reuses the existing durable operation journal and
   higher-fence cleanup behavior.

The Docker execution evidence binds the Scanner registration and plan digests, exact image and
container IDs, raw SARIF SHA-256 and byte length, normalization digest, and the before/after/delta
Target-log hashes and request-unit count to the execution receipt. Reload reparses the retained
delta and requires the recalculated request-unit Evidence digest, all three log hashes, and count to
equal those receipt-bound fields, so a coherent replacement of all retained sidecars is rejected.
Scanner execution evidence issued without these fields is not replayable and must be regenerated;
legacy non-Scanner v1alpha1 provider evidence keeps its existing wire and digest.

## SARIF normalization

The parser accepts only one SARIF 2.1.0 Run with the reviewed ZAP 2.17.0 tool identity and bounded
rule/result counts. Each result retains its rule ID, severity level, message hash, complete location
URI tuple, and a content-addressed candidate ID. A known P0-D1 surface requires the exact registered
scheme, host, port, lookup path, and `id` query key. Only registered ZAP SQL-injection rule IDs on
that exact surface count as a known Finding match.

Raw SARIF bytes are sealed unchanged through `RunStore.write_bytes`. The measurement reader reopens
the original registry-governed Harness and Target Runs, reloads receipt-bound provider evidence,
rereads the provider copy, re-parses it, and requires byte equality with the separately sealed
measurement copy.

WEB-002B composes this unchanged lifecycle through a separate outer authority. P0-E2B runnable or
past live status does not by itself prove WEB-002B conformance: the Web wrapper additionally requires
a fresh completed Target attempt, the exact eight-record durable journal, receipt-bound cleanup
provider evidence with `resourcesAbsent=true`, and contextful reload through the outer seal.

## Result semantics

Scanner observations report only what ZAP actually emitted. Zero candidates, valid candidates,
confirmed Findings, replay attempts, or human decisions are valid observations. A completed Result
still contains all twelve BENCH-001 metrics; Finding precision, time to first valid/confirmed
Finding, cost per confirmed Finding, replay success, and human intervention may be explicitly
`not-applicable` only when their semantic denominator is absent. Comparison rejects any Result with
an unmeasured metric.

The baseline does not synthesize confirmation or replay. A ZAP alert can improve surface recall or
Finding recall only through the code-owned exact matcher, while confirmed count remains zero.

## Required rejection behavior

- Scanner image, version, configuration, parser contract, plan, or output-format substitution;
- candidate-bearing, mutated, cross-target, or incomplete P0-E2A coordinates;
- non-internal network, published port, changed hardening, alternate command, or unexpected mount;
- missing, oversized, malformed, foreign-tool, foreign-origin, or mutated SARIF;
- malformed, noncanonical, query-bearing, or unsupported-method Target log records;
- receipt, operation, provider evidence, Harness, Target Run, registration, or source substitution;
- duplicate or missing seed/repetition sources; and
- candidate comparison or Supervisor activation escalation.

## Compatibility and rollback

The Scanner registration, provider, normalization, source, and measurement wire shapes are
additive. Existing P0-E1, Target lifecycle, registry-governed Harness, P0-E2A, and BENCH-003 readers
remain valid. `BenchmarkResult` now represents a denominator-free completed metric explicitly as
`not-applicable`; numeric comparison remains fail closed until every compared metric is measured.

Rollback stops issuing P0-E2B authorities and removes the additive provider/reader. Previously
sealed P0-E2B artifacts remain self-describing and must not be reinterpreted as P0-E1 or P0-E3.

## References

- [P0-E2A plan](P0-E2A-generic-scanner-baseline-plan.md)
- [BENCH-001 contract](BENCH-001-benchmark-contract.md)
- [P0-E1 measurement](P0-E1-deterministic-pajin-baseline-measurement.md)
- [ADR-0097](../adr/0097-run-concrete-zap-baseline-with-raw-sarif.md)
- [WEB-002B source measurement](WEB-002B-distinct-registry-governed-zap-source-measurement.md)
