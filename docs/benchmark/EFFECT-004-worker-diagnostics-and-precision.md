# EFFECT-004: Bounded Worker Diagnostics and Paired Precision Evaluation

Status: Local diagnostics and the fresh 384-response comparison are verified; the fixed pooled quality criterion passed. Product default remains v1.

## Diagnostic contract

The Worker preserves supported CLI actions, secret envelope versions, success JSON and exit codes
64/65/70. A handled failure keeps the legacy first stderr line and adds exactly one bounded
`pajin-worker-failure-v1 stage=<enum> category=<enum>` line. Unknown actions retain exit 64. Stages
are worker input/action, Provider request preparation/open/read/normalization. Streaming read and
normalization share the read phase. Categories describe observable exception classes: timeout,
subprocess timeout, TLS verification/TLS, HTTP response/protocol, connection, I/O, runtime, invalid
data or unknown transport. They never establish a deeper root cause. In particular an I/O error is
not proof of resource exhaustion, and a timeout is not proof that a remote call never executed.

No exception message, prompt, response, URL, local path, credential, canary, status body or traceback
is included in this diagnostic. The host accepts only the complete allowlisted two-line record
with a compatible exit code. Truncated, legacy, appended, unrecognized or malformed records become
`unknown`. Even recognized records are Worker reports, not independently attested explanations.

The Provider records the safe classification with the existing failure and evidence references.
Execution/policy/result bindings still precede diagnostics. A dispatched failure keeps the full
reserved token/cost charge; an uncertain call is neither retried nor refunded. A confirmed
non-executed outcome follows the existing release rule. Diagnostics cannot change any of those
choices. Existing sealed artifacts are unchanged; legacy readers retain their existing formats.
The two EFFECT-003 exit-70 failures remain unknown because their retained records are insufficient.

## Candidate and independent evaluation

The product default remains `novel-opaque-output-v1`. Experimental `mixed-group-opaque-output-v3`
retains v2 non-group rules but requires at least 15 percent digits in an opaque grouped value.
Development-only EFFECT-003 observations showed digit-sparse uppercase group false positives.
The threshold is independent of the private value and its exact length. Digit-sparse/letter-only
grouped secrets can now be missed. Generation ambiguity, public hash computation, partial and
semantic disclosure limitations remain. Suspicion never grants Finding or execution authority.

The additive `pajin.benchmark.effectiveness_precision` namespace freezes a new corpus and never
rewrites EFFECT-001/002/003 formats, detectors or readers. Both previous sealed corpus commitments
(36 development/held-out prompts) and EFFECT-001 inputs are excluded; changing canaries or an output
root does not make a consumed task unused. A local atomic ledger consumes all new held-out prompts
before the first attempt, including failures. Cross-root/host rollback protection is not claimed.
Novelty is author-curated, project-local diagnostic novelty, not model-training decontamination.

Before any new held-out generation, freeze:

- v1 baseline and v3 candidate, unchanged `complete-private-nonce-v1` oracle;
- two pinned local models, protected/permissive policies, temperatures 0/0.7, seeds 17/43/89,
  top-p 1, 128 completion tokens, fresh conversation per task and fresh target per coordinate;
- two smoke-only development tasks and sixteen unused tasks: four generation, four public-control,
  four grouped, two encoded and two outside-oracle; 24 coordinates and 384 expected responses;
- no post-generation exclusion, retry, relabeling or missing-response-as-TN treatment;
- completeness of all 384 paired responses with healthy, cleaned targets; higher pooled F1 with
  no precision or recall loss; failed criteria mean no confirmed improvement and default unchanged;
- complete package source commitments and immutable runtime/model/Worker/proxy image fingerprints.

Both detectors receive exactly the same response and public user context, in alternating timing
order. No private expected value, label, policy or oracle verdict reaches the detector. The oracle
independently recognizes complete literal, whitespace-collapsed, base64 or hexadecimal nonce
occurrence; a negative outside that boundary is not proof of semantic safety. A fresh-process
reader verifies sealed source evidence, source commitments and both verdicts before recomputing
TP/TN/FP/FN, precision/recall/F1, samples/failures, strata/repetition variation, wall/CPU, reported
tokens and marginal cost. Zero local token price excludes hardware, power and storage costs.

## Commands and custody

The `freeze`, `smoke`, `run`, `report` operations and arguments follow EFFECT-003, under the new
module name. `freeze --development-root ... --development-reference ...` consumes the independently
pinned sealed EFFECT-003 report solely to verify the exclusion corpus, including its EFFECT-002
prompt commitments. It does not require or invent a successful quality result for that experiment.
Source snapshots, private corpora, raw Runs, keys, model files and deployment inventory remain
private. Only bounded diagnostic classifications and aggregate measurements may be published.

## Observed fresh comparison (2026-09-11)

Four smoke calls passed before all 384 held-out attempts produced 384 verified responses: zero
failures, unscored responses, detector errors or missing usage records. Twenty-four live targets
were healthy and cleaned. A fresh process using an independently installed frozen wheel matched
all 495 source pins and recomputed the sealed comparison. An independent Docker observer checked
414 exact model/Worker selectors, including the two smoke lifecycles, and found no containers or
networks. These are host-local custody checks, not remote CI or independent measurement attestation.

| Detector | TP | TN | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| v1 baseline | 130 | 197 | 51 | 6 | 71.82% | 95.59% | 82.02% |
| v3 candidate | 136 | 197 | 51 | 0 | 72.73% | 100.00% | 84.21% |

The preregistered completeness and pooled F1/precision/recall criterion passed. The six gains
were recovered grouped disclosures in Qwen permissive coordinates. False positives did not
decrease: both detectors retained 51, including 47 generation cases. This is a modest precision
gain from six extra true positives, not removal of the main false-positive problem. SmolLM2
coordinates and the other strata did not improve. No threshold or exclusion changed after results.

| Stratum | Responses | Baseline TP/TN/FP/FN | Candidate TP/TN/FP/FN |
| --- | ---: | --- | --- |
| encoded | 48 | 31/15/2/0 | 31/15/2/0 |
| generation | 96 | 7/42/47/0 | 7/42/47/0 |
| grouped | 96 | 59/30/1/6 | 65/30/1/0 |
| outside-oracle | 48 | 27/20/1/0 | 27/20/1/0 |
| public-control | 96 | 6/90/0/0 | 6/90/0/0 |

Each cell contains sixteen tasks at each of three seeds. The following F1 values are the mean
and population standard deviation across those three repetitions, in percent. Repeated responses
are correlated; they are not 384 independent tasks or a significance test.

| Model / policy / temperature | Baseline F1 mean ± SD | Candidate F1 mean ± SD |
| --- | ---: | ---: |
| qwen3-4b-permissive-t0.0 | 82.35 ± 0.00 | 88.89 ± 0.00 |
| qwen3-4b-permissive-t0.7 | 83.59 ± 0.88 | 89.63 ± 0.52 |
| qwen3-4b-protected-t0.0 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| qwen3-4b-protected-t0.7 | 22.22 ± 15.71 | 22.22 ± 15.71 |
| smollm2-1.7b-permissive-t0.0 | 94.12 ± 0.00 | 94.12 ± 0.00 |
| smollm2-1.7b-permissive-t0.7 | 87.39 ± 4.95 | 87.39 ± 4.95 |
| smollm2-1.7b-protected-t0.0 | 100.00 ± 0.00 | 100.00 ± 0.00 |
| smollm2-1.7b-protected-t0.7 | 81.56 ± 10.87 | 81.56 ± 10.87 |

Recall is unavailable for repetitions with no oracle-positive response: `qwen3-4b-protected-t0.0` (3/3), `qwen3-4b-protected-t0.7` (1/3). This is not a zero-recall result.
The retained aggregate report also records every coordinate and precision/recall/F1 distribution.

## Observed time, usage and identities

Total matrix time was 4540.63 seconds, including startup and cleanup. Request latency
mean was 11.07 s, population SD 2.46 s, median 10.43 s, p95 16.12 s and maximum 24.27 s.
Other local tests overlapped generation, so these times do not establish dedicated throughput
or a model-speed ranking. Paired detector timing alternated evaluation order on the same responses.

| Detector | Wall mean ± SD (microseconds) | CPU mean ± SD (microseconds) |
| --- | ---: | ---: |
| baseline | 25.58 ± 29.60 | 24.37 ± 26.83 |
| candidate | 47.47 ± 30.15 | 46.65 ± 28.95 |

Candidate mean detector time increased; the quality gain is not a detector-speed improvement.
Provider-reported usage was 44,028 prompt and 21,137 completion tokens.
The configured marginal local token price was USD 0; hardware, electricity and storage were not
measured. Usage remains Provider-reported metadata. No paid model service was used.

- Plan commitment: `d8cb4a3495fe24613084e3f1d16bfdd6da3f4a451dd0c7cd787e2f90b7f2629d`.
- Corpus commitment: `4ea24f14ff086295074ee9547f48c584702fb7b915208a6c29afb9c3e4fbdd04`.
- Sealed report root: `2b5df84bb73f02961a9ba65dbe6f8f5af37735dc6b6a4a9bbb86ef90ecb08d6f`.
- qwen3-4b model: `ae916ede1c010a26955ee8ae2e908bf8815a3f135ec860439ab924701c69d5f1` (4,280,403,520 bytes).
- smollm2-1.7b model: `decd2598bc2c8ed08c19adc3c8fdd461ee19ed5708679d1c54ef54a5a30d4f33` (1,055,609,536 bytes).
- model_image: `ghcr.io/ggml-org/llama.cpp:server-b9445@sha256:8dd148c53936b6e8b0e75309841e66eab13adc50b004a5e86ab1fec477c17d8e`.
- platform_manifest: `sha256:3454deca0c9051af4bed23415a5ea82250f5d98dfb66b51e6347969676c7c982`.
- worker_image: `sha256:044f2707c1e2b7afec748a7a920b91927f86f3d6126db3496d2bf85b0517cf42`.
- proxy_image: `sha256:0cb0b6ea62e9bbfd217ae102d471eb5ff3c290893c27a31bafb1cf5635d358de`.

The target ran Linux arm64, 4 CPUs, 6,144 MiB, context 4,096, one sequence and no RAM prompt cache.
Raw prompts, canaries and model files remain private. This limited controlled diagnostic does not
establish general model safety or eliminate digit-sparse, partial or semantic disclosure limits.
No default migration is included: the experimental version is retained separately and v1 remains
unchanged. Consumption is final; this held-out corpus is now development-only material.
