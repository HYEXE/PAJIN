# EFFECT-005: Public Derived Disclosure Comparison and Detector CPU

Status: Implemented and measured locally. The frozen quality and CPU criteria were satisfied.

## Candidate boundary

Experimental `public-derived-opaque-output-v4` analyzes each response's token, spaced and grouped
forms once. It preserves the v3 grouped digit-density rule and existing single-format generation
ambiguity. Other random IDs remain suspicious. No private canary, case category, model policy,
expected value or oracle verdict is accepted by the detector. `finding_authorized` remains false.
The product default remains v1; v1, v2, v3 and their sealed readers remain unchanged.

For public quoted literals, the candidate independently computes the explicitly named SHA-1,
SHA-224/256/384/512 or MD5 UTF-8 digest. SHA names accept a hyphen, underscore or space. At most
six algorithms and sixteen literals of at most 1,024 characters are considered. Empty literals
and backtick delimiters are supported. Hexadecimal letter case does not change those digest bytes.
Only exact computed values or their recognized encoded representations are excluded. A private
opaque value next to a correct public digest still triggers suspicion. Input text is never executed.
Hash operations are public-data transformations, not cryptographic security recommendations.

## Frozen comparison protocol

Use the governed local model execution, independent complete-private-nonce oracle, image custody,
sealed RunStore and fresh-process source verification from the previous comparisons. EFFECT-005
owns a separate namespace, versioned plan, index and scorer. No consumed evaluation is rerun.

- Baseline: `mixed-group-opaque-output-v3`; candidate: `public-derived-opaque-output-v4`.
- Two new development tasks and sixteen new evaluation tasks: four generation, four public-control,
  four grouped, two encoded and two outside-oracle. Eight benign and eight extraction tasks.
- The preceding sealed plan supplies 54 excluded prompt commitments, including its development
  prompts. Legacy EFFECT-001 inputs are also excluded. Exact normalized novelty is verified;
  semantic novelty remains author-curated and model-training decontamination is unknown.
- Freeze two existing pinned local models, protected/permissive policies, temperatures 0/0.7,
  seeds 17/43/89 and all runtime/source fingerprints before the first held-out attempt.
- Twenty-four coordinates, sixteen responses each: 384 attempted paired responses. Each request
  has a fresh conversation; each coordinate has a fresh isolated target. No retry or post-hoc exclusion.
- A per-root atomic ledger consumes the held-out prompts before generation, including failures.
  Cross-root or host rollback protection is not claimed.
- One untimed call then 64 calls per detector; retain per-call average wall/CPU and require stable
  verdicts. Alternate baseline/candidate order per response. Timing repeats are not model repeats.
- Confirm improvement only for a complete healthy, cleaned 384-response comparison with fewer
  false positives, higher pooled precision and F1, no recall loss and lower mean detector CPU.
- Separately report confusion matrices, precision/recall/F1, strata and repetition distributions,
  failures/unscored inputs, wall/CPU, tokens and measured marginal cost. Undefined denominators
  stay unavailable. Local token price excludes hardware, electricity and storage.

## Validation and evidence

Public development tests cover exact derivation, case and algorithm spellings, quotation bounds,
wrong hashes, extra private content, encoded/grouped values, generation ambiguity, unchanged
defaults and rejected private inputs. Corpus, source, consumption, incomplete-result and fixed
quality/timing rules have separate tests. These tests do not establish model-quality improvement.

The `freeze`, `smoke`, `run`, `report` commands use `pajin.benchmark.effectiveness_derived` with the
same explicit root/reference/output and pinned model/image arguments as EFFECT-004. Supply the
sealed EFFECT-004 report to `--development-root` and `--development-reference` for corpus exclusion.
Private corpus bytes, canaries, raw responses, keys and source snapshots remain outside tracked
documentation. Only bounded aggregate outcomes and source commitments may be published.

The frozen source inventory contains 496 files and the plan binds 505 source pins. A separate wheel
was built and installed; its pins match the plan. Packaging used the unchanged, Git-verified build
backend in a separate copy. The original frozen tree and its inventory remain unchanged. Result
recomputation used this installed wheel after the single evaluation run finished.

## Measured result

The single preregistered evaluation completed all 384 responses with zero failures, unscored inputs
or detector errors. All 24 target lifecycles were healthy and cleaned. Plan commitment:
`3bef62db9fb282999fbab0b0ecafec263b5767d2aecf0ca37babfe4856318364`.

| Paired metric | Baseline v3 | Candidate v4 |
| --- | ---: | ---: |
| True positives / true negatives | 138 / 170 | 138 / 182 |
| False positives / false negatives | 76 / 0 | 64 / 0 |
| Precision | 64.49% | 68.32% |
| Recall | 100% | 100% |
| F1 | 78.41% | 81.18% |
| Mean detector CPU per call | 27.09 microseconds | 20.96 microseconds |
| Median detector CPU per call | 22.93 microseconds | 16.55 microseconds |
| CPU p95, nearest rank | 55.30 microseconds | 47.45 microseconds |
| Mean detector wall time per call | 27.18 microseconds | 21.01 microseconds |

The generation stratum accounts for all twelve fewer false positives: 45 to 33. Other strata are
unchanged: public-control 17, grouped 7, encoded 5 and outside-oracle 2 false positives. Sixty-four
false positives remain. These are paired outcomes on the new corpus; the preceding evaluation's
51 false positives are not a baseline for a cross-corpus improvement claim.

Elapsed evaluation time was 4,275.61 seconds. Mean request latency was 10.39 seconds and p95 was
16.36 seconds. Untrusted provider counters reported 45,180 prompt and 23,960 completion tokens;
the measured marginal local token price was zero, excluding the costs listed above. The two
detectors shared each generated response. The 64 timing repetitions do not create independent
statistical samples or prove an operational latency guarantee.

The frozen-source and separately installed-wheel reports were byte-identical, SHA-256
`2c7b0678585cc76e30931534f47b118e856b2fc6e03e3c6a55968ec81e827ad9`.
A separate read-only Docker observation checked all 414 exact ownership selectors across the
26 target lifecycles and 388 Worker requests, including the four development smoke responses.
No matching container or network remained. This is host-local evidence, not independent remote
attestation. The evaluation is consumed; retain its frozen wheel to read it after later code changes.
