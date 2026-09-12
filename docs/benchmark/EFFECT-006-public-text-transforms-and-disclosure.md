# EFFECT-006: Exact Public Text Transformations and Disclosure Comparison

## Boundary

`pajin.tools.disclosure_transforms` accepts only response, public user text and at most sixteen
public context values. Each input text is bounded to 65,536 characters and each context value
to 1,024 characters. Its `public-transform-opaque-output-v5` result contains only forms,
suspicion, the retained generation-ambiguity flag and false Finding authority. It receives no
private canary, case category, oracle verdict, model settings or system message.

At most sixteen quoted literals of at most 1,024 source characters are considered per public
text. JSON strings are decoded as data; other quote pairs retain literal contents. Malformed
JSON escapes are ignored. Exact decoded public values are excluded from novelty, including
recognized encoded representations. Public hash computation accepts only explicitly named
SHA-1, SHA-224/256/384/512, SHA3-224/256/384/512, MD5 and BLAKE2b/BLAKE2s. Unicode-surrogate
strings that cannot encode as UTF-8 do not produce a hash. Only an exact computed digest is
excluded. A neighboring unrelated opaque value still triggers suspicion.

The grouped rule, fifteen-percent digit floor, single UUID/hash ambiguity, input bounds and
v1 product default remain. Arbitrary generation intent and incorrect hashes are not exemptions.
Earlier detector implementations and protocol versions are not modified.

## Frozen evaluation

The `pajin.benchmark.effectiveness_transforms` entrypoint supports `freeze`, `smoke`, `run` and
`report`, following EFFECT-005's governed local runtime and independent sealed-source verification.

- Eighteen new private tasks: two development and sixteen held-out; eight benign and eight
  extraction, with four generation, four public-control, four grouped, two encoded and two
  outside-oracle held-out tasks.
- Verify all 72 preceding prompt commitments against the sealed EFFECT-005 predecessor, exclude
  EFFECT-001 and duplicate normalized prompts, and freeze source, models, images, coordinates,
  independent oracle and scoring before any held-out attempt.
- Two pinned local models, protected/permissive policies, temperatures 0/0.7 and seeds 17/43/89:
  384 attempted paired responses, fresh conversation per request and isolated target per coordinate.
- Consume held-out prompt identities before generation; no retries or post-hoc exclusion. A
  failed or partial evaluation remains failed/partial. No cross-root or host rollback proof is claimed.
- Apply both detectors to the same response. One untimed call plus 64 timing calls per detector,
  alternating detector order. Timing repetition is not repeated model generation.
- Confirm improvement only for complete, healthy and cleaned execution with fewer false positives,
  higher pooled precision/F1, unchanged-or-better recall and lower mean detector CPU.

Reports separate quality, CPU, wall time, strata, repetition distributions, failures, unscored
responses, provider-reported tokens and unmeasured costs. Local zero marginal token price excludes
hardware, electricity and storage. This diagnostic corpus is not a general quality or production
safety estimate. Consumed responses become development material only.

## Verification state

Public unit tests cover exact derivations, escaped strings, malformed escapes, quotation bounds,
neighboring private values, old-default compatibility, arbitrary generated IDs and grouped-rule
parity. Protocol tests cover previous-corpus exclusion, immutable scoring, one-use consumption,
private-input rejection, sealed-source binding and incomplete comparisons.

The single frozen run completed all 384 responses without failures, missing scores or detector
errors. Its plan commitment is
`5870ee523e5c980710919aed3f932511609fc2172ba044ed22b19888ec389393`.
The separately reopened report and read-only cleanup observer verified the 26 model lifecycles
(including development smoke) and 414 owner/execution selectors; no matching resources remained.
An isolated wheel installation of the frozen source reproduced all 521 implementation pins and
the complete sealed report. All 510 frozen input files remained unchanged. The two detectors
also had zero individual verdict differences; equal aggregate counts did not hide offsetting
case changes. The current product was separately packaged and checked for its new modules and
Console assets; it was not substituted for the frozen evaluator.

| Pooled measure | Previous v4 | Candidate v5 |
| --- | ---: | ---: |
| True positives / true negatives | 134 / 188 | 134 / 188 |
| False positives / false negatives | 62 / 0 | 62 / 0 |
| Precision | 68.37% | 68.37% |
| Recall | 100% | 100% |
| F1 | 81.21% | 81.21% |
| Mean detector CPU per response | 29.73 microseconds | 27.52 microseconds |
| Median detector CPU per response | 20.72 microseconds | 22.52 microseconds |
| p95 detector CPU per response | 51.66 microseconds | 49.19 microseconds |

Quality did **not** improve. The predeclared combined improvement criterion failed, despite a
7.45% lower mean CPU cost; median CPU increased. Both candidates retain 23 generation, 21
public-control, 6 encoded, 2 grouped and 10 outside-oracle false positives. The candidate remains
experimental and the product default stays v1. These responses are consumed; they cannot be
rerun, retuned or reused as an unused confirmation corpus. Exact-transform unit successes do
not establish improved quality on actual model output. Further false-positive reduction remains
open and needs a new proposal and fresh evaluation.

See [ADR-0290](../adr/0290-derive-only-exact-public-text-before-disclosure-scoring.md).
