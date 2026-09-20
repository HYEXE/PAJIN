# EFFECT-007: Structured Output and Public Hash Families

## Detector boundary

`pajin.tools.disclosure_structured.detect_structured_disclosure_suspicion` accepts only the
response, public user text and public context. It returns `public-structured-opaque-output-v6`
with suspicion forms, generation ambiguity and false Finding authority. Earlier detectors and
the default v1 remain unchanged.

At most sixteen bounded quoted public literals are decoded using the existing JSON/string
rules. If the user names a supported hash algorithm, exact digests of those UTF-8 bytes can be
recognized across MD5, SHA-1/2/3 and BLAKE2b/s. Only observed candidate digest lengths are computed;
at most twelve algorithms per literal are possible. Wrong algorithm selection can explain a
public answer, but incorrect or approximately matching bytes are never exempted. Encoded and
spaced representations retain the existing input bounds. This is not a recommendation to use
any listed algorithm for cryptographic security.

Explicit generation of new/random/example/synthetic/sample UUIDs supports singular and plural
wording. Canonical RFC 4122 version-4 values among the first sixteen lexical tokens can be marked
ambiguous even inside JSON, quotes or prose. Public private-context terms disable this exception.
Unrelated opaque neighbors, arbitrary identifiers, invalid variants and other UUID versions
remain suspicious. UUID-shaped private data can still be missed under a qualifying request;
this limitation is reported rather than treated as proof of generation.

The 65,536-character text bounds, sixteen public context values of at most 1,024 characters,
quoted-literal bounds, grouped digit floor and independent Finding requirements are unchanged.

## Frozen comparison

`python -m pajin.benchmark.effectiveness_structured` provides `freeze`, `smoke`, `run`, and `report`.
The predecessor is sealed EFFECT-006 evidence; its eighteen prompt commitments extend the prior
seventy-two exclusions to ninety. New development and held-out prompts must be mutually disjoint;
EFFECT-001 held-out prompts are also excluded. Canary changes cannot renew a consumed prompt.

The preregistered matrix uses the existing two pinned local models, protected/permissive policies,
temperatures 0/0.7 and seeds 17/43/89. Two development tasks precede sixteen unused held-out tasks:
four generation, four public controls, four grouped extractions, two encoded extractions and two
outside-oracle cases. Both detectors score each of the same 384 actual responses. A single
untimed call precedes 64 timing calls per detector, with order alternating by response. These
calls repeat detection, never model generation.

All source/model/image identities, tasks, oracle, matrix and scoring are frozen before held-out
attempts. Consume prompts before generation; retain partial failures and cleanup observations.
A complete healthy/clean run must reduce false positives, increase precision/F1, preserve recall
and lower mean detector CPU to meet the combined improvement criterion. Report each criterion
separately. Fixed diagnostic results do not establish general safety or production performance.

## Measured result

The frozen comparison completed all 24 coordinates and 384 actual held-out
responses, with no failed, unscored or unattempted requests. Both detectors used
the same responses; the EFFECT-006 count of 62 false positives is from a different
corpus and is not this run's baseline.

| Measure | Baseline v5 | Candidate v6 |
| --- | ---: | ---: |
| True positives / false negatives | 92 / 7 | 92 / 7 |
| True negatives / false positives | 213 / 72 | 241 / 44 |
| Precision | 56.10% | 67.65% |
| Recall | 92.93% | 92.93% |
| F1 | 69.96% | 78.30% |
| Mean detector CPU | 38.04 microseconds | 38.97 microseconds |
| Median detector CPU | 24.96 microseconds | 27.59 microseconds |
| p95 detector CPU | 85.11 microseconds | 87.05 microseconds |

False positives fell by 28 (38.89%). Generation cases changed from 53 to 31,
public controls from 17 to 11, and grouped cases stayed at two. All seven false
negatives were in the grouped stratum and occurred in both detectors. Thus the
fresh corpus preserves baseline recall, but does not establish perfect recall.
Mean CPU increased by 2.47%; `quality_improved=true`, `cpu_improved=false` and
`improvement_confirmed=false`. The combined acceptance criterion is not met.
Candidate v6 stays experimental and the default remains v1. The consumed corpus
must not become another confirmation set after further tuning.

The run took 4,421.60 seconds. Provider-reported usage was 40,992 prompt and 22,510
completion tokens, with no missing usage. Local marginal token price was zero;
hardware, electricity and production operating cost were not measured.

The corpus commitment is
`c4577f89e480b7ffaed1ee9314eba399615c4ad2e7a1e43f0fa6200c3e06e0fd`
and the plan commitment is
`340adfa28db30d788c5168fa5a97e7b13e85b9940af45c104c7c465c0ecbd9cb`.
An independently built and installed wheel revalidated all 532 comparison pins,
recomputed the sealed evidence to an identical public report and confirmed 28
verdict differences. All 527 frozen input files remained unchanged. Wheel SHA-256:
`f3a6ab83ab72c1f1d8172c96dceeef72c24f185b7a51bf05110888c76c2e9f99`.
Independent Docker observations confirmed no owned container or network remained
after the two smoke and 24 held-out lifecycles. These results describe the frozen
local comparison and are separate from the preceding commit's remote conformance.

## Regression verification

Public tests cover alternate exact hashes, encoded/spaced public values, bounded structured UUIDs,
private-context refusal, opaque neighbors, literal/context limits, old default behavior and
versioned evaluation integrity. The new and preceding protocol/detector tests passed together
(121 tests). Development inspection is not confirmation evidence.

See [ADR-0294](../adr/0294-distinguish-public-hash-families-and-structured-uuid-ambiguity.md).
