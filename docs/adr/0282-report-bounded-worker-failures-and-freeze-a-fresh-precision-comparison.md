# ADR-0282: Report Bounded Worker Failures and Freeze a Fresh Precision Comparison

Status: Accepted for additive diagnostics and an experimental comparison; no detector promotion.

## Context

The two failed EFFECT-003 calls have insufficient retained diagnostic detail to establish their
causes. Historical evaluations are consumed development material, not fresh evaluation samples.
The current context candidate gained recall while losing precision, especially on grouped text.

## Decision

Preserve Worker success JSON, legacy failure exit codes and the first generic stderr line. Add a
versioned second line containing only allowlisted observed failure stage and exception category.
Never serialize exception arguments, prompt/response text, paths or credentials. Provider parsing
accepts only the exact bounded, untruncated two-line form and records unknown otherwise. A report
is an observed Worker category, not proof of a deeper root cause. Executed/ambiguous calls keep
conservative charges; this diagnostic does not authorize retries or refunds.

Keep `novel-opaque-output-v1` as the default. Add `mixed-group-opaque-output-v3` as a separate
candidate, retaining the context candidate's public identifier checks and requiring sufficient
digit density for its additional grouped opaque-text signal. This intentionally misses some
letter-only or sparse-digit secrets. Do not tune it to private nonce lengths or test labels.

EFFECT-004 freezes fresh normalized prompts, private ground truth, oracle, seeds/policies/models,
sample rules, completeness and quality gates, source snapshots and immutable images before calls.
Exclude both prior corpora and atomically consume the new one across root copies. Score baseline
and candidate on the same output using the independent nonce oracle. Preserve old readers and
artifacts; freeze an independent source tree for fresh-process recomputation. Failed calls remain
unscored and cannot count as true negatives. Record an unsuccessful quality gate without promotion.

## Consequences

Diagnostics narrow future investigations without reconstructing historical causes. Detector output
remains suspicion, never Finding authority or evidence of general model safety. Local model timing
and deterministic remote fixture conformance are different measurements. Raw evidence and models
remain private; public reports contain counts, metrics, commitments and limits only.

## Consumption-scope clarification (2026-09-11)

The earlier "across root copies" wording does not describe an implemented cross-root guard.
The atomic prompt-consumption ledger is confined to its evaluation root. It prevents reuse in
that root, including failed attempts, but cannot detect a copied or rolled-back root on another
path or host. The experiment's exclusion rule still prohibits treating copied or re-canaryed
consumed tasks as unused. No cross-root enforcement or independent anti-rollback authority is
claimed; the versioned EFFECT-004 contract records this implemented limit.
