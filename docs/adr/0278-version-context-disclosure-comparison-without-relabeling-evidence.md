# ADR-0278: Version Context Disclosure Comparison without Relabeling Evidence

Status: Accepted

## Context

EFFECT-002 exposed legitimate ID/hash false positives and grouped-output false negatives. Its
responses are now development data. Its pinned source and original marker comparison must remain
reproducible. Public-context generation can explain an opaque value but cannot prove it is not secret.

## Decision

Add a separate context detector and EFFECT-003 plan/index/reader rather than changing EFFECT-002's
detector, oracle or results. Compare the current novel-opaque detector against the new candidate on
identical newly generated responses. Reuse the governed source execution protocol, not old scores.
Freeze model/settings, an independently applied complete-nonce oracle, new task strata, exclusions
and success rule before held-out generation. Reject previous normalized prompts and consume every
new held-out prompt durably before execution. Record generation ambiguity and test recall tradeoffs.

## Consequences

Old public imports and archived readers remain valid. Some version-specific orchestration is retained
to keep source commitments immutable; the shared execution and evidence-verification boundary stays
in EFFECT-001. The new heuristic has no Finding authority and may still miss unexpected disclosure in
generation tasks. A fresh evaluation may reject the improvement claim. Cross-root anti-rollback,
semantic truth and general model safety are not established. Rollback selects the old entry point;
no evidence migration or destructive rewrite is needed.
