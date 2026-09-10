# ADR-0274: Compare Disclosure Suspicion with a Fresh Private Evaluation

- Status: Accepted
- Date: 2026-09-09
- Extends: [ADR-0261](0261-separate-local-llm-effectiveness-from-synthetic-conformance.md)

## Context

EFFECT-001 exposed a mismatch between public-marker presence and actual private-nonce disclosure.
Reusing its responses as a new evaluation after improving the detector would contaminate the
comparison. Changing the existing M03 detector or its frozen suite would also invalidate retained
reports and imply a new validation authority for established AI contracts.

## Decision

Add an opt-in `detect_disclosure_suspicion` API that receives only an assistant response, public
user text and explicit public values. It checks novel opaque identifiers and bounded encodings,
excluding user echoes. Its result is a suspicion signal, with no Finding, scope or action authority.
It receives no expected private value, system message, case label or oracle verdict. It can flag
legitimate random identifiers and miss low-entropy/semantic disclosures; these limits remain explicit.

Create EFFECT-002 with a new private corpus and predeclared comparison rule. The previous complete
report is development provenance only. Freeze detector/oracle/comparison source digests, case
commitments, model files, images, settings and all coordinates before generating held-out responses.
Compare both detectors on each identical response before independent private-nonce adjudication.
Record per-detector CPU/wall time while alternating execution order. Do not charge inference twice.

Reuse EFFECT-001's verified Gateway/Worker/receipt/lifecycle implementation through a read-only
structural plan interface. Keep the original suite, scoring, M03 check and reader semantics intact.
Existing version-1 Run envelopes hold source evidence under a distinct caller-selected private
root; EFFECT-002 plan/index payloads require the new reader. No old plan is silently reinterpreted.

## Consequences and validation

The corpus is consumed by its normalized held-out prompt digest, independent of random canaries;
changing a nonce cannot reuse a consumed corpus within that root. Cross-root or whole-host rollback
protection is not claimed. Public manifests contain commitments and categories, never prompt or
response text. Retained results remain trusted-host observations rather than independent signatures.

Verify old-reader compatibility, split/previous-corpus overlap rejection, oracle-input separation,
exact model/settings/source identities, complete paired support, no-response/failed-score accounting,
tamper rejection and output guards. Use both actual pinned local models for the new comparison.
Higher pooled F1 counts as improvement only without precision or recall loss and with all expected
responses and cleanup verified. A failed gate or non-improved score stays visible.
