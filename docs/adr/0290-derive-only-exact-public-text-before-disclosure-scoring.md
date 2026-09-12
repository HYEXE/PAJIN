# ADR-0290: Derive Only Exact Public Text before Disclosure Scoring

Status: Accepted

## Context

EFFECT-005 retained 64 false positives in its consumed diagnostic corpus. A response-only
detector cannot establish whether an arbitrary identifier was generated or copied from private
input. Public text represented with JSON escapes and additional explicitly named hash algorithms
can, however, be independently reconstructed without private inputs or model assertions.

## Decision

Add experimental `public-transform-opaque-output-v5`, retaining v1 through v4 and the v1 default.
Decode at most sixteen bounded public quoted literals, using JSON semantics only for double
quotes. Treat exact decoded public text as already public. Recompute the explicitly requested
SHA-1/2/3, MD5 or BLAKE2 digest over those UTF-8 bytes. Handle straight, backtick and typographic
quotes without executing instructions. Preserve arbitrary-ID suspicion, the existing single-ID
ambiguity, independent Finding validation and all input bounds.

Preserve the grouped-value rule while retaining per-chunk digit counts instead of repeatedly
splitting every prefix. Cache only per-call novelty results; neither observations nor authority
decisions are shared across calls.

EFFECT-006 compares v4 and v5 on one newly frozen corpus and the existing 24-coordinate local
model matrix. The prior sealed plan excludes all 72 EFFECT-002 through EFFECT-005 prompts;
EFFECT-001 prompts are separately excluded. Generation, public-control, grouped, encoded and
outside-oracle strata remain fixed. Fewer false positives, higher precision/F1, no recall loss
and lower mean CPU are required for confirmed improvement. Failed criteria are reported.

## Consequences

Correct public derivations can be excluded; an invented or incorrect model hash remains
suspicious. These data transformations are not cryptographic-security recommendations. The
complete-private-nonce oracle does not establish general semantic safety. The frozen corpus
is consumed before generation and is never renewed by a new root, retry or response-based
tuning. New protocol wires and readers leave existing sealed evaluation formats unchanged.
