# ADR-0294: Distinguish Public Hash Families and Structured UUID Ambiguity

Status: Accepted

## Context

The consumed EFFECT-006 corpus retained 62 false positives. Development inspection found
model outputs that exactly equal a different hash algorithm over the same public bytes, and
UUIDs in quoted or plural structured output. Neither a wrong task answer nor output formatting
alone establishes that a value was private. Arbitrary generated IDs remain indistinguishable
from copied private IDs with these inputs.

## Decision

Add experimental `public-structured-opaque-output-v6`; leave v1 through v5 and the v1 product
default unchanged. For an explicitly named supported hash request, compare candidates with the
finite supported hash family over at most sixteen exact public UTF-8 literals. Compute only
algorithms whose output lengths occur in the response's inspected representations. No fuzzy
hash matching, model assertion, private input or oracle result is used.

Recognize singular or plural explicit new/random/sample UUID generation requests. When no
private-context terms occur, canonical RFC 4122 variant/version-4 UUID values among the first
sixteen lexical tokens are ambiguous generated-format values, including within JSON, quotes
and prose. Preserve suspicion for every neighboring unrelated opaque representation. This is
an uncertainty classification, not proof of generation; a private value with the same UUID
shape and public request can be missed. Invalid variants/versions and arbitrary IDs retain
suspicion. Preserve text/context bounds, grouped rules and false Finding authority.

EFFECT-007 uses a new disjoint corpus, the same 24-coordinate local model matrix and 384 paired
responses. Exclude all ninety EFFECT-002 through EFFECT-006 prompt commitments and the original
EFFECT-001 held-out corpus. Freeze source, corpus, scoring and runtime before held-out generation;
consume each held-out prompt once. Confirm combined improvement only with fewer false positives,
higher precision/F1, no recall loss and lower mean CPU on a complete healthy/clean evaluation.

## Consequences

An exact public derivation can be a task-error answer while not being a private disclosure.
Unknown or incorrect digests stay suspicious. The complete-nonce oracle does not measure general
semantic safety, and finite diagnostic strata are not a deployment quality estimate. Failed
quality or CPU criteria are retained. Consumed responses become development material only.
