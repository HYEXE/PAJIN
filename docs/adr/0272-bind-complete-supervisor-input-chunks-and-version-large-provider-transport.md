# ADR-0272: Bind Complete Supervisor Input Chunks and Version Large Provider Transport

- Status: Accepted
- Date: 2026-09-09
- Extends: [ADR-0120](0120-plan-supervisor-checkpoints-before-invocation.md)

## Context

SUP-002 permits a canonical input up to 4 MiB, while SUP-004A originally requires one user message
of at most 65,536 characters. Splitting that message alone is insufficient: Worker stdin, secret
envelopes, Provider serialization, and the plain HTTP proxy also have smaller byte ceilings.

## Decision

Keep the original two-message chat and `v1alpha1` request binding for inputs that fit. Larger
inputs use `supervisor-invocation-request/v1alpha2` and `supervisor-input-chunks/v1`. One code-owned
developer message explains reconstruction; each user message contains a canonical JSON header,
one newline, and a raw slice of the complete canonical input. Slices contain at most 60,000 Unicode
characters, preserving the shared 65,536-character Provider message limit and 100-message ceiling.

Headers bind the original input ID/digest, complete UTF-8 byte hash, byte/character counts, chunk
count, zero-based index, and character offset. Reconstruction rejects missing, duplicated, reordered,
mixed, edited, noncanonical, or oversized content and revalidates the complete typed Snapshot input.
Chunks and all reconstructed fields remain untrusted. No chunk is another model call or an
instruction. Existing request digests, stable request IDs, reservations, sealed receipts, current
Graph/source verification, and independent receipt consumption bind every message in order.

Large serialized Provider requests select the fixed `openai-chat-completion-v2` Worker action.
It accepts at most 16 MiB of UTF-8 input plus a bounded secret-envelope allowance. Generic actions
and the legacy Provider action retain their existing byte limits. The Gateway derives the optional
proxy `max_request_bytes` from the prepared action, and receipt verification reconstructs it. The
proxy bounds HTTP requests and records the complete canonical request hash; CONNECT retains opaque
visibility and separate request/response byte ceilings. The trusted Worker enforces the exact HTTPS
request. Response limits, scope, credentials, methods, request counts, and budget authority do not grow.

## Compatibility and consequences

No shared `ProviderChatRequest` message/schema limit changes. The old chat and request binding were
compared against the prior implementation and remain identical. Optional transport fields are
absent from legacy serialization. New chunk schedules cannot be downgraded to the legacy version.
Deploy the matching host, Worker image, and proxy image together; old images reject the new action
or policy. Preserve their matching verifier/runtime inventory when retaining new receipts.

Full input plus chunk framing contributes to the conservative Campaign and dedicated reservation;
an unaffordable call still fails before publication/dispatch. This supports bounded delivery, not a
guarantee that an external model accepts a particular context length or uses every input correctly.
Provider errors remain charged and fail closed through the existing invocation journal.

## Validation boundary

Tests reconstruct input just below 4 MiB, reject input above that ceiling, preserve Unicode and JSON
escapes, exercise chunk substitution and downgrade rejection, and verify one dispatch/two seals and
conservative budgets across an exact retry. Worker/proxy tests preserve legacy limits and the
independent response ceiling. The opt-in owned-host test exercises a real Worker process and HTTPS
through the actual proxy with certificate verification enabled. It is transport evidence, not
Docker isolation or model-quality evidence; current-commit Docker conformance remains a separate gate.
