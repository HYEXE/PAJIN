> Languages: [English](0016-tamper-evident-run-integrity.en.md) | [한국어](0016-tamper-evident-run-integrity.ko.md)

# ADR 0016: Tamper-evident Run integrity chain

- Status: Accepted
- Date: 2026-07-13

## Context

PAJIN validates that a Finding cites evidence inside its Run directory, but path containment alone
does not detect a file changed after execution. Audit Events were append-only by convention and had
no cryptographic ordering link. This left every Mode Pack vulnerable to consuming accidentally
modified, partially copied, or reordered local evidence.

A single manifest written at campaign completion is insufficient because Mode Packs add derived
assessment, remediation, retest, and submission-draft artifacts after the core runner finishes.
Overwriting that manifest would discard the earlier integrity checkpoint and blur which component
added each artifact.

## Decision

Every new Audit Event has a contiguous sequence, the previous Event hash, and a SHA-256 hash over
its canonical JSON content. The first Event has no previous hash. Loading an existing stream for
append or verification checks run identity, sequence, previous-hash linkage, content hash, and
offset-aware timestamps.

`RunStore.seal()` appends a record to `run-integrity.jsonl`. A seal contains:

- Run and seal identity, sequence, and timestamp;
- the previous seal root digest;
- the current Audit Event count and head hash;
- a canonically ordered list of newly sealed artifacts;
- each artifact's path, size, media type, SHA-256 digest, and available provenance;
- an artifact-list digest and a final root digest over the complete seal record.

Evidence JSON provenance includes its request ID, Tool ID, Worker execution ID, and related Audit
Event IDs when present. Other artifacts link to Events that cite their relative path.

The first seal captures all core execution artifacts. Later services must verify the complete Run,
write only new paths, append their completion Event, and append an extension seal linked to the
previous root. Previously sealed paths cannot be overwritten through `RunStore`. Direct Tool Loop
checkpoint claims extend the source Run; a signed Control Plane checkpoint copied outside a Run is
treated as external continuation state and the new continuation Run receives its own seal.

`verify_run_integrity()` and `pajin evidence-verify` fail when:

- an Event is edited, removed, added without a seal, or reordered;
- a seal is edited, removed inconsistently, reordered, or linked to the wrong root;
- a sealed artifact is changed, missing, duplicated, symbolic, or outside the Run;
- a new file exists without an extension seal.

Bug Bounty reporting and KISA assessment/retest verify the input Run before reading or extending it.

## Consequences

Local evidence consumers now receive one reproducible root digest and fail closed on common
tampering and incomplete-copy conditions. Post-processing retains the original checkpoint and
creates an auditable chain instead of replacing it. Existing Runs created before this ADR are
unsealed and must not be accepted by integrity-enforcing consumers without an explicit migration
and trust decision.

SHA-256 chaining does not authenticate who created a Run. A privileged actor able to replace the
entire directory and all externally unanchored roots can create a new internally consistent chain.
Production use therefore requires publishing the root digest to a separately controlled signed
record, transparency service, or immutable object store. Key management and remote anchoring are
outside this change.

## Validation

Tests cover successful core and extension seals, evidence provenance, sealed-file overwrite
prevention, changed and missing artifacts, unsealed additions, Event reordering and content
tampering, CLI success/failure, Bug Bounty rejection of a modified Campaign, KISA rejection of
missing evidence, and existing Tool Loop continuation behavior.
