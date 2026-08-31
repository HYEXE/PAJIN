# Documentation Authority Policy

## Purpose

PAJIN uses a repository-first documentation model. A clean clone contains the code-coupled
contracts, decisions, roadmap, current handoff, and known limitations required to resume work. A
future documentation website may publish repository-owned material but does not become another
authority. The former Notion roadmap is retained only as a historical snapshot.

## Authority map

| Information | Canonical authority | Repository location |
| --- | --- | --- |
| Executable behavior, schemas, and security boundaries | Code and tests | `src/`, `tests/` |
| Architecture decisions and immutable rationale | Accepted RFCs and ADRs | `docs/rfc/`, `docs/adr/` |
| Versioned implementation contracts | Contract specifications | `docs/benchmark/`, `docs/capability/`, `docs/discovery/`, `docs/graph/`, `docs/orchestration/` |
| Requirement-to-implementation traceability | Versioned traceability records | `docs/KISA_TRACEABILITY.md` |
| Installation and operator entry points | Root README | `README.md` |
| Navigation and documentation policy | Documentation index and this policy | `docs/README.md`, this file |
| Repository-wide working rules | Root agent instructions | `AGENTS.md` |
| Roadmap, priority, milestones, and completion criteria | Current repository plan | `PLAN.md` |
| Current checkpoint, verification, and next action | Executable handoff | `HANDOFF.md` |
| Reproduced unresolved limitations | Known-issues register | `KNOWN_ISSUES.md` |
| Decision navigation | ADR routing index | `DECISIONS.md` |
| Published product documentation | Future generated documentation site | Generated from canonical repository files |

When records conflict, executable code and tests take precedence over repository documents, and
repository contracts and accepted ADRs take precedence over operational status documents.
`PLAN.md` determines priority, while `HANDOFF.md` records the latest checkpoint and must be
verified against Git and the filesystem before use.

## Repository rules

1. README, RFC, ADR, versioned contracts, and other technical documentation use one canonical
   English file per subject.
2. The five root operational-state documents use Korean so the primary operator and subsequent
   agents share one unambiguous working language. Keep repository-relative commands, public
   identifiers, schemas, and disclosure-safe diagnostics in their original form.
3. Do not add sibling `.en.md` or `.ko.md` files. Translation belongs in a generated publication
   pipeline.
4. Keep operational state only in the five root documents defined above. Do not create additional
   roadmap, sprint-log, meeting-note, handoff, or backlog files.
5. Update a contract or security-boundary document in the same commit as the behavior it governs.
6. Accepted ADRs are append-only decision history. Supersede an accepted decision with a new ADR
   and cross-link the two; do not silently rewrite its rationale.
7. Keep `PLAN.md`, `HANDOFF.md`, and `KNOWN_ISSUES.md` bounded and current. Replace stale state
   rather than appending commit-by-commit history.
8. Keep `DECISIONS.md` as an index; do not duplicate ADR bodies or rationale there.
9. Add another document only when code review, release reproducibility, offline operation, or
   security auditability would be materially weaker without it.
10. Treat every tracked document as potentially public. Do not record absolute local checkout
    paths, personal identifiers, endpoint-security product/process/driver/socket details, account
    or billing state, private support identifiers, or repository-external backup names. Preserve
    only the reproducible effect, its classification, and the public-safe validation or recovery
    path. Keep private workstation and account incident records outside the repository.

The former Notion roadmap remains available as historical context but is not updated as a parallel
source of truth after the repository cutover.

## Lifecycle

- `README.md` stays concise enough to support installation and first use.
- RFCs describe architecture-level proposals and compatibility boundaries.
- ADRs record decisions and their consequences.
- Contract documents define versioned inputs, outputs, invariants, negative cases, migration, and
  rollback expectations.
- Completed work is reflected in the relevant contract and the current root plan/handoff state; it
  does not create a new progress report.
- Obsolete non-ADR documents are deleted after their durable requirements are consolidated into
  code, tests, or a current contract.

## Future documentation site

Build the product website only after public APIs and operator workflows stabilize. Generate it from
the canonical repository tree, with commit or release versioning and link validation. The site may
add navigation, search, examples, and translations, but edits must flow back to the repository
source instead of diverging in the published copy.
