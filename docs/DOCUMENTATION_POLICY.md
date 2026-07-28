# Documentation Authority Policy

## Purpose

PAJIN uses a hybrid documentation model. The repository owns records that must change with code;
Notion owns planning and operating context that changes independently of code. A future
documentation website will publish repository-owned material, not become another authority.

## Authority map

| Information | Canonical authority | Repository location |
| --- | --- | --- |
| Executable behavior, schemas, and security boundaries | Code and tests | `src/`, `tests/` |
| Architecture decisions and immutable rationale | Accepted RFCs and ADRs | `docs/rfc/`, `docs/adr/` |
| Versioned implementation contracts | Contract specifications | `docs/benchmark/`, `docs/capability/`, `docs/discovery/`, `docs/graph/`, `docs/orchestration/` |
| Requirement-to-implementation traceability | Versioned traceability records | `docs/KISA_TRACEABILITY.md` |
| Installation and operator entry points | Root README | `README.md` |
| Navigation and documentation policy | Documentation index and this policy | `docs/README.md`, this file |
| Roadmap, priority, progress, blockers, and milestones | [PAJIN Notion roadmap](https://app.notion.com/p/3a94b2ea35f081329974c7f57eda299a) | Not stored as a repository plan |
| Published product documentation | Future generated documentation site | Generated from canonical repository files |

When records conflict, executable code and tests take precedence over repository documents, and
repository contracts take precedence over Notion implementation summaries. Notion remains the
authority for what should be worked on next and the current verification state.

## Repository rules

1. Repository Markdown has one canonical file and one canonical language: English.
2. Do not add sibling `.en.md` or `.ko.md` files. Translation belongs in Notion or a generated
   publication pipeline.
3. Do not copy roadmaps, sprint status, commit-by-commit progress, meeting notes, or task backlogs
   into the repository.
4. Update a contract or security-boundary document in the same commit as the behavior it governs.
5. Accepted ADRs are append-only decision history. Supersede an accepted decision with a new ADR
   and cross-link the two; do not silently rewrite its rationale.
6. Prefer one durable link to the live Notion roadmap over repeated status prose.
7. Add a document only when code review, release reproducibility, offline operation, or security
   auditability would be materially weaker without it.

The removed localized files and repository product plan remain recoverable from Git history.

## Lifecycle

- `README.md` stays concise enough to support installation and first use.
- RFCs describe architecture-level proposals and compatibility boundaries.
- ADRs record decisions and their consequences.
- Contract documents define versioned inputs, outputs, invariants, negative cases, migration, and
  rollback expectations.
- Completed work is reflected in the relevant contract and Notion status; it does not create a new
  repository progress report.
- Obsolete non-ADR documents are deleted after their durable requirements are consolidated into
  code, tests, or a current contract.

## Future documentation site

Build the product website only after public APIs and operator workflows stabilize. Generate it from
the canonical repository tree, with commit or release versioning and link validation. The site may
add navigation, search, examples, and translations, but edits must flow back to the repository
source instead of diverging in the published copy.
