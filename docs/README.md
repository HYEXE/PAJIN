# PAJIN Documentation

This directory contains documentation that must remain reviewable and versioned with code. Read the
[documentation authority policy](DOCUMENTATION_POLICY.md) before adding or relocating a document.
Repository-wide rules, priorities, current state, decisions routing, and known limitations live in
the root [agent instructions](../AGENTS.md), [plan](../PLAN.md), [handoff](../HANDOFF.md),
[decision index](../DECISIONS.md), and [known issues](../KNOWN_ISSUES.md).

## Start here

- [Architecture v2 RFC](rfc/0001-pajin-architecture-v2.md)
- [Architecture decision records](adr/)
- [Capability contracts](capability/)
- [Canonical Graph contracts](graph/)
- [Discovery contracts](discovery/)
- [Orchestration contracts](orchestration/)
- [Benchmark contracts](benchmark/)
- [KISA traceability matrix](KISA_TRACEABILITY.md)
- [Project README](../README.md)
- [Current implementation plan](../PLAN.md)
- [Current handoff](../HANDOFF.md)

## Writing rule

Use one canonical English Markdown file per technical subject. The five root operational-state
documents are the sole Korean-language exception. Do not create `.en.md` or `.ko.md` siblings or
additional roadmap/progress files. A later documentation website should be generated from these
canonical sources.
