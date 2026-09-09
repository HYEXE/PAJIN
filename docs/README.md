# PAJIN Documentation

This directory contains documentation that must remain reviewable and versioned with code. Read the
[documentation authority policy](DOCUMENTATION_POLICY.md) before adding or relocating a document.
Repository-wide rules, priorities, current state, decisions routing, and known limitations live in
the root [agent instructions](../AGENTS.md), [plan](../PLAN.md), [handoff](../HANDOFF.md),
[decision index](../DECISIONS.md), and [known issues](../KNOWN_ISSUES.md).

## Start here

- [Architecture v2 RFC](rfc/0001-pajin-architecture-v2.md)
- [Multi-domain architecture RFC](rfc/0002-multi-domain-security-analysis-architecture.md)
- [Architecture decision records](adr/)
- [Capability contracts](capability/)
- [Canonical Graph contracts](graph/)
- [Discovery contracts](discovery/)
- [Orchestration contracts](orchestration/)
- [Measured product deployment and Console](orchestration/UX-010-measured-product-deployment-and-console.md)
- [Measured Docker conformance rerun policy](orchestration/MEASURED-CONFORMANCE.md)
- [Actual local LLM effectiveness evaluation](benchmark/EFFECT-001-local-llm-effectiveness.md)
- [Human review and remediation reports](orchestration/UX-011-human-review-and-remediation-report.md)
- [Single-host recovery and urgent stop](orchestration/OPS-001-single-host-recovery-and-urgent-stop.md)
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
