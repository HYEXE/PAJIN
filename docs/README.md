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
- [Pricing HTTP dependency security floor](orchestration/SEC-001-http-client-dependency-security.md)
- [Actual local LLM effectiveness evaluation](benchmark/EFFECT-001-local-llm-effectiveness.md)
- [Context-aware detector experiment and observed limitations](benchmark/EFFECT-003-context-disclosure-comparison.md)
- [Fresh disclosure detector comparison](benchmark/EFFECT-002-disclosure-detector-comparison.md)
- [Human review and remediation reports](orchestration/UX-011-human-review-and-remediation-report.md)
- [Registered Campaign and Snapshot history](orchestration/UX-012-registered-campaign-and-snapshot-history.md)
- [Review assignment and personal in-app notifications](orchestration/UX-013-review-assignment-and-internal-notifications.md)
- [Single-host recovery and urgent stop](orchestration/OPS-001-single-host-recovery-and-urgent-stop.md)
- [Isolated PostgreSQL operational drill](orchestration/OPS-002-isolated-postgres-operations.md)
- [Managed Linux hybrid operator recovery](orchestration/OPS-003-managed-hybrid-recovery.md)
- [Separately retained recovery witness](orchestration/OPS-005-separately-retained-recovery-witness.md)
- [Public text detector comparison and unchanged false positives](benchmark/EFFECT-006-public-text-transforms-and-disclosure.md)
- [Canonical Graph serialization cost comparison](benchmark/GRAPH-PERF-005-canonical-serialization-cost.md)
- [First and changed-history Graph page costs](benchmark/GRAPH-PERF-002-first-and-history-page-cost.md)
- [Authenticated System distribution read](orchestration/SYS-002-authenticated-os-release-read.md)
- [Current Graph page cost and bounded cache](benchmark/GRAPH-PERF-001-current-graph-page-cost.md)
- [Approved offline ELF header execution and report](orchestration/APP-002-bounded-offline-elf-header-execution.md)
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
