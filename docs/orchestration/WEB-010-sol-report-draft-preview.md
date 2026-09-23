# WEB-010: Local Sol Report Draft Preview

- Status: local draft admission and untrusted preview only
- Version: `pajin.dev/codex-sol-report-draft/v1alpha1`
- Scope: independently verified Findings from one strictly reloaded completed Web Campaign

## Input and admission

`CodexSolVerifiedInput` for `report-draft` contains only an opaque Finding reference, severity,
and CWE class for each independently verified Finding, plus the Promotion digest. It excludes
target text, raw Evidence, and source Run anchors. A caller must independently pin its exact
input digest. The local admission function rebuilds that input from a strictly reloaded completed
Campaign before parsing any draft.

The draft is bounded strict JSON with one short, single-line overview and exactly one note per
sorted Finding reference. Duplicate JSON keys, extra fields, missing or repeated references,
wrong input digest, control characters, oversized prose, and nonliteral authority markers are
rejected. Schema admission checks shape and reference lineage, not the truth of prose or its
model provenance.

## Output boundary

The only output is an in-memory Markdown preview labeled untrusted. Canonical severity and CWE
values come from the reloaded Finding signals; prose is escaped and identified as an unverified
draft. The preview carries no report writer, Graph writer, Gateway, Permit, Finding, or delivery
handle. It does not change the sealed canonical report, SARIF, redacted PoC, delivery manifest,
or completed parent.

No Sol call or hosted transfer is included. A future Sol turn needs its own exact input/model/
destination authorization, isolated no-tool executor, terminal receipt, and provenance-bound
draft loader. Incorporating validated narrative into a canonical delivered report requires a
separate versioned post-verification contract. The current WEB-005/006 report remains the
deterministic, independently verified output.

## Verification

Synthetic draft tests exercise exact reference mapping, rejected authority and malformed JSON,
source mismatch, and Markdown escaping. A read-only local smoke used the completed WEB-006 parent
and the retained Sol report input digest; a synthetic draft produced three untrusted notes while
the sealed parent root remained unchanged. No model or target call occurred in this check.

## Related decisions

- [ADR-0324](../adr/0324-route-hosted-codex-advisory-by-stage.md)
- [ADR-0327](../adr/0327-bind-hosted-recon-to-local-proposal-and-inert-topology.md)
