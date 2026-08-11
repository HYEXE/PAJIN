# UX-006A: Verified Finding SARIF Export

- Status: Implemented and verified
- Decision: [ADR-0164](../adr/0164-export-confirmed-findings-before-external-delivery.md)
- Export contract: `pajin.dev/sarif-export/v1alpha1`
- Format: SARIF `2.1.0`
- Command: `pajin sarif-export`

## Scope

UX-006A serializes the `product_confirmed_findings` of one exact sealed validation Run to a local
SARIF file. It does not read benchmark Scanner SARIF as Finding authority and does not call an Issue
Tracker, SIEM, SOAR, webhook, or other network sink.

Required caller inputs are:

- the validation Run directory;
- `--expected-run-id` for the exact sealed Run;
- `--expected-root-digest` for the exact final authority phase;
- `--output` for a standalone path outside that Run.

The loader verifies the Run and all versioned validation artifacts through the existing integrity,
same-authority, projection-content, seal-binding, and replay-lineage checks. Only
`verified-independent-replay` is exportable. A legacy unversioned confirmation or
`verified-replay-evidence` projection is rejected even when it contains a `validated=true` Finding.

## Deterministic serialization

- Results are sorted by portable, unique Finding ID.
- Rules are grouped by exact threat class and use
  `PAJIN-<sha256("pajin-sarif-rule-v1" + NUL + threat-class)>` IDs.
- The source Finding-set digest hashes canonical JSON in authority order.
- Each partial fingerprint hashes the exact full source Finding.
- No generated timestamp, random identifier, host path, or output path enters the SARIF bytes.
- `critical`/`high` map to `error`, `medium` to `warning`, and `low`/`safe` to `note`.

The SARIF run binds `sourceRunId`, `sourceRootDigest`, `sourceFindingSetDigest`,
`confirmationSemantics`, and the export API version. The source Run is reverified after
serialization so an appended phase cannot silently change the selected authority.

## Minimized fields and bounds

Included report fields are title, summary, threat class, severity, confidence, affected component,
impact, and remediation. Raw target, root cause, reproduction, and evidence are excluded. Only a
target SHA-256 is retained. This is deterministic minimization, not a claim that included reviewed
prose can never contain sensitive business content.

The contract allows at most 1,000 Findings. The source Finding set and final SARIF are each bounded
to 16 MiB; title, threat class, summary, detail, remediation item size, and remediation item count
have tighter limits. Unsafe Unicode controls/format characters and non-portable IDs fail closed.

The writer uses a no-follow atomic private file, rejects output inside the source Run, rereads with
a 16 MiB limit and single-link requirement, and compares exact bytes and SHA-256.

## Authority markers

The SARIF run fixes these properties:

- `externalDeliveryPerformed=false`;
- `deliveryReceiptAuthority=false`;
- `issueMutationAuthority=false`;
- `siemIngestAuthority=false`;
- `soarActionAuthority=false`.

The CLI prints the source root, Finding-set digest, SARIF digest, and `NOT PERFORMED` for external
delivery. It never treats a local write as remote acknowledgement.

## Failure behavior

| Condition | Result |
| --- | --- |
| Invalid or substituted Run ID/root digest | fail without output |
| Tampered or incomplete sealed validation projection | fail without output |
| Legacy/replay-evidence-only confirmation | fail without output |
| Unsafe/unbounded Finding export data | fail without output |
| Output inside source Run or through symbolic link | fail closed |
| Output reread or digest mismatch | fail closed |

## Threat model and compatibility

The primary threats are exporting an unconfirmed claim, confusing Scanner evidence with product
authority, selecting a stale/wrong Run phase, leaking raw target/evidence, path substitution,
consumer display injection, and treating serialization as delivery. Exact authority inputs,
existing validation verification, an allowlisted projection, bounded safe text, no-follow private
writes, and fixed false delivery markers address those threats.

The change is additive and local. It changes no existing schema, database, network policy,
benchmark metric, or external system. The next connector slice must define sink identity, secret
lease, idempotency, authenticated response, durable delivery receipt, retry, and reconciliation
before any outbound side effect is enabled.

## Completion criteria

Completion requires deterministic/read-back tests, explicit severity mapping, redaction checks,
legacy and stale-root rejection, unsafe-text and symlink tests, CLI success/failure tests, related
validation/CLI regressions, Ruff, format, strict mypy, documentation limits, and `git diff --check`.
