# REDTEAM-002: Initial Red Team Profile Benchmark

- Status: implemented contract and sealed aggregation
- Profile set: `pajin.dev/redteam-benchmark-profile-set/v1alpha1`
- Raw observation: `pajin.dev/redteam-benchmark-run-observation/v1alpha1`
- Report: `pajin.dev/redteam-initial-benchmark-report/v1alpha1`
- Decision: [ADR-0209](../adr/0209-measure-redteam-profiles-without-finding-authority.md)

## Purpose

Measure the initial REDTEAM-001 product profiles without treating Capability registration,
CAP-003 mapping, Tool success, or an Oracle Observation as a confirmed Finding. REDTEAM-002 is an
additive profile benchmark over existing BENCH-001, CAP-003, CAP-006, and RunStore primitives; it
does not replace their generic contracts.

## Closed profile denominator

The profile set is derived from the exact eight-Capability bundle that includes the opt-in MCP
extension, but admits only these five product Capabilities:

| Profile | Capabilities | Negative-control metric | Replay metric |
| --- | --- | --- | --- |
| `redteam-llm-v1` | M03, M06 KISA Capabilities | required | required |
| `redteam-llm-rag-v1` | A04 KISA Capability | required | required |
| `redteam-web-v1` | fixed Boolean SQLi Capability | required | N/A |
| `redteam-mcp-v1` | fixed registered MCP inspection | N/A | N/A |

Each entry binds the code-owned profile digest, exact CAP-002 authority-set reference, CAP-003
benchmark mapping digest, request-unit cost, and applicable CAP-006 Replay support and contract
IDs. The profile set contains no Security Domain routing field and declares that Security Domain is
not authority.

## Raw measurement sources

Every raw observation declares exactly one source kind:

- `profile-execution`: one exact product Tool call, exact request units, model-call count, and cost;
- `deterministic-reanalysis`: zero execution cost for an independently supplied control or Oracle
  re-analysis; or
- `independent-replay`: a separate source Run and supported CAP-006 Replay contract whose Tool,
  request-unit, model-call, and cost values are measured independently; or
- `policy-denial`: an expected denial with no Oracle, Permit consumption, Tool call, model call, or
  cost claim.

Detection sources require a content-addressed CAP-006 Oracle observation whose Capability,
benchmark ID, and evidence digest match the raw source. Ground Truth cases are explicitly
`known-positive` or `negative-control`; the detector outcome is recorded separately. Replay cases
must refer to a Ground Truth case in another unique source Run, use the Ground Truth-compatible
expected verdict, and name an exact CAP-006-supported Replay contract.

The raw recorder validates the closed profile set, writes one immutable observation artifact, and
seals the audit sequence. The aggregate runner reopens every source Run before producing its own
sealed profile set, raw-observation bundle, and report. Post-seal source or report mutation fails
verification.

## Metrics

Each profile result contains the same ordered metric vocabulary while preserving semantic N/A:

1. detection recall;
2. false-positive rate;
3. detection precision;
4. Replay success rate;
5. time to first valid Finding;
6. total request units;
7. total Tool calls;
8. total cost in USD;
9. cost per true-positive detection;
10. evidence completeness;
11. policy-denial correctness; and
12. cleanup success rate.

Measured ratios carry exact numerators and denominators. N/A values carry no numeric value and
require an explicit reason. The current MCP profile has no registered negative-control or Replay
measurement path. Web and MCP have no independent Replay path. No current profile creates a valid
Finding, and every current Capability is read-only with no cleanup requirement. Those metrics are
therefore N/A, not zero.

## Completion requirements

Aggregation fails closed unless:

- every exact Capability has at least one known-positive profile execution;
- every profile with required false-positive measurement covers a negative control for every
  Capability;
- every profile with required Replay measurement covers every Capability with supported Replay;
- every profile has at least one expected policy-denial observation;
- case, source, metric, profile, and Capability identities are unique and canonical; and
- evidence counts, request-unit costs, source kinds, Oracle identity, and applicability agree.

## Evidence and non-authority

The report binds all source observation digests and explicitly sets execution authority, Finding
authority, and Scope expansion to false. A perfect detection or policy-denial score does not create
a Capability release, approval, Permit, Finding, report delivery, Scope expansion, or new action.

Reference tests construct deterministic fixture observations to verify contract semantics and
tamper rejection. They are not published benchmark scores, external Target evidence, or production
conformance. A deployed measurement adapter remains responsible for supplying truthful raw facts
and source lineage.

## Compatibility and rollback

REDTEAM-002 introduces only new public benchmark types and artifacts. BENCH-001 metrics and result
wires, CAP-003 mappings, CAP-006 observations, REDTEAM-001 profiles, ActionPermit, Gateway, Worker,
Replay, Validation, and Finding contracts are unchanged. Stopping the REDTEAM-002 runner restores
the previous behavior without rewriting existing records.

## Verification

- exact profile, Capability, mapping, request-cost, and Replay-support denominator;
- positive, negative-control, Replay, policy-denial, evidence, and cost aggregation;
- explicit N/A for unavailable MCP/Web/valid-Finding/cleanup metrics;
- rejection of missing negative, Replay, or policy coverage;
- rejection of profile/mapping drift and unsupported Replay contracts;
- rejection of Finding claims in raw REDTEAM-001 observations; and
- sealed source/report reload and post-seal mutation rejection.
