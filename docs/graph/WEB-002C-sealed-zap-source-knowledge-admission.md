# WEB-002C Sealed ZAP Source Knowledge Admission

## Status

Implemented as an additive experimental Graph admission contract.

## Purpose

WEB-002C reopens one exact WEB-002B registry-governed ZAP source measurement and projects only
public-safe neutral knowledge into the existing Canonical Graph single writer. It does not run a
Target, ZAP, Worker, proxy, Replay, or controlled-validation request.

## Exact inputs

The caller supplies the complete context required by the WEB-002B trusted reload:

- the `WebZAPSourceMeasurementOutcome` and exact WEB-002A measured case;
- the signed Capability release context, target adapter, private Ground Truth profile, scanner
  plan and registration;
- the Target journal, catalog-bound provider, measurement trust anchor, registry activation store,
  signed distribution bundle, and distribution trust anchor; and
- a current non-empty Graph Snapshot reference, the existing Graph Admission Authority identity,
  and the exact pre-existing `web.http-operation` Graph Surface.

Private Ground Truth is an input only because the WEB-002B loader requires it to reconstruct and
verify the original measured case. No Ground Truth field or derived Finding truth is copied into
the WEB-002C candidate or Graph material.

## Source verification

`load_verified_web_zap_source_observation` performs both trusted reloads instead of trusting the
caller-held outcome models:

1. `load_web_zap_source_measurement_authority` reopens the outer Run seal and every WEB-002B
   predecessor;
2. `load_scanner_baseline_measurement_authority` independently reconstructs the scanner
   measurement and strict normalizations;
3. the outer authority artifact is loaded from the verified Run snapshot, parsed back to the exact
   reopened authority, required to use canonical bytes, and checked against the exact three audit
   event types and payloads before its path, bytes SHA-256, and Run root digest are bound; and
4. the neutral signal is recomputed as `any(finding.known_surface)` over the verified
   normalizations.

The signal does not read `matchesKnownFinding`, `knownFindingMatched`, benchmark Finding recall,
private Ground Truth, or validation-floor state. Its digest binds the source authority digest,
ordered normalization digests, and the exact Boolean result.

## Graph mapping

The current Graph projection must already contain the exact trusted-core Surface whose target ID,
surface type, locator schema, and locator digest match the typed WEB-002A Surface. WEB-002C does
not discover or admit a Surface and cannot expand Campaign Scope.

The Observation proposal contains exactly:

- one succeeded `Action` with authority kind `sealed-source-authority` and no Capability or Permit
  tuple;
- one fixed `web.protocol-observation` with target-derived origin and confidence `1.0`;
- one internal Evidence node referencing `web-zap-source-measurement-authority.json` by relative
  path and SHA-256; and
- one `produces` and one `supported-by` edge.

When and only when the exact registered-Surface signal is true, a second proposal adds one
agent-derived `web.security-property` Hypothesis with confidence `0.5` and one `enables` edge from
the Observation. Its text states only that separately controlled validation may be warranted; it
does not claim a vulnerability, exploitability, Finding, or negative conclusion.

Both proposals bind the same source authority reference, source Run, source root, Evidence
reference, and request digest. The intermediate verified projection retains only the measured
Surface/type-set references, source-authority reference, root/artifact/time/count coordinates, and
the recomputed signal; it does not expose the full WEB-002A measured case or WEB-002B runtime
authority. The Hypothesis must be admitted immediately after the Observation while that
Observation event remains the Graph head.

## Admission and retry semantics

Candidate preparation verifies the caller-bound Snapshot is the current canonical Graph head and
that the exact Surface is projected. Admission reparses the candidate, rebuilds it from the sealed
source, and rejects any difference before writing.

The first proposal uses `submit_if_current` against the Snapshot event-log head. The optional
Hypothesis uses another compare-and-set against the admitted Observation event. An exact retry
returns the previously admitted events. A reused proposal ID with different material, a stale
head, foreign Campaign, unregistered producer, untrusted lineage, or rejected event fails closed.

Before each first submission, the trusted lineage registry binds the sealed-source lineage to both
the exact canonical Proposal digest and that compare-and-set predecessor head. Reusing the lineage
for changed prose/value material or calling generic `submit` without the registered head is
rejected. If another event wins the head after Observation admission, the neutral Observation
remains append-only, the Hypothesis is not written, and an exact retry remains safely blocked until
a new source-bound candidate is prepared against a current Snapshot.

## Authority boundary

The candidate and admission fix all of the following to false:

- raw SARIF and private Ground Truth disclosure;
- Target/provider runtime identity embedding;
- controlled route use or controlled validation execution;
- validation-floor evaluation or satisfaction;
- Finding projection or confirmation;
- Scope expansion or Surface mutation, Capability activation, approval or Permit authority;
- Tool/Worker selection, credential/network access, Replay, or additional execution; and
- product activation, report delivery, or execution authority.

`sealed-source-authority` is mutually exclusive with CapabilityGrant, ActionPermit, and Capability
identity. It authenticates an already completed source projection only; it is not a substitute for
fresh execution authority.

## Verification

`tests/test_web_source_measurement_admission.py` covers:

- signal and no-signal projection;
- idempotent Observation plus bounded-Hypothesis admission;
- source re-opening after candidate preparation and resealed tamper rejection;
- authority/snapshot read-swap rejection through exact bytes and event-payload comparison;
- candidate identity and signal tampering;
- top-level, nested-model, and dataclass-contained unmodeled-state rejection;
- stale Snapshot rejection;
- exact Proposal/head trust binding, changed-payload direct-submit rejection, and
  Observation-to-Hypothesis head-race handling;
- source-authority and Capability/Permit confusion rejection;
- exact projected-Surface enforcement; and
- absence of raw SARIF, Ground Truth, Finding-match, and runtime-identity keys and sentinel values
  from the candidate, admission, Event Log, and post-admission Snapshot.

Canonical Graph model and admission suites additionally verify that the additive authority path
does not regress existing Capability- or Permit-backed proposals.

## Compatibility and rollback

Legacy Capability/Permit Graph wires and digests remain unchanged. New sealed-source nodes and
events require an upgraded strict reader even though they retain the experimental `v1alpha1`
identifier. After the first such event, do not downgrade the reader in place. A rollback must keep
the upgraded reader or restore a verified Graph Store backup from before that event; canonical
events must not be removed or rewritten. The current cross-domain gate explicitly rejects
sealed-source events because source-authority transfer is false.
