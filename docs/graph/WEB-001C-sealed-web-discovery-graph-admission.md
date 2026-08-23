# WEB-001C: Sealed Web Discovery Graph Admission

- Status: Implemented, bounded knowledge admission only
- API versions:
  - `pajin.dev/web-discovery-observation-candidate/v1alpha1`
  - `pajin.dev/web-discovery-admission/v1alpha1`
- Authority: `src/pajin/workflow/web_discovery_admission.py`
- Reused writer: PENTEST-002A `PentestReconDiscoveryAdmissionGate`
- Decision: [ADR-0214](../adr/0214-compose-web-knowledge-through-existing-graph-writer.md)

## Purpose

WEB-001C binds the exact WEB-001B concrete GET preparation to the already approved, executed, and
sealed Pentest Recon source. It reuses PENTEST-002A to independently reopen the sealed Run, verify
the request reservation, execution Evidence, normalized outcome, ActionPermit, approval receipt,
Worker admission, trusted HTTP receipt, and successful Oracle before proposing Graph knowledge.

The resulting Web proof is a content-addressed classification and lineage artifact. It is not a
second Graph producer or writer, and Security Domain metadata does not authorize admission.

## Exact composition

`WebDiscoverySourceInputs` carries only:

- one canonical `WebReadOnlyDiscoveryPreparation`; and
- one exact `PentestReconDiscoverySourceInputs` for the same prepared action.

The gate requires the WEB-001A locator to be a concrete GET endpoint. The complete
`PreparedCapabilityAction`, release, request ID, agent ID, Tool, method, target, and empty arguments
must equal the sealed Pentest dispatch intent. A related URL, another preparation, or a
URI-template Surface is not accepted.

## Sealed Observation and Evidence boundary

PENTEST-002A remains the source verification authority. It opens the sealed Run through the
verified Run loader and reconstructs one neutral `pentest-http-response-observed` Observation from
trusted normalized response metadata. The proposal binds three content-addressed Evidence nodes:

1. the one-use request reservation;
2. the trusted execution Evidence; and
3. the normalized Gateway outcome.

WEB-001C records the DOMAIN-002 `web.protocol-observation` semantic classification alongside the
actual Pentest Observation type. This classification does not rewrite the existing Graph node or
transfer authority from the Domain type-set. The Web candidate is content-addressed but is not a
separate sealed Run artifact; `sealedSourceVerified=true` and `evidenceSealed=true` mean that its
underlying execution source and referenced Evidence were reopened and verified as sealed.

## Existing Graph single writer

WEB-001C delegates admission to the exact existing PENTEST-002A gate, which in turn uses
`GraphAdmissionAuthority.submit_if_current`. No Web-specific ledger or writer is created. The
admitted event contains exactly:

- one succeeded `Action` backed by the already consumed ActionPermit;
- one neutral `Observation`;
- three `Evidence` nodes;
- one `produces` edge; and
- three `supported-by` edges.

It contains no `Surface`, `Hypothesis`, `CampaignFact`, or Finding. The WEB-001A typed Surface stays
an exact reference whose knowledge state is `registered-not-authorized`; admission does not turn
that reference into Scope or executable authority. Exact retries return the existing semantic
attempt and do not repeat the HTTP request.

## Fail-closed cases

Validation rejects:

- an unsealed, changed, unsuccessful, foreign, or incomplete Pentest source;
- WEB-001B preparation and sealed dispatch-intent mismatch;
- Surface, locator, Domain type-set, semantic type, release, request, Tool, target, or Evidence
  substitution;
- candidate or Graph admission identity/digest drift;
- stale Graph state before first admission;
- any node or relation outside the bounded neutral PENTEST-002A proposal; and
- authority-marker escalation or permissive boolean coercion.

## Explicit non-authority

The candidate and admission proof grant no Scope expansion, Capability activation, approval
authority, Permit issuance, Worker selection, new network access, execution, Replay, Finding
confirmation, or source-authority transfer. The prior approved action remains provenance only.
Worker-reported success without the sealed Run, trusted receipt, and successful Oracle is rejected.

WEB-001D separately owns independently authorized Replay and Web/API benchmark Ground Truth.
WEB-001C does not implement a bounded Web Hypothesis, validation floor, Finding, scanner, arbitrary
target support, active probing, or mutation.

## Compatibility and rollback

The implementation is additive. It does not change Campaign Profile, Security Domain, WEB-001A,
WEB-001B, CAP-002, ToolRequest, ActionPermit, Gateway, Worker, PENTEST-002A, Canonical Graph, Event
Log, Observation, or Evidence wire identities. Consumers import the specialized
`pajin.workflow.web_discovery_admission` module explicitly to avoid changing eager workflow import
order.

Rollback removes the additive module, tests, contract, and ADR. Existing Runs and Graph events
remain valid and require no migration.

## Verification

`tests/test_pentest_recon_dispatch.py` covers exact WEB-001B-to-sealed-intent binding, sealed source
verification, neutral Graph admission, idempotent retry, Web/source Observation type binding,
unsealed and foreign preparation rejection, candidate drift, authority escalation, boolean
coercion, and no-Finding state. Existing PENTEST-002A tests cover sealed artifact mutation,
unsuccessful Oracle, stale Snapshot, Graph candidate drift, and source authority boundaries.
