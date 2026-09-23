# WEB-008: Receipt-Bound Advisory Topology

- Status: first non-executing planning boundary implemented; governed action integration pending
- Version: `pajin.dev/governed-web-advisory-topology/v1alpha2`
- Scope: exact installed local Juice Shop adapter and one admitted hosted reconnaissance turn

## Purpose and inputs

The first WEB-008 artifact records how a verified WEB-007 advisory would relate to a future
governed Web Campaign. It is a candidate, not a Campaign plan or execution authorization.

`build_governed_web_advisory_topology` requires:

1. A strictly reloadable authenticated discovery Run and independent Run ID/root digest.
2. A `CodexReconCompilationResult`, the private terminal journal, attempt ID, independent
   receipt digest, and independent compiled proposal digest. The builder re-verifies the hosted
   event stream, admitted draft, local translation, and compiled proposal through the bridge.
3. Independent installed profile, diagnostic catalog, and bundle digests. The builder resolves
   the current code-owned profile and catalog again before admitting the artifact.

The topology digest covers the source, bridge, receipt, proposal, installed profile, diagnostic
catalog, bundle, fixed diagnostic and attack-path order, and two distinct future stage slots.
Each source/validation slot shares the candidate plan digest but has a different slot digest.
Both slots say `planned-no-dispatch`; all approval, Permit, target request, execution, Finding,
Graph, and report authority markers are literal `false`.

## Ordering and execution boundary

The model can rank the three closed diagnostics for analyst attention. That rank never schedules
an action. The candidate records the installed code order `sql-login`, `object-access`, `dom-xss`
and the two code-owned attack-path shapes. This preserves the WEB-005/v1alpha1 execution baseline
without treating the model as a scheduler. Discovered routes and forms do not expand Campaign
Scope or become Tool arguments.

The current governed parent still uses its v1alpha1 stage sequence and creates both action
intents during provisioning. Its Tool arguments and Worker job do not bind the candidate plan
digest. Therefore this artifact cannot be passed to the current parent to claim WEB-008
execution. A later additive parent and action contract must carry the exact plan through
discovery, model evidence, proposal verification, source decision/approval/Permit/Gateway/Worker,
sealed source outcome, and a separately authorized validation chain. Historical parent readers
must continue to reload their unchanged v1alpha1 artifacts.

WEB-009 subset selection, dependency closure, and replanning are separate successor contracts;
this version always records all three diagnostics and both path shapes. WEB-010 canonical report,
SARIF, and PoC admission likewise remain tied to independently verified outcomes, not this plan.

## Local verification checkpoint

The approved, already completed Luna attempt was reloaded locally with its terminal receipt and
the sealed WEB-007 discovery. The bridge produced proposal digest
`f1f611be1e11178fa0c3c10fecec8a39e537419e02280dd4708415a53bce20f9` and bridge digest
`93d9e9e751bddb7a7d1997e73f6eca4e3ca8d55ab4fac2dcf02d83036e265ca3`. Revalidation
produced candidate topology digest
`034f8d2c802b9884baea00ae77edbaed7223249442c3b0daa611651f602cbfc9` and plan digest
`1c77d07b16f947242269fe325a170e135585817aca5bc66d656a831615efee04`. The local
artifacts are retained in ignored owner-only storage. No new model invocation, target request,
approval, Permit, or Gateway dispatch occurred for this checkpoint.

Focused tests check rank independence, distinct slots, foreign source/receipt/profile/catalog
pins, forged bridge lineage, and rejected authority claims. These tests and the local reload
establish the candidate boundary, not an executable WEB-008 Campaign.

## Decisions

- [ADR-0327](../adr/0327-bind-hosted-recon-to-local-proposal-and-inert-topology.md)
- [ADR-0325](../adr/0325-track-reconnaissance-coverage-without-diagnostic-order.md)
