# ADR-0200: Require Externally Signed Ordered Worker Stage Activation

## Status

Accepted

## Context

PENTEST-004B can execute one approved Recon or Control and PENTEST-004C2A can execute one fresh
Replay. A Replay deployment cannot be fixed before its source is sealed and admitted because its
authority binds that source, the resulting Discovery admission, and a current Graph Decision.
Likewise, one Operator call cannot impersonate five independent direct-mTLS Worker sessions.

A coordinator that generated the next Graph Decision, approval, child deployment, or Worker
identity would silently become an action authority. A coordinator that only remembered process
state would lose its order and retry boundary after restart.

## Decision

Implement PENTEST-004C2B1 as a five-stage durable journal with the exact order `source`, `replay`,
`control-baseline`, `control-negative`, and `control-counterfactual`.

Each stage requires an Ed25519 statement issued by a deployment-pinned external authority after the
previous receipt exists. The statement binds the coordination deployment and Run, exact ordinal,
previous receipt digest, child deployment identity and digest, and one Worker subject. It explicitly
cannot issue action authority or impersonate a Worker.

The generic Recon/Control route and dedicated Replay route remain separate. The authenticated live
Worker subject must equal the signed subject and every stage must use a distinct Worker, child
deployment, and Run. Before calling a child adapter, the coordinator appends and seals a
`stage-started` event. After the child returns terminal sealed evidence, it records a body-free
content-addressed receipt and another seal.

If the process stops after the child seal but before the receipt, retry uses the same activation and
the child adapter's reconcile-only operation. Once an activation expires, dispatch is forbidden;
reconciliation is allowed only when the matching sealed `stage-started` event already exists and the
adapter can reopen terminal child evidence without another call.

After all five receipts exist, the coordinator reconstructs and freshly loads the body-free Replay
comparison and complete PENTEST-004C1 deployment. Only then does it publish
`workflowPreparationEligible=true`. The handoff grants no execution or Finding authority.

## Consequences

- Stage authority may be issued sequentially without trusting request possession or coordinator
  identity.
- A restart can distinguish a never-started expired activation from a started child that is safe to
  reconcile.
- Exact Worker, deployment, Run, predecessor, Control role, Replay target, and comparison drift fail
  closed before 004C1 eligibility.
- The current slice defines the durable runtime and injectable Worker routes. A concrete deployment
  registry and adapters that load 004B/004C2A child deployments remain PENTEST-004C2B2.

## Rejected alternatives

### Pin all five child deployments at coordinator startup

Rejected because Replay and later current-Graph authority depend on sealed source state that does not
exist yet.

### Let the coordinator issue the next approval or Graph Decision

Rejected because execution orchestration would become planning and action authority.

### Retry an expired activation through the ordinary dispatch adapter

Rejected because the coordinator could not prove that the child had already crossed its one-use
boundary. Expired activations are reconcile-only and require a sealed start record.

## Compatibility and rollback

The schemas and two Worker routes are additive and remain closed with no injected coordination
runtime. Removing the optional runtime leaves PENTEST-004B, PENTEST-004C2A, and PENTEST-004C1
unchanged. Existing sealed child Runs and coordination receipts remain independently verifiable.

## Related documents

- [PENTEST-004C2B1 contract](../orchestration/PENTEST-004C2B1-durable-worker-coordination.md)
- [PENTEST-004C2A contract](../orchestration/PENTEST-004C2A-dedicated-replay-worker-entrypoint.md)
- [PENTEST-004C1 contract](../orchestration/PENTEST-004C1-resumable-evidence-workflow.md)
