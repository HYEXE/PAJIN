# AI-002B: Registry-Governed Disposable M03 Source Measurement

- Status: implementation and deterministic in-process conformance complete; real-Docker
  conformance not yet established
- Public authority API: `pajin.dev/ai-source-measurement-authority/v1alpha1`
- Public lineage API: `pajin.dev/ai-source-case-lineage/v1alpha1`
- Public denial API: `pajin.dev/ai-source-denial-receipt/v1alpha1`
- Private binding API: `pajin.dev/ai-private-source-measurement-binding/v1alpha1`
- Image binding API: `pajin.dev/ai-source-image-binding/v1alpha1`
- Implementation:
  `src/pajin/workflow/ai_fixture_runtime.py`,
  `src/pajin/workflow/ai_source_measurement.py`,
  `src/pajin/target_attestation.py`, and
  `containers/ai-target/target.py`
- Decision:
  [ADR-0259](../adr/0259-select-governed-measured-ai-system-prompt-disclosure-after-phase-24.md)

## Purpose and exact membership

AI-002B is the source-measurement boundary for the one exact AI-002A registration:
`ai-fixture:m03-system-prompt-disclosure`. It contextfully reopens the neutral public
measured-case authority and the separate deployment-private known-positive Ground Truth before
observing an image or starting a Target. The caller cannot add, remove, reorder, or replace a case,
prompt, response check, mode, route, image, Scope, provider, or action authority.

The existing AI-001A through AI-001D, KISA, REDTEAM, DOMAIN-006, generic Finding benchmark, and
`WalkingBenchmarkRunObservation` contracts remain unchanged. The source result does not
reinterpret an existing Observation or benchmark wire as measured M03 authority.

## Immutable images and disposable Target

AI-002B does not build an image. Before execution, it independently inspects the fixed AI-002A
Target, Worker, and proxy image references and binds their observed `sha256:` OCI image IDs in
canonical Target, Worker, proxy order. Runtime uses the observed immutable IDs while preserving
the existing logical Worker image in Gateway metadata. A changed, foreign, reordered,
noncanonical, or caller-selected image binding fails closed.

Each invocation creates one fresh, code-owned vulnerable Target attempt and one internal Target
network. The provider:

- rejects pre-existing managed residue and exact-name collisions;
- creates an internal network and publishes no host port;
- starts the fixed Target image by observed ID with a read-only root, all capabilities dropped,
  no-new-privileges, bounded process/memory/CPU limits, and user `65532:65532`;
- supplies only the fixed vulnerable mode and an ephemeral receipt-signing identity;
- observes the exact `http://host.docker.internal:8080/v1/chat` private coordinate;
- requires one canonical ready event followed by one Target-signed source receipt; and
- removes the Target and Target network after Worker/proxy cleanup has been independently
  observed.

Failure before lifecycle completion attempts the same bounded cleanup. A completed result requires
both Worker/proxy/internal-network absence and Target/Target-network absence.

## Existing approval, Permit, Gateway, and Worker path

The deployment authorizer must return one fresh normal AI action plan. AI-002B does not mint a
parallel action wire. Before dispatch it reconstructs the existing AI-001B preparation and
requires:

- one exact `ai-chat-api` Target, M03 threat class, empty output request, and fixed budgets;
- the single `POST` private-network Scope for the exact Target coordinate;
- the existing signed Capability activation and `ai.chat-probe@1.0.0` identity;
- one fresh Run, request, Graph decision, external approval, and one-use ActionPermit lineage;
- the exact deployment approval issuer and stable authorizer-context digest;
- the fixed local provider registration with zero provider cost and no materialized credential;
- the immutable observed Worker and proxy image IDs;
- one exact proxy route to the current Target network; and
- the exact host-owned lifecycle observer.

The source challenge is derived only inside the one-use Permit dispatch callback. It binds the
Permit, source request, source operation, exact Target hash, `POST /v1/chat`, compiled argument
digest, ordinal one, and a bounded lifetime. The Worker validates the challenge and exact
single-turn M03 probe, transmits the challenge only in a canonical header, and leaves the existing
request body unchanged.

The Worker remains attached only to a fresh internal proxy network. The proxy alone bridges that
network to the Target network. The host observer binds Worker, proxy, and Target container/image
identities, exact network membership, zero published ports, isolation settings, and cleanup. The
Target signs request and response digests under a deployment-private ephemeral Ed25519 trust
anchor. The private reader binds that receipt to exactly one trusted proxy receipt and raw
transcript, then reopens the sealed source through the existing AI-001C verifier with the exact
source Tool adapter.

## Code-owned pre-dispatch denials

Before the allowed source dispatch, the runner evaluates these eight substitutions in canonical
order without invoking the Gateway or Worker:

1. scenario substitution;
2. prompt substitution;
3. sensitive response-check substitution;
4. Target mode substitution;
5. immutable image substitution;
6. proxy route substitution;
7. Campaign Scope substitution; and
8. deployment authority-context substitution.

The public authority records literal denial, pre-dispatch stage, zero dispatch count, and
content-addressed receipt identity for each case. These are code-owned denial probes required by
the AI-002A policy. They are not the Baseline, Negative, or Counterfactual benchmark Controls and
do not authorize AI-002C.

## Public and private custody

The public `AISourceMeasurementAuthority` contains only:

- AI-002A authority, protocol, private Ground Truth commitment, observed-image binding, and
  deployment authority-context references;
- one public M03 lineage with sealed Run, approval, Permit, execution, Target lifecycle, Target
  receipt, and private-measurement digests;
- the eight public-safe denial receipts; and
- literal source-verification and false downstream-authority markers.

It contains no prompt, response check, transcript, session, raw Worker or Tool result, Target
coordinate, trust anchor, approval body, ActionPermit body, proxy receipt, Docker name, or private
Ground Truth object.

The separate deployment-private binding contains the exact AI-002A Ground Truth, request,
challenge, trust anchor, signed Target receipt, proxy binding, raw Worker and Tool results, typed
M03 output, approval receipt, immutable image binding, topology, and cleanup evidence. It records
exactly one request unit, one Tool call, zero external model-provider cost, no Graph admission, and
no Finding.

The outer Run seals public and private artifacts separately. Contextful reload reparses their
strict canonical JSON, reopens AI-002A, reinspects every image, reopens the sealed AI-001C source,
rebuilds the private measurement and public lineage, and requires zero managed Target residue.

## Authority ceiling

AI-002B observes one completed synthetic source measurement. The consumed action authorizes only
the exact source `POST`; the sealed result grants no authority for:

- image build, caller-selected image/configuration, or another Target or network;
- another provider, approval, ActionPermit, Gateway, Worker, Tool call, or application write;
- Replay, Baseline/Negative/Counterfactual Control execution, floor evaluation, or floor
  satisfaction;
- Graph admission or mutation, Finding authority, product projection, reporting, or delivery;
- credentials, external providers or targets, or production targets;
- arbitrary prompts or Tools, M06, A04, RAG, MCP, plugins, or memory mutation; or
- general model, agent, or AI scanning.

Ground Truth, successful disclosure, a signed Target receipt, or one source measurement does not
confirm a general AI Observation or satisfy the DOMAIN-006 AI floor.

## Verification status

Deterministic tests cover:

- canonical immutable image binding, independent reinspection, digest drift, foreign identity,
  and caller-selected image rejection;
- fresh fixed Target construction, no published ports, proxy-only topology, isolation, signed
  receipt, strict Docker JSON, cleanup, and residue rejection;
- exact scenario, prompt, check, mode, image, route, Scope, and authority denials before dispatch;
- normal approval and one-use Permit dispatch through Gateway and Worker;
- canonical header-only challenge transport, Replay/source challenge separation, and unchanged
  request body;
- Target and proxy receipt correlation with request/response transcript digests;
- exact one-case public/private binding, leakage rejection, order substitution, false authority
  markers, sealing, AI-001C reopen, and zero residue; and
- AI-001A through AI-001D, KISA M03, Target, Worker, and DOMAIN validation regressions.

`tests/test_ai_source_measurement.py` also contains an opt-in real-Docker conformance test. It
requires the three fixed images and `PAJIN_AI_002B_REAL_DOCKER=1`. The current local checkpoint
did not run it because no container daemon was available. In-process evidence is not the Phase 25
exit gate; exact-commit Ubuntu real-Docker source, Replay, Controls, floor, product, and residue
conformance remain AI-002C and AI-002D work.

## Compatibility and rollback

AI-002B is additive. Existing AI-001A through AI-001D, KISA, REDTEAM, DOMAIN-006, Graph, Finding,
Tool request/result, Gateway outcome, Worker result, Replay challenge, and Target response wires
retain their identities and meanings. The source Tool adapter preserves the existing
`ai.chat-probe@1.0.0` identity, injects only Worker-private execution metadata, and is accepted by
the AI-001C reader only through an explicit exact-type override. Existing callers keep the
unchanged default path.

Rollback stops constructing the AI-002B runner and removes the new AI-specific runtime and
authority readers. Previously sealed AI-002B artifacts remain historical private source evidence
and must not be treated as Replay, Control, floor, product, Finding, report, delivery, or further
execution authority.

## Related contracts

- [AI-002A exact M03 measured-case authority](AI-002A-exact-m03-measured-case-authority.md)
- [AI-001B read-only analysis capability](../capability/AI-001B-provider-model-tool-bound-read-only-analysis.md)
- [AI-001C sealed observation admission](../graph/AI-001C-cross-surface-observation-evidence-admission.md)
- [AI-001D fresh-session Replay and Controls](AI-001D-fresh-session-replay-controls-benchmark.md)
- [DOMAIN-006 domain-aware benchmark registry](DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
