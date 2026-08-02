# ENG-002A: Common Engine Implementation Adapter and Structural Parity

- Status: Implemented
- Contract versions:
  - `pajin.dev/common-engine-implementation/v1alpha1`
  - `pajin.dev/common-engine-mode-adapter/v1alpha1`
  - `pajin.dev/common-engine-adapter-catalog/v1alpha1`
  - `pajin.dev/common-engine-structural-parity/v1alpha1`
  - `pajin.dev/common-engine-adapter-selection/v1alpha1`
- Decision: [ADR-0104](../adr/0104-register-implementation-identity-before-runtime-parity.md)

## Scope

ENG-002A binds each PROF-002 compilation to the exact existing Planner and Validator class
identities plus the shared `MultiAgentCampaignRunner`, scheduler, and projector identities. It
selects metadata only. It does not construct a runtime, Tool Registry, Policy, Worker, output path,
`MissionEnvelope`, or execute a Campaign.

The code-owned Mode-specific identities are:

| Mode | Planner | Validator | Candidate producer |
| --- | --- | --- | --- |
| `ai-redteam` | `KISAPlannerRuntime` | `KISAValidatorRuntime` | `KISACandidateProducer` |
| `bug-bounty` | `BugBountyPlannerRuntime` | `BugBountyValidatorRuntime` | none |
| `ctf` | `CTFTriagePlannerRuntime` | `CTFFlagValidatorRuntime` | none |

All three adapters bind these exact shared identities:

- `pajin.workflow.multi_agent.MultiAgentCampaignRunner`;
- `pajin.workflow.multi_agent_execution.MultiAgentExecutionScheduler`; and
- `pajin.workflow.multi_agent_projection.MultiAgentResultProjector`.

Implementation identity is a code-owned module-qualified class contract, not a source-tree hash,
package signature, constructor configuration, or runtime attestation.

## Adapter catalog and selection

Each `RegisteredCommonEngineImplementation` binds role, module-qualified class identity, contract
version, `constructionAuthorized=false`, and a content digest. A `CommonEngineModeAdapter` binds the
exact PROF-001 Profile and complete Mode-specific/shared implementation set. Tool Registry, Policy,
Worker, output path, runtime construction, and Common execution flags remain false.

`CommonEngineAdapterCatalog` binds the complete ENG-001 contract, PROF-002 compiler, and canonical
three-adapter set. Only metadata selection is allowed. `select_common_engine_adapter()` revalidates
the complete PROF-002 authority before selecting the matching Mode/Profile adapter.

There is no pentest legacy adapter because PROF-002 has no pentest mapping.

## Structural parity authority

Selection records all four ADR-0046 parity dimensions with identity evidence:

| Dimension | Structural basis | Evidence |
| --- | --- | --- |
| `scope` | same Campaign input identity | PROF-002 input digest |
| `capability` | same shared runner/scheduler identity | implementation digests |
| `tool-request` | exact legacy Planner identity | implementation digest |
| `outcome` | exact Validator/projector identity | implementation digests, plus AI candidate producer |

Every dimension has `fixtureMeasured=false` and `parityProven=false`. The selection records
`allRequiredDimensionsPresent=true` only to prove schema completeness; it explicitly keeps
`fixtureParityProven=false`. Structural identity is not behavioral parity.

## Unbound runtime inputs

ENG-002A does not bind:

- Planner or Validator constructor configuration, including KISA repetition thresholds;
- Tool Registry contents or Capability grants;
- Policy configuration, Worker backend, secrets, output path, or execution context;
- generated ToolRequests, Worker receipts, Findings, validation projections, or report bytes; or
- Mode-specific post-processing such as Bug Hunt triage drafts or CTF result/writeup artifacts.

ENG-002B must run identical fixtures through separately identified legacy and opt-in adapter paths
and compare these values before any Common execution eligibility can change.

## Negative cases

Validation rejects:

- cross-Mode Planner, Validator, candidate producer, or Profile substitution;
- runner, scheduler, projector, implementation, adapter, catalog, or compilation digest drift;
- missing, duplicated, reordered, or changed parity dimensions/evidence;
- any claim that structural evidence was measured or proved parity;
- runtime, Tool, Policy, Worker, output-path, Envelope, or execution authority escalation; and
- a pentest adapter introduced through legacy selection.

## Compatibility, migration, and rollback

The registry and selection APIs are additive and direct-call opt-in. Existing CLI/API runtime
construction, Campaign bytes, Mode behavior, artifacts, and readers are unchanged. Rollback removes
the additive metadata contracts and leaves the legacy paths intact. Previously serialized
selection records remain non-executable and cannot be treated as fixture parity evidence.
