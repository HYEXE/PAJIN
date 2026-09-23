# ADR-0324: Route Hosted Codex Advisory Work by Assessment Stage

- Status: Accepted
- Date: 2026-09-23
- Scope: successor model routing for PAJIN advisory analysis
- Implementation status: code-owned routing, target-neutral recon projection, strict inert draft
  parser, one-shot Luna CLI adapter with private terminal receipts, and closed Sol input contracts;
  one separately approved PAJIN recon turn completed, no Sol dispatcher

## Context

The local WEB-007 Qwen3 4B Q8 compact attempt consumed one authorized dispatch but produced no
response evidence before its outer Worker deadline. That terminal attempt cannot be replayed.
Changing the model name in its registration would also invalidate its local-model Capacity proof,
materialization attestation, signed authorization, Provider route, transport Pin, receipt, and
strict loader.

The operator wants more reconnaissance work under the Codex subscription allowance while reserving
a stronger model for penetration and vulnerability analysis and report drafting. Codex supports
programmatic local agents through the [SDK](https://learn.chatgpt.com/docs/codex-sdk) and
[`codex exec`](https://learn.chatgpt.com/docs/non-interactive-mode). ChatGPT sign-in uses the
subscription allowance; API-key sign-in uses separately billed API usage, as described in
[Codex authentication](https://learn.chatgpt.com/docs/auth). This agent interface is not the
single no-tool Chat Completions request used by the current PAJIN Provider contract.

## Decision

### Route advisory roles explicitly

The successor routing policy selects `gpt-6-luna` for bounded reconnaissance interpretation,
surface grouping, and hypothesis prioritization. It selects `gpt-6-sol` for penetration-plan
review, vulnerability analysis, and report-narrative drafting. The model choice is code-owned and
fixed by the typed stage; a model response or target observation cannot select or escalate its own
route. Reconnaissance has priority in the capacity plan, but neither route gains target execution
or Finding authority.

Use the same PAJIN task-level input and output token ceilings for both routes when an adapter can
enforce them before dispatch. The Codex client adds its own instructions and may make multiple
model calls in an agent turn. Its reported `turn.completed.usage` is an observed total, not a
pre-dispatch hard ceiling. Until a versioned adapter proves a conservative upper-bound reservation
and a hard per-turn stop, an equal token ceiling is a planning target and unattended dispatch stays
disabled. Lower model credit rates can make more reconnaissance possible, but neither a fixed
20-fold task count nor equal context windows are asserted by this decision. See
[Codex pricing](https://learn.chatgpt.com/docs/pricing) and
[model availability](https://learn.chatgpt.com/docs/models).

### Keep the hosted agent outside existing Provider and target authority

Introduce a new versioned hosted-advisory path. Do not substitute Codex for the pinned Qwen model,
OpenAI-compatible Provider registration, local no-egress Worker, or any historical WEB-007
authorization or Run. Codex subscription credentials are never converted to a Platform API key,
sent to a PAJIN Worker, copied into a Run, or used to call undocumented ChatGPT endpoints. An
API-key fallback is forbidden unless separately selected and budgeted by the operator.

The first Codex-visible input must be an exact, strictly reloaded, target-neutral projection with
credentials, cookies, request/response bodies, routes, locators, local paths, and raw target text
removed. A later Sol-specific input needs its own schema and independent redaction review.
Transmitting either input to the hosted Codex service is a new destination-bound action and
requires a separate explicit authorization identifying the exact projection and model route.
This ADR does not authorize that transmission.

The Codex process must be a trusted local, ephemeral client. Its stage-specific configuration must
disable shell, web search, connectors, plugins, and approval escalation. On the current macOS client,
the outer Seatbelt profile denies reads and writes under the operator home except a disposable
runtime root, literal ancestor directories needed for path traversal, and read-only access to the
ChatGPT sign-in file. The client retains access to operating-system/runtime files and its normal
connection to the Codex service. No target network tool is enabled. Before any data-bearing
invocation, conformance must show that the installed client honors these restrictions; a prompt
that asks the agent not to use tools is insufficient. A tool event or missing isolation evidence
fails the advisory attempt closed.

Each dispatch needs a fresh durable attempt identity, exact source/projection and client/model
coordinates, reserved budget, observed usage, bounded output, terminal receipt, cleanup evidence,
and no automatic redispatch after uncertainty. A registered operator authorization binds the exact
source Run/root, projection, prompt bytes, destination, client Pin, model, expiry, and one attempt.
Parse output through a strict stage-specific schema.
The output is an untrusted proposal or narrative draft. Reconnaissance and model analysis cannot
expand Campaign Scope, create a Capability or Permit, direct a Gateway/Worker, confirm a Finding,
write Graph state, publish a report, or send material to another destination. Offensive actions
remain behind the existing independent policy, approval, Permit, Gateway, Worker, and replay chain;
the canonical report remains PAJIN-authored.

## Compatibility and rollout

Historical Qwen code, signed bundles, Runs, and audit artifacts retain their exact meaning. The
hosted successor uses new schema, digest, authorization, and receipt domains; there is no in-place
migration or implicit fallback. Rollout order is: code-owned route and data projection; no-tool
client isolation conformance; budget and terminal-attempt journal; strict draft admission;
destination-bound authorization; then one separately approved data-bearing call. The Sol route
follows only after its own projection and report-data review. Rollback disables new hosted calls
and leaves existing local and hosted audit artifacts immutable.

## Verification status

The published Codex SDK, authentication, non-interactive, model, and pricing documentation supports
the selected subscription client path. The fixed route and adversarial tests retain false execution,
Finding, and publication authority. The strict sealed-source reload reproduced the saved 2,710-byte
recon projection and a 3,235-byte exact prompt. A temporary, SHA-256-pinned `codex-cli 0.156.1`
executed one synthetic Luna projection through the new adapter. Its Seatbelt probe admitted the
disposable input file and denied a sibling file; the completed JSONL contained no tool event,
reported 9,696 observed tokens, passed the exact draft parser, retained bounded event/stderr bytes
and a digest-bound terminal receipt, and cleaned the disposable runtime root. An explicit synthetic
tool-read probe failed with Code Mode disabled and exposed no sentinel. The first synthetic
structured-output schema was rejected by the service; a compatible schema succeeded in a later
independent synthetic attempt.

After separate operator approval of the exact 3,235-byte prompt hash, destination, and Luna route,
one PAJIN projection was sent through the same isolated client. The terminal receipt is `succeeded`:
the strictly admitted output ranked `sql-login`, `object-access`, then `dom-xss` and marked both
closed paths `investigate`. The completed JSONL had no tool event; observed usage was 9,513 input
and 957 output tokens (10,470 total), with no cached input. The receipt and bounded event/stderr
streams were durably stored in the private journal, reloaded against each other, and the disposable
client root was removed. This demonstrates a completed hosted advisory turn, not target execution,
the usefulness of its ranking, a confirmed vulnerability, or a PAJIN report. The admitted draft
also produced a closed, local Sol penetration-review input without invoking Sol.

The fixed-path private SQLite journal reserves planned usage before dispatch, atomically retains a terminal receipt
with event/stderr streams, forbids a second non-cancelled attempt for the same stage/input, and
charges observed usage. Unknown usage blocks later turns; an observed overrun blocks the next
reservation. A strict local reload reconciles the receipt against the retained streams and
journal state, including the admitted success events and token fields. This remains a soft
next-turn limiter, not a hard per-turn cap or tamper-resistant
allowance ledger. The Sol penetration input revalidates the closed Luna draft; vulnerability and
report inputs require a strictly reloaded completed campaign and export only opaque Finding refs,
severity, and CWE. The historical WEB-005 sample currently fails its pre-existing strict loader at
a WEB-004 Run-reference digest check, so no real verified Sol input was materialized. Sol dispatch,
Sol draft admission, useful model-quality evidence, approval for another hosted transfer,
and compatibility with the historical WEB-007 Provider remain unverified. The one approved
PAJIN transfer is consumed and its projection cannot be redispatched.

## Related decisions

- [ADR-0009](0009-provider-backed-agent-runtime.md): existing policy-bound Provider roles
- [ADR-0301](0301-bind-llm-web-analysis-to-inert-typed-proposals.md): local-only WEB-007 v1alpha1
- [ADR-0323](0323-bind-compact-live-operation-to-effective-pins-and-separated-issuance.md):
  historical compact local-model authorization and operator approval boundary

## 2026-09-23 verification addendum

After the WEB-006 full governed local Run and independent strict reload, the Sol vulnerability-analysis
and report-draft input builders each projected three independently verified Finding signals from the
new completed Campaign. Their respective input digests are
`70fb4989b66c391ae144f8b36cf5cc3d5902faa4119c1562e8eafe2088fc0d20` and
`5f82e1b49acb675842968be19096ac2719dffdcd9a4029e31103a7577b762f01`. The exact JSON inputs
were stored locally in owner-only, untracked files and contain no target URL, Run ID, raw Evidence,
credentials, or source anchor. This supersedes the earlier lack of a materialized Sol verified input
for the new WEB-006 Run; it does not repair the historical WEB-005 reader mismatch. No Sol invocation,
draft admission, report authority, or hosted transfer was performed.

## 2026-09-23 reader and bridge addendum

The historical WEB-005 completed Campaign now strictly reloads after a narrow legacy Run-reference
reader fix. The original sealed bytes and current WEB-006 wire were not changed. The previously
approved Luna terminal attempt was also locally revalidated from its retained receipt and event
stream, then compiled through the existing proposal authority. Its bridge and WEB-008 candidate
topology are governed by [ADR-0327](0327-bind-hosted-recon-to-local-proposal-and-inert-topology.md).
This adds no new hosted transfer or target authorization.

## 2026-09-23 report-preview addendum

The Sol `report-draft` input now has a local strict JSON admission and an escaped, explicitly
untrusted Markdown preview bound to a reloaded completed Campaign and an independent input digest.
Only synthetic draft content was admitted. No Sol response, model-origin receipt, canonical report
mutation, SARIF/PoC mutation, or external delivery is claimed. The limited output contract is
[WEB-010](../orchestration/WEB-010-sol-report-draft-preview.md).
