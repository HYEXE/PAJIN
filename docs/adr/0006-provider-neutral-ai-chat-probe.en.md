> Languages: [English](0006-provider-neutral-ai-chat-probe.en.md) | [한국어](0006-provider-neutral-ai-chat-probe.ko.md)

# ADR-0006: Provider-neutral AI Chat Probe and isolated validation target

- Status: Accepted
- Date: 2026-07-12
- Confirmation semantics amended by: [ADR 0027](0027-independent-reproduction-confirmation-boundary.en.md)

> The Validator described in this document is an evidence-review boundary that independently
> checks the original transcript. Since ADR 0027, product-level Confirmed requires a separate
> Restricted Reproducer, a fresh request and evidence, and a successful Oracle result.

## Context

The first KISA Mode Pack scenario validated the A01 and A02 boundaries with a network-free
`mock-agent`. System prompt leakage (M03), jailbreaks (M06), and memory poisoning (A04) require
observation of actual multi-turn AI responses and session state. Embedding a particular model
provider's SDK or authentication format directly in a Mode Pack would make scenarios, policies,
and evidence provider-dependent, while also increasing the risk that an Agent could construct
arbitrary HTTP headers or execution commands.

Development and regression testing also require an isolated target that can reproduce actual
attack signals deterministically without contacting external services or real user data.

## Decision

### Provider-neutral contract

1. PAJIN defines a fixed Chat API contract that accepts `sessionId`, `messages`, and `metadata`, and
   returns structured assistant message, safety, tool call, and memory write metadata.
2. Only the registered Tool `ai.chat-probe` calls this contract. An Agent cannot provide arbitrary
   commands, headers, URL credentials, or network policies.
3. Probe input is validated against strict types for a scenario ID, a single KISA threat, a session
   ID, at most 20 turns, and at most 20 decision conditions.
4. The Tool Adapter always prepares a network-none Worker Job. Only the Tool Gateway injects egress
   proxy policy from the Campaign Scope and rules of engagement.
5. The Worker limits response size and duration and returns the original request and response,
   decision results, and actual target response latency as structured evidence.

### Independent decision

1. The Worker applies catalog decision conditions to produce observations, but it cannot confirm
   them as final Findings.
2. The Validator compares the plan's original Probe conditions against the ToolResult's actual
   transcript again.
3. Even when `vulnerable=true`, no Finding is created if the response lacks the scenario marker or
   if the scenario, threat, or session does not match.
4. Repeated Findings for the same scenario are merged by the existing KISA deduplication stage,
   while all independent Worker evidence is retained.

### Isolated AI target

1. `pajin-ai-target:dev` is an intentionally vulnerable development target that deterministically
   reproduces M03, M06, and A04 signals.
2. The target runs in a separate container as non-root, with a read-only filesystem, all
   capabilities dropped, no-new-privileges, and CPU, memory, and PID limits.
3. Its port is published only on host loopback. The Worker does not connect directly and uses only
   the Campaign-authorized `host.docker.internal` path through the egress proxy.
4. Each repetition uses a unique session so that memory state cannot leak into another Task.
5. The `hardened` profile blocks all three signals and serves as a baseline for future retesting and
   defensive regression testing.

## Consequences

### Positive

- KISA scenarios remain separate from any particular LLM SDK.
- Actual HTTP, multi-turn behavior, session state, and egress policy are validated in one Docker
  campaign.
- A Tool cannot establish a Finding without a transcript, even if it manipulates the result flag.
- Vulnerable and hardened profiles use the same contract, providing a regression-testing baseline
  before and after remediation.
- Response-latency metrics measure actual target response time rather than Docker and proxy startup
  time.

### Trade-offs and residual risks

- Real provider APIs require separate Adapters to translate authentication, streaming, rate
  limits, and provider-specific tool-call schemas.
- String-marker decisions suit deterministic regression tests but cannot find every semantic
  jailbreak or partial leak. Classifiers, an LLM Judge, and variant datasets must be added.
- The development target is not an actual model and does not represent external-service
  nondeterminism, token costs, or long contexts.
- Because transcripts may contain sensitive responses, production requires Artifact encryption,
  masking, and retention policies.

## Verification

```powershell
docker build --tag pajin-worker:dev containers/worker
docker compose -f containers/compose.ai-lab.yaml up --build --detach
.venv\Scripts\pajin kisa-run examples\kisa-ai-chat-lab.yaml --worker docker --repetitions 2
docker compose -f containers/compose.ai-lab.yaml down
.venv\Scripts\pytest -q
.venv\Scripts\ruff check src tests containers
.venv\Scripts\mypy src
```

The implementation acceptance criteria at the time were six Specialist Tasks across M03, M06, and
A04; 100% requested-threat coverage; three legacy validation Findings; two Docker evidence items
per Finding; an egress proxy allow record for every call; measurement of target response latency;
rejection of a manipulated vulnerability flag; and cleanup of temporary containers and networks
after termination. These three Findings are not product-level Confirmed until the Restricted Replay
introduced by ADR 0027.
