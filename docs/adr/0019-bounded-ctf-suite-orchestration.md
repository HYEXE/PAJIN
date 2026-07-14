# ADR 0019: Bounded CTF Suite orchestration

- Status: Accepted
- Date: 2026-07-13

## Context

The Web and Crypto CTF Mode Packs can each run one five-role Campaign. Running them separately does
not demonstrate category-aware dynamic Specialist creation inside a single Campaign, and it leaves
operators to correlate two evidence roots manually. A Suite must preserve the stronger boundaries
of each member rather than turn two typed challenges into an open-ended target list.

## Decision

PAJIN adds `ctf-suite-run` for exactly two `CTFChallenge` manifests: one
`web.exposed-backup-config` member and one `crypto.single-byte-xor` member. Challenge IDs must be
unique and both manifests must name the same approving authority. Their authorization windows must
overlap; the Suite authorization starts at the later approval time and expires at the earlier
expiry time. A canonical digest in the Suite authorization evidence binds member identity,
category, complete member authorization, and expected flag digest.

The compiler orders targets as Web then Crypto for reproducibility and derives these fixed budgets:

- six agents: Supervisor, Planner, two Specialists, Validator, and Reporter;
- spawn depth one;
- two Tool calls and zero model-provider calls;
- zero external-service cost;
- duration equal to the two already bounded member durations.

Campaign-level scope, allowed methods, Tool categories, prohibitions, and stop conditions are the
union required by the two member profiles. The maximum risk tier is T1 because the Web probe is T1,
and the Web request ceiling remains the Campaign ceiling. This union does not grant either
Specialist the other member's authority: the deterministic plan creates one step per target, and
the orchestrator delegates a separate Capability Grant containing only that step's Tool and target.
The Crypto Worker still receives `NetworkMode.NONE`; the Web Worker receives only the fixed egress
policy for the loopback-bound fixture.

The multi-agent runner's call-budget allocator reserves one first attempt for each Specialist before
assigning retry slots. The Suite's exact two-call root budget therefore assigns one call to Web and
one to Crypto. Both fixed Tools declare the separate `parallelSafe` contract, so the local scheduler
runs them in one bounded wave while preserving plan-ordered results. Neither member receives a retry
slot that it could consume before the other starts.

Finalization first verifies the core Run seal and reconstructs the exact Suite Campaign from the
original typed manifests. It then binds each Tool result to its plan request, target, category Tool,
same-run evidence, and Mode-specific digest-verified solve observation. Each member is classified independently as
`solved`, `unsolved`, or `invalid-flag`. The aggregate `ctf-suite-result.json` and
`ctf-suite-writeup.md` are appended before a second seal. There is no credential, client, or route
for scoreboard submission.

## Consequences

One Campaign now demonstrates category-aware Specialist spawning and produces one verifiable Suite
evidence chain. Reversing CLI manifest order does not change the compiled contract. Approval
mismatch, non-overlapping windows, duplicate identities, duplicate categories, campaign drift,
missing validation, or unexplained findings fail closed.

The MVP is intentionally not a general CTF playlist. Adding a third member, repeated categories,
distributed scheduling, new challenge types, external artifacts, or scoreboard integration requires
a separate decision and additional policy contracts.
