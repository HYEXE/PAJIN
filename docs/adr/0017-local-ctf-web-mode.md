# ADR 0017: Local-only CTF Web Mode vertical slice

- Status: Accepted
- Date: 2026-07-13

## Context

PAJIN's product plan calls for category-specific CTF agents, flag verification, and write-up
generation. A general CTF agent with arbitrary shell, crawler, browser, or exploit authority would
not yet have an adequate safety boundary: a challenge manifest could redirect it to a public or
unrelated private target, and an agent-generated path or payload could expand a small exercise into
open-ended scanning.

The first slice must demonstrate the complete multi-agent and evidence architecture while keeping
the target, request grammar, network authority, and success condition finite and testable.

## Decision

PAJIN adds a `CTFChallenge` manifest and supports one category/scenario pair:

- category: `web`;
- scenario: `web.exposed-backup-config`;
- environment: `local-docker`;
- entry point: `http://host.docker.internal:8780/backup/config.json.bak`;
- expected result: lowercase SHA-256 plus the public `PAJIN{...}` format, never expected plaintext.

The schema rejects unknown fields and any other host, port, path, scheme, query, environment,
category, or scenario. It fixes the budget at five agents, depth one, one Tool call, zero model calls,
zero provider cost, and at most 120 seconds. The manifest cannot provide an image, executable,
command, request path, or scoreboard credential.

`CTFChallengeService` compiles this contract into a generic `Campaign` with L4 lab autonomy, exact
URL scope, GET-only rules, a T1 ceiling, private-network egress, and a category allowlist matching
the single Tool. The flag digest is carried in sealed Campaign metadata for the Validator but is
not included in the Specialist Tool input.

`CTFTriagePlannerRuntime` maps the typed Web scenario to one `ctf.web-backup-probe` step. The Tool
and trusted Worker independently recheck the fixed authority and path before the Gateway-created
egress proxy can dispatch a request. The Worker accepts only a bounded JSON response marked
synthetic and returns at most one format-constrained candidate.

`CTFFlagValidatorRuntime` reparses the observation, verifies target and challenge identity,
requires same-run Specialist evidence, hashes the candidate, and performs a constant-time digest
comparison. It ignores any untrusted solved claim. A digest match becomes a validated `CTF-WEB`
result, after which the generic runner still enforces declared-target and evidence binding.

`CTFModePack` verifies the core Run integrity root, checks the sealed Campaign against the original
challenge, classifies the outcome as `solved`, `unsolved`, or `invalid-flag`, writes
`ctf-result.json` and `ctf-writeup.md`, records that external submission was not performed, and
appends an extension seal. `ctf-web-run` always selects the Docker Worker and exits non-zero unless
the flag is independently verified.

The target container binds to host loopback port 8780, runs non-root with a read-only filesystem,
drops all capabilities, and contains only a public synthetic flag. Its hardened profile returns
404 for the same backup path.

## Consequences

This slice proves typed CTF ingestion, category routing, bounded Specialist authority, independent
flag verification, vulnerable/hardened behavior, evidence provenance, write-up generation, and
integrity-chain extension through one real HTTP request.

It is not a crawler, general Web CTF solver, browser agent, scoreboard client, public-target scanner,
or arbitrary exploit runner. It does not support Pwn, reversing, forensics, cryptography, OSINT, or
user-supplied tools. Each additional category or scenario requires a new typed contract, fixed or
formally bounded Tool grammar, request-cost declaration, isolated fixture, independent verification
logic, and explicit safety review.

## Validation

Tests cover exact local scope compilation, external and wrong-path rejection, budget and plaintext
flag rejection, inactive authorization, fixed Tool and Worker requests, vulnerable and hardened
target behavior, correct/absent/incorrect candidate classification, five-role execution, two-seal
evidence integrity, Docker-only CLI selection, and the absence of an external submission action.
