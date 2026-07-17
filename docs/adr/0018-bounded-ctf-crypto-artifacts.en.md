> Languages: [English](0018-bounded-ctf-crypto-artifacts.en.md) | [한국어](0018-bounded-ctf-crypto-artifacts.ko.md)

# ADR 0018: Bounded inline artifacts for CTF Crypto Mode

- Status: Accepted
- Date: 2026-07-13

## Context

The first CTF slice proves one Web Specialist but does not yet prove category-aware routing or an
offline analysis workflow. Pwn, reversing, forensics, and general cryptography usually require
files and broad tools. Adding arbitrary host paths, Worker bind mounts, shell commands, or
unbounded brute force would expand the safety boundary before PAJIN has a trusted artifact service
and per-tool filesystem capabilities.

PAJIN needs a second category that exercises artifact integrity and offline computation without
introducing network access, external processes, or user-selected files.

## Decision

PAJIN adds the `crypto.single-byte-xor` scenario with a bounded inline artifact contract:

- encoding is exactly lowercase hexadecimal;
- decoded size is between one byte and 4 KiB;
- the manifest supplies SHA-256 over the decoded bytes;
- the media type is fixed to `application/octet-stream`;
- scope, host paths, URLs, commands, and executables are forbidden;
- the expected flag remains a separate SHA-256 and never enters the Specialist Tool input.

Manifest validation decodes the artifact and performs a constant-time digest comparison. The
compiler derives `http://artifact.invalid/<challenge>/<artifact-sha256>` as a logical policy target.
This URL is an identity compatible with the current generic scope engine, not a network
destination. The Crypto Tool declares `network_access: false`, the Campaign forbids network access,
and the resulting Docker Worker Job retains `network: none` with no egress policy.

The Triage Planner maps only the typed Crypto category/scenario pair to
`ctf.crypto-single-byte-xor`. The Tool validates POST semantics, the derived content address, size,
hex grammar, and artifact digest before dispatch. It passes only the logical target, challenge and
scenario identity, artifact digest, and ciphertext to the fixed Worker command.

The Worker repeats every validation, then evaluates exactly the finite key space 0 through 255 in
process. It does not call a shell, subprocess, package manager, model, MCP server, or network API.
Only ASCII plaintext matching the complete `PAJIN{...}` grammar is retained. Zero matches produces
an unsolved observation; more than one match fails closed as ambiguous.

The existing Mode-specific digest Validator reparses the observation, verifies the artifact and challenge
identity, requires same-run evidence, and hashes the candidate against the expected digest. The
generic runner still enforces target and evidence binding. `CTFModePack` emits the same result and
write-up schema used by Web, including category-specific route and offline-analysis details, then
appends an integrity extension seal.

`ctf-run` becomes the category-aware CLI. `ctf-web-run` remains available as a Web-only alias and
rejects Crypto manifests before Worker selection. Neither command submits to a scoreboard.

## Consequences

This design proves a second Specialist category, content-addressed artifact validation, offline
Worker isolation, finite computation, independent flag verification, and shared reporting without
granting general filesystem or command execution authority.

Inline hex duplicates the small public challenge artifact in the manifest, Campaign, and Worker
input. It is suitable only for bounded synthetic fixtures, not large binaries or sensitive data.
Future reversing, Pwn, and forensics support should introduce a separately designed immutable
artifact service, media-specific parsers, read-only Worker mounts, decompression limits, and
explicit filesystem capabilities rather than increasing this inline limit.

## Validation

Tests cover Web/Crypto category pairing, digest mismatch and noncanonical hex rejection, derived
artifact identity, T0 and no-egress policy compilation, fixed Tool input, Worker-side digest
verification, complete 256-key evaluation, category-specific Specialist routing, independent
`CTF-CRYPTO` validation, two-seal result finalization, generic CLI routing, and Web-alias rejection.
