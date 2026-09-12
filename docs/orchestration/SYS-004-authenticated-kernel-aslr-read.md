# SYS-004: Authenticated Linux kernel ASLR setting read

Status: Implemented; actual Docker execution and independent verification passed locally.
New remote conformance is pending.

## Exact operation

`system.aslr-read` / `pajin.system.aslr-read` is one experimental, approval-required
System capability. `AslrInput` permits a canonical explicit-port HTTPS
`/v1/aslr` endpoint, an enrolled instance and `linux-aslr-v1`. The deployment
independently pins the CA, server and client certificates, agent/client source,
and immutable Worker/proxy images. There are no caller-selected headers, file
paths, commands, redirects or retries.

The non-root agent opens only `/proc/sys/kernel/randomize_va_space` read-only,
without following a leaf symbolic link. It bounds each read to three bytes and
requires two equal observations of exactly `0\n`, `1\n` or `2\n`. Procfs can
report a zero file size; that is not interpreted as empty content. Missing,
unsupported or changing values fail closed. No kernel setting is changed.

The [Linux kernel sysctl documentation](https://docs.kernel.org/admin-guide/sysctl/kernel.html#randomize-va-space)
defines mode 0 as disabled, mode 1 as address randomization for supported regions,
and mode 2 as also randomizing the heap. The returned `randomizeVaSpace` value
does not prove protection of individual processes or binaries. An owned Linux
container observes its guest kernel, not the identity or configuration of a
physical workstation.

## Authority and result

All CAP-002 roles have a distinct reviewed SYS-004 release. Preparation checks
explicit Campaign/CONNECT/GET Scope and produces unsigned intent. A separate
Ed25519 operator signs exact Campaign, grant, request, capability, code, image,
target and time coordinates. Graph durably consumes the approval and Permit
before ToolGateway dispatch. A one-use 30-second Secret Lease supplies mTLS
credentials to the constrained Docker Worker. The host-owned proxy records the
exact HTTPS CONNECT route; the fixed trusted client enforces method and path.

RunStore retains and seals authorization, detached Gateway/Worker evidence,
exact file bytes, normalized mode and observed cleanup. Product reading checks
independently supplied trust and Run roots, recomputes approval/Policy/Permit,
lease identity, Worker confinement and normalized evidence. A failed or unknown
cleanup is not complete execution. The normalized result includes `aslr`, whose
metadata contains `randomizeVaSpace`, plus exact byte count and SHA-256.
`findingAuthority`, `generalSystemSupport`, `processAslrVerified` and
`physicalHostVerified` are false.

Fresh re-execution requires distinct Run, request, approval, Permit and Worker,
after the source finishes. `aslrMatch` reports equality of the two observations;
a changed setting is not rewritten or silently considered equivalent. Comparison
does not authorize execution or certify remediation.

## Entry points

Use `pajin.system_aslr.runtime.prepare_aslr_action` and `approval_for_review` to
prepare exact reviewable intent. The deployment's separate signer supplies
`SignedAslrApproval`. `dispatch_aslr_action` uses `AslrGateway` after current
authority checks. Product code does not issue its own release or operator
signatures. No target or credentials are discovered automatically.

The product reader requires no private signer, agent credentials or new Worker:

```sh
python -m pajin.system_aslr --root <private-run-root> --trust <independent-trust.json> \
  --trust-digest <independent-commitment> --source-ref <pinned-source-reference.json> \
  --replay-ref <pinned-reexecution-reference.json>
```

The explicit disposable fixture accepts pinned local images and a new output:

```sh
python scripts/operational_system_aslr.py --image-id <observed-aslr-image-id> \
  --proxy-image-id <observed-proxy-image-id> --output <new-private-directory>
```

The Linux arm64 probe passed in 33.29 seconds. Two separately approved successful
reads observed mode 2 and exactly two bytes (`2\n`), agreeing with an independent
GNU coreutils 9.7 `od` observation. A fresh CLI process reconstructed the same
sealed comparison. Certificate, Scope, signature, nonce and path denials passed.
Four Worker lifecycles and both agent containers were independently observed
absent after cleanup. Existing SYS-002 also passed its separate four-Worker probe.
A separately built and installed wheel reconstructed both profiles' results
identically, with all 489 installed Python/type-marker source files matching.

The malformed-value case is explicit test fault injection, not a malformed kernel
observation. The first attempt failed at container startup because runc disallows
mounting a replacement file inside `/proc`. Its retained reproduction confirmed
that boundary. The corrected negative fixture mounts a fixed read-only file
elsewhere and redirects only the fixed open in its test launcher. The unchanged
agent performs real bounded reads and rejects `9\n` with HTTP 422; reuse of that
nonce is rejected with 409, and the governed Worker result stays incomplete.
The fixture records that no kernel value was changed and that this is not positive
execution evidence. Normal reads use the actual kernel file without redirection.
Both attempts and cleanup observations are retained separately; the product
image, permissions and fixed public input were unchanged.

The first attempt of [SYS conformance 34669912227](https://github.com/HYEXE/PAJIN/actions/runs/34669912227)
passed both the original SYS-002 and additional SYS-004 probes at clean commit
`1fd37d16d05887f9ff7956ccea4986b77cd4fe6c` on Ubuntu 24.04, Linux/amd64, Python
3.12.14. Each probe passed one actual test with four Worker lifecycles; the combined
outer runner took 86.51 seconds. The ASLR gate additionally verified the independent
GNU observation and fresh CLI reconstruction. The tracked-source commitment matched
`6326d2448a5a40dbe415e553aca8e2386dd2c15edc6e7635f0c59c8c18f84e4f`.
Cleanup and a separate read-only audit found no owned containers, networks or
volumes, with no fallback removal. The artifacts contain only three bounded public
summary files. These results cover this fixed profile and preserve all limits below.

## Compatibility and validation limits

SYS-002 inputs, source files, receipts, approvals and SYS-003 readers remain
unchanged. SYS-004's distinct signature domain cannot accept an OS-release
approval, and the new parser rejects OS-release source/schema aliases. Shared
execution engines retain their existing public contracts. Profile-specific
composition is versioned separately to preserve signed historical code contexts.

Focused tests cover exact modes, malformed/oversize data, fixed bounded file
access, changes between reads and descriptor closure, certificate/source commitments, wrong schema,
Scope, approval expiry/signature and the old approval domain. Failure reports,
tampering, independent trust and unknown cleanup remain fail-closed.
The fixture exits unsuccessfully if Worker lifecycle evidence is incomplete or resources remain,
even when the inner test process succeeds.

The agent's in-memory nonce ledger does not survive restart. The fixed endpoint
does not grant access to arbitrary host resources, process protection assessment,
physical-host attestation, general System support, Cloud access or a Finding.
This explicit CLI slice does not add a new Console/API endpoint or default
activation path. See [ADR 0288](../adr/0288-isolate-an-approved-kernel-aslr-read-from-os-release-authority.md).
