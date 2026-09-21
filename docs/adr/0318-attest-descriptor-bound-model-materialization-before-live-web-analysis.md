# ADR-0318: Attest Descriptor-bound Model Materialization before Live Web Analysis

- Status: Accepted
- Date: 2026-09-21
- Scope: WEB-007 compact Capacity v2 and proof-bound zero-dispatch live preparation
- Implementation status: Capacity v2 and live preparation implemented, exercised, sealed, and
  strict-reloaded; no model completion, Provider dispatch, target request, or downstream authority
  was authorized or performed

## Context

[ADR-0317](0317-prove-compact-skill-bound-web-analysis-capacity-before-model-dispatch.md) proved that
the compact `system` plus `user` request fits the pinned tokenizer context without invoking model
inference. A later security review identified two prerequisites before that proof could guard a live
successor: the output root had to remain the same filesystem object throughout production, and the
model bytes observed by Docker had to be bound to the registered model Pin rather than to a mutable
host pathname.

Holding the output-root descriptor closed the first issue. Capacity v2 closes the second issue by
opening the model with `O_NOFOLLOW`, holding that descriptor while Docker copies its bytes into an
owned volume, and observing the staged and read-only mounted identities inside the pinned image.

The first full Capacity v2 attempt, partial Run `run_20260921T045515Z_314d9364`, copied all
4,280,403,520 bytes, then failed closed before any tokenizer endpoint. Docker had preserved the host
file's mode `0600` and UID 501. The seed container had dropped all capabilities, so it could not read
the copied file. The partial Run remained unsealed, cleanup removed its container and volume, and no
Provider or target operation occurred. A second attempt, partial Run
`run_20260921T051853Z_485fc572`, stopped even earlier because Docker reports the admitted capability
as `CAP_CHOWN`, while the topology verifier expected the CLI spelling `CHOWN`. That Run also remained
unsealed and left no owned resource.

These failures showed that byte identity alone was insufficient. The runtime user also needs a
deterministic, independently checked ability to read the exact bytes.

## Decision

### 1. Materialize only from a held no-follow descriptor

The production Capacity backend opens the exact registered GGUF file as a regular POSIX descriptor
with `O_NOFOLLOW`, records its device, inode, size, modification time, and change time, verifies its
size and GGUF header, and keeps the descriptor open across the Docker copy. It copies from
`/dev/fd/<n>` with that descriptor explicitly inherited by the Docker CLI. It rejects any descriptor
identity change observed after the copy.

No host path is bind-mounted into either the seed or tokenizer container. The destination is a
fresh Docker-managed volume labelled with one random owner identity.

### 2. Normalize runtime readability in the isolated volume

The seed container uses the same pinned image and platform as the tokenizer. Its root filesystem is
read-only, network mode is `none`, all capabilities are dropped, and only `CAP_CHOWN` is added. Its
only writable mount is the owned model volume. The verifier checks this exact running topology
before copying bytes.

After the descriptor copy, fixed commands:

1. change only `/models/model.gguf` to UID/GID `10001:10001`;
2. as UID/GID `10001:10001`, set mode `0400`;
3. as that runtime user, observe `uid:gid:mode:size`; and
4. as that runtime user, compute SHA-256.

The seed is then removed. The tokenizer container mounts the same volume read-only, runs as
`10001:10001` with all capabilities dropped, and independently observes the same metadata and
SHA-256 before any tokenizer endpoint is admitted. The source file is never chmodded or chowned.

### 3. Bind normalization and observations into Capacity v2

The additive `v1alpha2` Capacity Pin binds a code-owned materialization-policy digest. Evidence,
Proof, Index, the mount-attested event, and strict loader bind:

- expected, staged, and mounted model SHA-256 and byte size;
- staged and mounted UID 10001, GID 10001, and mode `0400`;
- the pinned tokenizer image ID;
- descriptor-to-Docker-volume staging and Docker-copy materialization;
- the read-only `/models` runtime mount;
- runtime-user read verification before tokenizer endpoints; and
- mandatory cleanup and literal zero authority markers.

The successful Capacity v2 Run is:

```text
Run:                         run_20260921T052042Z_0932a478
root:                        d7864c15b7df572294fae99dfe65516543ac82672faab3ca84a53b1c47d8a574
Pin:                         f9d52ba8cdf9c84bf91319642d9b1f33eb486c546c749b0cde8b9cb4b789295a
Evidence:                    a74365288334af4cd6520f14f9745d073a0c5d4bdff91b42701e05b3b575f06d
Proof:                       f7f5f2566c397b3c459fd0701b39f6d80e81a1a4e32a81219af7b2f52ececedb
Index:                       5a8da58ae683e640c9e0fd9a455c015b5627b4f8d6bb0e8b836c147021baf137
materialization attestation: d6aec01b2c4e5bd1f30c97aa6cf7a572fbaae95f8ccb87931fcf6ef5168741da
materialization policy:      ff9fade94c0daea4fe4e9e4c9609d403c9cb8ae0560e160202c4bca1d98c3e48
```

It independently strict-reloaded the same 1,460 prompt tokens, 1,024 completion ceiling, 2,484
total, 1,612-token margin, and conservative Campaign total 51,168 of 65,536 established by the v1
proof. Model completion, inference, Provider dispatch, and target requests were all zero. Cleanup
and absence checks found no owned tokenizer container or model volume.

Historical Capacity v1 Runs remain readable, but they are not eligible as the live-successor gate.

### 4. Seal a proof-bound preparation without dispatch authority

The live-preparation producer strict-reloads the exact discovery, SKILL-002, and Capacity v2 Runs
under independently supplied Run, root, Pin, Proof, transport, and materialization-attestation
anchors. It creates exactly three artifacts, two events, one seal, and the terminal state
`prepared-not-authorized-no-dispatch`.

The successful preparation is:

```text
Run:                run_20260921T052213Z_801a9053
root:               c2b77fd6a1b70fcf60fb13d5b3c8a4d436cfc219f8868c6dedb572009dd010d5
preparation:        828dd003d53509a811b059cdc46da216ede629edb12580ba3d812ade8e44f7da
Index:              261b14a640349dea729e36c98fed8b6536b4ff9a360a179f45e4053bafea8d2a
live request:       8c6aeb84a386418cf12a9b9202f11fe3c3bc70c1d8c3b06b3d2d8cb76e935e7d
```

It performs no model runtime start, model invocation, Provider dispatch, target request, Tool
request, Capability activation, ActionPermit creation, Finding, Graph admission, report, or
delivery. It grants no future call authority. Equality, ancestor, descendant, resolved-alias, and
inode-rebinding checks keep its output root disjoint from every immutable input.

## Consequences

### Positive

- Host path rebinding cannot substitute different model bytes after preflight.
- Runtime readability is proved under the actual UID and read-only mount, not inferred from a host
  mode bit or a privileged hash process.
- The only added seed capability is explicit, topology-attested, networkless, and discarded before
  the tokenizer starts.
- The live request can now be reviewed as a sealed object without starting a model or creating an
  execution bearer.

### Cost and remaining work

- Capacity v2 copies and hashes the 4.28 GB model twice before tokenizer use, adding local latency
  and temporary Docker-volume storage.
- A hard host or Docker-daemon failure can leave labelled resources for operator cleanup even
  though ordinary failures perform and verify cleanup.
- Successful structured model output, latency, memory, proposal quality, Recipe binding, target
  execution, Finding promotion, and attack-path evaluation remain unverified.
- The next implementation step is an additive one-shot live successor that consumes this exact
  preparation while preserving the existing Provider, budget, one-dispatch, parser, compiler,
  terminal-receipt, and cleanup boundaries. A model completion still requires separate user
  authorization.

## Rejected alternatives

- Bind-mount the host model path after hashing it.
- Relax the source file mode or ownership in place.
- Hash as privileged root and assume the final runtime UID can read the file.
- Treat a historical Capacity v1 Run as sufficient for live admission.
- Let a passing Capacity or preparation Run authorize or automatically initiate a completion.

## Compatibility and rollback

This decision is additive. Capacity v1 and every historical WEB-007 or SKILL-002 artifact retain
their meanings. Rollback leaves the Capacity v2 and live-preparation consumers inactive; it does
not make an older proof gate-eligible, reopen a terminal Run, or grant any model, target, execution,
Finding, Graph, report, or delivery authority.
