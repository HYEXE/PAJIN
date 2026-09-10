# APP-002: Bounded Offline ELF Header Execution

- Status: Implemented and locally verified within the bounded support floor below
- Domain: Application
- Capability: `pajin.application.elf-header-read@1.0.0`
- Decision: [ADR-0276](../adr/0276-execute-one-approved-offline-elf-header-read.md)

## Selection and support boundary

Cloud and System were reviewed first. Their existing contracts still require a provider credential
lease or authenticated host agent, together with independent provider/host observations. No live
deployment satisfying those boundaries is configured. Application has a network-disabled Docker
Worker and an installed LLVM object-file reader that can independently inspect disposable fixtures.
The selected slice reads one authorized immutable ELF header; it does not claim general Application,
Cloud or System support.

The new opt-in Capability accepts a content digest and byte count, never a caller-selected filesystem
path, command or URL. Its target is an exact non-routable digest coordinate. An operator-authorized
local custody store resolves at most 256 KiB after approval and one-use Permit consumption. A fixed
non-root Docker parser receives an immutable byte copy on stdin, checks its digest, and reads ELF64
little-endian headers for x86-64 or AArch64. It reports bounded structural metadata only. ELF32,
big-endian, extended numbering, dynamic execution, disassembly, dependency resolution and Finding
production are outside this slice.

This is an additive APP-002 transport and Capability, not a runtime implementation or weakening of
APP-001B's broader mount/parser contracts. Existing imports, preparation markers, releases and
artifact readers remain unchanged. The artifact never becomes an executable or a host mount.

## Execution and evidence contract

1. Complete code-backed Capability roles and a current signed experimental Range release.
2. Exact current Campaign Scope, operator approval bound to the exact request and release, durable
   one-use Graph ActionPermit, and normal Tool Gateway policy re-entry before custody read/Worker.
3. Actual non-root, network-none, read-only/cap-drop/no-new-privileges Docker execution with explicit
   CPU, memory, process, timeout and output bounds and exact image/parser identity.
4. Sealed request, approval, Permit, Worker/result and cleanup evidence. Private artifact bytes and
   signing keys stay outside public documents and source control.
5. A separately authorized fresh Worker re-execution and a report that reopens both pinned Runs.
   Known fixtures also use the installed LLVM implementation as an independent structural oracle.
6. Normal, out-of-scope/approval/duplicate, malformed/wrong-digest and cleanup cases. Unknown cleanup
   or unavailable independent verification cannot be reported as verified success.

The generic ABI [ELF header specification](https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html)
defines the structural fields. LLVM's [object-file reader documentation](https://llvm.org/docs/CommandGuide/llvm-objdump.html)
describes the separate fixture inspection tool. Neither constitutes vulnerability ground truth.

## Concrete implementation

`src/pajin/application_elf/` contains the input/output models, standard-library parser, custody Tool,
complete Capability roles, signed activation/approval gate, dedicated Docker Gateway, sealed product
reader and report CLI. `containers/application-elf/` copies the parser into a fixed, non-root image.
No new Python dependency or shared Worker action is needed.

Deployment composition supplies `ELFCustody`, `ELFHeaderTool`, `ELFActivation`, an exact current
Campaign/grant and the independent operator public key. `prepare_elf_action` creates unsigned intent
and reserves one Run without reading artifact bytes. `approval_for_review` returns unsigned review
material. The separate operator signs `approval_message`; `SignedELFApproval` is verified by
`ELFOperatorAuthority`. `dispatch_elf_action` consumes the durable approval/Permit and invokes the
dedicated `ELFGateway`, which owns the exact Tool and real Docker backend. Calling the preparation or
report helper does not authorize artifact access. Product composition must supply actual deployment
authority; the fixture-only signing helper in `tests/app_002_support.py` is not a production issuer.
Preparation and approval re-entry also rebuild the actual Tool's complete code-authority reference
and compare it with the activated reference. Replacing the Tool object cannot substitute an image or
parser after a release or operator approval. Four new regression cases reproduced the missing
cross-object check before this correction; preparation, Permit consumption and Worker dispatch now
reject both substitutions.

Custody opens only `<authorized-sha256>.elf` relative to an owner-only directory descriptor. Regular
file, owner, private permissions, single link, byte count, before/after stat and SHA-256 checks bound
the immutable copy. The Gateway audit stores the input digest/size, never raw ELF bytes. The fixed
entrypoint accepts only the versioned envelope with an empty secret map and one fixed action.

The resource limits are 15 seconds, 128 MiB, 0.5 CPU, 16 processes, 1 MiB no-exec workspace, 4 KiB
stdout and 1 KiB stderr. The common Docker backend also supplies a 16 MiB no-exec temporary mount.
Limits are included in the signed code-authority context and rechecked by the product reader.

The entrypoint observes Linux `IFF_UP`, capability/privilege flags, root/tmpfs modes and route tables.
It permits only loopback to be active and requires zero non-loopback routes. A local network=none
namespace contained additional administrative-down links; treating every sysfs entry as an active
interface caused a false rejection and was corrected with actual state checks. The non-loopback
active-link/route, capability, privilege and writable/exec filesystem rejection tests remain strict.
See the [Linux interface flags](https://man7.org/linux/man-pages/man7/netdevice.7.html) and
[Docker none driver](https://docs.docker.com/engine/network/drivers/none/) documentation.

`seal_elf_execution` records actual host-observed container absence, presence, unknown or not-created
separately from Worker status. Custody and sealed evidence are deliberately retained. There is no
external target mutation to roll back. An uncertain invocation remains consumed; this component
does not provide distributed scheduling or whole-host recovery.

## Actual local evidence

On 2026-09-10 the final owned suite completed **12 passed in 9.36 seconds** (10.03 seconds including
the child process). Python ran on a POSIX arm64 host; the actual Worker containers ran Linux arm64.
All measured source files remained unchanged during that run.

| Case | Actual result |
| --- | --- |
| Compiled x86-64 ELF, 976 bytes | Source and separately approved fresh Worker matched; LLVM confirmed class/machine/entry/9 sections |
| Compiled AArch64 ELF, 1,064 bytes | Source and separately approved fresh Worker matched; LLVM confirmed class/machine/entry/9 sections |
| Maximum 256 KiB immutable input | Complete untruncated header output; container absence observed |
| Bad magic, unsupported machine, inconsistent table | Three actual parser failures, sealed as failures; container absence observed |
| Invalid approval signature, denied Scope, replacement image/parser | Rejected before custody/Worker; zero consumed Permits |
| Missing artifact and changed custody digest | Consumed Permit, failed preparation, no Worker created |
| Duplicate source/failure dispatches | Existing consumption returned without another Worker invocation |

Eight actual Worker executions occurred: four successful source/re-execution calls, one maximum-size
call and three parser failures. Every owned execution-label query was empty afterward. The two paired
reports were reopened and recomputed in fresh Python processes. Their source/Run/request/approval/
Permit/execution coordinates are distinct and replay starts after source completion.

LLVM independently checked four structural fields. The fixed compiler's `-c` contract supplies the
relocatable type. Other header fields are checked by the parser and fresh re-execution, not claimed
as independently verified by LLVM. Neither result establishes a vulnerability, runtime safety or
general binary-format validity.

The exact local image was
`sha256:4c136b7287b74f9dafb321f04e39fb865970e14675dbe192d2f0fd438047fcf7`.
Private results are under `.pajin/app002-live-06/`, including source manifests, independent deployment
checkpoint, fixture observations, sealed Runs, fresh reports and `pytest.log`. The conformance report
SHA-256 is `1d56424674fac5272e56e5b8fcf5e5dbafc308d573a86da7061ac32a0df4c7c4`.
The independent deployment-trust commitment is
`1526c1aa230ca95acfccf613899fc71259ed7551aa674875a11b45c42648da97`.
Private binary artifacts and signer material are not source-control inputs.

The regular suite adds **63 passing tests** for headers/limits, custody substitution/FIFO handling,
activation/approval/Scope, budget reservation, duplicate/failed dispatch, runtime confinement,
cleanup uncertainty, independent trust/root pins and sealed evidence tampering. Those unit failure
injections are separate from the actual Docker evidence above.

The final wheel and source distribution were built from the integrated source. A separate environment
installed the hash-locked Control Plane dependencies plus the wheel (39 compatible packages). Both
architecture reports were recomputed with that environment's `python -I`; they matched the verified
source-tree reports exactly. Every packaged Python module was compared byte-for-byte with current
source, and the distributions exclude the private evidence tree.

## Reproduction and product report

From the repository root, build the dedicated image and capture its actual ID:

```sh
docker build -f containers/application-elf/Dockerfile -t pajin-app-002:local .
docker image inspect pajin-app-002:local --format '{{.Id}}'
.venv/bin/python scripts/operational_application_elf.py --image-id <observed-sha256-image-id> --output .pajin/app002-new-run
.venv/bin/python -m pytest -q tests/test_application_elf.py tests/test_application_elf_runtime.py tests/test_application_elf_report.py
```

The disposable suite requires Docker, clang's x86-64/AArch64 ELF object output and LLVM `objdump`.
It accepts a local image ID and a new output directory, never an external target or credential.
Successful cases invoke the real product functions; it does not replace execution with a fixed
success response. Missing prerequisites are failures, not added skip conditions.

The installed package can independently read or compare supplied sealed references:

```sh
python -m pajin.application_elf --root <private-run-root> --trust <deployment-trust.json> --trust-digest <independent-trust-commitment> --source-ref <source-reference.json> --replay-ref <replay-reference.json>
```

Omit `--replay-ref` for one Run. Supply trust and Run-root pins through an independent deployment
checkpoint; do not derive trusted values from arbitrary execution output. Reports remain historical
evidence and cannot activate a Capability or authorize another read.

## Remaining support limits

This is an opt-in local execution/report feature with POSIX custody and trusted Linux Docker. It
does not add default server/Console activation, Windows custody, automatic Graph/Finding admission,
remote attestation, production deployment, broad Application analysis, or Cloud/System runtime.
The exact-clean Ubuntu Web/Network/AI gates required by the overall dependency changes remain a
separate approval-dependent verification obligation; this local dirty-checkout suite does not admit them.
