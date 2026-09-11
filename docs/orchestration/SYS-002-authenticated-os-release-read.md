# SYS-002: Authenticated Linux OS-release Read

Status: Implemented; full authenticated local Docker execution and independent checks passed.

## Supported boundary

One experimental System capability reads the userspace distribution metadata of an explicitly
owned Linux container through a fixed mTLS host agent. This is an actual network agent read of
`/usr/lib/os-release`, not Application ELF parsing, an imported report or a registry-only capability.
It does not describe the physical host, kernel, general System execution or SYS-001 conformance.

The deployment independently pins the HTTPS origin, exact `/v1/os-release` endpoint, agent instance,
CA, server/client certificates, agent/client implementation and Docker Worker/proxy images. Scope
must explicitly allow that HTTPS authority for CONNECT and the exact endpoint for the GET. The
fixed Worker performs one verified mTLS GET, with no redirects/retries or caller headers/paths.
The agent authorizes the pinned client certificate before reading, accepts one fresh request ID,
bounds its nonce ledger and file bytes, and returns exact bytes plus their digest and request identity.
Client credential material is delivered by a one-use Secret Lease and is never request metadata.

## Authority and evidence

A current reviewed experimental CAP-002 release owns every role. Preparation creates unsigned intent;
a separate Ed25519 operator approves exact Scope, Campaign, grant, request, code, image and target
coordinates. Graph durably consumes the approval/Permit before Gateway execution. Every dispatch
rechecks current authority and expiry. Discovery, normalized output and replay plans grant no rights.

RunStore seals the detached Gateway/Worker receipts, authorization, file bytes and parsed result.
The read-only product reader receives independent root and deployment trust pins, recomputes the
signature/Policy/Permit and result, and reports bounded execution without Finding authority.
Re-execution requires a fresh Run, request, approval, Permit and Worker; comparison cannot authorize it.
The actual fixture also reads OS-release using Python's independent `platform.freedesktop_os_release`.

## Compatibility and failure

All formats and entry points use SYS-002 versions. APP-002, SYS-001 and previous artifacts are unchanged.
Reject out-of-scope endpoints, invalid/expired approval, revoked activation, certificate mismatch,
malformed/oversize files and duplicate requests. Failed or ambiguous transport does not retry, refund
or claim success. Target resources exist only in an explicit disposable fixture; cleanup must be
observed independently of Worker output. In-memory agent nonce history does not survive restart.

See [ADR-0281](../adr/0281-execute-one-authenticated-system-os-release-read.md). The actual local
commands, successful authenticated execution and limits are recorded below.

## Operator entry points and observed validation

`pajin.system_read.runtime.prepare_system_action` prepares reviewable intent;
`approval_for_review` returns unsigned bytes. The deployment's separate signer supplies
`SignedSystemApproval`; `dispatch_system_action` performs current checks and one-use dispatch through
`SystemGateway`. Product code does not issue its own operator or release signatures. The deployment
passes a private JSON credential value containing CA, client certificate and key to the Gateway's
bounded Secret Broker. No default target or secret is discovered or inferred.

The reader is independently runnable:

```sh
python -m pajin.system_read --root <private-run-root> --trust <independent-trust.json> \
  --trust-digest <independent-commitment> --source-ref <pinned-source-reference.json> \
  --replay-ref <pinned-reexecution-reference.json>
```

The explicit disposable fixture runner accepts only local pinned images and a new private output:

```sh
python scripts/operational_system_read.py --image-id <observed-system-image-id> \
  --proxy-image-id <observed-proxy-image-id> --output <new-private-directory>
```

The final actual suite passed in 32.19 seconds. Two separate approved Runs read the real distribution
file through mTLS and one-use leased credentials; a fresh CLI process reproduced the sealed comparison.
Python `platform.freedesktop_os_release` inside the owned agent independently matched all three fields.
The same environment rejected a reused agent nonce, arbitrary path, untrusted CA, a different CA-signed
client, out-of-scope authority and invalid operator signature. A separate malformed-file agent could
not produce a successful result. Four Docker Workers ran; the external fixture runner independently
observed their containers/proxies/networks and both owned agent containers absent.

Earlier attempts exposed a Docker inspect-field incompatibility, invalid test certificate subjects
and a reader assumption about pre-dispatch job metadata. The fixes use the current network inventory,
distinct CA/leaf names with SKI/AKI, and the Gateway's separately recorded final Secret Lease. The
reader verifies audience, Run, binding, fingerprint, duration, one consumed use and revoked state.
TLS verification was never disabled. All failed attempts retained their results and cleanup checks.

The normalized report omits raw bytes, returns distribution fields and exact file commitment, and
sets `findingAuthority=false` and `generalSystemSupport=false`. It does not certify a physical host.
Commit `3c66c2e3824d86c0a38bb82fbe69e8cb52ce320a` passed ordinary remote CI and the existing
Web/Network/AI Docker workflows. Those workflows did not execute the SYS-002 read. SYS-002 itself
was verified locally. A dedicated `sys-002-conformance.yml` workflow is now implemented; its new
remote run still requires explicit approval and observed results for the same new commit.

The 2026-09-11 follow-up reran the actual source/replay/denial/failure probe against the current
local package and freshly verified Linux arm64 agent image
`sha256:a7c99ac3c2733324952d269275109f5e77605933b984eedb1de0f8675821e301`.
The final integration test passed in 39.17 seconds, with four Worker executions, unchanged source inventory and
independent cleanup. The new CI wrapper accepted its actual report and pytest result. A separate
read-only Docker observer confirmed the exact four execution labels and agent ownership label
had no containers, networks or volumes. This local result does not establish remote CI success.
