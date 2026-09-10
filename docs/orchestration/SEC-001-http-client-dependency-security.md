# SEC-001: Pricing HTTP Dependency Security Floor

Status: Local remediation, remote alert closure, and same-commit CI/Docker conformance verified.

## Scope and evidence

The 2026-09-09 read-only GitHub query found six open Dependabot alerts: three high and three
moderate, representing five advisories. Root `uv.lock` and the exported Control Plane image lock
both contained HTTPX2 and HTTPcore2 2.7.0. The upstream latest release was 2.12.0.

| Advisory | Affected package and fixed floor | Reproduced boundary |
| --- | --- | --- |
| [GHSA-8xx6-hgc6-gc2m](https://github.com/pydantic/httpx2/security/advisories/GHSA-8xx6-hgc6-gc2m) | httpx2 < 2.12.0 | gzip/deflate and stacked decoding must yield bounded chunks and close failed streams |
| [GHSA-pf96-p4fj-6566](https://github.com/pydantic/httpx2/security/advisories/GHSA-pf96-p4fj-6566) | httpx2 < 2.11.0 | bytes/JSON/form/multipart requests must not auto-add Content-Length alongside Transfer-Encoding |
| [GHSA-h4x7-gw46-3wm6](https://github.com/pydantic/httpx2/security/advisories/GHSA-h4x7-gw46-3wm6) | httpx2 < 2.11.0 | reject CR/LF in part Content-Type and custom header names/values |
| [GHSA-7mj9-2mp8-4m2p](https://github.com/pydantic/httpx2/security/advisories/GHSA-7mj9-2mp8-4m2p) | httpx2 >= 2.6.0 and < 2.10.0; httpcore2 < 2.10.0 | sync/async SOCKS wss routes must perform TLS and reject an untrusted certificate |
| [GHSA-f2fp-rgf2-35cp](https://github.com/pydantic/httpx2/security/advisories/GHSA-f2fp-rgf2-35cp) | httpx2 >= 2.5.0 and < 2.10.0 | fragmented SSE input must not repeatedly scan the accumulated line |

The source and installed metadata establish:
`pajin -> pydantic-ai-slim 1.107.1 -> genai-prices 0.0.71 -> httpx2 -> httpcore2`.
HTTPX2 pins its matching HTTPcore2 release. The `genai_prices` package imports its updater;
`UpdatePrices.fetch()` issues an HTTPX2 GET and reads the complete price JSON response. An
application explicitly starting that updater can reach compressed-response decoding. Incremental
decoding bounds intermediate allocations; it does not bound an application's final buffered JSON.

PAJIN's `agents/pydantic_ai.py` permits only the exact local TestModel. Repository source has no
`UpdatePrices` start/fetch calls. Installed `genai_prices.data_snapshot.get_snapshot()` uses bundled
data unless a caller explicitly sets an updated snapshot. Importing the updater is not starting it.
The governed model adapter in `providers/openai_compatible.py` instead creates a Worker job under
the existing Gateway. Direct Control Plane HTTP clients use the separate `httpx` package; Worker
and proxy transport are separately implemented. They were not migrated to HTTPX2.

Consequently, the inspected default PAJIN path does not expose attacker-selected uploads, SSE or
SOCKS WebSockets to HTTPX2. The updater exposes GET only when explicitly enabled by embedding
code. These are source-backed reachability limits, not grounds to leave vulnerable installed
packages in place, and not proof about arbitrary downstream embedding applications. Before the
change, the SOCKS extras were absent from the inspected environment. Tests now install that extra
only in `dev` to exercise the affected optional transport.

## Change and compatibility

`pyproject.toml` declares `httpx2>=2.12,<3` as a runtime floor, protecting wheel installations as well
as locked development installs. Both locks select HTTPX2/HTTPcore2 2.12.0 without updating the
pricing, PydanticAI, OpenAI, HTTPX or HTTPcore versions. The development SOCKS extra adds socksio;
it does not add a product transport or runtime permission. The new upstream jsfetch dependency is
conditional on Emscripten and is not installed on the tested native host or Linux target.

The [upstream release](https://github.com/pydantic/httpx2/releases/tag/v2.12.0) changes optional
Zstandard decoding to backports.zstd on Python <= 3.13. PAJIN selects neither Zstandard nor Brotli
extras. The focused decompression regressions cover gzip, deflate and stacked gzip/deflate;
optional Brotli/Zstandard behavior and Emscripten are not claimed as locally verified.

No public PAJIN API, wire format, approval, verifier, Scope or Permit contract changes. Existing
TLS checks remain enabled. A rollback must retain patched package floors or take the affected
installation out of use; reverting to the vulnerable versions is not a supported remediation.

## Verification

`tests/test_dependency_security.py` exercises installed dependency behavior, legitimate multipart
and SSE controls, stream closure, and character-scan work instead of a timing threshold.
`tests/test_dependency_socks_tls.py` uses a disposable loopback SOCKS peer, actual TLS handshakes,
temporary certificates, synchronous/asynchronous clients, and closed sockets/threads. It observes
the first wire byte before TLS and requires real certificate validation. No external target is used.
The packaging smoke also checks the emitted wheel's runtime floor.

Against isolated 2.7.0 packages, the same 19 cases yielded 17 failures and two legitimate-control
passes. This includes plaintext `GET` on the SOCKS wss route. Against 2.12.0, all 19 passed. The
initial default sandbox denied loopback binding; the actual socket tests were rerun with local
network permission, without skips or weakened assertions.

The focused suite covers these cases plus Provider, Provider agents/session, exact PydanticAI
adapter, HTTP Tool/Worker, packaging and deployment export checks. Wheel/sdist creation, a clean
hash-locked Control Plane dependency installation, installed metadata, Ruff and Linux strict mypy
are separate checks. Exact current commands/results and local evidence locations are retained in
`HANDOFF.md`; no previous CI result validates this change.

The path policy selects Web, Network and AI Docker conformance for both dependency locks.
After explicit approval, the six implementation/checkpoint commits were pushed on 2026-09-10.
GitHub re-evaluated commit `72bdbd9ea281741d1120f64b0016047d95955bdd`; alerts 2 through 7 changed to
`fixed` at 08:24:01–08:24:02 UTC. The subsequent API query reported zero open alerts. This observed
remote result is separate from the local package/version and behavioral checks above.

For that exact commit, [CI](https://github.com/HYEXE/PAJIN/actions/runs/34454851268) passed Quality and
all 24 shards: 8,238 passed and 76 existing opt-in skips. The 24 retained duration records bind the
same clean source commit and exit 0, with 8,314 unique tests and no duplicate shard assignments.
[Web](https://github.com/HYEXE/PAJIN/actions/runs/34454971625),
[Network](https://github.com/HYEXE/PAJIN/actions/runs/34454974833), and
[AI](https://github.com/HYEXE/PAJIN/actions/runs/34454978127) each passed their actual Docker
conformance test on the same commit, including exact clean-source and unconditional zero-residue
gates. Runtime/image identities and complete logs are retained with the checkpoint. No prior
commit's success was substituted, and no deployment was performed.
