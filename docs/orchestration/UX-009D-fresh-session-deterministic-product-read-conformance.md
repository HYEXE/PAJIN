# UX-009D: Fresh-session Deterministic Product-read Conformance

## Purpose

Prove that the UX-009A measured-Web product projection can be published and consumed
deterministically through the exact UX-009B reader and UX-009C Operator endpoint after deployment
composition is rebuilt in a fresh operating-system process. UX-009D is conformance only. It does
not add a runtime API, artifact, event, registry format, setting, environment selector, endpoint,
database schema, product field, or execution authority.

The conformance reuses one already completed WEB-002D lifecycle. Product publication and reading
must reopen that exact source authority; neither operation may start another Target, scanner,
controlled-validation Worker, proxy, provider execution, or Docker lifecycle.

## Exact fresh-spawn deployment composition

The fresh-session boundary is a newly spawned Python interpreter with fresh module imports. A new
reader object in the parent interpreter, a fork that inherits parent memory, or a child that keeps a
monkeypatched WEB-002D loader does not satisfy this boundary.

Before product consumption, the conformance driver prepares deployment-owned, test-private input
that identifies the already sealed WEB-002D and UX-009A Runs and the durable stores needed to
reconstruct their verifier context. Each spawned interpreter independently reconstructs:

- the exact source-owned `CatalogBoundDockerZAPScannerTargetFactoryAdapter` and its production
  subprocess Docker runner;
- the exact production `DockerWebControlledValidationAdapter`, route authority, claim ledger,
  Target journal, Worker Evidence store, and Docker boundary inspector;
- the measured-case authority, private Ground Truth profile, WEB-002B reopen context, floor policy,
  Finding mapping, trust anchors, and denial-route authority;
- the accepted exact `WebMeasuredProductFlowOutcome` and one
  `WebMeasuredProductSourceReopenContext`; and
- fresh process-local reader compositions selected by one fixed deployment ID.

Each success interpreter constructs exactly one immutable registration, single-registration
registry, exact reader, and Control Plane app for the accepted outcome. The integrity-batch
interpreter constructs the same accepted composition plus thirteen isolated candidate outcomes;
each candidate receives its own immutable registration, single-registration registry, exact
reader, and app. It never places accepted and rejected outcomes in one registry or converts a
failure case into caller-selected reader input.

The child may receive only deployment-owned conformance coordinates needed to reopen those exact
durable objects. They are not a product request, public configuration format, serialized registry,
or caller-selectable reader input. The child must not accept an alternate Run, root, artifact,
provider, adapter, trust anchor, ledger, journal, mapping, source, projection, or outer JSON object.
`WebMeasuredProductReader.read()` remains zero-argument.

The registry and resolver remain an explicit deployment TCB. This conformance proves that the
selected registration is content-consistent and reproducible; it does not prove that a compromised
deployment selected the intended registration. A byte-identical sealed Run relocated and selected
by that trusted registry is not independently distinguishable by the reader. Path substitution in
this contract therefore means a caller selector or a foreign Run/path identity pair, not proof that
content addressing replaces deployment selection authority.

## Deterministic publication and repeated reads

Two UX-009A publications from the same exact WEB-002D authority must use distinct product Run IDs
and preserve the same source Run. Their canonical
`web-measured-product-flow-projection.json` bytes, `flowId`, `flowDigest`, source authority ID and
source authority digest must be identical. Publication may create only those explicitly requested
product Runs and is completed before the read-only whole-call audit begins.

Each fresh-spawn composition reads the selected sealed product at least twice. Every read resolves
the deployment registration, invokes `load_web_measured_product_flow()`, first reopens the complete
WEB-002D authority through `load_web_controlled_validation_authority()`, verifies the sealed
UX-009A Run, and rebuilds the projection. No projection or successful response may be reused from a
cache.

The following values must be identical across repeated reads in one child, across separately
spawned children, across the two deterministic publications, and with the selected sealed artifact:

- canonical by-alias JSON bytes, including the final newline;
- `flowId` and `flowDigest`;
- source Run, authority ID, and authority digest;
- every measured-case, source-measurement, floor, evaluation, Finding, and policy reference; and
- all fourteen ordered public metric identities, digests, applicability states, comparisons, and
  signed-64 rational values.

Process IDs, interpreter hash seeds, temporary lock locations, deployment-private paths, child
timestamps, principals, and deployment IDs must not enter the projection or affect its bytes or
digests.

## Authentication and transport conformance

A fresh-spawn Control Plane application receives only the exact reconstructed UX-009B reader and
exercises the fixed `GET /v1/products/web-measured-flow` route:

- missing or invalid bearer credentials return `401` without resolving or reading the product;
- authenticated Approver, Auditor, generic Worker, and Replay Worker roles without Operator return
  `403` without resolving or reading the product;
- any query string or non-empty GET body returns the fixed `400` before the reader is called;
- method substitution returns `405` and cannot become a selector or action;
- an Operator read returns the unchanged UX-009A by-alias object without a wrapper; and
- a reader integrity failure returns the fixed `409` without reflecting a path, provider, private
  marker, verifier context, or exception text.

Every exercised `/v1/` response remains non-cacheable and carries the existing `Cache-Control:
no-store, max-age=0`, `Pragma: no-cache`, no-referrer, and `nosniff` boundary. It sets no cookie,
CORS permission, or conditional validator. Repeated successful requests must produce repeated
reader calls.

## Fail-closed conformance cases

Each mutation case operates on an isolated copy so one failed case cannot contaminate another or
the accepted source. The following rejection families are mandatory across the combined UX-009A,
UX-009B, UX-009C, and UX-009D focused and fresh-spawn conformance suites:

- source or product Run ID, canonical root, path, artifact name, flow identity, authority identity,
  or digest substitution;
- product artifact mutation, non-canonical JSON, duplicate-key JSON, or oversized JSON;
- source or product audit-event type, order, or payload equivocation even when the attacker
  recomputes the event hash chain and reseals the Run;
- a source or product Run extended with another event and sealed again after the selected outcome
  became stale;
- a substituted or incomplete WEB-002D reopen context, provider, adapter, trust anchor, ledger,
  journal, mapping, denial authority, source outcome, or projection;
- strict boolean coercion in any nested Scope, Evidence, floor, Finding, report, disclosure, or
  authority marker;
- metric identity, digest, order, signed-64 rational, applicability, comparison, or count drift;
- claim-ceiling escalation above `benchmark-ground-truth-match`;
- impact or severity escalation above `not-evaluated-information-only`;
- generic production-vulnerability or negative-security confirmation; and
- Graph inclusion or mutation, report availability or delivery, route reuse, Permit issuance,
  Capability activation, or additional execution authority.

The dedicated UX-009D real-Docker fresh-spawn batch must exercise at least these thirteen isolated
cases through the exact production reader: strict boolean coercion; claim, impact, and severity
escalation; metric drift; separately rehashed and resealed product-event and source-event
equivocation; stale product and source roots; a foreign Run/path pair; and non-canonical,
duplicate-key, and oversized product JSON. Each case must reach the Operator endpoint and return
the fixed integrity `409` without private context disclosure.

Composition substitutions that make the provider, adapter, trust anchor, registry, journal,
ledger, mapping, source outcome, or projection invalid are rejected before a Control Plane app can
be started and therefore cannot produce an endpoint `409`. UX-009A and UX-009B focused tests cover
those construction-time and field-wise permutations. They remain mandatory, while the real-Docker
batch proves the representative production reopen cases above instead of duplicating every nested
field permutation. A mocked loader cannot satisfy any positive production-composition assertion or
replace the thirteen-case fresh-spawn minimum.

A bare integrity failure is not sufficient evidence for audit-event equivocation. The conformance
must include syntactically valid, rehashed, and resealed conflicting event sequences in both the
product and source Runs and prove that each semantic event contract rejects its sequence.

## Exact whole-call side-effect audit

The read-only audit begins only after WEB-002D completion, cleanup, UX-009A publication, deployment
composition, and Control Plane startup. It snapshots the following before denied, rejected, and
successful product reads and requires the same state afterward:

- source and product Run files, bytes, modification times, event sequences, and seals;
- Control Plane database state;
- route-claim ledger, Target operation journal, provider state, Worker Evidence store, activation
  state, and distribution state;
- Graph events, projection state, and snapshots;
- report, export, delivery, approval, Permit, Tool, Worker, and dispatch records or output roots;
- Docker Target identity and topology; and
- all PAJIN-managed or execution-labelled Docker container and network inventories.

`RunStore.create()` is prohibited during product consumption. The audit also records Docker CLI
operations made by the spawned reader. Only the existing read-only Evidence checks are allowed:

- `docker container ls` and `docker network ls` queries that verify completed execution resources
  remain absent; and
- `docker image inspect` queries that reverify the exact Worker and proxy image identities.

Any `run`, `create`, `start`, `exec`, `connect`, `disconnect`, `stop`, `kill`, `rm`, `remove`,
`restart`, `pull`, `build`, or other Docker mutation during product consumption fails conformance.
The child makes no Target-network request and may not invoke a provider execution or controlled
adapter execution method.

The shared integrity loader's advisory coordination is the only filesystem exception. A fresh host
TEMP may create or secure the exact `.pajin-run-locks[-uid]` root and open its immediate
`<64-lowercase-hex>.lock` regular files while verifying sealed snapshots. Only that root and those
exact files are excluded from application-state equality after their type, link count, available
ownership, and POSIX private modes are checked. A nested directory, another filename, link, special file, or
other mutation is not exempt. The lock files are not product artifacts or security authority.
Read-only provider SQLite access and the Docker queries listed above are observations, not side
effects.

## Real-Docker workflow requirement

The dedicated Ubuntu 24.04 WEB-002D real-Docker conformance workflow must execute the UX-009D
fresh-spawn conformance against the exact lifecycle result created by that workflow. It must not
run a second WEB-002D lifecycle for product reading. The workflow retains its unconditional final
residue audit for PAJIN-managed, execution-labelled, and exact-name containers and networks.

Fast local tests may cover protocol, authentication, deterministic serializer, and isolated
negative cases, but a mocked source loader, fake provider, test-only controlled adapter, same-process
reader, or non-Docker fixture cannot replace the required workflow evidence. A workflow that was
not run or did not complete successfully is reported as unverified, not as passing conformance.
Linux evidence and Windows platform limitations remain separate from the product-read authority.

## Verification evidence

Exact checkpoint `6cb58c1cf69795c86a4ccb6614b4e6fdf445ecbf` completed the dedicated Ubuntu
24.04 workflow as run `33410801762`, job `99549584968`. The UX-009D fresh-spawn conformance passed
in 836.08 seconds, and the unconditional final audit found no PAJIN Docker residue. This evidence
satisfies the Phase 23 workflow requirement without extending any product, Graph, report,
delivery, or execution authority.

## Compatibility and rollback

UX-009D changes no UX-009A API, artifact, event, projection field, canonical-byte rule, flow ID, or
flow digest. It changes no UX-009B registration, resolver, or reader API and no UX-009C endpoint,
authentication, response, or Console behavior. It adds no database migration and does not alter any
WEB-002A/B/C/D, DOMAIN-006, Capability, approval, Permit, Worker, Graph, Finding, report, export, or
delivery wire.

Rollback removes the UX-009D conformance test assets, workflow invocation, and this contract. It
does not rewrite or delete accepted WEB-002D or UX-009A Runs and does not weaken the A/B/C runtime
guards. A failing conformance blocks the Phase 23 Exit Gate; it is not bypassed by removing an
assertion, skipping a required case, or treating a fresh-spawn failure as a platform success.

## Related documents

- [ADR-0257](../adr/0257-project-web-002d-through-a-read-only-operator-product-flow.md)
- [UX-009A contract](UX-009A-sealed-measured-web-product-flow-projection.md)
- [UX-009B contract](UX-009B-deployment-pinned-contextful-product-reader.md)
- [UX-009C contract](UX-009C-operator-only-measured-web-product-view.md)
- [WEB-002D contract](../benchmark/WEB-002D-independent-controlled-validation-floor-and-finding-projection.md)
- [DOMAIN-006 contract](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
- [WEB-002D real-Docker workflow](../../.github/workflows/web-002d-conformance.yml)
