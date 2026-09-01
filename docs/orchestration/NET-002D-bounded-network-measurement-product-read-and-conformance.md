# NET-002D: Bounded Network Measurement Product Read and Conformance

## Purpose

NET-002D projects one exact, sealed NET-002C evaluation into a Network-specific public product and
allows one deployment-selected Operator read. It adds no measurement, execution, scanner, service
confirmation, Finding, Graph, report, or delivery authority. The existing generic benchmark and
Finding wires remain unchanged and are not reinterpreted as Network metrics or product authority.

The implementation is complete locally, but Phase 24 remains conformance-pending until the
dedicated exact-commit Ubuntu 24.04 real-Docker workflow succeeds with an unconditional
zero-residue audit.

## Versioned product

The only product artifact is network-measured-product.json, validated as
pajin.dev/network-measured-product/v1alpha1 / NetworkMeasuredProduct. Its content is limited to:

- the content-addressed product ID and digest;
- one exact NET-002C public evaluation reference;
- the canonical NET-002A case references in the exact order FTP, IMAP, POP3, SMTP, SSH, and the
  unknown negative Control;
- five synthetic-known-positive-matched states followed by one
  synthetic-negative-control-unresolved state;
- the exact DOMAIN-006 Network floor policy reference;
- fourteen canonically ordered public metric observations, including eleven required and three
  explicit not-applicable metrics;
- the satisfied independent fresh-Worker Replay floor state and synthetic-only marker; and
- literal-false disclosure and authority markers.

The product excludes raw banners, expected or observed private labels, private binding identifiers,
source/Replay lineage, image identity, runtime coordinates, Worker or Tool results, Graph content,
Finding content, and report content. Unknown-Control success means that the fixed unknown banner
remained unresolved; it does not confirm an unknown service.

The projector first contextfully reopens the complete NET-002C source and Replay through the
NET-002A public/private mapping and the fixed Docker image inspector. It then creates a distinct
sealed product Run. The loader repeats the complete NET-002C reopen, verifies the product artifact,
event type/order/payload, Run separation, strict canonical JSON bytes, product digest, exact cases,
metric order, applicability, comparison, rational values, and false ceiling, and rebuilds the
product from the source evaluation. Any drift fails closed with the fixed NET-002D integrity error.

## Deployment-pinned read

NetworkMeasuredProductReadRegistration binds one deployment ID to the exact product Run, product
ID/digest, source evaluation ID/digest, product outcome, and complete private verifier context.
NetworkMeasuredProductReadRegistry is immutable and rejects duplicate deployment, product Run, or
product identities. It is deployment TCB, not caller input and not a public registration wire.

NetworkMeasuredProductReader.read() takes no arguments. Every call resolves the fixed deployment
registration and runs the full NET-002D loader. It accepts no caller-selected path, Run, provider,
image, profile, case set, metric policy, or verifier context, and it does not cache a prior product.

## Operator endpoint

The Control Plane may receive one exact deployment-composed reader and expose:

GET /v1/products/network-measured-service-identification

The route:

- requires an authenticated Operator;
- rejects missing or invalid authentication with 401;
- rejects authenticated non-Operator roles with 403;
- rejects any query string or non-empty GET body with 400;
- rejects method substitution with 405;
- returns 503 when no exact reader is configured;
- returns a fixed non-reflective 409 for any integrity failure; and
- returns the unchanged by-alias product object without a wrapper on success.

All responses retain the existing no-store, max-age=0, Pragma: no-cache, no-referrer, and nosniff
boundary and set no cookie, CORS permission, ETag, or Last-Modified validator. This deployment
endpoint does not make the product's httpEntrypointAuthorized: false marker true; that marker
prevents the product from authorizing another endpoint.

## Closed authority boundary

Every product marker for the following remains literal false:

- Docker image build, Target creation, network creation, provider selection, and caller
  configuration;
- approval issuance, ActionPermit issuance, Gateway execution, Worker execution, live measurement,
  further product projection, and additional execution;
- service confirmation, Graph admission or mutation, Finding authority, reporting, and external
  delivery;
- DNS, UDP, port ranges, port enumeration, raw sockets, and active application-protocol writes;
  and
- credential access, external or production targets, and general scanning.

The public product cannot disclose or reconstruct the separate private Ground Truth binding.
Possession of the product, its source reference, a passing floor, or the Operator endpoint does not
grant any source/replay execution or product-publication authority.

## Fresh-process read conformance

The local conformance starts a new Python interpreter using spawn. The child receives only the
sealed product outcome, exact measured-case mapping, deployment-owned audit root, and a literal
test-owned choice between the fake provider and the production Docker inspector. It reconstructs a
fresh provider, reopen context, immutable registration, registry, reader, and Control Plane app.
That recipe is test-private and is not a runtime setting or request format.

The child performs all denial cases and two successful Operator reads. Both successes must invoke
the resolver and full NET-002C reload independently and reproduce the exact sealed canonical product
bytes. The whole-call filesystem snapshot must remain identical. RunStore.create, product
projection, source measurement, Replay, Worker execution, and Target lifecycle methods are
prohibited during the audit.

Docker access during product reading is limited to the exact fixed image-inspection commands and
container/network list queries needed to reverify immutable image identities and absence of managed
residue. Any Docker create, run, start, exec, connect, pull, build, stop, or removal command fails
the conformance. Integrity-loader advisory lock files are coordination state, not product
artifacts, and are the only excluded temporary filesystem entries.

## Exact-commit real-Docker requirement

The manual network-002d-conformance.yml workflow is the only Phase 24 Exit Gate evidence for the
real-Docker boundary. It requires explicit confirmation, pinned Actions, locked dependencies, an
exact clean GITHUB_SHA, Ubuntu 24.04, and the three repository-built fixed images.

The opt-in test must:

1. start with no managed Network residue;
2. execute the six NET-002B source cases and a globally disjoint six-case NET-002C Replay;
3. verify both five-case policy-denial sets and the exact satisfied fourteen-metric floor;
4. publish one NET-002D product only after those twelve executions finish and cleanup succeeds;
5. read that same product twice in a fresh process without another Target, Worker, Replay, or
   product Run; and
6. finish with no managed, execution-labelled, or exact-name Target, proxy, or network residue.

An unrun, skipped, failed, non-exact-commit, non-Linux, fake-provider, or same-process result is not
real-Docker conformance evidence and cannot complete the Phase 24 Exit Gate.

## Compatibility and rollback

NET-002D is additive. It changes no NET-001A through NET-001D identity, NET-002A through NET-002C
wire, DOMAIN-006 metric registration, generic benchmark/Finding wire, accepted ADR, approval,
ActionPermit, Worker, Graph, report, or delivery contract.

Rollback removes the NET-002D product, reader, route, tests, workflow, and this document. It does not
rewrite or delete accepted source, Replay, or product Runs and does not weaken the A/B/C validators.
A failed exact-commit workflow leaves Phase 24 conformance-pending rather than weakening or skipping
the required assertions.

## Related documents

- [ADR-0258](../adr/0258-select-governed-measured-network-service-identification-after-phase-23.md)
- [NET-002A](../benchmark/NET-002A-exact-isolated-service-measured-case-authority.md)
- [NET-002B](../benchmark/NET-002B-registry-governed-disposable-network-source-measurement.md)
- [NET-002C](../benchmark/NET-002C-independent-fresh-worker-network-floor-evaluation.md)
- [DOMAIN-006](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
- [NET-002D workflow](../../.github/workflows/network-002d-conformance.yml)
