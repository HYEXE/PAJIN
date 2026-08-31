# UX-009B: Deployment-pinned Contextful Product Reader

## Purpose

Read one exact UX-009A measured-Web product projection through deployment-owned selection rather
than caller-provided filesystem or verifier inputs. The reader returns only the unchanged
`WebMeasuredProductFlowProjection` after the existing UX-009A loader has contextually reopened the
complete WEB-002D source and reproduced the sealed product Run.

UX-009B is not an HTTP, authentication, authorization, or UI boundary. It creates no Run, event,
artifact, database row, Graph record, report, delivery instruction, approval, Permit, Tool call,
Worker dispatch, Target lifecycle mutation, controlled-validation execution, target-network action,
or application durable-state mutation.

## Runtime API and unchanged wire

- Runtime registration: `pajin.workflow.web_measured_product_reader.WebMeasuredProductReadRegistration`
- Runtime registry: `pajin.workflow.web_measured_product_reader.WebMeasuredProductReadRegistry`
- Runtime reader: `pajin.workflow.web_measured_product_reader.WebMeasuredProductReader`
- Returned wire: unchanged `pajin.dev/web-measured-product-flow-projection/v1alpha1`

UX-009B adds no serialized registration format, product artifact, Run event, or database schema.
The process-local registration is deployment-private and is never a product response. UX-009A's
artifact name, three-event sequence, projection schema, flow ID, and flow digest remain unchanged.

## Deployment registration and resolver boundary

Each immutable registration pins:

- one deployment ID selected during process composition;
- the exact product Run ID, content-addressed flow ID, and flow digest;
- the exact WEB-002D source Run ID, authority ID, and authority digest;
- the exact `WebMeasuredProductFlowOutcome`; and
- the complete `WebMeasuredProductSourceReopenContext` with its measured case, private Ground
  Truth profile, WEB-002B source context, floor policy, private/public Finding mapping, route trust
  anchor, claim ledger, Target journal, source-owned provider, controlled-validation adapter, and
  denial-route authority.

The registry canonicalizes both Run paths to existing absolute directories, rejects product/source
Run reuse, and requires every registered identity to agree with the UX-009A projection and WEB-002D
source candidate. Deployment IDs, product Run IDs, and flow IDs are unique in one registry.

`WebMeasuredProductReader` pins one deployment ID in its constructor. Its `read()` method accepts no
arguments. A caller therefore cannot supply or override a root, Run path, artifact path, provider,
adapter, trust anchor, claim ledger, Target journal, private mapping, source outcome, product
projection, dictionary, or JSON document. The registry or another deployment-owned implementation
of `WebMeasuredProductReadResolver` is the only input authority.

The resolver is an explicit deployment TCB. Content addressing proves the selected data's
integrity; it does not prove that a compromised deployment selected the intended registration.

## Contextful read order

Every `read()` performs this order without using a cached projection:

1. resolve the registration for the reader's constructor-pinned deployment ID;
2. require the exact registration, outcome, source-outcome, context, identity, artifact-name, and
   distinct canonical Run-path types;
3. call `load_web_measured_product_flow()` with only that registered outcome and context;
4. let UX-009A first call `load_web_controlled_validation_authority()` and rebuild the complete
   WEB-002D chain;
5. let UX-009A verify the product Run seal, event sequence and payloads, strict canonical JSON,
   registered source identities, and rebuilt projection; and
6. return only the detached bounded projection.

A newly composed process-local registry and reader follow the same path. No in-memory product
candidate can replace the sealed source or product reconstruction, and a valid bare outer JSON
document cannot satisfy the resolver contract.

## Read-only and disclosure boundary

The reader does not call `RunStore.create()` and does not write either registered Run. It does not
change the route claim ledger, Target operation journal, activation state, Evidence, Graph, report,
delivery, or other application durable state. The shared Run-integrity loader retains its existing
advisory snapshot locking; a fresh host TEMP may create ephemeral `.pajin-run-locks` coordination
files. Those locks are not product or security-authority records and must not be bypassed because
they protect sealed snapshot reads from races.

Contextual WEB-002D reconstruction retains its deployment-owned read-only provider and inspector
Evidence checks. Those checks may inspect the already completed Target receipts and image identity;
they do not reset, create, start, execute, network-connect, stop, remove, or otherwise mutate a
Target or provider resource.

The return value contains no Run path or reopen context. All UX-009A disclosure and authority
ceilings remain unchanged, including no private Ground Truth, expected reference, raw SARIF,
controlled query, response body, transcript, raw Evidence, route or approval details, Permit,
request, dispatch, filesystem coordinate, Graph content, report, or additional execution
authority.

## Fail-closed cases

Registration or reading rejects:

- an empty registry, duplicate deployment/product Run/flow identity, or invalid deployment ID;
- a registration, product outcome, source outcome, or reopen context of another runtime type;
- a missing, non-directory, aliased, reused, or substituted product/source Run path;
- a changed product Run, flow, source Run, source authority, artifact name, or digest;
- an unregistered deployment ID or a resolver returning another result type;
- a caller-provided dictionary, JSON document, path, provider, adapter, trust anchor, journal,
  ledger, private mapping, source, or projection;
- any WEB-002D context, source, seal, event, canonical-byte, metric, Finding, disclosure, or
  authority failure already rejected by UX-009A; and
- any attempt to create a Run during reading.

## Compatibility, rollback, and remaining work

UX-009B is additive and reuses the UX-009A and WEB-002D APIs without changing their wires. It has no
database migration. Rollback removes the registry and reader while retaining every sealed source
and product Run as historical records.

UX-009C adds the separate authenticated Operator-only Control Plane endpoint and same-origin strict
text-only Web Console view while leaving this reader and its wire unchanged. Request-level response
caching and authorization remain outside this reader. UX-009D must perform the independent
fresh-session deterministic conformance and side-effect audit across repeated reads.

## Related documents

- [ADR-0257](../adr/0257-project-web-002d-through-a-read-only-operator-product-flow.md)
- [UX-009A contract](UX-009A-sealed-measured-web-product-flow-projection.md)
- [UX-009C contract](UX-009C-operator-only-measured-web-product-view.md)
- [WEB-002D contract](../benchmark/WEB-002D-independent-controlled-validation-floor-and-finding-projection.md)
