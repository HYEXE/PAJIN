# CAP-003: Capability Authoring SDK and Scaffold

- Status: locally implemented
- Date: 2026-07-26
- Prerequisites: ARCH-001, CAP-001, CAP-002, ADR-0051, ADR-0052

## Purpose

Increase Capability authoring speed without turning the generator into a new execution authority
or a free-form attack DSL. CAP-003 produces a deterministic scaffold that binds CAP-001 metadata to
the seven CAP-002 code-backed roles by exact digests.

Every generated authority class is abstract. It cannot be instantiated, registered, or executed
until its role method is implemented in reviewed code.

## Task contract

- **Task ID:** CAP-003
- **Threat Model:** path traversal and overwrite, symlink or junction substitution, template code
  injection, metadata/schema drift, external schema substitution, executable incomplete stubs,
  secret-bearing template context, and generated-file tampering
- **Changed Trust Boundary:** reviewed authoring spec to CAP-002 adapter implementation code
- **Schema/API Versions:** `pajin.dev/capability-scaffold/v1alpha1`,
  `pajin.dev/capability-authority-template/v1alpha1`,
  `pajin.dev/capability-benchmark-mapping/v1alpha1`, and
  `pajin.dev/capability-scaffold-manifest/v1alpha1`
- **Audit Artifact:** content-derived `CapabilityScaffold`, per-file SHA-256, and a write-last
  `scaffold-manifest.json`
- **Benchmark Impact:** no runtime wiring changes. The generated benchmark mapping is input for
  later CAP-006 coverage measurement.

## Authoring input

`CapabilityScaffoldSpec` accepts bounded strict JSON only. YAML, import strings, module scans, and
shell commands are not part of the contract.

- a safe Python package name and PascalCase class prefix;
- a shared authority version;
- an exact `CapabilityDefinition`;
- a standalone strict JSON parameter schema; and
- an exact `CapabilityBenchmarkMapping`.

The parameter schema must be a JSON Schema draft 2020-12 object and must set
`additionalProperties: false`. Required fields must be a sorted unique subset of declared
properties. `$ref` is limited to bounded local `$defs` references. The canonical schema digest must
match the CAP-001 `parameterSchemaDigest`. Root composition/pattern expansion and dynamic or
external reference-scope changes are rejected.

The benchmark mapping binds an exact Capability reference, sorted benchmark IDs, and expected
observables to a content-derived digest.

## Authoring SDK

The SDK exposes these abstract base templates:

1. `MaterializerTemplate`
2. `ActionCompilerTemplate`
3. `ExecutorAdapterTemplate`
4. `ResultNormalizerTemplate`
5. `SuccessOracleTemplate`
6. `ReplayStrategyTemplate`
7. `CleanupHandlerTemplate`

The common base supplies role, authority ID/version, exact Capability reference, and canonical
configuration. A concrete class must explicitly declare `stable_execution_context()` in its own
class body, as required by CAP-002. The generator places that delegating method in every class while
leaving the role method abstract.

## Scaffold generator

`generate_capability_scaffold()` always produces the same files and digests for the same spec:

- package `__init__.py` and `py.typed`;
- `authorities.py` with seven abstract authority classes;
- exact `metadata.json`;
- `capability-definition.schema.json`;
- digest-bound `parameter-schema.json`;
- exact `benchmark-mapping.json`;
- a generated authoring/review/activation `README.md`;
- a negative-test template proving incomplete classes remain abstract; and
- a root manifest binding every file path, media type, and SHA-256.

User values are either constrained to Python identifiers or encoded as JSON string literals. No
free-form code or command is inserted into generated Python.

## Safe writer and CLI

```powershell
pajin capability-scaffold capability-scaffold-spec.json --output .\generated-capability
```

The writer never overwrites an existing destination. Existing directories, files, and links fail.
It creates a new root once and uses the existing no-follow atomic writer for every file.
`scaffold-manifest.json` is written last; a directory without it is incomplete and must not be
consumed.

## Verification

- deterministic file set and scaffold digest for the same spec;
- seven generated classes remain abstract and non-instantiable;
- metadata and parameter-schema digest binding;
- strict-schema, external-`$ref`, and unsorted-required rejection;
- generated content/digest tamper rejection;
- existing-destination overwrite rejection with the prior manifest preserved;
- concrete-template stable-context identity and secret-like-context rejection; and
- CLI success, repeated-write failure, and no traceback or untrusted error detail.

## Compatibility, migration, and rollback

- Existing Capability, Tool, Registry, Gateway, Replay runtime APIs, and persistent schemas do not
  change.
- The CLI and public SDK imports are additive.
- Generated output is not automatically registered. CAP-004 signed review/activation and explicit
  bootstrap remain required.
- Rollback means not using the scaffold CLI/SDK. CAP-001/002 and existing runtime behavior remain
  unchanged.
- A partial write has no manifest and cannot be mistaken for a complete artifact. The writer does
  not perform risky automatic deletion.

## Follow-up boundaries

- organization-specific CAP-004 authorization workflow and durable Registry storage
- additional authoring templates beyond the explicit CAP-005 existing-mode adapter bundle
- CAP-006 Registry coverage, authoring lead time, Oracle, and Replay metrics
- opt-in GRAPH-006 ActionPermit and Tool Gateway runtime wiring
- Linux CI and clean-clone scaffold-consumer verification
