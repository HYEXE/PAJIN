# ADR-0053: Inert Deterministic Capability Scaffolds

- Status: Accepted
- Date: 2026-07-26

## Context

CAP-002 fixes seven code-backed authority interfaces, but manually creating identity, metadata,
parameter schema, benchmark mapping, role classes, negative tests, and documentation makes drift
and omission the ceiling on authoring speed.

Allowing free-form code, import paths, shell steps, or YAML attack sequences in a template would
turn the scaffold generator into an unreviewed execution language and code-loading authority.
Allowing a generated stub into the CAP-002 Registry would also create fail-late runtime errors and
false coverage.

## Decision

1. Authoring input is limited to one strict-JSON `CapabilityScaffoldSpec`.
2. The spec contains an exact CAP-001 definition, canonical standalone parameter schema, exact
   benchmark mapping, safe package/class identifiers, and an authority version.
3. The parameter schema requires a strict object, `additionalProperties: false`, sorted required
   fields, bounded local `$defs` references, and an exact CAP-001 digest match.
4. The SDK provides abstract base templates for all seven CAP-002 roles.
5. Every generated class declares `stable_execution_context()` in its own class body while leaving
   the role method abstract. An incomplete stub therefore cannot be instantiated, registered, or
   executed.
6. The generator deterministically creates code templates, metadata instance/schema, parameter
   schema, benchmark mapping, negative tests, README, and typed-package marker.
7. Scaffold identity is content-derived from the spec digest and sorted per-file path, media type,
   and SHA-256.
8. The writer accepts a new destination only and uses the no-follow atomic file writer. The root
   manifest is written last as the commit marker.
9. The generator never mutates a runtime Registry or automatically imports or registers output.

## Rejected alternatives

- **Jinja or user-authored template code:** expands template-injection and arbitrary-code surfaces.
- **YAML Capability DSL:** mixes metadata with execution semantics and bypasses CAP-002 code review.
- **Python entry-point or module scanning:** promotes package metadata to activation authority.
- **Complete pass-through stubs:** lets unimplemented semantics register as a normal Capability.
- **Existing-directory merge or force overwrite:** creates path confusion, stale files, link attacks,
  and loss of user changes.
- **Writing the manifest first:** lets a partial file set look complete.
- **Recursive cleanup on failure:** risks deleting unintended files during path races.

## Consequences

- Authors focus on role methods and security semantics instead of repeated boilerplate.
- Generated artifacts are auditable through exact metadata/schema/benchmark/file digests.
- Incomplete scaffolds fail closed before execution.
- A failed write leaves a directory without a manifest, choosing an explicit incomplete state over
  unsafe automatic recovery.
- Generated output does not gain maturity before CAP-004 signing, review, and activation.

## Compatibility, migration, and rollback

- This is an additive SDK and CLI with no runtime or persistent-schema migration.
- Not using the generator preserves existing CAP-001/002 behavior.
- `v1alpha1` output requires an explicit version bump when fields or files change.
- Long-term generated-source API stability is not claimed. Preserve the manifest and exact input,
  then regenerate into a separate directory with a new generator version.

## Related documents

- [ARCH-001 PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
- [ADR-0051 Versioned Capability Definition and Tool Binding](0051-versioned-capability-definition-and-tool-binding.md)
- [ADR-0052 Code-backed Capability Authority Set](0052-code-backed-capability-authority-set.md)
- [CAP-002 Metadata + Code-backed Authority Interfaces](../capability/CAP-002-metadata-code-backed-authority-interfaces.md)
- [CAP-003 Capability Authoring SDK and Scaffold](../capability/CAP-003-capability-authoring-sdk-scaffold.md)
- [ADR-0054 Signed Reviewed Capability Lifecycle](0054-signed-reviewed-capability-lifecycle.md)
- [CAP-004 Maturity, Signing, Review, and Deprecation](../capability/CAP-004-maturity-signing-review-deprecation.md)
