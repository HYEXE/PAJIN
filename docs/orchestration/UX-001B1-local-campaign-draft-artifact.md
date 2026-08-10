# UX-001B1: Local Campaign Builder Draft Artifact

- Status: Implemented
- Artifact schema: `pajin.dev/campaign-builder-draft/v1alpha1`
- Decision: [ADR-0154](../adr/0154-store-campaign-drafts-outside-run-authority.md)
- Predecessor: [UX-001A](UX-001A-campaign-profile-scope-builder-draft.md)

## Scope

UX-001B1 persists and reloads one complete UX-001A `CampaignProfileScopeDraft` without compiling a
Campaign. It adds:

- `write_campaign_profile_scope_draft(draft, output_root)`;
- `load_campaign_profile_scope_draft(path)`;
- `campaign-draft-create`; and
- `campaign-draft-inspect`.

It supports the existing exact mappings only:

| Typed source | Selected Profile |
| --- | --- |
| `BugBountyProgramManifest` | `pajin.profile.bug-hunt@1.0.0` |
| `CTFChallengeManifest` | `pajin.profile.ctf@1.0.0` |

## Artifact identity and wire

The artifact path is deterministic:

`<output-root>/<draftDigest>/campaign-profile-scope-draft.json`

The stored object is the complete UX-001A wire object. JSON object keys are sorted. The following
typed set fields are sorted before serialization without changing any ordered source field:

- Bug Bounty `allowedMethods`, `allowedToolCategories`, `prohibitedTechniques`, and `stopOn`;
- each Bug Bounty testing window's `days`; and
- Bug Bounty reporting `requiredFields`.

The writer reconstructs the draft before writing and verifies it again from the committed file.
Repeated writes of the same draft use the same path and bytes. The path is a locator only; its
directory name is never accepted as proof of content identity.

## Read boundary

The reader requires one regular file reached without symbolic-link or junction traversal and with
exactly one hard link. It enforces:

- maximum 4 MiB UTF-8 JSON;
- maximum nesting depth 64;
- maximum 50,000 JSON nodes;
- no duplicate object keys;
- no non-finite numbers; and
- stable file identity, size, and revision across the read.

After strict parsing, `CampaignProfileScopeDraft` validation re-resolves the registered Profile and
catalog and re-derives source digest, Scope preview, compiler identifier, remaining gates, draft ID,
draft digest, and every false authority marker from the embedded typed source.

## CLI behavior

`campaign-draft-create` requires a source path and explicit `--profile-id`; `--profile-version`
defaults to `1.0.0`, and `--output` defaults to `.pajin/drafts`. It selects only the exact source
loader associated with the requested supported Profile, builds the draft, writes it, and prints
non-sensitive identity and count fields.

`campaign-draft-inspect` accepts the exact artifact path and renders the same bounded summary only
after the full read boundary succeeds. Neither command renders the embedded source, approval
evidence, policy text, or target endpoints.

## Authority boundary

The artifact remains `input-validated-not-compiled` with Scope, target execution, Campaign
compilation, Capability, Permit, and execution authority fixed false. Neither command calls
`BugBountyScopeService.compile_campaign` nor `CTFChallengeService.compile_campaign`.

The artifact is deliberately outside `RunStore`, the Control Plane managed sealed-Run artifact
repository, and the Canonical Graph. It carries no Run seal or artifact admission authority. A
later compiler handoff must reload the original embedded typed source and supply an independent
approval or evaluation time to the existing compiler; the preview and draft digest cannot satisfy
those inputs.

## Negative cases

Loading fails closed for:

- duplicate-key, non-finite, oversized, over-deep, or over-wide JSON;
- symbolic-link, junction, special-file, hard-link alias, or unstable file paths;
- source mutation under a retained digest;
- Profile, catalog, source kind, preview, compiler, gate, ID, or digest substitution; and
- any Scope, target, Campaign, Capability, Permit, or execution authority marker changed to true or
  a non-boolean value.

CLI tests replace both existing compiler methods with failing sentinels and prove that supported
Bug Bounty and CTF create/inspect flows never invoke them.

## Compatibility, migration, and rollback

The artifact API and CLI commands are additive. Existing Campaign schemas, compilers, approvals,
Run stores, Control Plane routes, Graph records, and execution defaults do not change. No migration
is required. Rollback removes the additive reader, writer, exports, and commands; stored JSON
remains non-executable data.

Control Plane read exposure, editing, retention, Pentest and AI Assessment sources, CTF Suite
composition, and explicit compiler handoff are outside UX-001B1.
