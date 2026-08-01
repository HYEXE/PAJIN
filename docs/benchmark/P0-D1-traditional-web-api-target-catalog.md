# P0-D1: Traditional Web/API Target Catalog and Ground Truth Profile

- Status: Implemented contract
- Public registrations: `pajin.dev/benchmark-target-profile-registration/v1alpha1`,
  `pajin.dev/benchmark-target-profile-catalog/v1alpha1`
- Private binding: `pajin.dev/benchmark-target-ground-truth-binding/v1alpha1`
- Selection authority: `pajin.dev/benchmark-target-profile-selection/v1alpha1`
- Decision: [ADR-0087](../adr/0087-traditional-web-api-target-catalog.md)
- Predecessor: [P0-C2B2B](P0-C2B2B-local-docker-provider-evidence.md)

## Scope

P0-D1 registers the existing synthetic Boolean-SQLi lab as the first Traditional Web/API Target
profile without turning the Docker adapter into an arbitrary-image runner. The public catalog
binds the exact profile and Target Factory identities, provider profile digest, empty mutation
allowlist, internal-network policy, and private Ground Truth digest. It never embeds Ground Truth
cases or matcher contents.

The private binding pairs one complete `BenchmarkGroundTruth` with the exact public registration.
The first profile has one seeded SQLi Finding, one HTTP API Surface, one single-surface chain, and a
code-owned matcher digest for the receipt-bound Docker execution probe. It does not claim a
holdout, AI/RAG/MCP, Hybrid, or Mutation profile.

## Authority split

| Artifact | Visibility | Bound material |
| --- | --- | --- |
| `BenchmarkTargetProfileRegistration` | Public | Target family, profile/factory IDs and versions, factory/provider digests, mutation allowlist, network policy, Ground Truth digest |
| `BenchmarkTargetProfileCatalog` | Public | Canonically sorted unique registrations and catalog revision/digest |
| `BenchmarkTargetGroundTruthBinding` | Private | Complete Ground Truth and exact public registration |
| `BenchmarkTargetProfileSelectionAuthority` | Public-safe | Catalog/registration, Manifest, adapter, provider profile, and private binding digests |

All four artifacts reject unknown fields, use bounded canonical UTF-8 JSON, and bind
domain-separated SHA-256 identities. Registration keys are sorted and unique by profile ID and
version; duplicate registration digests are also rejected.

The selection authority fixes `targetProfileAdmitted=true` but
`providerExecutionAuthorized=false`. It is a content-addressed catalog decision, not a Capability,
measurement signature, registry activation, or sealed Harness admission. Existing P0-C2A and
P0-C2B2A2 gates remain responsible for provider lifecycle recovery and governed measurement.

## Code-registered profile

`registered_traditional_web_api_ground_truth` constructs only this exact case:

- profile: `bug-bounty.api.boolean-sqli-lab@1.0.0`;
- Target Factory: `target-factory:docker-bug-bounty@1.0.0`;
- seeded Finding: `finding:boolean-sqli-user-lookup`;
- Surface: `surface:http-api-user-lookup`;
- chain: `chain:single-surface-boolean-sqli`;
- matcher: `matcher:docker-boolean-sqli-probe@1.0.0`; and
- mutation allowlist: empty.

The matcher digest binds the P0-C2B2B evidence API, execution stage, successful dedicated Worker,
positive vulnerable probe, Finding, Surface, chain identity, and the complete fixed P0-C2B2B
Observation count mapping for Tool/model/cost, Surface/Finding/chain, replay, policy, human, and
open-world facts. The Ground Truth builder rejects caller-supplied cases or matcher substitutions
because the catalog builder compares the complete private object with the code-owned reconstruction.

Exact Docker image IDs remain provisioning inputs because they differ after a legitimate local
image rebuild. Once provisioned, the existing immutable Docker profile binds both fixed image
references and exact IDs into the Target Factory digest, and the catalog registers that complete
digest. P0-D1 does not authenticate who provisioned a catalog; signed catalog distribution and
durable anti-rollback activation remain separate future work.

## Selection and execution boundary

`select_traditional_web_api_target_profile` admits a selection only when all of these are exactly
equal:

1. Manifest benchmark ID and private Ground Truth benchmark ID;
2. Manifest profile/factory IDs, versions, factory digest, mutation choice, and Ground Truth
   digest;
3. adapter factory ID, version, and digest-bearing Target Factory identity;
4. provisioned Docker profile API version and full profile digest;
5. the complete caller-supplied public catalog and the code-registered reconstruction; and
6. the complete private Ground Truth and code-owned seeded matcher profile.

`CatalogBoundDockerBugBountyTargetFactoryAdapter` applies that selection before any provider
operation. It snapshots the selected adapter and provider identities and rechecks them before every
operation, so post-selection replacement fails closed. After execution it retrieves evidence only
through the exact stage receipt and independently checks adapter, coordinate, operation, receipt,
evidence digest, image IDs, Worker result, positive probe, and the complete registered Ground Truth
counts before returning the Observation. Cleanup remains the enclosing P0-C lifecycle's
responsibility if this post-execution admission fails.

## Required rejection behavior

The implementation and tests reject:

- unknown, duplicate, reordered, or stale catalog registrations;
- forged registration, catalog, private binding, or selection digests;
- unregistered profile versions or mutation profiles;
- Manifest, adapter, image-profile, benchmark, or Ground Truth substitution;
- cross-profile Ground Truth and matcher/case replacement;
- provider identity drift after selection;
- foreign receipt, operation, coordinate, or evidence binding; and
- measured known Surface, Finding, or chain counts that differ from the registered probe result.

## Compatibility, migration, and rollback

The catalog models, builders, wrapper, and exports are additive. BENCH-001 Manifest/Ground Truth,
P0-C lifecycle, receipt, provider evidence, Observation, recovery, registry, and sealed Harness
wire formats are unchanged. Existing callers can still use the raw Docker adapter; governed
Traditional Web/API benchmark entry points should wrap it with the catalog boundary.

Migration creates the private Ground Truth from the exact provisioned Docker profile, creates the
public catalog from those two values, updates the Manifest Ground Truth digest, and inserts the
catalog wrapper below the existing recoverable and registry-governed runners. Rollback removes the
wrapper and catalog selection while preserving all already sealed P0-C Runs. It must not rewrite a
Manifest, Ground Truth, provider profile, or historical result digest.

## Remaining work

P0-D must add separately registered AI/RAG/MCP, Hybrid, Holdout, and Mutation profiles. Catalog
distribution signatures, durable revision activation, cross-host provider fencing, generic Ground
Truth matcher execution, and sealed linkage of the catalog selection into the final governed
Harness authority remain outside P0-D1.

## Related documents

- [BENCH-001 contract](BENCH-001-benchmark-contract.md)
- [P0-C2B2B contract](P0-C2B2B-local-docker-provider-evidence.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
