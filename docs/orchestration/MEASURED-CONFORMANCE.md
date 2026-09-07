# Measured Docker Conformance Rerun Policy

This policy covers the existing Web, Network, and AI measured-product boundaries. A successful
synthetic fixture run demonstrates the covered execution and verification contract. It does not
establish general vulnerability detection performance or grant execution authority for other targets.

## Change requirements

`scripts/measured_conformance.py` reports the required workflow families from a Git comparison.
The ordinary CI quality job publishes the report in its job summary. It does not dispatch Docker
workflows or interpret their results.

| Changed scope | Required measured Docker workflows |
| --- | --- |
| Any product source, common Worker/proxy, shared test/helper, dependency lock, build setting, CI orchestration, or unclassified path | Web, Network, AI |
| `containers/bug-bounty-target/` or `containers/benchmark-worker/` | Web |
| `containers/network-banner-emitter/` | Network |
| `containers/ai-target/` | AI |
| One domain's `*-002d-conformance.yml` | That domain |
| Root operational Markdown, README, LICENSE, or Markdown under `docs/` only | No additional Docker run selected by the path comparison |
| Missing or unavailable baseline | Web, Network, AI |

The broad product-source rule is deliberate: the application, registries, and verifier imports
cross domain boundaries. An AI-prefixed Python filename alone is insufficient evidence that Web
and Network are unaffected. Non-Markdown contracts and new paths remain in the broad category.
Documentation-only changes still require contract review and documentation checks; they do not
create a new conformance result or erase an outstanding gate.

Use the actual previous comparison commit as the baseline. For example, replace the placeholder
below with a verified commit; the tool never fetches it or substitutes another branch:

```sh
python scripts/measured_conformance.py --base <baseline-commit> --head HEAD
python scripts/measured_conformance.py --base HEAD --include-working-tree
```

The first command compares two committed trees. The second is a local preview including staged,
unstaged, deleted, and untracked non-ignored paths. Rename detection is disabled so both old and new
paths influence the decision. A working-tree comparison requires the actual current HEAD.

The report identifies both resolved commits, baseline availability, working-tree inclusion and
cleanliness, changed paths, required workflows, `verificationStatus: not-executed`, and
`dispatchAuthorized: false`. CI fetches two commits for the common single-commit push case. If a
multi-commit push or PR baseline is outside that shallow history, all three families remain required.
A missing report or unavailable comparison cannot be interpreted as an empty requirement set.

The comparison baseline is not automatically a verified release baseline. Before reusing an older
result, independently verify its commit, covered source and image identities, completed test, and
residue audit. Initial validation and any outstanding gate still require fresh conformance.

## Completion evidence

For a checkpoint requiring all three families, complete this sequence:

1. Review the final source, tests, contracts, and Git state. Obtain any required commit/push and
   external-execution approval, then identify the exact published commit.
2. Confirm the ordinary CI quality job and all 24 test shards passed for that commit. A running,
   skipped, missing, or failed required job is incomplete evidence.
3. Run each required manual workflow with its explicit confirmation input against that commit.
   Keep the fixed Ubuntu 24.04 runner, locked dependencies, source-built images, immutable base
   images, and the Web workflow's digest-pinned ZAP image.
4. Require the workflow's clean-commit check, actual conformance test, and unconditional residue
   audit to pass. An opt-in test that was skipped is not a successful Docker run.
5. Record the exact commit, workflow/run URL, terminal conclusion, runtime/image identity evidence,
   covered test, and residue result in the current checkpoint. If a required boundary changes,
   recompute the requirements for the new commit.

| Family | Workflow | Covered path |
| --- | --- | --- |
| Web | `web-002d-conformance.yml` | Source ZAP measurement, controlled validation and denial, cleanup, bounded product, independent process and integrity failures |
| Network | `network-002d-conformance.yml` | Six source cases, six independent Replay cases, floor, product, fresh-process reads, cleanup |
| AI | `ai-002d-conformance.yml` | Source, two supporting Replay operations, three comparison controls, floor, product, fresh-process reads, cleanup |

All three tests also export the UX-010 private deployment inventory and reconstruct the Operator
API from that JSON in a separate process. The live path uses the actual Docker command runners.
The inventory remains private; do not publish it as a CI artifact.

Local Docker runs are useful preflight evidence. Record their platform and actual result separately;
a dirty working tree or another host architecture does not satisfy the exact clean-commit Ubuntu
gate. Preserve failure evidence, fix or identify the cause, and rerun only the affected check.
Never repair source evidence, weaken its assertions, or bypass cleanup to make conformance green.

## References

- [UX-010 deployment and Console contract](UX-010-measured-product-deployment-and-console.md)
- [Web conformance workflow](../../.github/workflows/web-002d-conformance.yml)
- [Network conformance workflow](../../.github/workflows/network-002d-conformance.yml)
- [AI conformance workflow](../../.github/workflows/ai-002d-conformance.yml)
