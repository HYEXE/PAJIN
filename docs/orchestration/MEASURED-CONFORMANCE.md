# Measured Docker Conformance Rerun Policy

This policy covers Web, Network, AI, OPS-003/004, and SYS-002/004 boundaries. A successful
synthetic fixture run demonstrates the covered execution and verification contract. It does not
establish general vulnerability detection performance or grant execution authority for other targets.

## Change requirements

`scripts/measured_conformance.py` reports the required workflow families from a Git comparison.
The ordinary CI quality job publishes the report in its job summary. It does not dispatch Docker
workflows or interpret their results.

| Changed scope | Required measured Docker workflows |
| --- | --- |
| Any product source, common Worker/proxy, shared test/helper, dependency lock, build setting, CI orchestration, or unclassified path | Web, Network, AI, OPS, SYS |
| `containers/bug-bounty-target/` or `containers/benchmark-worker/` | Web |
| `containers/network-banner-emitter/` | Network |
| `containers/ai-target/` | AI |
| One domain's `*-002d-conformance.yml` | That domain |
| Only `ops-003-conformance.yml` or `sys-002-conformance.yml` | Web, Network, AI and the selected operational boundary |
| Root operational Markdown, README, LICENSE, or Markdown under `docs/` only | No additional Docker run selected by the path comparison |
| Missing or unavailable baseline | Web, Network, AI, OPS, SYS |

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
multi-commit push or PR baseline is outside that shallow history, all five families remain required.
A missing report or unavailable comparison cannot be interpreted as an empty requirement set.

The additive `requiredOperationalBoundaries` and `requiredOperationalWorkflows` fields select
OPS and SYS separately; the original three-domain fields retain their meaning. Broad product,
shared helper, Worker/proxy, build/lock/CI and unclassified changes require both operational
workflows as well as all three existing workflows. A change only to one new operational workflow
selects that operational boundary and preserves the existing broad Web/Network/AI rule. Existing
domain-only target contexts and their workflows do not select OPS/SYS. Markdown-only changes
select neither operational boundary; a missing baseline selects both. Selection grants no
permission to dispatch a workflow.

The comparison baseline is not automatically a verified release baseline. Before reusing an older
result, independently verify its commit, covered source and image identities, completed test, and
residue audit. Initial validation and any outstanding gate still require fresh conformance.

## Completion evidence

For a checkpoint requiring measured conformance, satisfy every selected family below before marking
the checkpoint complete. After approval and identification of the exact published commit,
ordinary CI and the independent Docker workflows may execute concurrently. This changes only
scheduling: every required check must still pass for that same commit. A source fix requires
fresh evidence for the changed commit; a result from the previous commit cannot cover it.

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

When GitHub reruns a failed job, retain the successful jobs from earlier attempts of that same
run and commit. Read all attempts and use the latest attempt for each required job name; require
one successful quality job and all 24 distinct successful shard names. A latest-attempt-only
job listing can omit the earlier successes. Preserve the initial failure and its diagnosis;
rerunning a job does not replace investigating the cause.

| Family | Workflow | Covered path |
| --- | --- | --- |
| Web | `web-002d-conformance.yml` | Source ZAP measurement, controlled validation and denial, cleanup, bounded product, independent process and integrity failures |
| Network | `network-002d-conformance.yml` | Six source cases, six independent Replay cases, floor, product, fresh-process reads, cleanup |
| AI | `ai-002d-conformance.yml` | Source, two supporting Replay operations, three comparison controls, floor, product, fresh-process reads, cleanup |
| OPS | `ops-003-conformance.yml` | Existing OPS-003 recovery plus separately retained OPS-004 checkpoint head, old archive/pin rejection, read-only anchor mount and approved continuation |
| SYS | `sys-002-conformance.yml` | Existing SYS-002 OS-release plus separately approved SYS-004 ASLR reads, independent parser/coreutils checks, fresh-process readers, denials/failures and eight Worker lifecycles |

The Web, Network and AI tests also export the UX-010 private deployment inventory and reconstruct the Operator
API from that JSON in a separate process. The live path uses the actual Docker command runners.
The inventory remains private; do not publish it as a CI artifact.

Local Docker runs are useful preflight evidence. Record their platform and actual result separately;
a dirty working tree or another host architecture does not satisfy the exact clean-commit Ubuntu
gate. Preserve failure evidence, fix or identify the cause, and rerun only the affected check.
Never repair source evidence, weaken its assertions, or bypass cleanup to make conformance green.

## Dedicated operational workflows

Both new workflows require explicit confirmation plus the approved full `expected_commit` SHA.
They build from that clean checkout on `ubuntu-24.04`, use locked dependencies and observed
`linux/amd64` image IDs, then invoke the existing actual Linux probes through
`scripts/linux_boundary_conformance.py`. The CI-only wrapper refuses a local or self-hosted
environment and refuses cleanup admission if any matching fixture resources already exist.
Its private admission marker binds the commit, tracked-source digest, workflow Run and attempt.

The execution step verifies all eleven original OPS checks plus fifteen OPS-004 checks, or
both actual passing System pytests with four observed Worker executions each. The ASLR path
also requires independent coreutils bytes to match both sealed observations. Original and
additional probes retain separate private directories, logs and bounded public counts;
success of the original probe alone cannot complete the workflow. The SYS workflow builds
and pins a separate ASLR image. Its cleanup admission includes both agent ownership labels.
The unchanged confirmation input names now explicitly describe both covered profiles.
The unconditional cleanup step removes only resources admitted on
that fresh dedicated runner; finding fallback residue still fails conformance even if removal
succeeds. A separate unconditional, read-only audit requires zero remaining containers, networks
and volumes. Failed resource removal does not prevent attempts to clean the other owned resources.

Only three explicitly named, bounded JSON summaries are public artifacts: execution, cleanup,
and independent residue observations. Run evidence, source inventories, logs, generated fixture
keys, database dumps and credentials remain private. Missing/skipped execution, source drift,
failed verification or cleanup can never be reported as success. Container termination tests do
not demonstrate physical power-loss recovery, production failover or arbitrary System support.
GitHub's [runner environment variables](https://docs.github.com/en/actions/reference/workflows-and-actions/variables)
define the dedicated-host admission input; it is checked alongside the actual platform and Git SHA.

## Verified expanded checkpoint

Commit `1fd37d16d05887f9ff7956ccea4986b77cd4fe6c` passed ordinary CI and all five required
conformance families on their first attempts, including both newly added operational paths:

| Workflow | Verified result |
| --- | --- |
| [CI 34669692639](https://github.com/HYEXE/PAJIN/actions/runs/34669692639) | Quality and 24 shards; 8,566 passed, existing 76 skipped |
| [Web 34669907026](https://github.com/HYEXE/PAJIN/actions/runs/34669907026) | 1 actual test passed in 133.03 s |
| [Network 34669908622](https://github.com/HYEXE/PAJIN/actions/runs/34669908622) | 1 actual test passed in 296.50 s |
| [AI 34669909903](https://github.com/HYEXE/PAJIN/actions/runs/34669909903) | 1 actual test passed in 79.89 s |
| [OPS 34669911248](https://github.com/HYEXE/PAJIN/actions/runs/34669911248) | Original 11 plus additional 15 checks; combined outer runner 248.66 s |
| [SYS 34669912227](https://github.com/HYEXE/PAJIN/actions/runs/34669912227) | Original and additional profiles each passed 1 actual test and 4 Worker executions; combined outer runner 86.51 s |

The 24 duration artifacts identify the same clean SHA and exit zero. Their 8,642 unique test IDs
match local collection, preserve all 8,517 previous IDs and add 125 tests. Skip locations, reasons
and counts are unchanged. Ruff and strict Linux mypy passed for 490 source files, 13 explicitly
included scripts and 2 additional agent/client files. All five conformance jobs passed exact-image,
clean-commit and independent residue gates.

OPS/SYS ran on Ubuntu 24.04, Linux/amd64, Python 3.12.14. Their source commitment matches all
1,505 tracked files read independently from that Git commit:
`6326d2448a5a40dbe415e553aca8e2386dd2c15edc6e7635f0c59c8c18f84e4f`.
Both original and additional probes exited zero. Cleanup and a separate read-only audit found zero
owned containers, networks and volumes without fallback removal. Each artifact contains only the
three bounded public JSON summaries. Local arm64 probes and earlier failed local fixture attempts
remain separate evidence. These results do not establish physical-host recovery, trusted-anchor
rollback detection, process ASLR protection or general System support.

The result-only documentation follow-up is Markdown-only and requires its own ordinary CI check.
It selects no additional Docker family when compared with this verified code commit, and does not
claim a new product execution result.

## Earlier checkpoint and retained failure

The historical results below cover only the boundaries present at their recorded commit. They do
not substitute for the expanded checks above.

The first OPS run for `27127bd1872c56c98a0ffc93cabaa834cfcc0259` failed during the actual probe,
while unconditional cleanup and independent residue checks succeeded. Its exact internal cause
remains unconfirmed. Independently reproduced UID/socket-group assumptions were corrected in
`51aeb02721f4d914e17fc8f028f02a31a0fa21ee`, which passed all six required workflows on their first
attempts for that new commit:

| Workflow | Verified result |
| --- | --- |
| [CI 34566919945](https://github.com/HYEXE/PAJIN/actions/runs/34566919945) | Quality and 24 shards; 8,441 passed, existing 76 skipped |
| [Web 34566997794](https://github.com/HYEXE/PAJIN/actions/runs/34566997794) | 1 actual test passed in 113.87 s |
| [Network 34566999714](https://github.com/HYEXE/PAJIN/actions/runs/34566999714) | 1 actual test passed in 334.96 s |
| [AI 34567001711](https://github.com/HYEXE/PAJIN/actions/runs/34567001711) | 1 actual test passed in 87.34 s |
| [OPS 34567003501](https://github.com/HYEXE/PAJIN/actions/runs/34567003501) | 11 actual checks passed; outer runner 170.80 s |
| [SYS 34567005667](https://github.com/HYEXE/PAJIN/actions/runs/34567005667) | 1 actual test and 4 Worker executions; outer runner 44.68 s |

All 24 duration artifacts identify the same clean SHA and exit zero. Their 8,517 unique test IDs
match local collection, preserve the previous 8,502 IDs and add 15 tests. Existing skip locations,
reasons and counts are unchanged. Ruff and strict Linux mypy passed for 475 source files plus the
10 explicitly included namespace scripts. All five conformance jobs passed exact-commit/image and
independent residue gates. OPS/SYS additionally matched tracked-source commitment
`a9d177eb40212c790660cc4f6fad6bca9d7a9445681aefc373dff8d3e037e2ee`; cleanup and read-only audits
found zero containers, networks and volumes without fallback removal. Their public artifacts contain
only the three bounded summary files. These results do not certify later source changes or production
recovery. Post-run documentation records these measured results separately from the verified commit.

## References

- [UX-010 deployment and Console contract](UX-010-measured-product-deployment-and-console.md)
- [Web conformance workflow](../../.github/workflows/web-002d-conformance.yml)
- [Network conformance workflow](../../.github/workflows/network-002d-conformance.yml)
- [AI conformance workflow](../../.github/workflows/ai-002d-conformance.yml)
- [OPS conformance workflow](../../.github/workflows/ops-003-conformance.yml)
- [SYS conformance workflow](../../.github/workflows/sys-002-conformance.yml)
