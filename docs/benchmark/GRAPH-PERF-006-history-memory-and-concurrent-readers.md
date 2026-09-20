# GRAPH-PERF-006: Historical reads and simultaneous reader memory

## Scope and acceptance

Compare the same immutable medium and large historical SQLite fixtures before
and after ADR 0295. Keep full verification and every existing authority boundary.
Require identical public results, lower large-history first-read peak RSS, and
lower repeated historical-page latency. Report mixed or worse cells explicitly.
No result is a production SLO or a claim about physical host disk latency.

## Protocol

`scripts/profile_graph_history_readers.py` calls the real current-page reader,
`GraphCampaignBrowser.catalog`, and `GraphCampaignBrowser.page` for the second
newest Snapshot. Two fixtures, three read paths, one/two fresh processes,
observed warm/cold guest file pages, and three independent repetitions produce
72 groups per implementation. Each group has one first and two repeated reads.
The same immutable Linux image, two CPU and four GiB envelope, frozen source
trees and profiler inputs are used on both sides. Model evaluation and other
expensive local verification do not overlap the timed measurement.

| Fixture | Database bytes | Snapshots | Current/selected older nodes | Current/selected older edges |
| --- | ---: | ---: | ---: | ---: |
| Medium | 20,406,272 | 6 | 1,002 | 2,000 |
| Large history | 158,212,096 | 12 | 5,002 | 10,000 |

Each group records read wall/CPU time, individual process high-water RSS, and
simultaneous summed RSS sampled from `/proc/<pid>/statm` at a target five
millisecond interval. It reports the actual largest observed interval and the
coordinator-inclusive aggregate separately. Sampling can miss a shorter peak;
shared pages count per process, not once per physical page. Group elapsed time
also includes result verification and transport. Public result commitments must
match across processes, repetitions and implementations.

The timed interval includes the API call and conversion of page models into
JSON-compatible values. Equality hashing and transport serialization are outside
it. Garbage collection precedes each synchronized batch. The sampled RSS covers
the query phase; individual high-water RSS also includes process startup. These
are direct read APIs, not HTTP latency or browser rendering measurements.

`mincore` must observe zero resident fixture pages for the cold first read or all
resident pages for warm reads. Eviction advice applies only to a fresh owned
fixture; no global cache flush is used. File bytes must remain unchanged, all
children must exit successfully, and the owning container must be absent after
cleanup. Host filesystem and storage-device caches remain unknown.

Completed groups are checkpointed with `complete=false` until the whole matrix
finishes. Child stdout/stderr is retained, and child errors also reach the
controller log. Successful owned database copies are deleted only after their
unchanged bytes have been checked. Original fixtures remain read-only. Diagnostic
archives exclude database copies and include final cgroup memory observations.

## Current result

The verified comparison completed 72 groups, 216 synchronized batches and 324
individual reads per implementation. All six fixture/view result commitments
matched across readers, repetitions and implementations. Frozen source inventories
contained 523 baseline and 524 candidate inputs, with exactly the four Graph files
changed; the currently edited Graph files match the candidate pins. All original
fixture bytes remained unchanged and both owned containers were absent after
cleanup. Retained partial results matched the complete results.

The preregistered memory and repeated-history criteria passed. In the large cold,
two-reader historical-page cell, sampled reader RSS fell from 1,114.3 to 976.8 MiB
and repeated read time fell from 8.0919 to 0.2929 seconds. Including the probe
coordinator, first-read RSS fell from 1,367.8 to 1,230.3 MiB.

This is a tradeoff: every one of the 24 first-read cells was slower, including
8.0779 to 8.8719 seconds in that historical-page cell. All eight current-page
repeat cells were also slower. Catalog and historical-page repeat cells improved,
and sampled first-read RSS decreased in all 24 cells. The measured result does
not establish that every Graph operation became faster or identify the cause of
every latency difference.

Each arrow below means baseline to candidate. First time is the median of three
slowest-reader times; repeat time is the median of six slowest-reader times
(two subsequent batches per repetition). Memory values are the median of three
sampled first-batch peaks. Full precision, per-reader CPU, high-water RSS and all
individual samples remain in the private measurement artifacts.

| Fixture / view | Readers | First guest pages | First seconds | Repeat seconds | Reader RSS MiB | Readers + coordinator MiB |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| Medium / current | 1 | warm | 0.9380 → 0.9471 | 0.0411 → 0.0467 | 314.1 → 300.2 | 568.3 → 554.4 |
| Medium / current | 1 | cold | 0.9547 → 0.9740 | 0.0430 → 0.0491 | 314.9 → 300.1 | 568.4 → 553.6 |
| Medium / current | 2 | warm | 0.9967 → 1.0066 | 0.0461 → 0.0486 | 626.0 → 600.2 | 880.3 → 854.4 |
| Medium / current | 2 | cold | 1.0128 → 1.0161 | 0.0442 → 0.0483 | 627.0 → 600.2 | 880.5 → 853.7 |
| Medium / catalog | 1 | warm | 0.9078 → 0.9196 | 0.9042 → 0.0220 | 313.1 → 300.1 | 567.3 → 554.4 |
| Medium / catalog | 1 | cold | 0.9195 → 0.9367 | 0.9084 → 0.0217 | 314.2 → 300.0 | 567.7 → 553.5 |
| Medium / catalog | 2 | warm | 0.9522 → 0.9780 | 0.9565 → 0.0224 | 626.1 → 600.1 | 880.3 → 854.3 |
| Medium / catalog | 2 | cold | 0.9736 → 0.9882 | 0.9510 → 0.0214 | 629.1 → 600.1 | 882.6 → 853.6 |
| Medium / historical-page | 1 | warm | 0.9088 → 0.9479 | 0.9084 → 0.0460 | 313.1 → 300.1 | 567.2 → 554.3 |
| Medium / historical-page | 1 | cold | 0.9232 → 1.0574 | 0.9089 → 0.0473 | 313.1 → 300.1 | 566.5 → 553.6 |
| Medium / historical-page | 2 | warm | 0.9592 → 1.0139 | 0.9586 → 0.0499 | 626.0 → 600.2 | 880.2 → 854.4 |
| Medium / historical-page | 2 | cold | 0.9800 → 1.0138 | 0.9557 → 0.0489 | 627.0 → 600.1 | 880.5 → 853.6 |
| Large history / current | 1 | warm | 7.6178 → 8.1796 | 0.2610 → 0.2810 | 557.1 → 489.0 | 811.4 → 743.2 |
| Large history / current | 1 | cold | 7.7000 → 8.2251 | 0.2618 → 0.2823 | 557.7 → 488.4 | 811.2 → 741.9 |
| Large history / current | 2 | warm | 8.1357 → 8.7322 | 0.2747 → 0.2935 | 1112.6 → 967.4 | 1366.8 → 1221.6 |
| Large history / current | 2 | cold | 8.1853 → 8.8021 | 0.2777 → 0.2925 | 1099.6 → 967.0 | 1353.1 → 1220.5 |
| Large history / catalog | 1 | warm | 7.3881 → 7.9771 | 7.4003 → 0.1540 | 560.2 → 488.5 | 814.5 → 742.7 |
| Large history / catalog | 1 | cold | 7.4560 → 8.3231 | 7.4173 → 0.1566 | 558.0 → 488.2 | 811.5 → 741.7 |
| Large history / catalog | 2 | warm | 7.8377 → 8.6364 | 7.8430 → 0.1622 | 1106.3 → 966.7 | 1360.5 → 1221.0 |
| Large history / catalog | 2 | cold | 7.9905 → 8.7580 | 7.8878 → 0.1615 | 1115.0 → 967.1 | 1368.4 → 1220.6 |
| Large history / historical-page | 1 | warm | 7.4360 → 8.3456 | 7.3923 → 0.2839 | 561.5 → 488.3 | 815.7 → 742.5 |
| Large history / historical-page | 1 | cold | 7.4819 → 8.4567 | 7.4049 → 0.2894 | 559.1 → 488.5 | 812.6 → 742.0 |
| Large history / historical-page | 2 | warm | 7.8529 → 8.8954 | 7.8809 → 0.2989 | 1111.0 → 968.1 | 1365.1 → 1222.3 |
| Large history / historical-page | 2 | cold | 8.0779 → 8.8719 | 8.0919 → 0.2929 | 1114.3 → 976.8 | 1367.8 → 1230.3 |

The largest observed sampling gaps were 37.88 ms before and 16.80 ms after, despite
the 5 ms target. Cgroup `memory.peak` for the entire respective measurement was
1,789,259,776 and 1,614,475,264 bytes. Those counters include charged file pages
and controller processes and are separate from query-phase reader RSS. Both
containers reported zero memory-limit, OOM and OOM-kill events.

The immutable Linux arm64 runtime was
`sha256:bfc1dea247ab1e32f305d198d3b43bb3b758205f8c22db85e76cc89bda0aad97`.

Profiler SHA-256: `cb0e6573daea8622668b7bcaf36aab6d78da7c4bf9e3f585b2d29fe15c70841e`.
Cache helper SHA-256: `5e2fba43e9942f1ddbcc6a8f876f186d2f3aab2eda981d6792c12c37a12004df`.

The first baseline attempt completed 66 groups and failed in the large-history,
two-reader, warm historical-page group. Its container exited with code 1 without
an observed container-level OOM flag and was removed. The original controller
did not retain the child error; the exact cause is unresolved. A direct execution
of that coordinate then passed. After adding retained diagnostics, partial
checkpoints and bounded temporary-copy lifetime, both implementations use the
same newly pinned profiler. The incomplete attempt is not counted as a completed
comparison or silently combined with the replacement run.

## Retained boundaries

One bounded history entry is shared across the browser's registry, with complete
database hashes, schema and head checks on each hit and an independent copy on
return. The byte limits do not cap Python object overhead or total process RSS.
Cache misses, catalog/page alternation and different Snapshot selections still
require full verification. A historical result never grants current approval,
execution, Capability, Permit or Finding authority.
