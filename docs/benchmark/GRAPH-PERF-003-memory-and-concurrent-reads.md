# GRAPH-PERF-003: Memory and Concurrent Current-Graph Reads

Status: Bounded implementation and identical-protocol local comparison complete. Commit
`27127bd1872c56c98a0ffc93cabaa834cfcc0259` passed ordinary CI and Web/Network/AI/SYS conformance.
OPS conformance failed during the actual probe; its fixture correction and a fresh exact-commit
validation remain pending. These CI outcomes do not replace the local performance measurements.

## Experiment

Reuse the exact retained synthetic database bytes from GRAPH-PERF-002. The medium fixture has
1,002 nodes, 2,000 edges and five/six snapshots before/after history append; database sizes are
18,489,344/20,406,272 bytes. The history fixture has 5,002 nodes, 10,000 edges and eleven/twelve
snapshots; database sizes are 148,643,840/158,212,096 bytes. Each phase requests a 100-node first
page once and then repeats twice, verifying counts and the expected snapshot digest on every read.

`scripts/profile_graph_memory.py` uses three fresh processes for each fixture and workload: one
reader, two simultaneous requests sharing one reader, and two independent readers in one process.
Requests start behind a barrier. It separately records request wall/thread CPU, batch wall/process
CPU, throughput, OS block counters and process peak RSS. It records analytically expected full-hash
bytes separately; these are not an observed total of SQLite logical I/O.

Three additional fresh traced processes per fixture measure live allocation before collection,
retained allocation after collection, peak allocation and verification-stage retention. Tracing
results are excluded from timing/RSS performance comparisons. Process RSS includes imports and
allocator behavior; it is neither live Python allocation nor cache capacity. Warm filesystem pages
are expected because fixture validation/copying precedes queries. Cold physical disk, separate
process concurrency, maximum history and production SLOs remain unmeasured.

The local analytic budget is 4 GiB per process for at most two concurrent readers. The basis is
the prior approximately 1.6 GiB single-reader history high-water observation, doubled with headroom.
This is an experimental comparison threshold, not an enforced cap or production memory guarantee.
The test host runs macOS arm64 and Python 3.12.13 with 32 GiB physical RAM. Compare identical script/source pins and fixture digests;
retain each raw sample and report regressions as well as improvements.

## Diagnosis and change

A separate initial allocation diagnostic, while unrelated work was active, observed 508.15 MiB
live allocation after loading the eleven historical snapshots and 543.59 MiB after the twelfth.
Peak traced allocation was 639.54/684.10 MiB, whereas only about 35.48 MiB remained after a query
and collection. The projection verification stage retained about 189.20 MiB. Its timing is not
part of the before/after comparison. This identifies simultaneous historical snapshot retention,
including already read raw rows, as a transient cost distinct from the retained cache.

Stream projection and snapshot rows through SQLite cursors. For current-snapshot reads, retain
only the requested snapshot object while still validating every row's model, canonical bytes,
index, digest, ordinal, chain link and equality with the published projection. Keep the final head
digest and current projection comparison. Complete history, backup and recovery callers retain
the default full snapshot mapping. No object interning or new sharing escapes through public readers.

The cache limits, full database hashes before/after every eligible read, schema/integrity/current-head
checks, path identity, defensive copies, cursor binding, authorization and fallback are unchanged.
Focused regressions include corruption in discarded first/middle history rows even when the
requested snapshot is missing, full independent history reads, concurrent stale/current requests,
existing raw-file and concurrent-writer checks, changed settings/credentials, limits and fallback.

## Quiet comparison

The completed comparison contains 24 fresh processes per source: eighteen uninstrumented timing/RSS
processes and six separately traced allocation processes. The protocol, fixture bytes, repetitions
and host are identical. Model evaluation and other task-owned heavy checks had stopped. Source trees
contain 484 files each and differ only in `pajin/graph/sqlite_store.py`. The baseline Graph file comes
from the original copy frozen before editing; a later independent deployment serialization
compatibility fix is identical in both trees. Neither the protocol nor original baseline was rewritten.

Profiler SHA-256: `b0bb04237d0a226e02a3661d01d3b84f8a0488c067b4f9df46366f1b5fee563b`.
Baseline Graph SHA-256: `225fb19f8e451ff2f6af777985c7a941e9cd182b52993396d1ae5f48b79acaa8`.
Changed Graph SHA-256: `b7e0bb71602bd5891ee3299c9a39e7e084a01b4b2cf3e73eef20f9a06cf5485c`.
The unchanged projection, cache and API reader fingerprints and complete source/fixture inventories
are retained with the private measurement records.

```sh
python scripts/profile_graph_memory.py measure --directory <retained-fixtures> \
  --source-root <frozen-src-directory> --output <new-private-report.json>
```

All tables show before → after. Dispersion is population standard deviation, not a confidence
interval. Modes are **1** (one reader), **2S** (two requests sharing a reader) and **2I** (two independent
readers in one process). Shared first requests include one validating/cache-building request and
one waiting request; thread CPU therefore differs substantially even within the same batch.

### Process peak RSS

Each row has three uninstrumented process observations covering both phases and all six batches.

| Fixture | Mode | Mean ± SD (MiB) | Maximum (MiB) | Mean change |
| --- | --- | --- | --- | --- |
| medium | 1 | 371.76 ± 5.85 → 353.95 ± 6.17 | 380.03 → 362.67 | -4.79% |
| medium | 2S | 368.75 ± 0.03 → 351.64 ± 0.19 | 368.78 → 351.86 | -4.64% |
| medium | 2I | 472.68 ± 0.76 → 436.61 ± 2.27 | 473.72 → 438.98 | -7.63% |
| history | 1 | 1424.56 ± 0.18 → 769.73 ± 0.43 | 1424.81 → 770.34 | -45.97% |
| history | 2S | 1425.97 ± 0.79 → 770.99 ± 0.90 | 1427.08 → 772.27 | -45.93% |
| history | 2I | 1928.19 ± 9.21 → 1278.38 ± 9.84 | 1936.08 → 1290.77 | -33.70% |

Every observed process remained below the analytic 4 GiB threshold. History single-reader mean RSS
decreased by 654.83 MiB (45.97%); two independent readers decreased by 649.82 MiB (33.70%).
This is a process high-water result, not a per-request memory cap. The smaller fixture improved
less, and concurrent independent readers still have substantial duplicate verification cost.

### Request latency and thread CPU

Values are seconds, mean ± SD. First rows pool three requests for mode 1 and six for modes 2S/2I;
warm rows pool six and twelve requests respectively. Requests in a process are correlated.

| Fixture | Mode | Phase | Cache | Request wall (s) | Request thread CPU (s) |
| --- | --- | --- | --- | --- | --- |
| medium | 1 | base | first | 1.0692 ± 0.0073 → 1.0768 ± 0.0079 | 1.0688 ± 0.0072 → 1.0763 ± 0.0078 |
| medium | 1 | base | warm | 0.0380 ± 0.0005 → 0.0383 ± 0.0003 | 0.0380 ± 0.0005 → 0.0383 ± 0.0003 |
| medium | 1 | changed | first | 1.2145 ± 0.0052 → 1.1915 ± 0.0035 | 1.2139 ± 0.0051 → 1.1912 ± 0.0034 |
| medium | 1 | changed | warm | 0.0398 ± 0.0003 → 0.0401 ± 0.0003 | 0.0398 ± 0.0003 → 0.0401 ± 0.0002 |
| medium | 2S | base | first | 1.0880 ± 0.0195 → 1.0819 ± 0.0199 | 0.5534 ± 0.5150 → 0.5502 ± 0.5126 |
| medium | 2S | base | warm | 0.0574 ± 0.0189 → 0.0573 ± 0.0189 | 0.0381 ± 0.0008 → 0.0381 ± 0.0004 |
| medium | 2S | changed | first | 1.2178 ± 0.0201 → 1.2166 ± 0.0210 | 0.6187 ± 0.5789 → 0.6182 ± 0.5779 |
| medium | 2S | changed | warm | 0.0596 ± 0.0196 → 0.0596 ± 0.0196 | 0.0396 ± 0.0005 → 0.0396 ± 0.0007 |
| medium | 2I | base | first | 2.2465 ± 0.0031 → 2.2456 ± 0.0134 | 1.1510 ± 0.0775 → 1.1504 ± 0.0637 |
| medium | 2I | base | warm | 0.0629 ± 0.0009 → 0.0634 ± 0.0011 | 0.0421 ± 0.0005 → 0.0423 ± 0.0006 |
| medium | 2I | changed | first | 2.5128 ± 0.0563 → 2.4831 ± 0.0275 | 1.2835 ± 0.1172 → 1.2705 ± 0.0761 |
| medium | 2I | changed | warm | 0.0643 ± 0.0008 → 0.0652 ± 0.0011 | 0.0436 ± 0.0005 → 0.0442 ± 0.0007 |
| history | 1 | base | first | 10.2099 ± 0.0107 → 10.2874 ± 0.0432 | 10.2065 ± 0.0116 → 10.2740 ± 0.0411 |
| history | 1 | base | warm | 0.2359 ± 0.0006 → 0.2390 ± 0.0020 | 0.2359 ± 0.0006 → 0.2388 ± 0.0019 |
| history | 1 | changed | first | 10.9536 ± 0.0891 → 11.1738 ± 0.0426 | 10.9497 ± 0.0876 → 11.1684 ± 0.0409 |
| history | 1 | changed | warm | 0.2432 ± 0.0009 → 0.2448 ± 0.0018 | 0.2431 ± 0.0009 → 0.2448 ± 0.0018 |
| history | 2S | base | first | 10.5220 ± 0.2257 → 10.3589 ± 0.1698 | 5.3323 ± 5.0143 → 5.2552 ± 4.9450 |
| history | 2S | base | warm | 0.3943 ± 0.1584 → 0.3935 ± 0.1569 | 0.2760 ± 0.0404 → 0.2750 ± 0.0387 |
| history | 2S | changed | first | 11.2456 ± 0.2664 → 11.2444 ± 0.1309 | 5.6841 ± 5.3611 → 5.6801 ± 5.4348 |
| history | 2S | changed | warm | 0.4066 ± 0.1620 → 0.4116 ± 0.1603 | 0.2841 ± 0.0397 → 0.2846 ± 0.0355 |
| history | 2I | base | first | 21.5614 ± 0.3215 → 21.5578 ± 0.1464 | 10.9999 ± 0.6298 → 10.9975 ± 0.3162 |
| history | 2I | base | warm | 0.4811 ± 0.0062 → 0.4808 ± 0.0072 | 0.3163 ± 0.0597 → 0.3159 ± 0.0600 |
| history | 2I | changed | first | 23.2401 ± 0.4719 → 23.2891 ± 0.2082 | 11.8510 ± 0.9099 → 11.8241 ± 0.9613 |
| history | 2I | changed | warm | 0.4983 ± 0.0067 → 0.4937 ± 0.0117 | 0.3289 ± 0.0657 → 0.3271 ± 0.0609 |

### Batch latency, process CPU and throughput

First rows contain three batches and warm rows six. Throughput is completed requests divided by
batch wall time; the table averages those per-batch observations.

| Fixture | Mode | Phase | Cache | Batch wall (s) | Process CPU (s) | Requests/s |
| --- | --- | --- | --- | --- | --- | --- |
| medium | 1 | base | first | 1.0695 ± 0.0073 → 1.0771 ± 0.0079 | 1.0691 ± 0.0072 → 1.0766 ± 0.0078 | 0.9351 ± 0.0064 → 0.9285 ± 0.0069 |
| medium | 1 | base | warm | 0.0382 ± 0.0005 → 0.0385 ± 0.0003 | 0.0382 ± 0.0005 → 0.0386 ± 0.0003 | 26.2027 ± 0.3154 → 25.9537 ± 0.1948 |
| medium | 1 | changed | first | 1.2147 ± 0.0052 → 1.1917 ± 0.0035 | 1.2142 ± 0.0051 → 1.1914 ± 0.0034 | 0.8232 ± 0.0035 → 0.8391 ± 0.0025 |
| medium | 1 | changed | warm | 0.0400 ± 0.0003 → 0.0402 ± 0.0003 | 0.0400 ± 0.0003 → 0.0403 ± 0.0003 | 25.0207 ± 0.2066 → 24.8470 ± 0.1595 |
| medium | 2S | base | first | 1.1076 ± 0.0034 → 1.1011 ± 0.0066 | 1.1072 ± 0.0034 → 1.1008 ± 0.0065 | 1.8058 ± 0.0056 → 1.8165 ± 0.0108 |
| medium | 2S | base | warm | 0.0766 ± 0.0010 → 0.0764 ± 0.0005 | 0.0766 ± 0.0010 → 0.0765 ± 0.0005 | 26.1214 ± 0.3541 → 26.1630 ± 0.1664 |
| medium | 2S | changed | first | 1.2380 ± 0.0029 → 1.2370 ± 0.0057 | 1.2377 ± 0.0029 → 1.2367 ± 0.0057 | 1.6155 ± 0.0037 → 1.6168 ± 0.0075 |
| medium | 2S | changed | warm | 0.0795 ± 0.0006 → 0.0795 ± 0.0010 | 0.0795 ± 0.0006 → 0.0796 ± 0.0010 | 25.1722 ± 0.1841 → 25.1579 ± 0.3103 |
| medium | 2I | base | first | 2.2487 ± 0.0025 → 2.2479 ± 0.0132 | 2.3025 ± 0.0036 → 2.3013 ± 0.0136 | 0.8894 ± 0.0010 → 0.8898 ± 0.0052 |
| medium | 2I | base | warm | 0.0640 ± 0.0004 → 0.0644 ± 0.0007 | 0.0846 ± 0.0006 → 0.0848 ± 0.0009 | 31.2721 ± 0.2088 → 31.0396 ± 0.3561 |
| medium | 2I | changed | first | 2.5149 ± 0.0563 → 2.4852 ± 0.0273 | 2.5673 ± 0.0509 → 2.5414 ± 0.0259 | 0.7956 ± 0.0176 → 0.8048 ± 0.0088 |
| medium | 2I | changed | warm | 0.0653 ± 0.0004 → 0.0662 ± 0.0008 | 0.0875 ± 0.0004 → 0.0887 ± 0.0009 | 30.6424 ± 0.1743 → 30.2189 ± 0.3750 |
| history | 1 | base | first | 10.2102 ± 0.0107 → 10.2877 ± 0.0432 | 10.2068 ± 0.0116 → 10.2742 ± 0.0411 | 0.0979 ± 0.0001 → 0.0972 ± 0.0004 |
| history | 1 | base | warm | 0.2361 ± 0.0006 → 0.2392 ± 0.0020 | 0.2361 ± 0.0006 → 0.2391 ± 0.0019 | 4.2347 ± 0.0106 → 4.1809 ± 0.0347 |
| history | 1 | changed | first | 10.9539 ± 0.0891 → 11.1740 ± 0.0426 | 10.9499 ± 0.0876 → 11.1687 ± 0.0409 | 0.0913 ± 0.0007 → 0.0895 ± 0.0003 |
| history | 1 | changed | warm | 0.2434 ± 0.0009 → 0.2451 ± 0.0018 | 0.2433 ± 0.0009 → 0.2450 ± 0.0018 | 4.1092 ± 0.0153 → 4.0809 ± 0.0303 |
| history | 2S | base | first | 10.6819 ± 0.1597 → 10.5146 ± 0.0688 | 10.6650 ± 0.1423 → 10.5108 ± 0.0672 | 0.1873 ± 0.0028 → 0.1902 ± 0.0012 |
| history | 2S | base | warm | 0.5529 ± 0.0071 → 0.5507 ± 0.0070 | 0.5525 ± 0.0070 → 0.5505 ± 0.0069 | 3.6179 ± 0.0469 → 3.6326 ± 0.0462 |
| history | 2S | changed | first | 11.4081 ± 0.2132 → 11.3675 ± 0.0467 | 11.3686 ± 0.1627 → 11.3607 ± 0.0451 | 0.1754 ± 0.0032 → 0.1759 ± 0.0007 |
| history | 2S | changed | warm | 0.5688 ± 0.0087 → 0.5710 ± 0.0199 | 0.5686 ± 0.0085 → 0.5696 ± 0.0173 | 3.5170 ± 0.0538 → 3.5065 ± 0.1170 |
| history | 2I | base | first | 21.5680 ± 0.3230 → 21.5661 ± 0.1462 | 22.0003 ± 0.3074 → 21.9955 ± 0.1137 | 0.0928 ± 0.0014 → 0.0927 ± 0.0006 |
| history | 2I | base | warm | 0.4841 ± 0.0056 → 0.4838 ± 0.0067 | 0.6330 ± 0.0068 → 0.6321 ± 0.0077 | 4.1320 ± 0.0474 → 4.1350 ± 0.0566 |
| history | 2I | changed | first | 23.2512 ± 0.4726 → 23.3003 ± 0.2076 | 23.7025 ± 0.4636 → 23.6487 ± 0.1267 | 0.0861 ± 0.0017 → 0.0858 ± 0.0008 |
| history | 2I | changed | warm | 0.5013 ± 0.0062 → 0.4966 ± 0.0114 | 0.6582 ± 0.0066 → 0.6546 ± 0.0130 | 3.9900 ± 0.0499 → 4.0297 ± 0.0922 |

The main result is lower transient memory, not a general latency improvement. History mode 1 first
reads regressed from 10.2099 to 10.2874 seconds (+0.76%), and after history append from 10.9536 to
11.1738 seconds (+2.01%). Its warm reads rose by approximately 3.10/1.69 ms. Medium mode 1 base first
reads rose by 7.61 ms (+0.71%). History mode 2S base first request mean improved by about 1.55%,
but its changed warm request mean rose by about 1.23%. No uniform concurrency throughput gain is
established. The three sequential before/after repetitions do not isolate thermal or time-order effects.

### Allocation and retained state

Three separate traced process observations per row. Values are MiB. Each cell is the before → after
mean; every population SD is below 0.0002 MiB at the recorded precision. Traced latency and RSS are
excluded from the preceding performance tables.

| Fixture | Phase | Peak allocation | Live after query | Retained after GC | Live at snapshot stage | Snapshot objects retained |
| --- | --- | --- | --- | --- | --- | --- |
| medium | base | 74.5904 → 62.4049 | 7.2606 → 7.2607 | 7.1313 → 7.1314 | 59.2399 → 45.0385 | 5 → 1 |
| medium | changed | 83.5134 → 63.8256 | 7.2659 → 7.2655 | 7.1357 → 7.1358 | 66.3372 → 45.0423 | 6 → 1 |
| history | base | 639.5448 → 318.5373 | 35.4973 → 35.6045 | 35.4752 → 35.4752 | 508.1518 → 224.6421 | 11 → 1 |
| history | changed | 684.1013 → 318.5409 | 35.6083 → 35.5012 | 35.4790 → 35.4791 | 543.5923 → 224.5413 | 12 → 1 |

The changed history peak falls from 684.10 to 318.54 MiB and snapshot-stage live allocation from
543.59 to 224.54 MiB, while post-GC retained allocation stays approximately 35.48 MiB. This is the
expected reduction of temporary full-history objects, not a reduction in the retained cache. Base
history live allocation immediately after the query rises by about 0.1072 MiB; transient collection
timing must not be conflated with retained state.

### I/O and remaining limits

All recorded OS input/output block deltas are zero. Warm filesystem pages and the host accounting
interface prevent interpreting that as zero bytes read or as a cold-storage benchmark. The unchanged
analytical full-file hash budget per request is 36,978,688/40,812,544 bytes for medium base/changed and
297,287,680/316,424,192 bytes for history base/changed. Two-request batches double these amounts.
Additional SQLite reads are not included in that analytical count.

Complete sample records include min/max, each request and batch, source fingerprints, database
digests and verification results. All requests returned the pinned current snapshot and expected
page counts. Focused correctness coverage also preserves corrupt-history rejection, concurrent
writer detection, stale cursor rejection, cache invalidation, changed credentials/settings, size
limits and fallback. This experiment does not measure HTTP queueing, multiple server processes,
cold physical disk, maximum supported data size, long-running fragmentation or production SLOs.

## References

- [GRAPH-PERF-002](GRAPH-PERF-002-first-and-history-page-cost.md)
- [Current canonical Graph view](../orchestration/UX-002B-current-canonical-graph-view.md)
- [ADR-0285](../adr/0285-validate-all-graph-history-with-bounded-current-snapshot-retention.md)
