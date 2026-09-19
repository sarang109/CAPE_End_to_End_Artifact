# Dense scalability stress test (supplementary, additive)

This is new, supplementary work. It does not modify `scalability_benchmark.py`,
`planning_benchmark.py`, or any of their already-published results -- it only
adds two new files: `dense_scalability_timing.csv` and
`dense_scalability_summary.json`.

## Why

A reviewer pass on `scalability_benchmark.py` (see `SCALABILITY_README.md` in
this directory) noted that its configured 50-domain instances only touch
~18.5 active domains at the median, since each candidate observation there
samples at most 3 dependency domains -- realistic for this artifact's
evidence topologies, but not a demonstration of performance on dense graphs,
large fault budgets, or hundreds of active domains. This benchmark answers
that directly, using `cwr_plan` (`src/cape_artifact/algorithms.py`,
unmodified): candidates here sample up to 25 domains each, domain counts run
up to 500, and fault budgets run up to 20.

Reproduce with:

```bash
.venv/Scripts/python.exe -m cape_artifact.section6_reproduction.dense_scalability_benchmark
```

## Results

**This sweep is genuinely dense.** Across 480 instances, active domain count
(the union of domains actually touched by at least one observation) has a
median of 100 and a maximum of 377 -- five to twenty times denser than the
original sweep's 18.5-domain median, and squarely in the "hundreds of active
domains" range the reviewer asked for.

**The resource-limit fallback engages constantly at this density**, unlike
the original sweep where it never triggered: 360 of 480 instances (75%) were
recorded as `skipped_resource_limit=1` with a `STEP_UP` fallback rather than
solved, because their estimated corruption-hypothesis count exceeded the
same `HYPOTHESIS_LIMIT = 20,000` advisory threshold `scalability_benchmark.py`
uses -- almost entirely at the higher fault budgets (10, 20), where the
number of possible corrupted-domain subsets grows combinatorially with `f`
regardless of how cheap the underlying solver is. This is the fallback
behavior the manuscript recommends (Section 5.4/8.4) being exercised by CWR
itself, not just by DFMR as in the original sweep.

**Where CWR *did* solve an instance, it stayed cheap even at this density**:
median planning time ranged from 0.050 ms at 50 domains to 0.126 ms at 500
domains (p95 up to 0.23 ms) -- the exact algorithm's cost tracks the
*realized* hypothesis count, not the nominal domain count, so instances that
clear the resource-limit check keep the same sub-millisecond character the
original, sparser sweep found, even with far more active domains and higher
fault budgets. This is an empirical result specific to the instances that
were actually solved (a quarter of this sweep); the other three-quarters is
precisely the regime the resource-limit guard exists for.

## Files

- `dense_scalability_timing.csv`: per-instance domain count, active domain
  count, fault budget, candidate count, estimated hypothesis count,
  skip/solve status, and CWR timing where solved.
- `dense_scalability_summary.json`: aggregate counts, active-domain-count
  median/max, and timing percentiles by domain count.
