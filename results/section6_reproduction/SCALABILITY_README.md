# Scalability stress test (supplementary, additive)

This is new, supplementary work produced after the original submission. It
does not modify `planning_benchmark.py`, its results, or anything else
described in `README.md` in this directory -- it only adds four new files:
`scalability_timing.csv`, `scalability_dfmr_timing.csv`,
`scalability_correctness.csv`, and `scalability_summary.json`.

## Why

Section 8.4 of the manuscript states the exact planner "remains
exponential" and cautions that its own 600-instance planning benchmark
(six abstract domains, six or nine candidates) "should not be read as a
general bound... these measurements say little about graphs with thousands
of correlated domains or a large corruption budget." That claim was never
actually measured at a larger scale. This benchmark does that: it reruns
CWR and DFMR (`src/cape_artifact/algorithms.py`, unmodified) across
provenance-domain graphs and candidate counts larger than the original
workload, using the same generator style as `planning_benchmark.py`.
Reproduce with:

```bash
.venv/Scripts/python.exe -m cape_artifact.section6_reproduction.scalability_benchmark
```

It takes roughly 90 seconds (this is a deliberately heavier, larger-scale
run than the original suite's "under 30 seconds").

## Results

**CWR stays cheap well past the paper's own scale.** Across 1,080 timed
instances spanning 6 to 50 domains and up to 18 candidates (fault budgets
1-3), CWR's resource-limit fallback (a 20,000-hypothesis advisory ceiling)
never actually triggered, and its median planning time only grew from
0.056 ms at 6 domains to 0.278 ms at 50 domains (p95: 0.226 ms -> 5.82 ms).
This is an empirical result specific to this candidate density, not a
claim that CWR is cheap at every graph size -- larger candidate counts or
denser dependency sets would eventually reach the hypothesis-count ceiling
and engage the same fallback DFMR hits below.

**DFMR's cost is the real scalability constraint, and it is driven by
candidate count, not domain count.** Its exact recurrence must branch over
every remaining unqueried candidate regardless of how many provenance
domains exist, so the timing sweep holds domain count fixed (6, 20, 50)
and varies candidates instead. Median per-instance cost grew from 1.3 ms at
4 candidates to 15.9 ms at 6, 128.9 ms at 8, and 228.3 ms (max 1.17 s) at
9 -- roughly an order of magnitude per +2 candidates. Instances above 9
candidates were not run; they were recorded as `skipped_resource_limit=1`
with a `STEP_UP` fallback, directly exercising the resource-limit-and-fall-
back behavior the manuscript recommends (Section 5.4/8.4) but does not
itself measure. This is direct, measured evidence for the manuscript's own
caveat that DFMR's recurrence "remains exponential in the worst case" and
is "suitable for the present proof-of-concept benchmark, not as an
unrestricted production solver" (Section 5.5).

**CWR still matches brute-force exhaustive search beyond the original six
domains.** At 6, 10, and 15 domains with 8-12 candidates (450 instances,
larger than the paper's own six-domain setup though still small enough for
an independent exhaustive oracle to be trustworthy), CWR agreed with
exhaustive subset enumeration on feasibility and minimum cost in all 450
cases (100%), extending the empirical check behind Proposition 3 to a
moderately larger scale than Section 6.4/7.2's original 600-instance run.

## Files

- `scalability_timing.csv`: per-instance CWR timing across domain counts
  6-50, fault budgets 1-3, candidate counts 6-18.
- `scalability_dfmr_timing.csv`: per-instance DFMR first-query timing
  across candidate counts 4-10 at fixed domain counts 6/20/50 (candidate
  counts above 9 are recorded as skipped, not run).
- `scalability_correctness.csv`: CWR vs. brute-force exhaustive agreement
  at domain counts 6/10/15, candidate counts 8/10/12.
- `scalability_summary.json`: aggregate timing percentiles and the
  correctness-agreement count above.
