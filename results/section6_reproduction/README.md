# Sections 6.2-6.6 generator and results

This directory holds the output of the code in
`src/cape_artifact/section6_reproduction/`, which implements the
controlled workloads of Sections 6.2-6.6: the factorial authorization-variant
workload, the CWR planning benchmark, the structural finite-verification
checks, the drift / latency / durable-state experiments, and the DFMR
finite-world benchmark.

Run it with (`.venv\Scripts\python.exe` on Windows):

```bash
.venv/bin/python -m cape_artifact.section6_reproduction.run_all
```

It is pure local Python (no network, no paid API, no credentials) and takes
under 30 seconds. It regenerates every file in this directory.

## Provenance: this generator is a reconstruction

**The original generator for Sections 6.2-6.6 was not available.** This code
was written afterwards, from the manuscript's prose description of the method
(source layouts, event cases, seed schedule, cost conventions) and the
existing `algorithms.py` and `models.py` modules. It is not the code that
produced the numbers in earlier manuscript drafts.

Consequences a reader should know:

- **The headline numbers changed.** Earlier drafts reported 4,200 / 1,460 /
  1,007 / 789 post-cache fetches (Full / Affected / Residual / CWR), 550
  feasible planning instances, and 523 ALLOW / 477 DENY worlds. The current
  manuscript reports the values this generator produces: 4,040 / 1,440 /
  1,101 / 923 fetches, 539 feasible instances, and 514 / 486 worlds. The
  manuscript's current numbers therefore come from this reconstruction, so
  agreement between the paper and this directory shows the paper was
  regenerated from this code, not that two independent implementations agree.
- **Qualitative findings are unchanged.** CWR agrees with exhaustive search
  on all 600 planning instances; Full, Affected, Residual and CWR record zero
  unsafe authorizations; the fetch ordering Full > Affected > Residual > CWR
  holds (see `factorial_workload_summary.csv`).
- **Exact enumerations are independent of the reconstruction.** The two
  finite-verification counts in `structural_checks_summary.json` (92,648
  combinations / 18,528 accepted / 0 false-predicate acceptances; 38,416
  residual-subset agreements) are exhaustive counts over a fully specified
  space and matched the earlier manuscript's figures exactly.
- **Latency is environment-specific.** `latency_sweep.csv` times in-memory
  set arithmetic only. Its medians (for example CWR at 24 sources: 0.030 /
  0.018 / 0.284 ms for 0 / half / all changed) show the same pattern as
  Table 7 (CWR is slowest when every source changed) but not the same values,
  which depend on the host. Table 7's exact values come from a separate
  Linux run whose raw file is not in this repository.
- **Included files were generated on Windows, Python 3.14.3.** See
  `run_all_environment.json`. The manuscript states Linux, Python 3.12.14.

## Files

- `factorial_workload_runs.csv` / `_summary.csv` / `_summary.json`
- `planning_instances.csv` / `planning_summary.json`
- `structural_checks_summary.json`
- `drift_sweep.csv`, `latency_sweep.csv`, `durable_state_budget.csv`,
  `durable_state_idempotency.csv`, `performance_state_summary.json`
- `dfmr_benchmark_runs.csv` / `dfmr_benchmark_summary.json`
- `run_all_index.json`, `run_all_environment.json`
