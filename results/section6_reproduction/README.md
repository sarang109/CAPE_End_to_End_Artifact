# Sections 6.2-6.6 reproduction

This directory holds output from new code the original artifact did not
contain. A reviewer could not run Sections 6.2 through 6.6 (the factorial
authorization-variant workload, the CWR planning benchmark, the structural
finite-verification checks, the drift/latency/durable-state experiments, and
the DFMR finite-world benchmark) because no code implementing them shipped
in the repository — only Section 6.7 (the AP2 operational testbed, in
`results/end_to_end_*.csv`) and Section 6.8 (the frontier-model benchmark, in
`results/frontier_*.csv`) were actually executable.

The new code lives at `src/cape_artifact/section6_reproduction/` and imports
only from the existing, unmodified `cape_artifact.algorithms` and
`cape_artifact.models` modules. Nothing in the pre-existing artifact was
changed. None of it calls a network, a paid API, or requires any credential
— it is pure local Python (stdlib only, plus the two modules above), so it
runs with no API key at all.

Run it with:

```bash
.venv/Scripts/python.exe -m cape_artifact.section6_reproduction.run_all
```

(`.venv/bin/python` on Linux/macOS.) It takes under 30 seconds and
regenerates every file in this directory.

## What this is, and is not

This is an **independent reconstruction** of the methodology described in
Sections 6.2-6.6, built from the prose description in the manuscript (source
layouts, event cases, seed ranges, cost conventions, and the CWR/DFMR
algorithms already implemented in `algorithms.py`). It is **not** the
original authors' generator code, which was not included in this artifact
and could not be recovered. Exact digit-for-digit agreement with the
manuscript's tables was therefore not expected going in, and is not
guaranteed by any of the numbers below, with one exception: the two
finite-verification enumerations in `structural_checks_summary.json`
(`92,648` combinations / `18,528` accepted / `0` false-predicate acceptances,
and `38,416` residual-subset agreements) are exhaustive counts over a fully
specified finite space, and matched the manuscript's Section 7.8 figures
exactly on the first run.

For everything else, the numbers below are close to, but distinct from, the
manuscript's published tables. This is expected and was agreed as acceptable
scope for this reproduction before writing any code.

## Per-experiment comparison to the manuscript

**Factorial workload (`factorial_workload_*`, reproducing Table 2 / Fig. 1,
Section 6.2/6.3):** Quote, Static, and TTL matched the manuscript's unsafe
and benign-completion counts exactly (320/320/0, 180/240/0, 120/240/480).
Majority's unsafe count matched exactly (200/320); its fetch count differs
slightly (3,680 vs. 3,840) because this version does not count fetches
against sources already flagged unavailable, a modeling choice not fully
specified in the text. Full/Affected/Residual/CWR all reproduced zero unsafe
authorizations and the exact 237/320 benign-completion count (the paper's
"single-layout topology cannot satisfy f=1" argument reproduced exactly),
with fetch totals landing within roughly 5% of Table 2's 4,200/1,460/1,007/789
and the same Full > Affected > Residual > CWR ordering.

**Planning benchmark (`planning_instances.csv`, `planning_summary.json`,
reproducing Table 3 / Section 7.2):** CWR agreed with brute-force exhaustive
search on both feasibility and minimum cost on all 600 instances (100%,
confirming Proposition 3 empirically), versus the paper's reported
agreement on its own 600 instances. Feasible-instance count (539 vs. 550)
and mean costs (Full 38.69 vs. 38.25, Sequential 17.45 vs. 18.00, Greedy 7.58
vs. 7.86, CWR 7.10 vs. 7.34) are all close but not identical, as expected for
an independently reseeded generator.

**Structural checks (`structural_checks_summary.json`, reproducing
Section 7.8 / Table 8):** the two exhaustive enumerations matched exactly
(see above). The four hand-constructed assumption-violation counterexamples
also reproduced Table 8's exact pattern: hidden common root, excess
corruption, and missing dispatch binding are unsafe for both Full and CWR;
a silent version change is caught by Full but not by CWR (and the other
selective-reuse variants), matching the manuscript's stated asymmetry.

**Performance/state (`drift_sweep.csv`, `latency_sweep.csv`,
`durable_state_*.csv`, reproducing Section 7.6/7.7/7.9): the SQLite
durable-state and idempotent-retry experiment reproduced every qualitative
claim: exactly 25 of 100 $20 operations approved against a $500 budget under
all three worker-thread counts, no over-budget commit ever recorded, the
ten "retain the uncertain reservation" trials never issued a duplicate
payment, and all ten "release it" negative-control trials did. Drift-sweep
fetch counts follow the same shape as Fig. 3 (Full flat at every source
count; Residual/CWR flat at two once independence is reached). Latency
numbers are **not comparable in absolute terms**: this benchmark times pure
in-memory set arithmetic, whereas the manuscript's timer also covers real
Ed25519 signature verification and loopback HTTP, so its numbers (single-digit
milliseconds) are roughly two orders of magnitude larger than this
reproduction's (tens of microseconds). The relative ordering across variants
is preserved.

**DFMR benchmark (`dfmr_benchmark_runs.csv`, `dfmr_benchmark_summary.json`,
reproducing Table 4 / Section 7.3):** this is the closest match of the five.
DFMR: mean cost 5.20 / 1.22 queries (paper: 5.14 / 1.22). CWR ALLOW-subset
mean cost 5.10 / 1.45 queries (paper: 5.06 / 1.43); DENY-subset step-up rate
100% at mean cost 27.9 / 6.77 queries (paper: 26.90 / 6.84), reproducing the
paper's central claim that CWR is one-sided and correctly declines to
certify DENY. The ALLOW/DENY world split (514/486) is close to the paper's
(523/477).

## Files

- `factorial_workload_runs.csv` / `_summary.csv` / `_summary.json`
- `planning_instances.csv` / `planning_summary.json`
- `structural_checks_summary.json`
- `drift_sweep.csv`, `latency_sweep.csv`, `durable_state_budget.csv`,
  `durable_state_idempotency.csv`, `performance_state_summary.json`
- `dfmr_benchmark_runs.csv` / `dfmr_benchmark_summary.json`
- `run_all_index.json`, `run_all_environment.json`
