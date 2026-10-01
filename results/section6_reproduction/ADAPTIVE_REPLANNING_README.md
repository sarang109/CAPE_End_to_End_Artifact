# CWR adaptive-replanning realized cost (supplementary, additive)

New, supplementary work. Does not modify `gateway.py`, `payee_gateway.py`,
`algorithms.py`, `scalability_benchmark.py`, or any of their already-published
results -- it only adds two new files: `adaptive_replanning_runs.csv` and
`adaptive_replanning_summary.json`.

## Why

`cwr_plan`'s minimum-cost guarantee is proven for a single planning call:
*given* candidates that will report positive, this is the minimum cost that
certifies the predicate. `gateway.py`'s actual use of it is adaptive: plan,
query, and if a source comes back negative or unavailable, replan over what's
left. A reviewer pass noted the theorem doesn't cover the realized cost of
that full adaptive loop when early guesses are wrong. This benchmark measures
it directly: for generated instances, a fresh (not imported from
`gateway.py`) implementation of the same replanning loop runs against a
hidden ground truth, and its realized total query cost (including wasted
queries against sources that turned out negative) is compared to `cwr_plan`'s
own single-shot minimum computed with full foreknowledge of which candidates
are truly positive -- an honest **lower bound** on any strategy's cost, not a
claim that this is the optimal achievable adaptive cost.

Three adversary levels generate the ground truth: `benign` (everything truly
positive, sanity check), `random` (each candidate positive with probability
0.7, independently), and `adversarial` (the cheapest 60% of candidates --
the ones CWR's planner would prefer first -- are deliberately made falsely
negative). Reproduce with:

```bash
.venv/Scripts/python.exe -m cape_artifact.section6_reproduction.adaptive_replanning_benchmark
```

## Results

**Sanity check passes exactly.** Under `benign` (every candidate truly
positive), realized cost equals the theoretical minimum in all 348 resolved
instances (`overhead_ratio` = 1.0, 0 wasted queries) -- confirming the
adaptive loop reduces to the single-shot case when nothing ever comes back
negative, as it should.

**Random negative outcomes cost a modest, bounded overhead.** Under `random`
(70% true-positive rate per candidate), CWR resolved to ALLOW in 306 of 360
instances, at a median 1.09x and mean 1.27x the theoretical minimum (max
3.0x), averaging 0.93 wasted queries per instance. The remaining 54
instances correctly `STEP_UP` rather than force a certificate through
insufficient true positives.

**An adversary targeting CWR's own cheapest picks roughly doubles realized
cost.** Under `adversarial` (the planner's preferred low-cost candidates
deliberately falsified), CWR still resolved to ALLOW in 266 of 360 instances,
but at a median 1.91x and mean 2.00x the theoretical minimum (max 3.375x),
averaging 4.14 wasted queries per instance -- direct, measured evidence that
the single-shot theorem's minimum-cost guarantee does not, by itself, bound
the realized cost of adaptive execution against an adversary who can
influence which sources return positive, and a first empirical
characterization of how large that gap can get in this evidence model.

## Files

- `adaptive_replanning_runs.csv`: per-instance domain/fault-budget/candidate
  configuration, adversary level, theoretical minimum cost, realized cost,
  verdict, wasted-query count, replanning round count, and overhead ratio.
- `adaptive_replanning_summary.json`: per-adversary-level aggregate
  resolution counts and overhead-ratio statistics.
