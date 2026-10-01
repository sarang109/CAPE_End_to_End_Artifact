# Realistic cost/latency simulation (supplementary, additive)

New, supplementary work. Reads `results/end_to_end_runs.csv` **read-only**
and does not modify it, `gateway.py`, or any other already-published result
-- it only adds two new files: `realistic_cost_model_runs.csv` and
`realistic_cost_model_summary.json`.

## Why

The manuscript's cost model is dimensionless and additive
(`query_cost = sum(source.cost)`), with no representation of parallel
queries, network-tail latency, per-source failure probability, or retries.
This module layers an explicitly **simulated** (not measured) realistic
latency estimate on top of the existing results, using each row's
already-recorded `defense` and `queries` count. All parameters
(lognormal latency median/shape, failure probability, retry multiplier) are
named, documented illustrative assumptions -- see
`src/cape_artifact/section6_reproduction/realistic_cost_model.py`'s
docstring for the exact values and reasoning, including the one real
modeling choice this makes: `CWR`/`FULL`/`MAJORITY`/`TTL`'s "query every
source" style is modeled as one parallel batch (latency = the slowest call,
not the sum), while `DFMR`'s adaptive one-at-a-time queries are modeled as
strictly sequential.

Reproduce with:

```bash
.venv/Scripts/python.exe -m cape_artifact.section6_reproduction.realistic_cost_model
```

## Results

Under this simulation, mean estimated realistic latency is **125.96 ms for
CWR** vs. **233.61 ms for DFMR** -- DFMR's sequential querying costs roughly
twice CWR's parallel-batch latency on average in this model, a distinction
the abstract additive cost model cannot express at all (both would just sum
per-source costs identically regardless of whether queries could run
concurrently). `FULL` and `MAJORITY` (233.13 ms / 227.26 ms mean) are
similar to each other since both query every source in one batch; `AP2_ONLY`
and `TTL` show 0 ms in this sample (no fresh queries were issued in any
recorded row for either). This is a simulation meant to make the abstract
model's blind spot visible and quantifiable, not a claim about real network
behavior.

## Files

- `realistic_cost_model_runs.csv`: per-row abstract cost/latency alongside
  the new simulated realistic latency.
- `realistic_cost_model_summary.json`: the documented assumption parameters
  and per-defense simulated-latency statistics.
