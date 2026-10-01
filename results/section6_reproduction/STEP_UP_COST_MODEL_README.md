# STEP_UP / human-confirmation cost simulation (supplementary, additive)

New, supplementary work. Reads `results/end_to_end_runs.csv` **read-only**
and does not modify it or any other already-published result -- it only
adds two new files: `step_up_cost_model_runs.csv` and
`step_up_cost_model_summary.json`.

## Why

The manuscript never measures how often human confirmation succeeds after a
`STEP_UP`, or how long it takes -- and no real user study exists in this
artifact to measure it from. Rather than invent numbers and present them as
measured, this module builds an explicitly labeled **simulation**: a
lognormal confirmation-latency model (median 45s) and an assumed 92%
eventual-resolution probability, both stated as illustrative assumptions,
not measurements, in `step_up_cost_model.py`'s docstring. Applied to every
`STEP_UP` row in the existing results. Reproduce with:

```bash
.venv/Scripts/python.exe -m cape_artifact.section6_reproduction.step_up_cost_model
```

## Results

57 of the deterministic experiment's rows resolved to `STEP_UP`. Under this
simulation, mean confirmation latency ranges from 65.98s (`CWR`, 27 rows) to
126.30s (`MAJORITY`, only 3 rows -- too few to be a stable estimate);
simulated resolved rate ranges from 88.89% (`CWR`) to 100% (`FULL`,
`MAJORITY`). These differences are artifacts of this sample's random draws
under one fixed set of illustrative parameters, not a claim that any
defense's step-ups are intrinsically easier or harder for a human to
resolve -- the model applies the *same* latency/success distribution to
every defense's step-up rows. The point of this file is to make "the cost
of STEP_UP is currently unmeasured" a quantified, labeled placeholder rather
than a silent gap; replacing these assumptions with a real user study
remains future work.

## Files

- `step_up_cost_model_runs.csv`: per-STEP_UP-row simulated confirmation
  latency and resolution outcome.
- `step_up_cost_model_summary.json`: the documented assumption parameters
  and per-defense simulated statistics.
