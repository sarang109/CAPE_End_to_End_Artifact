# Multi-predicate joint evidence planning (supplementary, additive)

New capability, not just new results. Does not modify `algorithms.py`'s
existing `cwr_plan`/`dfmr_choose_next` behavior (verified: the shared bitmask
solver they now both delegate to reproduces the exact same values, and the
existing 450-instance CWR-vs-exhaustive correctness sweep still shows 100%
agreement after the refactor), `gateway.py`, or `payee_gateway.py`.

## Why

A reviewer pass noted real commerce policies often combine several
conditions at once (category, merchant, geography, recurring-payment
status, ...), while this artifact evaluates one boolean predicate at a
time. Running the existing `cwr_plan`/`dfmr_choose_next` once per predicate
and ANDing the verdicts is already possible with the unmodified code -- not
a new capability, just composition. `src/cape_artifact/joint_algorithms.py`
adds the capability composition cannot express: when a source's evidence is
relevant to more than one predicate at once, a joint planner can let one
query count toward more than one predicate's certificate, for one cost.

## What was built

- `JointCandidate`, `joint_positive_certificate`, `joint_bilateral_decision`
  (ALLOW iff every predicate ALLOWs; DENY if any predicate is
  DENY-certified; else STEP_UP), `joint_cwr_plan`, `joint_dfmr_choose_next`.
- A backward-compatible refactor of `algorithms.py`: `cwr_plan`'s bitmask
  min-cost-exact-cover solver is now a shared `_min_cost_exact_cover`
  helper, reused unchanged by `joint_cwr_plan` over a combined,
  per-predicate-offset hypothesis space, instead of duplicating the DP.
- `tests/test_joint_algorithms.py`: hand-crafted cases plus a **brute-force
  joint-exhaustive cross-check** (mirroring
  `scalability_benchmark.py`'s `_exhaustive_plan` pattern) across 120
  randomly generated 2- and 3-predicate instances -- 0 mismatches.
- `src/cape_artifact/joint_gateway_demo.py`: a proof-of-concept combining
  the real, unmodified `payee_gateway.PAYEE_SOURCES` with a small,
  same-shape illustrative category evidence set and **one new, explicitly
  illustrative** shared source (a hypothetical merchant-and-payee
  directory) -- this artifact's two existing evidence topologies are
  otherwise disjoint, confirmed by reading both.

Reproduce with:

```bash
.venv/Scripts/python.exe -m unittest tests.test_joint_algorithms tests.test_joint_gateway_demo -v
.venv/Scripts/python.exe -m cape_artifact.joint_gateway_demo
```

## Results

The exhaustive cross-check found **zero mismatches across 120 random
instances** (2- and 3-predicate, varying domain/candidate/fault-budget
configurations) -- `joint_cwr_plan` matches brute-force search on cost and
feasibility. In the proof-of-concept demo (fault budget 1), planning
category and payee independently costs 3 + 3 = 6; planning them jointly,
letting the one hypothetical shared source count toward both predicates'
certificates, costs 5 -- a saving of exactly the shared source's own cost
(1), because the joint plan pays for it once instead of twice. This is a
demonstration of the mechanism, not a measurement of how much joint
planning would save in this artifact's *current* real topologies, which do
not actually share a source today.

## Files

No new `results/` files -- this phase's evidence is the test suite's
exhaustive-agreement result and the demo's own printed output (see
`src/cape_artifact/joint_gateway_demo.py`, run directly for the numbers
above).
