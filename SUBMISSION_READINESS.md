# Submission readiness

## Completed in this artifact

- Official AP2 SDK integration pinned to a commit
- Twenty-one-scenario operational threat matrix with premise status recorded per row
- 2,520 matched deterministic payment flows and 936 model-to-gateway records
- Two named, hashed, free/local models with raw outputs and decoding settings
- Case-cluster uncertainty for the model study and case-level paired comparisons for the designed matrix
- Successful counterexamples for excess corruption and incomplete provenance
- Safety, benign completion, abstention, query cost, and latency reported separately
- Thirteen passing regression tests, including mandate binding and processor idempotency
- Reproduction commands, data dictionary, threat model, environment metadata, and machine-readable results

## Author actions before journal upload

1. Select the target journal and apply its exact Word template, word limit, reference style, and figure-resolution rules.
2. Confirm whether review is double-blind; if so, remove author names, emails, repository identity, and self-identifying artifact metadata from the review package.
3. Add the journal's required CRediT roles, funding statement, conflict-of-interest statement, and data/software DOI after depositing the frozen archive.
4. Verify every bibliographic entry against the final published metadata; several 2026 works are currently cited as public preprints.
5. Decide whether to make the small-model experiment a main result or an explicitly exploratory appendix. It improves practicality but does not replace a frontier-model or public shopping benchmark evaluation.
6. Preserve the negative results. In particular, do not merge premise-violation failures into the in-model safety count or describe safe abstention as successful task completion.

No artifact can guarantee acceptance at an elite journal. The package is technically reviewable and substantially stronger than a replay-only proof of concept; external labels, a held-out public benchmark, and broader model coverage remain the clearest paths to stronger external validity.
