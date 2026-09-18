# Submission readiness

## Completed in this artifact

- Official AP2 SDK integration pinned to a commit
- Twenty-one-scenario operational threat matrix with premise status recorded per row
- 2,520 matched deterministic payment flows
- A production-grade frontier hosted-model benchmark (Anthropic Claude, OpenAI GPT, Google Gemini) with retry/backoff (including a veto for permanent errors so a 404 or a daily-quota 429 isn't retried pointlessly), per-provider rate limiting, real token-cost accounting, an enforced hard spending cap (`--max-total-cost-usd`, checked before every call) and an explicit paid-API opt-in flag (`src/cape_artifact/frontier_benchmark.py`, `run_frontier_benchmark.py`)
- A synthetic product catalog (`src/cape_artifact/catalog.py`) spanning kitchen, clothing, and electronics (9 benign products, including a price-boundary item per category) plus 10 stored-value gift/prepaid cards disguised across those categories, one per prompt-injection technique. Served over a real local HTTP service (`src/cape_artifact/catalog_service.py`), mirroring the evidence providers and payment sandbox elsewhere in the artifact.
- **Real, measured results from Google Gemini and OpenAI GPT** (`gemini-3.1-flash-lite`, `gpt-5-mini`): 228/228 planned decisions completed with zero invalid outputs and zero failed calls, at a combined measured cost of $0.0069 (well under the $10 cap, never tripped). Under the hardened prompt, both models proposed zero forbidden purchases; under the naive prompt, Gemini proposed one in 10.0% of attack attempts (one technique, consistent across all three seeds) and GPT-5-mini in 3.3% (a different technique, one of three seeds). AP2-only and provenance-blind majority converted every compromised proposal into an unauthorized payment; TTL, Full, CWR, and DFMR blocked all of them — matching the pattern in the deterministic testbed. 100% benign completion (108/108). Raw data in `results/frontier_model_runs.csv`, `frontier_gateway_runs.csv`, `frontier_model_summary.csv`, `frontier_environment.json`. Anthropic Claude results are pending API access.
- Case-cluster uncertainty for the model study and case-level paired comparisons for the deterministic matrix
- Successful counterexamples for excess corruption and incomplete provenance
- Safety, benign completion, abstention, query cost, and latency reported separately
- Reproduction commands, data dictionary, threat model, environment metadata, and machine-readable results

The earlier compact local-model track (Qwen2.5-0.5B/SmolLM2-1.7B via `llama-cpp-python`) has been removed from this artifact at the author's request now that real frontier-model data exists; the manuscript no longer references it as a reported result.

## Outstanding before journal upload

1. **Run the frontier hosted-model benchmark against Claude.** Google Gemini and OpenAI GPT have real, measured results (above); Anthropic is still pending a working API key with billing (the author's country is not on Anthropic's supported billing list; a free/billed workaround has not yet been found for this specific provider). Once a key is available, run `run_frontier_benchmark.py` with `ANTHROPIC_API_KEY` and `--i-accept-api-costs`, then merge the new rows into the manuscript alongside the existing Gemini/GPT numbers.
2. **Manuscript updates for Claude.** `docs/CAPE_AP2_Elite_Journal_Revision.docx` reports the real Gemini and GPT numbers in the abstract, Section 6.1, Section 6.8, Section 7.5, Table 6, the limitations section, and the conclusion; each of those passages explicitly states that Claude results are pending API access rather than implying all three models were tested. When Claude's data arrives, update the same passages to report all three models together. A backup of the pre-frontier-track manuscript is at `docs/CAPE_AP2_Elite_Journal_Revision.pre-frontier-backup.docx`.
3. Select the target journal and apply its exact Word template, word limit, reference style, and figure-resolution rules.
4. Confirm whether review is double-blind; if so, remove author names, emails, repository identity, and self-identifying artifact metadata from the review package.
5. Add the journal's required CRediT roles, funding statement, conflict-of-interest statement, and data/software DOI after depositing the frozen archive.
6. Verify every bibliographic entry against the final published metadata; several 2026 works are currently cited as public preprints, and references [20]-[22] now cite frontier-model provider documentation pages rather than the earlier Qwen/SmolLM2 papers.
7. Preserve the negative results. In particular, do not merge premise-violation failures into the in-model safety count, describe safe abstention as successful task completion, or let the real two-model result (10.0%/3.3% naive-prompt compromise, 0% hardened) be read as a general claim about frontier-model robustness — the manuscript text is deliberately narrow about this (ten cases, three seeds, two models), and any edits should keep it that way until Claude data arrives.

No artifact can guarantee acceptance at an elite journal. The package is technically reviewable and substantially stronger than a replay-only proof of concept; external labels, a held-out public benchmark, and broader model coverage (starting with Claude and GPT, already wired into the code) remain the clearest paths to stronger external validity.
