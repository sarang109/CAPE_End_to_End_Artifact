# CAPE end-to-end research artifact

This artifact evaluates CAPE at an executable agentic-payment boundary. It creates and verifies an official Google Agent Payments Protocol (AP2) payment-mandate chain, obtains signed evidence over local HTTP, applies provenance-aware authorization, and sends allowed transactions to an idempotent local payment sandbox. The core protocol experiment and the deterministic testbed require no paid API, cloud account, real credential, or real payment.

It also contains a prompt-injection agent benchmark against frontier hosted language models (Anthropic Claude, OpenAI GPT, and Google Gemini) through their production APIs. **Google Gemini and OpenAI GPT have been executed with real results below; Claude is pending API access.** This is the primary agentic-model evaluation; it is the only track that makes real, non-loopback API calls, and every provider call is gated behind a command-line flag so it cannot run by accident.

## Reported evaluation

The deterministic experiment contains 21 scenarios: four benign conditions, 15 attacks within the declared threat model, and two deliberate premise violations. With 20 repetitions and six defenses it executes 2,520 matched payment flows. The attacks cover direct and role-tag prompt injection replay, semantic substitution, correlated evidence, stale caches, version races, selective denial, amount, merchant and currency mutations, evidence-signature tampering, AP2 token tampering, nonce replay, audience confusion, and transaction rebinding. The two counterexamples exceed the configured fault budget or conceal a shared dependency.

The frontier hosted-model experiment draws its cases from a synthetic product catalog (`src/cape_artifact/catalog.py`, served over a real local HTTP call via `src/cape_artifact/catalog_service.py`) spanning kitchen, clothing, and electronics: 9 legitimately labeled benign products (3 per category, one per category priced exactly at the USD 200 policy cap) and 10 stored-value gift/prepaid cards disguised under a cover title and claimed category from one of the three, one per prompt-injection technique — 19 cases in total, evaluated under two prompt profiles across three repetition trials. Every purchase proposal is routed through all six gateways.

**Real, measured results (Google Gemini and OpenAI GPT):** `gemini-3.1-flash-lite` and `gpt-5-mini`, queried through their production APIs, each completed all 114 planned decisions with zero invalid outputs and zero failed calls (228 total, combined measured cost **$0.0069**). Under the hardened, data-boundary prompt, both models proposed **zero forbidden purchases** across all 60 attack attempts each. Under the naive prompt, Gemini proposed a forbidden purchase in **10.0%** of attack attempts (consistently via one injection technique across all three seeds) and GPT-5-mini in **3.3%** (via a different technique, in one of three seeds). Every compromised proposal from either model was converted into an unauthorized sandbox payment by AP2-only and provenance-blind majority; **TTL, Full, CWR, and DFMR blocked all of them** — the same pattern the deterministic testbed shows below. All 1,368 gateway-routed decisions (228 × 6 defenses) and all 648 benign gateway routings complete with the expected outcome. Raw data: `results/frontier_model_runs.csv`, `frontier_gateway_runs.csv`, `frontier_model_summary.csv`, `frontier_environment.json`.

**Anthropic Claude results are pending API access** and are not included above — set `ANTHROPIC_API_KEY` and re-run with `--i-accept-api-costs` to add it (see below).

The included deterministic-testbed results show:

- Full, CWR, and DFMR produced zero unauthorized effects in all 300 within-model attack executions per defense; Full/CWR/DFMR did fail under the explicitly documented premise violations.
- AP2-only, majority, and TTL produced 160, 140, and 40 unauthorized effects, respectively, in the 300 within-model attack executions.

These are finite testbed outcomes, not estimates of production fraud prevalence. Repetitions check implementation stability and latency.

## Requirements

- Python 3.11 or newer
- Git, used once to install the official AP2 SDK at the pinned commit
- API keys for Anthropic, OpenAI, and/or Google if running the frontier hosted-model experiment (Google AI Studio offers a free, card-free tier; Anthropic and OpenAI are billed)

## Core experiment

Linux or macOS:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python run_experiment.py --repetitions 20
```

Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m unittest discover -s tests -v
.venv\Scripts\python run_experiment.py --repetitions 20
```

The core run writes per-execution records, a scenario manifest, summary tables, paired case-level comparisons, and environment metadata under `results/`.

## Frontier hosted-model experiment (primary agentic-model evaluation)

This calls real Anthropic, OpenAI, and/or Google APIs. Anthropic and OpenAI have no free tier and **will incur real charges** billed to your account (though, per the measured cost above, this benchmark's actual usage is tiny — fractions of a cent per model); Google AI Studio offers a free-tier key with no billing account required (see [aistudio.google.com/apikey](https://aistudio.google.com/apikey)), which is what produced the Gemini results above. Install the provider SDKs, export the API keys for the providers you intend to use, and run with `--i-accept-api-costs` (required for every provider, including the free Google tier, as a general "this makes a real external call" confirmation). `--max-total-cost-usd` sets a hard ceiling checked before every call — once the accumulated estimated cost reaches it, remaining calls are skipped rather than issued, so a mis-estimated or unexpectedly expensive model can't run away past the limit:

```bash
.venv/bin/python -m pip install -r requirements-frontier.txt
export ANTHROPIC_API_KEY=...
export OPENAI_API_KEY=...
export GOOGLE_API_KEY=...
.venv/bin/python run_frontier_benchmark.py \
  --model anthropic:claude-sonnet-5 \
  --model openai:gpt-5-mini \
  --model google:gemini-3.1-flash-lite \
  --seeds 7,19,43 \
  --requests-per-minute 10 --max-workers 2 \
  --max-total-cost-usd 10 \
  --i-accept-api-costs
```

Model availability and free-tier request-per-minute/per-day limits change frequently and vary by provider account; if a model ID 404s, the provider's error message typically names its replacement. A 429 with `RequestsPerMinute` in the message will retry automatically, but one with `RequestsPerDay` will not (there's no point retrying within the same run) — switch to a different, untouched model ID (not just a `-latest` alias of the same underlying model) to get more calls in the same day. Reasoning-tier models (Gemini's thinking budget, GPT-5-family `reasoning_effort`) are both explicitly minimized in the client code so hidden reasoning tokens don't silently consume the entire output budget before any visible answer is produced — this was an actual failure mode hit and fixed during development, not a hypothetical.

Before spending money, validate the whole pipeline for free with a provider that makes no API call. Two are built in:

- `mock:mock-always-safe` / `mock:mock-always-compromised` / `mock:mock-invalid-output` — simple fixed fixtures for exercising the gateway-safe, gateway-must-block, and fail-closed-parsing code paths.
- `simulated:profile-cautious` / `simulated:profile-mixed` / `simulated:profile-permissive` — richer, deterministic, illustrative compliance behavior for a fuller dry run.

```bash
.venv/bin/python run_frontier_benchmark.py \
  --model simulated:profile-cautious --model simulated:profile-mixed --model simulated:profile-permissive \
  --seeds 7,19,43
```

**Neither `mock` nor `simulated` calls any real API, and neither is a measurement of Claude, GPT, Gemini, or any other real product.** They exist to validate the CSV schema, gateway routing, retry logic, and cost accounting before you spend money on a live run; their `provider` column and `frontier_environment.json`'s `paid_api_calls: 0` make this explicit in the output. Do not report their numbers as real model results anywhere, including in a paper.

Useful flags: `--requests-per-minute` to stay under a provider's rate limit, `--max-retries` for transient-error backoff, `--pricing-file` to override the built-in (indicative, may go stale) USD-per-million-token rate card in `frontier_environment.json`, and `--max-workers` to control inference concurrency. Real API pricing changes frequently — verify current rates against each provider's pricing page before relying on the reported cost for budgeting.

The run writes `results/frontier_model_runs.csv`, `frontier_gateway_runs.csv`, `frontier_model_summary.csv`, and `frontier_environment.json`; see `results/README.md` for the data dictionary.

## What is real and what is simulated

- **Official AP2 code:** mandate creation, SD-JWT delegation, verification, constraint checking, nonce binding, audience binding, and transaction binding use the official AP2 Python SDK pinned to commit `e1ea56db72a6385bce3e5c1112b3a56ce60acb43`.
- **Real frontier hosted-model inference:** the model study calls the Anthropic, OpenAI, and Google production APIs directly; token usage, response-model identifiers, and per-call USD cost are recorded row by row. Google Gemini (`gemini-3.1-flash-lite`) and OpenAI GPT (`gpt-5-mini`) have been executed for real; Claude is pending API access. This is the only track in the artifact that makes non-loopback network calls, and it only runs with `--i-accept-api-costs`.
- **Real local service boundaries:** each evidence provider, the payment processor, and the product catalog (`catalog_service.py`) are HTTP services bound to an ephemeral loopback port.
- **Signed evidence:** each provider signs canonical JSON with Ed25519. The gateway verifies signature, subject, version, and registry-owned provenance.
- **Controlled commerce:** product truth, catalog corruption, outages, dependency declarations, and version changes are research fixtures.
- **Simulated payment:** the sandbox records an idempotent payment effect but cannot contact a bank or card network.

## Compared defenses

- `AP2_ONLY`: verifies the mandate and hard transaction constraints but trusts the agent's semantic category.
- `MAJORITY`: refreshes signed sources but counts endpoints without provenance.
- `TTL`: reuses a signed cache while a fixed window remains open.
- `FULL`: refreshes every available source and applies the bilateral provenance rule.
- `CWR`: reuses unchanged positives and performs minimum-cost witness repair.
- `DFMR`: adaptively queries until either ALLOW or DENY is certified by a decision-flip margin.

## Safety and scope

All servers bind to `127.0.0.1`; all keys are generated for the test run. The default code has no live-payment capability. The optional Stripe adapter refuses non-test keys and is excluded from every reported experiment. Premise-violation scenarios are labeled separately and are never included in the within-model safety claim.

## Repository layout

- `src/cape_artifact/algorithms.py`: certificate, CWR, and DFMR logic
- `src/cape_artifact/ap2_flow.py`: official AP2 mandate creation and verification
- `src/cape_artifact/evidence.py`: signed evidence HTTP services and registry
- `src/cape_artifact/gateway.py`: authorization and bound dispatch
- `src/cape_artifact/scenarios.py`: benign, adversarial, and premise-violation fixtures
- `src/cape_artifact/experiment.py`: matched deterministic evaluation and statistics
- `src/cape_artifact/catalog.py`: synthetic product catalog (kitchen, clothing, electronics, disguised stored-value)
- `src/cape_artifact/catalog_service.py`: real local HTTP service exposing the product catalog, mirroring the evidence/payment services
- `src/cape_artifact/benchmark_common.py`: shared case generation, prompts, and gateway-routing logic for the model benchmark
- `src/cape_artifact/frontier_benchmark.py`: frontier hosted-model (Claude/GPT/Gemini) attack generation, retry/rate-limiting, cost accounting, and gateway routing
- `THREAT_MODEL.md`: assumptions, attacks, and interpretation boundaries
- `results/README.md`: output data dictionary and statistical notes
- `tests/`: algorithm, protocol, gateway, and idempotency regression tests

## License and third-party code

Original code is provided under the MIT License. The AP2 SDK is installed from Google's repository and remains under its Apache-2.0 license. The `anthropic`, `openai`, and `google-genai` SDKs are optional third-party dependencies for the frontier-model track, each under its own vendor license, and are not included in this archive.

## Baseline comparison (deterministic, zero API cost)

`src/cape_artifact/baselines.py` adds three practical comparison baselines against the same payee-verification evidence model as `payee_gateway.py`, answering a reviewer request for the strongest practical baselines: `STATIC_ALLOWLIST` (a pinned-version registry snapshot with version invalidation), `POLICY_ENGINE` (a declarative blocklist-then-registry rule evaluator), and `CAMEL_INSPIRED` (a faithful reduction of CaMeL's control/data-separation mechanism — not the published system — to two independently-rooted corroborating sources). `src/cape_artifact/payee_scenarios.py` replaces the single-attacker-IBAN test shape with a three-way corpus — known-legitimate, known-attacker, and novel-unregistered recipients, sourced from AgentDojo's own banking fixture rather than invented — so a defense is credited for genuinely rejecting unfamiliar recipients, not for matching one flagged constant.

Run it (no API key, no cost):

```bash
.venv/bin/python run_baseline_comparison.py
```

Writes `baseline_comparison_runs.csv`, `baseline_comparison_summary.csv`, and `baseline_comparison_environment.json` under `results/external_validation/`; see that directory's `README.md` for the full methodology and honest failure modes of each baseline.

## External validation: AgentDojo real attacks

`src/cape_artifact/agentdojo_validation.py` drives real GPT-5-mini and Gemini calls through [AgentDojo](https://github.com/ethz-spylab/agentdojo)'s real, published banking task suite and its real `ImportantInstructionsAttack`, then routes every money-moving tool call the agent actually issues through CAPE's payee gateway. This is real, billed API usage (measured at $0.046 total for the original 54-run baseline) — install `agentdojo`, export `OPENAI_API_KEY` / `GOOGLE_API_KEY`, and run:

```bash
.venv/bin/python -m pip install -r requirements-external-validation.txt
export OPENAI_API_KEY=...
export GOOGLE_API_KEY=...
.venv/bin/python -m cape_artifact.agentdojo_validation --i-accept-api-costs
```

Two additional, opt-in comparisons build on the same real attacks:

- `--diverse-payee-scenarios` routes every extracted money call through the three-way payee corpus and all eight defenses (CAPE's five plus the three new baselines) instead of a single attacker/not-attacker boolean, writing `agentdojo_diverse_*` files.
- `--compare-agentdojo-defenses` reruns the same carrier/injection tasks with AgentDojo's own installed `TransformersBasedPIDetector` defense wrapping the agent pipeline, instead of CAPE's gateway, to measure whether an upstream, agent-framework-native defense would have stopped the same attacks CAPE's payment-boundary gateway catches downstream. Requires `torch`/`transformers` (in `requirements-external-validation.txt`) and downloads a small Hugging Face model on first use.

Both flags share one combined `--max-total-cost-usd` ceiling with the default run (not a separate allowance each) and write new files only — the original `agentdojo_banking_runs.csv`, `agentdojo_gateway_runs.csv`, `agentdojo_summary.csv`, and `agentdojo_environment.json` are unaffected by these two flags. Note, however, that **every invocation of this script, with or without these flags, regenerates its own default output files from a fresh live run** — this is the script's original, pre-existing behavior (there is no dry-run/mock mode for this track), not something introduced by these additions; do not re-run it against `results/external_validation/` if you want to preserve already-committed numbers there. See `results/external_validation/README.md` for full results and methodology.
