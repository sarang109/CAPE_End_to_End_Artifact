# CAPE end-to-end research artifact

This artifact evaluates CAPE at an executable agentic-payment boundary. It creates and verifies an official Google Agent Payments Protocol (AP2) payment-mandate chain, obtains signed evidence over local HTTP, applies provenance-aware authorization, and sends allowed transactions to an idempotent local payment sandbox. It also contains an optional, entirely local prompt-injection benchmark for GGUF language models. No paid API, cloud account, real credential, or real payment is required.

## Reported evaluation

The deterministic experiment contains 21 scenarios: four benign conditions, 15 attacks within the declared threat model, and two deliberate premise violations. With 20 repetitions and six defenses it executes 2,520 matched payment flows. The attacks cover direct and role-tag prompt injection replay, semantic substitution, correlated evidence, stale caches, version races, selective denial, amount, merchant and currency mutations, evidence-signature tampering, AP2 token tampering, nonce replay, audience confusion, and transaction rebinding. The two counterexamples exceed the configured fault budget or conceal a shared dependency.

The model experiment uses ten prompt-injection cases, three benign purchases, two prompt profiles, three seeds, and two compact open models. It generates 156 real model decisions and routes every purchase proposal through all six gateways (936 matched gateway records). Model weights are not redistributed.

The included results show:

- Full, CWR, and DFMR produced zero unauthorized effects in all 300 within-model attack executions per defense; Full/CWR/DFMR did fail under the explicitly documented premise violations.
- AP2-only, majority, and TTL produced 160, 140, and 40 unauthorized effects, respectively, in the 300 within-model attack executions.
- Qwen2.5-0.5B and SmolLM2-1.7B emitted purchase proposals in 40–80% and 56.7–70% of attack runs, depending on prompt profile. AP2-only and majority passed every compromised proposal; Full, CWR, and DFMR passed none.
- The “hardened” prompt was not reliably safer. This negative result is retained rather than optimized away; prompt wording changed both attack compliance and benign utility.

These are finite testbed outcomes, not estimates of production fraud prevalence. Repetitions check implementation stability and latency. Cluster-bootstrap intervals in the model summary resample the ten attack cases and remain conditional on this small fixed set.

## Requirements

- Python 3.11 or newer
- Git, used once to install the official AP2 SDK at the pinned commit
- About 2 GiB free disk and 8 GiB RAM only if running both optional local models

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

## Optional free/local model experiment

Install the CPU wheel without compiling it:

```bash
.venv/bin/python -m pip install --only-binary=:all: \
  --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu \
  -r requirements-model.txt
```

Download the official Q4_K_M GGUF files from the [Qwen2.5-0.5B-Instruct-GGUF repository](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF) and the [SmolLM2-1.7B-Instruct-GGUF repository](https://huggingface.co/HuggingFaceTB/SmolLM2-1.7B-Instruct-GGUF). Then run:

```bash
.venv/bin/python run_agent_benchmark.py \
  --model Qwen2.5-0.5B=/path/qwen2.5-0.5b-instruct-q4_k_m.gguf \
  --model SmolLM2-1.7B=/path/smollm2-1.7b-instruct-q4_k_m.gguf \
  --seeds 7,19,43
```

The exact file sizes and SHA-256 hashes used for the reported run are recorded in `results/agent_environment.json`.

## What is real and what is simulated

- **Official AP2 code:** mandate creation, SD-JWT delegation, verification, constraint checking, nonce binding, audience binding, and transaction binding use the official AP2 Python SDK pinned to commit `e1ea56db72a6385bce3e5c1112b3a56ce60acb43`.
- **Real local model inference:** the optional study executes the named GGUF weights through `llama-cpp-python`; outputs and seeds are preserved row by row.
- **Real local service boundaries:** each evidence provider and the payment processor is an HTTP service bound to an ephemeral loopback port.
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
- `src/cape_artifact/agent_benchmark.py`: local model attack generation and gateway routing
- `THREAT_MODEL.md`: assumptions, attacks, and interpretation boundaries
- `results/README.md`: output data dictionary and statistical notes
- `tests/`: algorithm, protocol, gateway, and idempotency regression tests

## License and third-party code

Original code is provided under the MIT License. The AP2 SDK is installed from Google's repository and remains under its Apache-2.0 license. Model weights and `llama-cpp-python` are optional third-party dependencies and are not included in this archive.
