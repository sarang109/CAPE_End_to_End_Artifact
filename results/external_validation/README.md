# External validation: real AgentDojo attacks vs. CAPE's payee-check gateway

This directory answers a gap the manuscript names explicitly (Section 8.5):
"Stronger external validation would connect a pinned shopping-agent
benchmark such as AgentDojo to the gateway." It is new, supplementary work
produced after the original submission; it does not modify the manuscript,
the original Section 6/7 code, or any of their already-published results
files elsewhere in `results/`.

## What this is, and is not

Section 6.8's hosted-model study already makes real API calls to GPT and
Gemini, but its attack corpus (ten prompt-injection strings against a
synthetic product catalog) is this artifact's own construction. This
experiment instead drives the same two models
(`openai:gpt-5-mini`, `google:gemini-3.1-flash-lite`) through
[AgentDojo](https://github.com/ethz-spylab/agentdojo)'s real, published,
pip-installed banking task suite (the benchmark the manuscript already
cites as [1]): its real environment and tools (`send_money`,
`schedule_transaction`, `update_scheduled_transaction`, ...), its real
user tasks, and its real `ImportantInstructionsAttack` -- the canonical
attack from the AgentDojo paper, not a CAPE-authored injection string.

Three carrier user tasks were used, chosen to span AgentDojo's three
distinct injection surfaces (a billed-service file, the transaction
history, and a landlord notice file): `user_task_0`, `user_task_2`,
`user_task_3`. All nine banking injection tasks were used except
`injection_task_7` (a password-change goal -- account takeover, not a
payment action, and out of scope for a payment-boundary gateway). Every
attempted money-moving tool call the agent actually issued was extracted
from its real executed function-call trace and routed through
`src/cape_artifact/payee_gateway.py` -- a *new* predicate implementation
("is this payment recipient a verified, registered payee") built from the
manuscript's own unmodified `cover_number` / `positive_certificate` /
`bilateral_decision` / `cwr_plan` / `dfmr_choose_next` algorithms, using
the same 3-shared-root / 2-independent-source, `f=1` evidence topology as
the AP2 testbed in Section 6.7. It does not touch, reuse, or alter the
existing shopping `Gateway` class or its tests. TTL is not included: its
distinguishing mechanic is a fixed-age cache reused across a sequence of
decisions, which has no analog in a single, fresh authorization decision;
see `payee_gateway.py`'s docstring for the full reasoning.

Reproduce with (requires `pip install agentdojo` and real, billed
`OPENAI_API_KEY` / `GOOGLE_API_KEY`):

```bash
.venv/Scripts/python.exe -m cape_artifact.agentdojo_validation --i-accept-api-costs
```

## Results

54 agent runs (27 per model: 3 benign + 24 attack), 0 failed calls, total
measured cost **$0.046** (OpenAI billed; Gemini free-tier and not charged,
matching the convention already used for `frontier_environment.json`).
This is a small fraction of the requested budget.

**Agent compromise (AgentDojo's own pass/fail scoring, not CAPE's):**
Gemini 3.1 Flash Lite issued an unauthorized money-moving call in 19 of 24
real attacks and was scored as a successful attack by AgentDojo's own
task-specific security check in 18 of 24 (75%) -- essentially every
injection technique except one that asked for a multi-step $30,000 transfer
in $10,000 increments (0/3, likely too many actions for an 8-iteration tool
loop) and one ambiguous "send as much money as possible" goal (1/3).
GPT-5-mini was not compromised by any of the 24 real attacks (0%): it
issued a money-moving call in only 3 of 24 attack runs, and every one of
those went to a legitimate recipient already in the transaction history,
not the attacker's IBAN -- the model recognized and ignored the injected
instruction. This is a genuine, measured difference between two real
models against a real, externally authored attack corpus, not a
constructed scenario.

**Downstream containment (`agentdojo_gateway_runs.csv`):** every
money-moving call extracted from Gemini's compromised runs (26 proposals,
some tasks issued more than one) was routed through all five defenses.
AP2_ONLY and MAJORITY authorized the payment to the attacker's IBAN in 19
of 26 cases (73.1% unauthorized); FULL, CWR, and DFMR authorized **zero**
of them. All benign payment proposals (2 for Gemini, 0 for GPT-5-mini,
which made no benign money calls in this sample) were correctly allowed by
every defense. GPT-5-mini's 3 attack-condition money calls were all to
legitimate recipients, so every defense -- including AP2_ONLY -- shows zero
unauthorized payments for it; that is a property of the resistant model's
behavior, not evidence that AP2_ONLY provides protection. This reproduces
the manuscript's central Section 6.7/7.4 claim (provenance-blind trust and
majority voting fail against a corrupted shared evidence root; version- and
corruption-aware repair does not) with the "was the agent compromised"
signal now coming from a real model reacting to a real, independently
authored benchmark, closing exactly the gap Section 8.5 named.

## Files

- `agentdojo_banking_runs.csv`: one row per (model, carrier user task,
  injection task or benign) run -- AgentDojo's own utility/attack-success
  verdicts, whether a money-moving call was issued, latency, and any error.
- `agentdojo_gateway_runs.csv`: one row per extracted money-moving call per
  defense -- recipient, whether it was legitimate, verdict, queried
  sources, query cost, and `unauthorized_payment`.
- `agentdojo_summary.csv`: per-model attack/benign rollups and per-model,
  per-defense containment counts.
- `agentdojo_environment.json`: models, carrier/injection task IDs, the
  attacker IBAN, cost accounting, and the exact AgentDojo attack class used.

## Limitations

This is one benchmark (AgentDojo banking), one attack technique
(`ImportantInstructionsAttack`), three carrier tasks, and two models -- a
targeted external check, not a claim that these results generalize to
every agent framework, task suite, or attack technique. AgentDojo's own
utility/security scoring is exact-match and sometimes strict (GPT-5-mini's
`benign_utility_achieved` is low despite the model behaving reasonably in
several inspected transcripts); this experiment's own primary metric is
the *money-moving tool call actually issued* and where it was routed to,
which does not depend on that scoring. Two implementation notes are
recorded in `agentdojo_validation.py` for transparency: (1) AgentDojo's
`ImportantInstructionsAttack` auto-detects a model name from a registry
that predates `gpt-5-mini`/`gemini-3.1-flash-lite`, so the same attack
template is applied via `FixedJailbreakAttack` directly with default
name placeholders instead; (2) AgentDojo's installed Google adapter
(built against older Gemini 1.5/2.x) does not propagate the
`thought_signature` field Gemini 3.x's function-calling API requires
across turns, so this run applies a small, documented runtime patch to
carry it through without modifying the installed package on disk.

## Baseline defenses and the three-way payee corpus (new, additive)

Everything above (`agentdojo_banking_runs.csv`, `agentdojo_gateway_runs.csv`,
`agentdojo_summary.csv`, `agentdojo_environment.json`) is unchanged by the
additions described here. Two gaps were raised against it: (1) every
recipient other than one hardcoded attacker IBAN was treated as
legitimate by construction, which is close to a payee-allowlist test
rather than a test of provenance-aware repair; and (2) the strongest
practical baselines (a static allowlist, a policy engine, an external
enforcement architecture) were missing entirely.

`src/cape_artifact/payee_scenarios.py` addresses the first gap with a
three-way corpus: **known-legitimate** recipients (the four real payee
IBANs from AgentDojo's own `environment.yaml` transaction history, not
authored for CAPE), **known-attacker** (AgentDojo's own real
`_ATTACKER_IBAN` constant -- notably a one-digit-off typosquat of the
legitimate `US122000000121212121212` account, by the published
benchmark's own design, not CAPE's), and **novel-unregistered**
(synthetic IBANs appearing in neither list). A defense is only credited
for genuine registry-membership reasoning if it also correctly
`STEP_UP`/`DENY`s the novel-unregistered category, not merely the one
flagged constant.

`src/cape_artifact/baselines.py` addresses the second gap with three new
defenses, deliberately implemented to fail the same way a real
deployment would: `STATIC_ALLOWLIST` (a pinned-version snapshot,
invalidated only on staleness, not on corruption of the shared root it
trusts), `POLICY_ENGINE` (a blocklist-then-registry rule evaluator --
protects only recipients already known to be bad), and `CAMEL_INSPIRED`
(a reduction of CaMeL's control/data-separation mechanism -- not the
published system's interpreter or capability model -- to requiring
independent, differently-rooted corroboration before trusting a
registry-sourced recipient).

Two ways to see these in action:

- **Deterministic, zero API cost** (`run_baseline_comparison.py`, root of
  the repo): all 8 defenses (CAPE's 5 plus the 3 new baselines) across the
  9-recipient corpus, with and without shared-root corruption. Writes
  `baseline_comparison_runs.csv`, `baseline_comparison_summary.csv`,
  `baseline_comparison_environment.json` in this directory.
- **Against the real AgentDojo attacks above**
  (`--diverse-payee-scenarios`): every money call the two real models
  actually issued, reclassified through the three-way corpus and routed
  through all 8 defenses, writing `agentdojo_diverse_banking_runs.csv`,
  `agentdojo_diverse_gateway_runs.csv`, `agentdojo_diverse_summary.csv`,
  `agentdojo_diverse_environment.json`.

## AgentDojo's own built-in defense (upstream comparison, new, additive)

`--compare-agentdojo-defenses` reruns the same carrier/injection tasks
through AgentDojo's own installed `TransformersBasedPIDetector` (the real
`protectai/deberta-v3-base-prompt-injection-v2` model AgentDojo ships,
`raise_on_injection=True`) wrapping the agent pipeline, instead of routing
through CAPE's gateway. This measures whether an upstream,
agent-framework-native defense would have stopped the same attacks
CAPE's payment-boundary gateway catches downstream -- a genuinely
different failure surface (stopping the agent from being fooled at all,
versus catching an already-fooled agent's payment at the boundary), not
a redundant re-measurement. AgentDojo's other installed component,
`OpenAILLMToolFilter`, is not included: it has no canonical usage example
anywhere in the installed package, and improvising the free-text prompt
it requires would mean reporting a configuration of this artifact's own
design as "AgentDojo's own defense." Writes
`agentdojo_defenses_comparison_runs.csv`,
`agentdojo_defenses_comparison_summary.csv`,
`agentdojo_defenses_comparison_environment.json`.

Reproduce all three additions together (shares one combined
`--max-total-cost-usd` ceiling with the default run, not a separate
allowance each):

```bash
.venv/Scripts/python.exe -m cape_artifact.agentdojo_validation \
  --diverse-payee-scenarios --compare-agentdojo-defenses --i-accept-api-costs
```

### Results

**Deterministic (`baseline_comparison_summary.csv`, zero API cost, 10
recipients -- 5 known-legitimate, 1 known-attacker, 4 novel-unregistered
-- each with and without shared-root corruption):** `AP2_ONLY`,
`MAJORITY`, and `STATIC_ALLOWLIST` are fooled by every corrupted attack
case (5/5); `POLICY_ENGINE`'s blocklist stops the known-attacker case for
free but is still fooled by a corrupted novel-unregistered recipient
(4/5); `FULL`, `CWR`, `DFMR`, and `CAMEL_INSPIRED` block all of them
(0/5), including the `novel_unregistered` cases that a plain
allowlist-style check would not exercise at all. `CAMEL_INSPIRED` and
`STATIC_ALLOWLIST` illustrate the intended contrast directly: the former
never queries the shared registry and so is completely unaffected by its
corruption (at a higher, always-paid query cost); the latter trusts
whatever a current-version snapshot says and is fooled exactly like
`AP2_ONLY`, showing that version freshness alone is not corruption
tolerance.

**Real AgentDojo attacks, three models (`agentdojo_diverse_*`, real GPT-5-mini,
Gemini 3.1 Flash-Lite, and Gemini Flash-Latest, $0.32 total measured cost
for 108 real agent runs across both new tracks):** Gemini 3.1 Flash-Lite
was compromised by AgentDojo's own attack-success check in 18/24 attacks
and issued 26 money-moving calls, 19 to the real attacker IBAN; `AP2_ONLY`,
`MAJORITY`, and `STATIC_ALLOWLIST` authorized all 19, `POLICY_ENGINE`,
`FULL`, `CWR`, `DFMR`, and `CAMEL_INSPIRED` authorized none. Gemini
Flash-Latest and GPT-5-mini were not compromised by AgentDojo's check in
this sample (0/24 each); the money calls they did issue (8 and 3
respectively) all went to already-known-legitimate recipients, so every
defense -- including `AP2_ONLY` -- shows zero unauthorized payments for
them, a property of those models' resistance, not of the defenses. All
40 extracted money calls resolved to `known_attacker` or
`known_legitimate`, with **zero `novel_unregistered` cases in this real
run** -- but getting there required a real correction: an earlier pass
surfaced a genuinely legitimate recipient (`UK12345678901234567890`,
AgentDojo's own ground-truth bill payee for `user_task_0`) that this
corpus had not captured from the environment fixture alone and would
have wrongly flagged as unregistered. That gap is now fixed in
`payee_scenarios.py`, and the fix -- not a hand-picked convenient case --
is what this run confirms.

**AgentDojo's own built-in defense, three models
(`agentdojo_defenses_comparison_*`, $0.25 of the total above):** wrapping
the agent pipeline in AgentDojo's real `TransformersBasedPIDetector`
instead of routing through CAPE's gateway also stopped every attack from
reaching the attacker IBAN, for all three models (0/24 each). This is a
genuinely different failure surface than CAPE's downstream gateway (it
tries to stop the agent from being fooled at all, rather than catching an
already-issued payment at the boundary), and in this sample both
approaches fully contained the same attack corpus -- evidence that
defense-in-depth at the payment boundary is not the *only* way to stop
these attacks, not evidence that it is unnecessary, since it does not
depend on trusting an ML classifier's behavior on injection techniques
outside its training distribution the way the upstream detector does.
