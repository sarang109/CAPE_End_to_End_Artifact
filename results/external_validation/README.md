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
