# Draft text for reviewer response / manuscript updates

Written for: the paper's author(s), to review and decide what (if anything) to insert into `CAPE_AP2_Elite_Journal_Revision.docx`. Nothing here has been inserted into the manuscript — per your instruction, this is a standalone draft for you to review first. Paragraph numbers below reference the manuscript's current paragraph indices (extracted read-only via `python-docx`) so you can locate each insertion point exactly.

## Key finding before the drafts: the manuscript already discloses these limitations

Reading the propositions directly turned up something worth knowing before you decide what to add: the reviewer's proof-rigor and adaptivity concerns are **already disclosed in the manuscript's own text**, just without empirical backing until now:

- ¶59 (end of Section 4.2): "Soundness is preserved, although the realized total cost can exceed the minimum that a clairvoyant algorithm could have chosen after seeing every response in advance." -- this is precisely CWR's adaptive-replanning gap the reviewer flagged.
- ¶102, Proposition 6 (DFMR optimality): "The proposition is intentionally local to the finite model; it is not a competitive guarantee against an unconstrained adaptive adversary." -- the same caveat for DFMR.
- ¶89 (Section 5.4): "An implementation facing a much larger state space should impose a resource limit and fall back to full revalidation or step-up." -- exactly the guard that existed only in the benchmark wrapper before this pass's Phase A change.
- ¶165 (Section 7.4): "These values describe the fixed case matrix and do not support prevalence inference." -- already a generalizability caveat on the McNemar comparison, just terse.

So the honest framing for a response letter is not "we added missing rigor" but "the manuscript's own stated caveats are now backed by new, cited empirical measurements" -- a stronger, more defensible claim.

## 1. Connecting ¶59 / Proposition 6 to the new adaptive-replanning benchmark

**Where:** end of ¶59 (Section 4.2) and end of ¶102 (Proposition 6).

**Proposed addition to ¶59** (append as a new sentence): "Section 8.4's supplementary artifact now measures this gap directly (`adaptive_replanning_benchmark.py`): under a random 30% false-negative rate, realized cost exceeds this clairvoyant minimum by a median 9%; under an adversary that specifically falsifies the cheapest candidates, by a median 91% -- a first empirical bound on a gap this section states but does not quantify."

**Proposed addition to ¶102** (append as a new sentence): "The adaptive-submodular-cover literature [17]-[19], already cited above for the planning objective's lineage, gives the natural theoretical framework for a future competitive-ratio analysis against an unconstrained adversary; the present artifact instead reports this gap empirically (see the addition to §4.2/¶59 above) as a first step."

## 2. Connecting ¶89's resource-limit recommendation to the now-real guard and the denser sweep

**Where:** end of ¶89 (Section 5.4).

**Proposed addition:** "This guard now exists in the actual request path (`gateway.py`, `payee_gateway.py`), not only in the benchmark that first measured its threshold; a supplementary denser sweep (`dense_scalability_benchmark.py`) confirms it engages as designed at higher density -- median active domain count 100 versus the original sweep's 18.5, up to 377 active domains, fault budgets up to 20 -- with the fallback correctly triggering on 75% of that sweep's instances rather than never triggering as in the original, sparser configuration."

## 3. Expanding the McNemar generalizability caveat

**Where:** ¶165 (Section 7.4), after the existing "do not support prevalence inference" sentence.

**Proposed addition:** "This follows from the test's design, not a limitation of the statistic itself: McNemar's test compares two classifiers' *discordant* outcomes on a shared, fixed sample -- valid for asking whether DFMR and a given baseline disagree systematically on these fifteen designed scenarios, but silent on how often any of these specific attack patterns would occur against a real, unconstrained attacker population. Treating the reported p-values as evidence about real-world attack prevalence would be a misuse of the test, not merely an extrapolation past its confidence interval."

## 4. Reference-currency checklist (verify before final submission, not drafted text to insert)

Pulled directly from the current reference list -- these are the entries most likely to have changed by the time of publication:

- **[3], [4], [5]** (AP2 security analyses): all three are 2026 arXiv preprints (`2602.06345`, `2608.23858`, `2609.00060`). Check for peer-reviewed versions before final submission; cite the published venue if one exists by then.
- **[6]**: cites a live institutional profile URL (`researchprofiles.herts.ac.uk`) for a 2026 UK AI Conference proceedings paper -- confirm the DOI/proceedings citation has stabilized and prefer it over the profile link if available.
- **[12]**: the AP2 GitHub repo, "accessed September 17, 2026" -- confirm the pinned commit (`e1ea56d...`, per ¶105) still resolves and the spec hasn't materially changed at the cited path.
- **[13]**: Stripe's "Idempotent Requests" doc, dated access only (no URL captured in the extracted text) -- add the direct URL if missing, and re-verify the page still describes the same behavior this artifact's new `stripe_lifecycle.py` (Phase F, this pass) actually exercised against Stripe's real test-mode API.
- **[20]-[22]**: provider model-documentation pages, "accessed September 17, 2026" -- these pages change frequently (model deprecations, renamed tiers); re-verify at final submission, and note that this pass's new experiments also used `gemini-flash-latest` (a rolling alias, not a fixed model version) -- worth a one-line disclosure wherever [22] is cited if that model's results are added to the manuscript.

## 5. Where the new supplementary work could be cited, if you choose to reference it

Not drafted as insertable text (that depends on how much of this pass's new work you want the manuscript to describe), but for orientation: Section 8.5 already lists "stronger external validation" as future work the AgentDojo bridge (prior pass) closed one instance of. The natural place for pointers to this pass's new artifacts -- `dense_scalability_benchmark.py`, `adaptive_replanning_benchmark.py`, `realistic_cost_model.py`, `step_up_cost_model.py`, `stripe_lifecycle.py`, `joint_algorithms.py` -- would be either extending that same Section 8.5 list (marking each as closed, the way the AgentDojo item now would be) or a new short subsection summarizing all of this pass's supplementary artifacts with pointers to their respective `results/*/README.md` files, mirroring how `results/external_validation/README.md` is already structured.
