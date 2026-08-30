# The Draftsman

## Problem Statement

How might a human drafting a policy for a new use case ground every choice in
stored conduct evidence, instead of writing rules from intuition and finding out
at the gate?

The lifecycle audit found the gap: caseharden verifies a policy's past
justification (the chain re-derives) but nothing measures present relevance.
Nobody asks "has rule X denied anything in 30 days" or "what does this use case's
conduct actually look like". That is rule rot, and drafting without evidence is
how rot gets written in the first place.

## Recommended Direction

A drafting-side CLI helper, `python -m caseharden.draftsman`. It sits on the
Proposer side of the independence wall — it reads `conduct_live` and the policy
registry, and it can never touch the sealed exam. It is NOT the Curator: the
Curator (docs/DEVPOST.md what's-next) is exam-side and stays unbuilt.

Four subcommands, deterministic core, every number carries a re-runnable
BigQuery job id (the detectors' own pattern):

1. **`rot`** — per-rule denial counts over a window, across every active line.
   Reads active versions from the registry, parses their rules, one grouped
   query over `conduct_live.decision_rule`. Verdict per rule: EARNING (denied
   something) or DORMANT (zero denials in the window — a rot candidate, stated,
   never auto-removed: retirement widens authority and stays forbidden).
2. **`patterns`** — grounded research for a use case (payments is the one
   wired). Aggregates conduct for the refund tool surface: volumes and deny
   share, amount distribution, per-session call counts, cross-tenant flags.
   Output is the evidence a human proposes a family taxonomy from.
3. **`overlap`** — the conflict check. Each draft rule against every active rule
   in every line, using the same predicate-subset logic as the Examiner's
   structural monotonicity: DUPLICATE (same predicates), COVERED (an active rule
   already denies everything the draft rule denies — the draft is redundant),
   WIDER (the draft would deny a superset of another line's rule — ownership
   question). Deny-only algebra means no semantic contradiction is possible.
   The comparison is structural, deliberately: a draft `at_least 1000000` under
   an active `at_least 500000` reports nothing, exactly as the Examiner's
   structural check would refuse to analyse it. A report, never a gate — it
   flags, the human decides.
4. **`draft`** — assemble a candidate: rules validated through the closed DSL
   vocabulary (a hallucinated field cannot parse), overlap check run inline,
   policy file written, and the exact `notary` command that carries the file
   into the governed lifecycle printed. The job-id provenance lives in the
   `rot` and `patterns` reports the human drafted from; `draft` itself queries
   no conduct.

Optional `--narrate` on `rot`/`patterns`: Gemini (via `creds.genai_client`)
summarizes the evidence JSON and suggests rule shapes. Behind an import guard —
absent library skips with a printed line. Model output is labelled narration,
never evidence: the numbers come from BigQuery, the draft must still parse, and
the gate still decides. The model suggests; it never grants.

## The exam-guard (notary)

`parent_basis` accepts a genesis parent, so `notary seed` on `payments-policy`
would today score the candidate against `holdout_sealed` — the CONDUCT exam.
That is the wrong exam wearing a passing grade. Fix: a line-to-exam map in the
notary (`conduct-policy` → `holdout_sealed`, nothing else); `promote` and `seed`
refuse any line with no sealed exam of its own, before anything is written:
the line stays at its registered floor until it earns its own exam. This is the
lifecycle's honest edge, and the demo ends on it.

## Key Assumptions to Validate

- [x] `conduct_live` attributes denials to rules — `decision_rule` column exists.
- [x] Per-rule subsumption is decidable — `structurally_monotonic`'s
      predicate-subset trick, reused per rule pair.
- [ ] Live `conduct_live` has enough refund traffic for a non-empty patterns
      capture — checked at capture time.

## MVP Scope

`caseharden/draftsman.py` + `tests/test_draftsman.py`; exam-guard in
`caseharden/notary.py` + tests; glossary entry; capture on the live project:
rot report across both lines, payments patterns, a v2-pay draft, overlap
verdicts, and the honest exam-guard refusal.

## Not Doing (and Why)

- **Curator / exam evolution** — exam-side, opposite of the wall; stays what's-next.
- **Union enforcement across lines** — day-10 boundary unchanged; registry and
  serving are line-aware, enforcement is not.
- **A payments sealed exam** — earning one is the Curator story, not a night's work.
- **Auto-retiring dormant rules** — retirement widens authority; the rot report
  states, a human decides, and today even the human has no retirement path.
- **Gemini as a hard dependency** — requirements-verify.txt is untouched (no
  model library added); the narration step is optional and labelled.

## Post-build notes (adversarial scope review, dispositions)

A second-engine scope review ran against the working tree before commit. What
it found and what happened to each finding:

- **`genesis` was ungated**: a second genesis in a line would have replaced an
  active floor with no exam and no chain. Fixed — genesis now refuses any line
  that already has a version; replacing what is in force is a promotion.
- **A CLI path to the exam**: `--impersonate examiner-sa` plus
  `--dataset holdout_sealed` would have read exam material through the bench.
  Fixed with two refusals — the bench rejects the examiner identity and the
  exam datasets outright. The operator's own credentials could always mint
  that token; the bench refusing is the statement.
- **Overlap claim overstated**: threshold nesting (`at_least 1000000` under
  `at_least 500000`) is invisible to the structural comparison. The claim was
  corrected above rather than the code — the conservatism is shared with the
  Examiner's structural check and is deliberate.
- **Rot counts not version-attributed**: denials group by rule id across the
  versions that enforced them. The report now says so on screen.
- **The lifecycle handoff was implied**: `draft` now prints the exact `notary`
  command, with `--policy-id`, that carries the file forward.

## Open Questions

- proposer-sa holds no read on the policy registry, so `rot`, `overlap` and
  `draft` run under `--impersonate notary-sa` (a reader that still has no
  standing on the sealed exam). The clean fix is one dataset-ACL command,
  `infra/bq_grant.py <project> policy READER proposer-sa@...`, left to the
  operator.
- Narration wiring is checked at capture time and skipped in writing if the
  local environment lacks the library.
