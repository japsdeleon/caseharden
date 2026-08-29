# Multi-Policy Lines

## Problem Statement

How might we let one governance plane grow new policy domains — each with its own
AI-drafted rules and its own sealed exam — without ever weakening the guarantee that
authority only narrows and the examined never sees the exam?

## Recommended Direction

Introduce the **policy line**: a named lineage of policy versions with its own genesis, its
own gate baseline, and eventually its own sealed exam. The registry and the serving layer
become line-aware; enforcement does not change yet.

The composition argument is why this is safe to build small. Every rule in every line is
deny-only, so fleet authority is the complement of the union of all active lines' denial
sets. A promotion inside one line replaces that line's contribution with a superset (the
existing per-line MONOTONICITY leg), and the union of a superset with unchanged sets is a
superset: fleet authority narrows under any interleaving of promotions across lines. The
BENIGN leg composes the same way, because deny predicates do not interact. No new theorem
is owed; the deny-only DSL was chosen so authority only narrows, and cross-line
composition is a consequence of that same choice.

The build is therefore mechanical: a `policy_id` column on `policy.versions` (registry
metadata, hashed into no chain link, so no existing attestation moves), a deactivation
UPDATE scoped to the line, a `--policy-id` flag defaulting to `conduct-policy`, a
cross-line parent refusal, and a `/policy/<line>/active` route beside the unchanged
`/policy/active`. Demonstrated with a second line, `payments-policy`, registered at
genesis with one rule: deny `issue_refund` at or above 500000 cents.

## Key Assumptions to Validate

- [ ] The deployed Policy Server tolerates the new column before its redeploy — its
      queries select named columns and it never writes the registry. Validate by running
      the ALTER first and hitting `/policy/active` before redeploying.
- [ ] The full re-sweep stays green in one run: 300+ tests, then the mutation harness run
      alone. Validate by keeping the logic diff small and giving every new branch a
      targeted test before the sweep starts.
- [ ] A registry row without `policy_id` (pre-migration, or written by old code) must
      behave as `conduct-policy` everywhere. Validate with an explicit test on the
      legacy-row path.

## MVP Scope

In: the `policy_id` column and backfill; scoped deactivation; version-name uniqueness
across lines; cross-line parent refusal; the line route; `payments-policy` genesis; a
capture showing both lines active at once with the cross-line refusal and each line's
honest verify state; THREATS.md entry 11; CONTEXT.md term.

Out: everything that makes `payments-policy` more than a floor.

Descoped from the capture list after the build (the validator flagged both as promised
and absent, so the descope is recorded here rather than left silent):

- *A conduct promotion leaving payments untouched.* A live promotion needs a candidate
  that passes the gate, and the day-8 run established that no expressible candidate
  currently does — the honest system cannot stage a promotion for a screenshot. The
  scoped deactivation is proven in the direction that did happen (payments genesis
  leaving conduct's v5 active) and by a mutation test on the UPDATE's scope.
- *A late event quarantining `conduct-policy` alone.* Streaming a synthetic event into
  the cited evidence window the day before the deadline mutates the exact record the
  submission stands on. Per-line verify independence is what the mutation tests and the
  day-3/day-4 quarantine captures already establish; re-staging it for a two-line
  screenshot is not worth touching live evidence.

## Not Doing (and Why)

- **Union enforcement** — the workload keeps enforcing `conduct-policy` alone. The
  enforcement hot path, its refusal wording, and the decision-row schema stay untouched
  48 hours before the deadline. THREATS 11 states this out loud.
- **A sealed exam for `payments-policy`** — an exam is domain-specific, and corpus design
  is days, not hours. The line stays an honestly labelled human-granted floor: served,
  active, not yet attested. Its first evidence-derived promotion is the Curator story.
- **A composite `(policy_id, version)` key** — version names stay globally unique with the
  line tagged in the name (`v1-pay`; the DSL requires versions to start `v<digits>`, so the
  tag is a suffix). The composite key ripples through link hashing, certificate paths, and
  every existing test for zero demo value.
- **The AI exam Curator** — narrated in DEVPOST as what's-next, not built. The exam
  gaining its own provenance chain is a design, and designs are not demos.

## Open Questions

- When `payments-policy` earns its exam, does its holdout live in the same dataset with
  its own access list, or in its own dataset? (Leaning: own dataset, so each line's
  access list stays a one-entry artifact.)
- Does the roster annotation on Agent Registry entries need a line name once two lines
  exist? (Today every entry carries the conduct root.)
