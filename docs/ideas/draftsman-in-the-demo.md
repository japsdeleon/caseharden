# Draftsman in the demo: graft, not act

Decision record for the open question left by the 2026-08-30 session handoff:
the 240s script demos `conduct-policy` end to end and never narrates the
lifecycle of adding a new policy line — where the Draftsman
(`rot`/`patterns`/`overlap`/`draft`) and the LINE_EXAMS refusal live.
Fifth act, or separate video?

## Problem Statement

How might the video show that even the roadmap is gated — the LINE_EXAMS
refusal — without weakening a fully packed, unrecorded 240s script due
2026-08-31 17:00 PT?

## Recommended Direction

**Neither. Graft one refusal frame (≤12s) into the 3:40–4:00 close, cut from
`captures/day11-draftsman.txt`. Leave the script otherwise untouched.**

The close is the only compressible slot. It is a static architecture card with
one "where this sits" line at 3:50; every other beat is either untouchable or
already on the written cut list. Replace ~10s of card dwell with one terminal
frame:

> `$ python3 -m caseharden.notary promote --version v2-pay --parent v1-pay ...`
> `REFUSED — payments-policy has no sealed exam, so the gate cannot measure a
> candidate against evidence. The line stays at its registered floor.`

Voice, two sentences, then the thesis verbatim as the last line, unchanged:

> "There is already a second policy line — a human-granted payments floor. The
> gate refuses to promote it: no sealed exam yet. Even the roadmap is gated."
> … "An agent's authority to act is derived from evidence, not granted by
> config."

This converts the DEVPOST "What's next" paragraph from a said claim into a
shown refusal, and it is cut from a capture — the same production pattern the
2:34 promotion beat already uses, so it costs no live take.

**Why not a fifth act.** The script is at the 4:00 hard maximum; a fifth act
means cutting scripted beats deeper than the written cut list and re-scripting
an unrecorded, unrehearsed video with about a day left. Worse than the
schedule: an act whose surface is "AI drafts the next rule, a human approves
it" is the exact prior art the 0:26 beat disclaims (Unit21, Sublime). Filming
the Draftsman as a narrative act invites the misfiling the ordering rule
exists to prevent. The Draftsman's honest content in a demo is not its
workflow — it is that its output cannot become authority.

**Why not a separate video.** Devpost evaluates one video, four minutes. A
second video is an unclicked link in the write-up, and its production time
comes out of the only critical path that exists right now: recording and
dress-running video one.

## Key Assumptions to Validate

- [ ] The REFUSED frame reads in under 10s to a judge who just learned the
      vocabulary — check on the first dress run; if it needs explaining, cut it.
- [ ] The close survives losing ~10s of card dwell with the thesis still
      landing — timing check on the same dress run.
- [ ] The graft stays under 4:00 total. If the run comes in long, this graft is
      the first thing cut, before any item on the written cut list.

## MVP Scope

One frame from `captures/day11-draftsman.txt` (the `promote` REFUSED block),
two spoken sentences, inserted at ~3:45. No new footage, no new captures, no
script renumbering. `docs/DEVPOST.md` already carries the narrative in text;
nothing there changes.

## Not Doing (and Why)

- **Fifth act** — no time in the video or the calendar, and it demos the
  disclaimed prior art's silhouette.
- **Separate video** — unevaluated by the rules, and it doubles production the
  day before the deadline.
- **Showing `rot`/`patterns`/`overlap` on screen** — drafting-bench workflow,
  supporting cast; the refusal is the only Draftsman moment that advances the
  thesis.
- **Making `payments-policy` fully work first** — the handoff already settled
  this: the line is stronger as the honest, exam-less floor the system refuses
  to fake.

## Open Questions

- None blocking. Priority order for remaining time is unchanged from
  `docs/HANDOFF_UI.md`: beat table and dress runs before any polish, this
  graft included.
