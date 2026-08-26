# Workbench sprint — Aug 27–30, locked 2026-08-26

Final pre-submission sprint. Scope settled through an adversarial design review:
two independent engines (Codex CLI and an in-house reviewer) attacked the draft
plan against this repo; every decision below survived or was reshaped by that
review. Submission: Devpost, 2026-08-31 17:00 PT.

## Built on Day 8 (2026-08-26), against this plan

Day 1 and Day 2 are done, code and live. `115_prove_copilot_session.py` exits 0
against the deployed Copilot, which clears the gate on decision 5, and the
console has been run in live mode against the deployed Policy Server with every
pane filling from BigQuery and no error recorded. `BUILD_LOG.md` carries the
per-route results. What remains on those days is chasing the approval status.

| | |
|---|---|
| `caseharden/workbench.py`, `caseharden/workbench.html` | the console: evidence, verdict chat, chain timeline, registry, attestation pane, offline fixture mode, 50-minute token cache |
| `caseharden/copilot_client.py` | the ADK session flow, extracted so nothing imports the loop driver to reach it |
| `infra/115_prove_copilot_session.py` | the standalone gate: two turns on one session, and nothing written to `review.decisions` |
| `infra/110_run_loop.py` | writes `out/finding-live.json` after the fan-out answers, atomically |
| `tests/test_workbench.py` | 72 tests; the identity rule and the subject guard are asserted, not documented |
| README, DEVPOST, PLAN, THREATS, `agents/copilot/agent.py` | the reconciliation below |

Test count is **257**, not 179 and not 161. The 179 in this document was stale
when it was written; the repo was already at 185 before this sprint.

## Decisions locked

1. **Target**: everything serves the 4:00 demo video. Live deployment of the new
   UI is out of scope.
2. **The UI**: an analyst **workbench** — one HTML file + vanilla JS, served by a
   new stdlib HTTP module (`python3 -m caseharden.workbench`), run locally with
   the `caseharden` gcloud config. Dense enterprise console look, dark, no
   framework, no build step. Framed everywhere as *an operator console: read-only
   over the same records, its single write goes through the unmodified, screened
   Copilot*. It is not a security boundary and must never be presented as one.
3. **Identity rule**: the workbench never calls `verify()` and never holds
   `examiner-sa`. Attestation state comes from the Policy Server only. Reads use
   the same impersonation the day-5 loop already proved (`notary-sa` /
   `detector-sa`).
4. **No polling queue.** Nothing reaches `chain.links` before promotion, so a
   queue has no source of truth. The loop driver dumps its finding dict
   (including `job_id` and `rows`) to `out/finding-live.json` after
   `investigate()`; the workbench tails that file for the evidence pane and the
   pre-filled verdict subject. Subject must equal the driver's `job_id` exactly
   or `wait_for` stalls 900s.
5. **Verdict = thin chat through the Copilot session** (decision: build it, not
   the stock-chat fallback), with a hard gate: the ADK session flow
   (session PUT → `/run` POST with foreman-sa id token, per
   `infra/110_run_loop.py:283-318`) is extracted and proven **standalone before
   any UI is built on it**. The canned 25s "Yes, store it" confirm is dropped —
   the pane shows the Copilot's replies and the human answers. If the standalone
   proof is not green by midday Day 1, fall back to typing the verdict in the
   stock Copilot chat and the workbench only displays the `review.decisions` row
   appearing.
6. **The APPROVAL is a second human write** and stays in the stock Copilot chat,
   scripted as its own beat — it doubles as the Model Armor
   analyst-text-screened beat.
7. **Demo story = one full live v6 run** (decision: live run, not the historical
   v5-capture route). Exactly one promotion is budgeted, and it is the take.
   Every other beat (tamper, quarantine, reattest) is rehearsed against the
   pre-take state without promoting. Fallback if the v6 gate refuses all 4
   attempts on camera: the day-5 v5 promotion captures stand in for the
   promotion beat.
8. **Post-take tail is scheduled work, not cleanup**: re-export fixtures (v6),
   update README root/metric numbers, re-register the fleet, run the offline
   recheck, commit.
9. **Offline fixture mode is a required deliverable**, not a stretch: the
   workbench renders `fixtures/<v>` with no credentials. It is the recovery
   asset and the judge-runnable path; it does not substitute for the live flip.
10. **Dropped**: deploying the workbench, Agent Gateway/Runtime, closing
    THREATS.md holes beyond the doc reconciliation below.

## Panes

- Evidence view: cited conduct rows from `out/finding-live.json`.
- Verdict thin-chat (per decision 5).
- Chain timeline: **all 9 link kinds** (`caseharden/chain.py:36-46`), including
  `EVIDENCE-CHANGED` and `DRAFT-REJECTED` — the remedy beat emits one.
- Version registry: driven from `ChainStore.versions()`, never a hardcoded
  list; badges attested / quarantined / frozen.
- Attestation pane: renders the Policy Server response including
  `checked_s_ago` and `cached` — no timer-driven animation. The server caches
  60s; the flip lags the tamper by up to a minute and the wait is cut in
  editing.

## Known traps (each verified in code during review)

| Trap | Guard |
|---|---|
| `tamper.py` defaults to `conduct_train`; v6 evidence cites `conduct_live` | always pass the table flag (REHEARSAL.md already does) |
| Tamper rows undeletable ~90 min; every reattest appends a link | pre-record the flip transition once with a fresh event id; treat it as the fallback clip |
| BQ token minting shells out to gcloud per call | cache tokens ~50 min in the workbench (~10 lines) |
| Promotions only narrow; a rehearsal promotion can make the take's incident undemoable | one-promotion budget (decision 7) |
| "One write only" is a front-end convention — the Copilot service exposes `record_verdict` AND `approve`, and stores verdicts even when screening fails | claim precisely: "the workbench submits only a verdict; approval authority stays with the Copilot service" |
| Do not `import` the loop driver module (drags in proposer/drive_agent) | extract the ~35-line helper instead |

## Doc reconciliation (Day 1, ~1.5h, judge-facing)

- README.md "No UI was written for this entry", DEVPOST.md "the analyst surface
  had to be something I did not write", PLAN.md:243 bespoke-console rejection,
  `agents/copilot/agent.py` docstring — all rewritten to the operator-console
  framing, via a decision-log entry at the top of PLAN.md.
- THREATS.md and DEVPOST.md still claim spans do not reach Cloud Trace; the
  Day 7 BUILD_LOG entry records the `ALWAYS_ON` sampler fix and a 9/9 proof.
  Rewrite in past tense; keep the still-true `traceparent`-trust residual. The
  trace DAG is an available video beat again.
- Counts: **179 tests**, not 161, everywhere the number appears.

## Schedule (confirmed)

**Day 1 — Aug 27.** Standalone Copilot session-flow proof FIRST (gate for the
thin-chat decision). Workbench core: server, file-fed evidence pane, decision-row
display, thin-chat verdict. Doc reconciliation above. Chase employer approval
status (email already sent; repo must flip public before judging).

**Day 2 — Aug 28.** Chain timeline, version registry, attestation pane, token
cache, offline fixture mode. Then record raw proof clips, one beat per clip:
tamper→quarantine transition (once), retention lock refusing the owner,
Proposer 403, offline recheck, trace DAG, Copilot approval/Model Armor beat.

**Day 3 — Aug 29.** The take: full live v6 loop through the workbench (the one
promotion). Post-take tail (decision 8). Remaining clips, begin assembly.

**Day 4 — Aug 30.** ≥4h edit reserve: assembly, captions, 1080p readability
pass, claim audit against the repo. Devpost form from docs/DEVPOST.md. Billing
screenshot. Flip repo public, load README logged-out, confirm badge green.
15-min re-proof: `infra/100_prove_fleet.py`, `verify`, offline recheck,
`pytest`. Submit.
