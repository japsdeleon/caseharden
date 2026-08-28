# Hackathon concept tournament — final championship plan

> **Migration note:** this document contains no employer code, data, or infrastructure. Moved into the hackathon repo on Day 1.

> **Escalations approved by the entrant on 2026-08-25, in session:** the section 2 isolation rewording below; locking the retention policy at 30 days; taking the repo private until the employer approval email is sent. The first is the only change to a section 2 claim.
>
> **Decision log.** 2026-08-25, Day 1 build: IAM deny policies are unavailable on this project. `roles/iam.denyAdmin` binds only at organization or folder scope and the project has no parent, and `iam.denypolicies.create` is rejected from custom roles. Both errors are recorded in `infra/40_seal_holdout.sh`. Section 2's isolation sentence is reworded from a deny binding to dataset access control, and the holdout's access list is hashed into chain link 1 so that granting the Proposer access later quarantines the version. The 403 itself is unchanged and reproduces; see `captures/day1-proposer-403-on-holdout.txt`.
>
> **Decision log.** 2026-08-26, Day 8: an analyst **workbench** is built, partially reversing the section 7 rejection of "bespoke live console with attack feed". The rejection stands as written and is not edited: what it refused was a custom console *as the agent surface*, competing with `adk deploy cloud_run --with_ui` and costing days that six did not have. What is built instead is an operator console outside the trust boundary. It runs locally, reads the chain, the registry and the finding under review, takes attestation from the Policy Server rather than deciding it, and routes its one write through the unmodified Copilot. Its compose box offers a verdict and it writes no review row itself; what is stored is decided by the Copilot service. It has no approve affordance and no way to prevent an operator typing one, so the claim is about what the console offers, not about what the Copilot can be asked to do. It never calls `verify` and holds no credential for the sealed exam; `tests/test_workbench.py` asserts both against the parsed module. `--fixture` renders a sealed record with no credentials, which is the judge-runnable path section 7 wanted from entry C without the offline reroute it rejected. The claim "no custom UI exists" is therefore withdrawn from the README, DEVPOST draft and the Copilot's docstring, and replaced with the narrower one the code supports.
>
> **Decision log.** 2026-08-27, Day 9: the v6 take was run live on 2026-08-26 and the Examiner refused all four candidates, so **the refusal stands and the promotion beat is cut from the Day 5 v5 captures**. This is the fallback written into decision 7 of `docs/WORKBENCH_SPRINT.md`, taken as written. Nothing reached the chain: v6 is unregistered and v5 is still active and attested on root `e2a559358933`, which is what the fleet enforces and what the beat now shows. The cause was that the verdict asked for a rule the DSL cannot express, recorded as `THREATS.md` **Not covered 7**. The run is kept at `captures/day8-gate-refuses-v6-no-improvement.txt`. No second attempt was made: drafting against a failing gate leg until it passes is tuning to the sealed exam by trial, which is the property the Proposer and Examiner split exists to prevent.
>
> **Decision log.** 2026-08-25: the domain shift from promo and referral abuse to agent-conduct governance is **accepted**, overriding the earlier locked decision to build in the promo-abuse domain. Two further decisions taken the same day: the thesis is stated at platform altitude (section 1), and the demo opens on the break rather than on the build (section 5).

Date: 2026-08-25. Method: five independent Opus 5 designers, each given the same verified brief but a different angle, produced complete entry concepts. Three blind judges (Devpost veteran, Google platform engineer, adversarial skeptic) ranked anonymized entries by win probability with a hard 6-day solo feasibility gate. A synthesizer grafted runner-up strengths onto the winner and addressed every judge-listed weakness.

## Leaderboard

| Rank | Entry | Angle | Avg win prob | Avg weighted (0.4/0.3/0.3) | Infeasible votes |
|---|---|---|---|---|---|
| 1 | **Caseharden** (B) | fraud + governance | 0.193 | 8.25 | 0 |
| 2 | Titer (D) | fleet immune system | 0.187 | 8.27 | 0 |
| 3 | Ratchet (A) | guardrails that learn | 0.120 | 7.75 | 0 |
| 4 | Recusal (E) | wildcard | 0.103 | 7.55 | 0 |
| 5 | Nullius (C) | verifiable audit passport | 0.103 | 7.87 | **2** |

Judge split: devpost-veteran picked Nullius (judge-runnable verification), google-platform picked Titer (architecture that *needs* the platform), skeptic picked Caseharden (only claim that survives adversarial prior-art attack). Caseharden won on feasibility-adjusted win probability; Nullius was disqualified by two infeasibility votes.

## The five concepts (one-liners)

- **Ratchet** — governance control plane where every guardrail is a versioned artifact carrying a signed passport from incident through verdict, AI-drafted change, and sealed replay.
- **Caseharden** — a detection rule stays in production only while its own provenance chain re-verifies from raw events; proposer isolation and record immutability enforced by BigQuery IAM and a GCS retention lock, not by our code.
- **Nullius** — every promoted policy is proof-carrying: a signed hash-chained evidence object a stranger re-checks offline in one command.
- **Titer** — a fleet that attacks itself on a schedule and proves each guardrail made it safer without making it useless (two-sided gate).
- **Recusal** — internal-affairs fleet: the policy-drafting agent is governed by its own policies, IAM-sealed from its exam, and recuses when the case is its own.

---

# CASEHARDEN — Final Championship Concept
*All Things Agentic Hackathon. Solo entry. Aug 25 to Aug 31 2026, europe-west3.*

---

## 1. Concept

**Name:** Caseharden

**Thesis, stated at platform altitude:** an agent's authority to act is derived from evidence, not granted by configuration.

That sentence is the position the entry takes. It costs no extra code, because the build below already implements it: the derivation is the provenance chain, and withdrawing the derivation withdraws the authority. Use it as the first line of the Devpost text and the last line of the video.

**One-liner:** A governance plane for an enterprise agent fleet where a guardrail keeps its authority only while its provenance chain re-derives from raw evidence, and the two guarantees that chain rests on, proposer isolation and record immutability, are enforced by BigQuery IAM and a Cloud Storage retention lock rather than by our code.

**Product identity**

Caseharden governs what an enterprise's AI agents are allowed to do, and how that answer is allowed to change.

A workload agent does ordinary support work with two tools: a tenant-scoped account read and a refund write. Every turn it takes is screened by Model Armor, traced by Agent Observability, and written as one structured conduct event to BigQuery. Four detector agents, discovered through Agent Registry rather than named in config, run governed SQL conduct checks over that event stream: tool call outside declared scope, tool call in a turn carrying an injection hit, cross-tenant read volume spike, and read-then-write privilege sequencing.

A finding goes to a human analyst, who renders a verdict in chat. A Proposer agent drafts a guardrail change in a small deny-only DSL. A deterministic Examiner, not a model, scores that draft against a sealed holdout the Proposer is IAM-denied from reading, and applies a two-sided gate: attacks must go down, benign traffic must not, and the new version must only narrow authority relative to the current one. On approval a new policy version goes active and every agent callback enforces it on the next turn.

Every step is a hash-linked record in a BigQuery chain, append-only by convention, whose root is sealed into a retention-locked GCS object and annotated onto the Agent Registry entry for that policy version. The lock is what makes a rewrite detectable.

The product is not the detection. The product is the attestation. A guardrail version is served as `attested` only while `caseharden verify` re-derives its evidence and its exam from the raw conduct events and re-walks every link in its chain. When the evidence changes, the version is quarantined: it keeps blocking, but it loses attested status and nothing can be promoted on top of it until it re-derives. The governance agents run behind the same enforcement callback and appear in the same registry, so the plane sits inside its own blast radius.

---

## 2. README: innovation claim and prior-art defense

### The claim

An agent's authority to act is derived from evidence, not granted by configuration. In Caseharden the provenance record is load-bearing rather than descriptive. A guardrail version is authoritative in production only while its chain re-derives from the raw conduct events that justified it, so changing the evidence withdraws the version's authority instead of filing a discrepancy report. The two guarantees the chain rests on are discharged outside this project's code: that the proposing agent never read its own evaluation data is BigQuery access control producing a real 403, and the access list that produces it is itself hashed into the chain, so a later grant to the Proposer breaks the chain rather than going unnoticed, and that an edit to the record cannot be hidden is a Cloud Storage retention lock that refuses a delete from the project owner, so a rewritten chain no longer matches the root sealed when it was written. Refusals are stored as links in the same chain as approvals, so the record attests to what was prevented and not only to what occurred.

### What already exists

| Prior work | What it already does |
|---|---|
| Unit21 AI Rule Recommendation Agent (Oct 2025) | Analyzes analyst dispositions, drafts optimized rules, shadow-tests against historical data, deploys on approval |
| Sublime Security ADE (Sept 2025) | LLM drafts detection rules in a constrained DSL, PR-style human review |
| Stripe Radar Assistant, DataVisor Co-Pilot | LLM-drafted rules, backtested, human-approved |
| MLflow-era MLOps | Holdout-then-promote, versioned artifacts, champion/challenger, rollback |
| **sigstore / cosign, in-toto, SLSA** | **Signed attestations binding an artifact to its build inputs, verified before use** |
| **OPA Gatekeeper, Kyverno admission control** | **Refuse to admit an artifact whose attestation does not verify** |

Caseharden claims none of it as new. The verdict-to-policy loop is shipped product. Signed-artifact verification gating admission is shipped infrastructure, and it is the closest analogue to this entry's actual claim, which is why it is named here rather than left for a judge to find.

### The delta, stated against the closest prior art

Against Unit21 and Sublime: in those systems the audit trail is a report. It describes the promotion and has no authority over it, and the assurance that the proposing model did not see its validation set is a statement of internal practice rather than an artifact a reviewer can test.

Against sigstore, in-toto, SLSA and admission control, which are the harder comparison: those attest an **artifact** against its **build inputs**, verify a **signature over a digest**, and gate at **admission time**. Caseharden attests a **decision** against its **evidence**, and verification does not stop at a hash. It re-executes the deterministic Examiner over the sealed holdout to reproduce the metric that justified the promotion, and it re-derives the evidence link by re-scanning the conduct events the finding cited. A signature proves nobody edited the claim. Caseharden proves the claim is still true. That difference is the reason a late-arriving event can quarantine a version that no attacker ever touched, which no signature scheme detects and no admission controller re-checks after admission.

Also unclaimed by any of the above: the negative links. A 403, a Model Armor block, and a DSL parse rejection are stored in the same chain as the approval, so the certificate records the attempts the system refused.

The claim is a construction, not a priority claim. No earlier product refutes it.

### What is explicitly not claimed

Not claimed: first AI-proposed policy under human review, first constrained-DSL drafting, first holdout gate, first signed provenance, first monotone policy versioning. Each of those is prior art and each is cited above.

---

## 3. Architecture

### Agents and services

| Component | Host | Role |
|---|---|---|
| **support-agent** (workload) | Cloud Run, own identity | The governed agent and the attack target. Two mock tools: `lookup_account` (tenant-scoped read), `issue_refund` (write). Deliberately ordinary, with no defensive prompting, so the guardrail layer is what changes. |
| **Foreman** (orchestrator) | Cloud Run, own identity | Discovers detectors at runtime via `AgentRegistry.list_agents()` bound to `RemoteA2aAgent`. No hard-coded endpoints. Fans an investigation window out to four detectors in parallel, merges findings, opens a case, pulls reviewer precedent from Memory Bank. |
| **Detectors ×4** | Cloud Run, one template instantiated four times, each its own registry entry | `cross-tenant`, `scope-escape`, `injected-turn`, `privilege-sequencing`. Each runs a governed parameterized BigQuery check and returns findings plus the SQL job id. |
| **Analyst Copilot** | Cloud Run, `adk deploy cloud_run --with_ui`, unmodified | Human surface. Verdict and approval are typed messages backed by two ADK tools. No custom UI is built. Model Armor screens inbound analyst text and outbound rationale. |
| **Proposer** | Cloud Run, `proposer-sa` | Gemini 3.5 Flash structured output constrained to the Caseharden DSL, conditioned on the finding, the verdict, and Memory Bank precedent. Reader on the training window and the benign corpus; its drafting tool queries the training window. IAM-denied on `holdout_sealed`, and the demo makes it try. |
| **Examiner** | Cloud Run job, `examiner-sa` | Deliberately not an LLM. About 400 lines of deterministic interpreter, the only principal with read access to `holdout_sealed`. Compiles a candidate to a BigQuery predicate and returns catch rate, benign pass rate, false-positive cost, and the monotonicity check. Having no model, it cannot be argued into a pass. |
| **Notary** | Cloud Run service, `notary-sa` | Writes hash-linked rows into the chain, seals the root into the retention-locked bucket, annotates the Agent Registry entry with the root hash, implements `caseharden verify` and `caseharden reattest`. |
| **Policy Server** | Cloud Run | The enforcement point that makes the record load-bearing. Serves the active version with an attestation state, and freezes the promotion path when that state is not green. |

### Gemini Enterprise Agent Platform components, and what each carries

- **Agent Registry (GA):** the fleet roster and the discovery layer. Nine entries, seven of them this project's; the other two are Google's `Workspace Agent` and the `caseharden-memory` entry Vertex created with the Agent Engine. Foreman hard-codes nothing. Each promoted version's chain root hash is written as an annotation on its registry entry, so the platform's own discovery layer carries the audit anchor.
- **Agent Runtime (GA):** an Agent Engine is deployed and it backs Memory Bank. **No agent is hosted on it.** Every agent in this entry runs on Cloud Run, which the build plan pre-approved under the Day 4 hour-5 cutoff, and each one is published into the same registry by the same script. The registry pattern is therefore demonstrated on one host, not two. Decided on Day 5 and recorded in BUILD_LOG.md.
- **Agent Identity (GA):** load-bearing, not decoration. `proposer-sa` and `examiner-sa` are distinct principals. No principal in the project holds a project-wide BigQuery data role, and `holdout_sealed`'s access list is reduced to a single entry: `examiner-sa` as its owner. `bigquery.tables.getData` is not part of `roles/owner`, so the human project owner is refused the exam as well. Isolation is a property of Google's authorization layer, reproducible by any judge with the dataset's access list open, and the Cloud Audit entry names `bigquery.tables.getData` as denied.
- **Model Armor (GA):** dual role. Screens the analyst's free-text verdict inbound and the Proposer's rationale outbound. Its verdict fields, prompt-injection score and jailbreak score, are **first-class predicates in the DSL**, so policy composes with Model Armor instead of re-implementing it. A block becomes a chain link.
- **Memory Bank (GA, free through the window):** per-reviewer, per-check-family verdict history. Before drafting, the Proposer retrieves "this reviewer rejected two prior scope proposals for over-broad tool matching". Retrieved memory ids are recorded in the chain link, so the conditioning is auditable.
- **Agent Observability (GA):** OTel tracing default-on. The trace id for each fan-out and each governed tool call is stored inside the corresponding chain link, so a link opens the real execution DAG.
- **Agent Gateway (GA):** one policy point for A2A traffic between Foreman and the detectors. **Explicitly first on the cut list.** Nothing else depends on it.

### GCP services

BigQuery (conduct events, sealed holdout, benign corpus, append-only chain, policy registry) · Cloud IAM (one service account per role, dataset-scoped grants, no project-wide read) · Cloud Run (services, jobs, and the ADK chat UI) · Cloud Storage with retention lock (immutable certificates) · Cloud Trace and Cloud Logging · Cloud Build via `adk deploy` · Vertex Gemini 3.5 Flash, europe-west3 regional endpoint, Flash only.

### The attestation state machine

This is the part that answers "what happens in production when verification fails", and it is three states plus one cache.

| State | Trigger | Enforcement | Promotion path |
|---|---|---|---|
| `attested` | Chain re-derives, root matches | Version enforces | Open |
| `quarantined` | A link fails to re-derive; the failing link and offending id are named | **Version keeps enforcing.** Block reasons are marked unattested | **Frozen.** No proposal may be based on an unattested version |
| `unknown` | Verify itself errors, for example a BigQuery outage | Version keeps enforcing, last known state retained | Frozen, alert raised |

Attestation gates **authority, not availability**. A broken chain never reduces enforcement, because an audit layer that switches off your guardrails is a worse failure than the one it detects. What a break withdraws is the version's standing as justified, and the fleet's ability to build the next version on top of it.

Verify budget: a single partition-pruned, clustered scan bounded to the finding's window, plus a deterministic replay. Target under 5s p95, cached 60s, and the measured p95 is published in the README rather than asserted in the video.

### Data flow

A seeded generator writes about 40k synthetic conduct events into BigQuery: `conduct_train` covers days 1 to 76, `holdout_sealed` covers days 77 to 90 with labels, and `benign_corpus` holds 600+ legitimate tool-call turns. Four abuse patterns are injected at known rates, so catch rate and false-positive rate are measurements rather than narration. `holdout_sealed` lists `examiner-sa` and nobody else, and no principal holds a project-wide data role that would reach it.

An analyst asks Foreman to investigate the last 24 hours. Foreman lists the registry, binds four detectors as RemoteA2aAgents, fans out over A2A, merges findings, and pulls reviewer precedent. The Notary writes link 1, an evidence fingerprint hashed over the conduct rows the finding cited, and link 2, the finding itself carrying SQL job ids and the trace id.

The analyst types a verdict. Model Armor screens it. Link 3 records the verdict and the screening result. The Proposer drafts into the DSL; a draft failing Pydantic validation is written as its own rejection link rather than retried silently. The Proposer then attempts to self-check against the sealed holdout and receives a 403; the verbatim exception and the matching audit log entry become link 5.

The Examiner scores the candidate against sealed attacks, the benign corpus, and the current active version, and applies the gate. The analyst approves. The Notary computes the root, writes the certificate to the retention-locked bucket, and annotates the registry entry. From then on the Policy Server serves that version with its live attestation state.

---

## 4. Build plan

Six days, roughly 40 hours. Aug 31 is submission only, no code.

**Aug 25, Day 1, ~7h. The two platform-owned guarantees, before anything depends on them.**
Fresh personal project in europe-west3, billing on, APIs enabled. Five service accounts. BigQuery datasets `conduct_train`, `holdout_sealed`, `benign_corpus`, `chain`, `policy`. `holdout_sealed` reduced to one access entry, `examiner-sa`, with no project-wide data role for any principal. Retention-locked GCS bucket. Synthetic conduct generator producing the corpora described above, committed as a seeded script.
**Exit criterion, the only one:** a recorded terminal capture of `proposer-sa` taking a real 403 with principal and permission visible, and a recorded capture of `gcloud storage rm` refused by the retention policy. If either does not reproduce cleanly today, the concept is re-cut today rather than on Day 5.

**Aug 26, Day 2, ~7h. DSL, Examiner, and the two-sided gate.**
Pydantic schema: fixed feature vocabulary, about six predicates including Model Armor verdict fields, deny-only actions. Roughly 200-line deterministic interpreter compiling to a BigQuery predicate. Examiner CLI under `examiner-sa` returning catch rate on sealed attacks, benign pass rate, false-positive cost, and a monotonicity check that replays the candidate and the current version over the benign corpus and asserts the new version's denial set is a superset.
Gate: attacks blocked must rise, benign pass rate must not fall, monotonicity must hold.
One pytest file with three assertions that matter: an over-blocking candidate must FAIL the gate, a widening candidate must FAIL monotonicity, a good candidate must PASS.

**Aug 27, Day 3, ~7h. The chain, verify, the attestation state machine, the Policy Server.**
Append-only hash-linked chain table. Notary writes links, seals the root, annotates the registry entry. `caseharden verify` re-derives link 1 from raw events over the pruned window, recomputes every link, compares roots, and fails at the exact link naming the offending id. `caseharden reattest` re-scores against current evidence and appends an evidence-change link if the gate still passes. Policy Server implementing the three attestation states with a 60s cache. Certificate viewer: one Python script rendering the chain to a static HTML page, about 80 lines.
**Exit criterion: the memorable moment is complete on Day 3, on hand-fed links.** Green, quarantine, promotion refused, re-attest, green again.

**Aug 28, Day 4, ~7h. The fleet.**
One ADK detector template parameterized by check family, deployed four times to Cloud Run, four registry entries. The `support-agent` workload with two mock tools and the shared callback: enforce active policy, screen through Model Armor, write the conduct event with trace id, policy version, and attestation state. Foreman on Agent Runtime discovering workers via `list_agents()` and fanning out over A2A. Memory Bank wired.
**Hard cutoff at hour 5.** If Agent Runtime is still fighting, Foreman and Proposer ship on Cloud Run, auto-register identically, and Agent Gateway is dropped. Nothing in the demo script names a host.

**Aug 29, Day 5, ~7h. Close the loop and run it for real.**
Proposer under `proposer-sa` with structured output into the DSL, Memory Bank conditioning, and schema rejection written to the chain. Model Armor on verdict in and rationale out with results recorded. Analyst Copilot via `adk deploy cloud_run --with_ui`, verdict and approve as two ADK tools.
Then run the loop for real: incident, verdict, an over-blocking candidate rejected by the gate, a revised candidate promoted to v4 with a green certificate. Freeze the ledger and capture screen recordings of the real run, so Day 6 is editing rather than performing.

**Aug 30, Day 6, ~5h. Rehearse, record, write.**
Two full dress runs timed against the written cut list, every console tab pre-opened. Record the video, 4:00 hard.
README and Devpost text: the thesis line first, the prior-art table above including the supply-chain row, the innovation claim as worded, the verify SLO with measured p95, the degraded-mode table, THREATS.md listing how the system could be fooled and which control stops each, the architecture diagram, the clean-room disclosure, and the billing screenshot.
**Cut-list item, drop first if the day is short:** export the chain and evidence snapshot as a committed JSONL fixture and add a GitHub Action that runs the pure-Python hash re-check on a clean checkout, for a green badge from a machine that is not mine.

**Aug 31.** Devpost submission and upload. No code.

---

## 5. Demo video script

Thirteen beats, 240 seconds. Written cut list at the end.

**Ordering rule.** The video opens on the break, not on the build. The failure mode this entry has to beat is a judge filing it as "audit log plus approval workflow" inside the first minute, at which point the mechanism is never seen. So the first fourteen seconds show a guardrail that is still blocking and no longer authoritative, before anything is explained. The detailed break beat stays at 2:52, where it is earned rather than asserted.

| Time | Beat | On screen |
|---|---|---|
| **0:00-0:14** | **THE STAKE.** Cold open, no preamble, no product name. An injection attack hits the fleet and is denied by conduct policy v4. Then one `curl` shows that same v4 reporting `attested: false, state: QUARANTINED, promotions: FROZEN`. Voice, flat: "That rule is still blocking. It is no longer authoritative. Nobody attacked the rule. Somebody changed the evidence behind it." | Two panes, no cuts. Left: chat UI, `issue_refund denied by conduct policy v4`. Right: the curl response with `QUARANTINED` and `FROZEN` on screen together with the denial. |
| **0:14-0:26** | Rewind and name what was lost. `caseharden verify conduct-policy@v4` as it stood before the break. Seven links print green, ending in a root hash and `ATTESTED`. Voice: "This is what that rule had an hour ago. An agent's authority to act is derived from evidence, not granted by config. This is the derivation." | Full-screen terminal. Seven green lines: EVIDENCE, FINDING, VERDICT, DRAFT, HOLDOUT-DENIED, EXAM, APPROVAL. Caption: "re-derived from raw events in 2.4s". |
| **0:26-0:38** | Name the prior art before a judge can, including the hard one. Voice: "An AI drafts a rule and a human approves it. Unit21 shipped that in October, Sublime in September. Signed attestations gating admission are sigstore and Kyverno. Both exist. Neither re-derives the decision from its evidence, continuously, at serve time." | One static slide, two rows: "Already shipped: the loop" and "Already shipped: signed artifacts gating admission". One line below: "Not shipped: a record that re-proves the claim, not just the signature." |
| **0:38-0:56** | The fleet, and the first autonomy claim. Four conduct checks, one workload agent, one orchestrator. Voice: "Seven of these are mine. The orchestrator discovers them from the roster when its container starts. It names none of them in its source." | Terminal `gcloud alpha agent-registry agents list --location=europe-west3` returning nine entries; cut to the same nine rows in the GCP console. Caption: "discovery, not configuration". |
| **0:56-1:22** | **THE FAN-OUT.** The incident is the setup; the beat is what answers it. A support ticket carries an embedded instruction and the agent calls `issue_refund` across a tenant boundary. The Foreman fans the investigation out over A2A and four detectors answer in parallel, each returning a finding and the BigQuery job id that produced it. Voice: "Four agents, four queries, one round trip. Every number on screen has a job id a reviewer re-runs." | Four detector answers in the terminal with four distinct job ids visible at once, the offending tool call lit red; the ADK finding card beside them. Caption: "job id and trace id both live inside chain link 2." **The trace-DAG shot is back, as of the Day 7 sampler fix.** |
| **1:22-1:32** | Precedent, then verdict. **Ten seconds, deliberately.** Memory Bank surfaces two prior rejections by this reviewer, the analyst records one disposition, Model Armor screens it. Voice: "That is the only human turn in this loop." | Chat UI "Reviewer precedent" block, the verdict submitted, the Model Armor result. Cut on the decision id; do not film the typing. |
| **1:32-1:52** | Bounded authorship. The Proposer emits a candidate. The first attempt fails schema validation and is written to the chain as a rejection rather than retried silently. | Side by side: the 12-line DSL diff v3 to v4 on the left; on the right, `DRAFT REJECTED: unknown predicate — link 4a written`. Caption: "There is no allow verb in this grammar." |
| **1:52-2:10** | **THE SEAL.** The Proposer is asked to check its own work against the holdout. It tries. BigQuery refuses. Voice, flat: "It cannot read the exam. That is not our check. That is IAM." | Red `403 Access Denied: Table holdout_sealed.turns` with `proposer-sa@` visible; cut to the `holdout_sealed` access list, one row, `examiner-sa`; then the same read refused for the project owner; then the Cloud Audit entry naming `bigquery.tables.getData` denied for `proposer-sa@`; cut to link 5, "DENIED — recorded as evidence". |
| **2:10-2:34** | **THE GATE, refusing twice.** First refusal: a hand-written candidate catches one more sealed attack and also blocks two legitimate turns, so BENIGN throws it out. Second refusal, from the live Day 8 run: the Proposer's own candidates score 30/40 three times and CATCH refuses all of them. Then the ceiling, said as arithmetic. Voice: "Ten attacks per family, four families. Three families are a rule about one row. The fourth is a read and a write inside one session, which is a self-join and not a field. Thirty of forty is not a shortfall. It is the ceiling of the language, and the system can show its own." | Split: `policies/v5-candidate-a-overblocking.json` refused on BENIGN on the left; `captures/day8-gate-refuses-v6-no-improvement.txt` showing `[FAIL] CATCH 30/40 -> 30/40` on the right. Caption: "a refusal is a chain link, not a missing row". |
| **2:34-2:52** | Approve, promote, seal, enforce. v4 goes active, the certificate lands in the retention-locked bucket, the root hash is annotated on the registry entry, and the replayed attack is denied. | Chat UI approval; certificate viewer with seven green links and the root; 4-second cut of the GCS object showing retention expiry; chat UI: `issue_refund denied by conduct policy v4`. |
| **2:52-3:20** | **THE BREAK, explained.** This is the opening shot, now earned. One late-arriving event is inserted into the window v4 cited. Not an attack, just data. Voice: "That is the whole tamper. One row of ordinary data, and the version can no longer prove it was justified. Authority withdrawn, enforcement untouched, and nothing can be promoted on top of it." | Terminal: a sub-second streaming insert; then `curl` returning `200 {version: v4, attested: false, state: QUARANTINED, break: link 1 EVENT-WINDOW, event e_88214, promotions: FROZEN}`. Certificate link 1 flips red with the offending event id named. Then an attempted v5 promotion: `REFUSED — cannot build on an unattested version`. |
| **3:20-3:40** | The remedy. `caseharden reattest v4`. The Examiner re-scores against the evidence as it now stands, the gate still passes, link 8 records the evidence change, and the version goes green. Voice: "The fix is re-derivation, not editing the record. The record cannot be edited. The bucket refuses." | Terminal reattest output, new link 8 `EVIDENCE-CHANGED`, chain green; 3-second cut of `gcloud storage rm` on the v4 certificate returning a retention-policy error. |
| **3:40-4:00** | Close. At roughly 3:50, one line about where this sits: "Today the chain root is a custom annotation on a registry entry, and it is the only field on that roster that changes when the evidence does." Then the last spoken line is the thesis, verbatim, unchanged: "An agent's authority to act is derived from evidence, not granted by config." | Architecture card: nine registry entries, nine private Cloud Run services, the chain table, the locked bucket, the arrow from `proposer-sa` to `holdout_sealed` drawn in red and crossed. Bottom bar: repo URL, europe-west3, Gemini 3.5 Flash, and the billing report showing spend to date. |

**Version numbers in this table are the walk-through's, not the fleet's.** The beats above
say v3 and v4 because they were written before anything ran. The live project promoted v4
on Day 3 and **v5** on Day 5, and v5 is what the fleet enforces today. Rehearse against the
version that is active on the day, and keep the beat structure; the four untouchable beats
are untouched by this note.

**The 2:34 promotion beat is cut from captures, not shot live.** The v6 take on 2026-08-26
was refused by the gate, so no promotion happens on camera. The source is
`captures/day5-loop-promotes-v5.txt`, which carries the whole beat: parent accepted, seven
links written, root `e2a559358933`, and the certificate sealed to
`gs://caseharden-certificates-506416/certificates/v5/007-e2a559358933.json`. Everything after
the moment of promotion is still live and can be shot today, because v5 is the active version:
`verify --version v5` returns seven green links, `out/certificate-v5.html` renders them, and the
GCS object shows its retention expiry.

Two consequences worth keeping straight. The 2:10 gate beat gains a second, different refusal
in `captures/day8-gate-refuses-v6-no-improvement.txt`, where the reason is no improvement on
sealed attacks rather than a benign regression. And the 2:52 break beat still works exactly as
`docs/REHEARSAL.md` scripts it, because `v6` was never registered and is still the free version
name that beat attempts and is refused.

**Written cut list, in order.** 1) The retention-expiry cut at 2:34. 2) The rejected-draft half of the 1:34 beat. 3) The registry console page at 0:38, keeping the terminal only. 4) The rewind beat at 0:14, folding the green chain into the 2:52 payoff.
**Untouchable, in priority order.** The cold open at 0:00. The 403 at 1:52. The gate rejection at 2:10. The break at 2:52.

---

## 6. Grafts taken

| Graft | Source | Why it raises win probability without breaking feasibility |
|---|---|---|
| **Two-sided promotion gate, with the over-blocking candidate rejected on camera** | Entry D; both the google-platform and skeptic judges called it the best beat in the field | Over-blocking is the real production failure mode of auto-generated rules, and it lands squarely on Operational Utility, the heaviest criterion. The Examiner already computes benign pass rate, so the gate is one boolean and the beat is one red banner. Highest score per line of code in this document. |
| **Domain shift from promo abuse to agent-conduct governance** *(accepted by the entrant 2026-08-25; overrides the earlier locked domain decision)* | Entries A, D, E; flagged as B's innovation cap by two of three judges | Promo abuse was the single named ceiling on B's innovation score, and it was visible in the Devpost text before a judge presses play. The switch costs a relabel of the synthetic generator and the predicate vocabulary, plus one workload agent. It also makes the enforcement point real: the thing being withdrawn is agent authority, not a report. |
| **Supply-chain prior art named first** (sigstore, in-toto, SLSA, cosign, Kyverno) | Skeptic judge, winner weakness 1 | Pure README text. B's whole credibility strategy is naming prior art before a judge does, and it was missing the one analogue closest to its claim. The delta that survives, re-deriving the claim rather than verifying a signature, is stronger for having been forced to articulate it. |
| **Monotonicity checked as a property, not promised** | Entry A's ratchet direction, Entry C's verifier | About 15 lines inside a replay loop that already runs. Buys the third leg of the gate and, more importantly, makes the quarantine fallback argument sound: versions only narrow, so the last attested version is a known bounded state. |
| **Model Armor verdict fields as first-class DSL predicates** | Entry D | Free. Policy composes with Model Armor instead of re-implementing screening, which is the platform-native move a Google reviewer notices. |
| **Governance plane inside its own blast radius** | Entry A | Zero code. A deployment choice plus one caption: the Proposer runs behind the same callback and appears in the same registry. |
| **Written cut list with named untouchable beats** | Entry E | Free, and it converts an overrun from "the ending is rushed" into "a middle beat was dropped". |
| **CI hash re-check on a clean checkout, badge in the README** | Entry C, reduced to about 5 percent of its scope | The cheapest available answer to "we only have your word for it": a committed chain export plus a GitHub Action running the pure-Python link recompute. Roughly one hour, and it is explicitly a Day 6 cut-list item. |
| **Tamper by streaming insert, remedy by re-attest** | Skeptic judge, winner weakness 5 | Replaces a slow on-camera DML UPDATE with a sub-second insert, and replaces "undo my own tamper" with the production remedy path. Better story, fewer seconds, more credible. |

---

## 7. Grafts rejected

| Rejected | Source | Why |
|---|---|---|
| **Scheduled adversary agent and the titer matrix** | Entry D's centerpiece | Adds a Gemini-backed agent on Cloud Scheduler, the only unbounded recurring cost in the field, plus emergent generational quality the entry's own judge flagged as possibly needing to be staged. The two-sided gate delivers the same reversal beat deterministically. Cost without added score. |
| **KMS asymmetric signing and the offline verifier** | Entry C | Two of three judges marked C infeasible on scope, and one noted the offline framing spends the video's best seconds on a laptop with no GCP, against a requirement to show the GCP backend. Canonical JSON plus signing plus a five-property verifier is the classic half-day loss. The append-only chain, the sealed access list and the locked retention policy already carry the claim. |
| **Bespoke live console with attack feed** | Entry D | B's discipline is that no custom UI exists. `adk deploy cloud_run --with_ui` plus one 80-line static certificate renderer is what makes six days work. |
| **Recusal and a second identical proposer** | Entry E | Two judges called it correctly: identical code and identical weights behind a different service account provides no independence. It is an if-statement in a suit, and it would invite the exact "gimmick" read that costs credibility. |
| **Model Armor as policy actuator, compiling to a template revision** | Entry E | Attractive on paper, but Model Armor templates carry fixed filter settings and cannot express a tool-level deny with a rate cap. The beat risks visibly under-delivering in front of the judges who own the product. Model Armor stays as sensor and screen, and as DSL predicates. |
| **`make attack`, a public judge-facing injection endpoint** | Entry C | Unbounded exposure during the judging window with no ability to respond. Small upside, uncapped downside. |
| **Rerouting the whole entry to offline verifiability** | Entry C's thesis | It is the least visual of the five deltas and depends on a judge running a command. Most do not. |

---

## 8. Every winner weakness, addressed

The skeptic judge listed six weaknesses in Caseharden. Each is fixed, mitigated, or accepted with a reason.

**1. Prior-art table omits the closest analogue: sigstore, in-toto, SLSA, Kyverno.**
**Fixed.** Both rows are now in the table, above Unit21, and the delta is stated in the terms a supply-chain-literate judge will use: those verify a signature over a digest at admission time; Caseharden re-executes the deterministic Examiner and re-derives the evidence at serve time. The demo spends five of its 240 seconds naming them out loud, which is where that credibility is cheapest to buy.

**2. Fail-closed governance takes fraud enforcement offline. No SLO, no degraded mode.**
**Fixed, and it improved the concept.** Attestation now gates authority, not availability. A quarantined version keeps enforcing; what freezes is its standing as justified and the ability to promote on top of it. A verify **error**, as distinct from a verify **failure**, yields `unknown`, retains the last known state, and alerts, so a BigQuery outage is not an incident. Verify budget is under 5s p95, cached 60s, measured and published. The README carries the three-state table. The demo now shows it before it says it: the cold open at 0:00 puts a denied attack and a `QUARANTINED` policy state in the same frame, and the voice line "authority withdrawn, enforcement untouched" lands at 2:52.

**3. Domain visibility. The Devpost text lists four promo-fraud detectors before a judge presses play.**
**Fixed by the domain switch.** The detectors are now `scope-violation`, `injected-turn-tool-call`, `cross-tenant-egress`, and `privilege-sequencing`, and the one-liner leads with agent-fleet governance. The crowded specimen that capped innovation at 6.5 in the baseline scoring is gone, and the enforcement point became more legible in the process.

**4. Twelve beats, three console proofs, 240 seconds, no cut list.**
**Mitigated, and the count is stated honestly.** Thirteen beats, not fewer, because the break-first ordering adds a cold open and a rewind. Four of the thirteen run under 15 seconds. What actually protects the ending is the written cut list in priority order, four named untouchable beats, and every console tab pre-opened during Day 6's two dress runs. An overrun costs the registry console cut, then the rewind beat, not the ending.

**5. Two weak filler beats: the retention-lock delete refusal, and a slow BigQuery DML on camera.**
**Fixed.** The retention lock is no longer a standalone beat. Its proof, the refused delete, is folded into the 3:20 re-attest beat where it makes an argument ("the fix is re-derivation because the record cannot be edited") rather than demonstrating a storage feature. The tamper is a sub-second streaming insert of a late-arriving event, which is faster, more realistic, and a better story than a malicious UPDATE.

**6. The 2.1s link-1 re-derivation and the 60s cache are unvalidated against a growing table.**
**Fixed.** Link 1 re-derivation is a partition-pruned, clustered scan bounded to the finding's window, so it does not grow with the warehouse. The README publishes the measured p95 with the row count it was measured at, and states the verify SLO plus the `unknown` state that covers a breach of it. The video quotes the measured number, not a hoped-for one.

**Also addressed from the ranking rationales:** Agent Gateway remains honestly marked droppable and sits first on the Day 4 cut list. That is **accepted**, not fixed. Seven load-bearing platform components is already a strong showing, and adding a dependency on the eighth to avoid an honest disclaimer would be exactly the checklist posture a platform reviewer penalizes.

**On the other judges' winner weaknesses:** those attach to entries C and D, and they are the reason for two rejections above. D's titer matrix depends on emergent adversary quality and on a 60-transcript benign corpus a judge could read as engineered, so the adversary was rejected and the benign corpus here is 600+ turns. C's Day 5 and Day 6 scope failed two feasibility gates, so only its cheapest artifact, the CI hash re-check, was taken, and even that sits on the cut list.

---

## 9. Top three remaining risks

**1. Agent Runtime or A2A wiring consumes Day 4.**
Cloud Run is the pre-approved fallback host for every agent and auto-registers into Agent Registry identically, so the registry-driven discovery pattern, the A2A fan-out, the visible roster, and every hard requirement survive the swap. Hard cutoff at hour 5 of Day 4: Foreman and Proposer move to Cloud Run, Agent Gateway is dropped. Nothing in the demo script names a host, so the video does not change.

**2. The gate's rejection beat has to come from a real candidate, not a fixture.**
The gate itself is pinned by pytest on Day 2, so the rejection is a property of the code before any agent exists. The benign corpus is 600+ turns rather than a number small enough to engineer. On Day 5 the real Proposer runs and, on precedent, over-blocking drafts are the common failure, so the rejected candidate is expected to be genuine. If it is not, the entrant hand-writes the over-blocking candidate, the README says the candidate was hand-written, and the gate result stays real. Honest labeling costs a sentence and protects the claim the whole entry is funded by.

**3. The three-state attestation machine is the entry's core claim and is new code.**
It is three states, one cache, and one error path. It is built on Day 3 against hand-fed links before any agent exists, with one pytest per transition including the `unknown` path. The memorable moment is therefore complete and rehearsable three days before filming, which is the schedule property that separates this plan from the entries that scheduled their climax for Day 5.

**Budget.** Flash only, no Pro. The Examiner and the Notary make no model calls. No scheduled adversary and no unattended loop. Estimated spend is roughly $30 of the $150 credit, and the billing report is on screen in the final frame.
