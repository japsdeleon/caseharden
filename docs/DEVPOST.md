# Devpost submission text

Paste-ready. Section headings match Devpost's own fields.

---

## Elevator pitch (200 characters)

Governance plane for enterprise agent fleets: guardrails keep authority only while their evidence re-verifies, refusals are recorded beside approvals, and the record's root is delete-proof.

*(paste into the form as one line)*

---

## Inspiration

Every agent-governance product I have seen ends the same way: the AI drafts a rule, a human
approves it, and the system writes an audit log. The log describes the promotion. It has no
authority over it. Nobody reads it again.

The failure mode this defends against is documented, not invented. In November 2025 AppOmni
Labs showed that text submitted inside an ordinary service ticket could make a ServiceNow Now
Assist agent recruit a second, more privileged agent, read a record the submitter had no right
to, and copy its contents into a record the submitter owned. The vendor's own prompt-injection
protection was enabled while that worked. Screening the input was not the control. It is a
vendor lab demonstration rather than an incident in the wild, and the boundary crossed was an
ACL boundary inside one instance, so it is cited here for the shape of the attack and not for
its scale.

The supply-chain world already solved the neighbouring problem. sigstore, in-toto and SLSA
bind an artifact to its build inputs and verify the signature before use. Kyverno and OPA
Gatekeeper refuse to admit an artifact whose attestation does not verify.

But a signature proves nobody edited the claim. It does not prove the claim is still true.
That gap is what Caseharden is about.

Two pieces of work got there first, and they are named in the README's prior-art table rather
than left for a judge to find. Microsoft's Agent Governance Toolkit, MIT-licensed since April
2026, already intercepts every tool call before it executes, with Cedar and Rego behind it.
Salfeld-Nebgen's *Governing Actions, Not Agents* (arXiv 2606.26298, June 2026) already states
the authority-from-attested-evidence model. Neither addresses what happens after the evidence
moves. That is the part this entry builds: the quarantine state itself — enforcement retained,
standing lost, promotion frozen. A late-arriving event can quarantine a version no attacker
ever touched, which no signature scheme detects.

## What it does

Caseharden governs what an enterprise's AI agents may do, and how that answer is allowed to
change.

The friction it removes is specific. A security team tightens a rule that governs an AI agent,
and learns in production whether the tightening broke legitimate work. Caseharden makes that
answer a precondition of the change rather than a consequence of it.

**The human appears exactly twice in the loop, to judge and to approve. Everything else runs
unattended.**

A support agent does ordinary work with two tools, a tenant-scoped read and a refund write.
Every tool call is screened by Model Armor and written as one structured conduct event to
BigQuery. An orchestrator then reads Agent Registry at container start, names no detector
anywhere in its source, and fans an investigation out over A2A (the agent-to-agent protocol)
to whatever the roster lists. Four detectors answer in parallel. Each returns a finding and
the BigQuery job id that produced it, so a reviewer re-runs the query instead of trusting a
summary. W3C trace context rides the fan-out, so one investigation is one Cloud Trace trace:
361 spans across the orchestrator and all four detectors, and every conduct row and chain
link carries the trace id that opens it.

The finding reaches a human analyst, who records one verdict in the Agent Development Kit's
(ADK) own chat window. That is the first human turn; the second is the approval that ends the
loop. Between them a Proposer agent reads the fleet's own review history out of Memory Bank,
drafts a guardrail change in a small deny-only DSL (a rule language that can only forbid), and
is refused by BigQuery with a real 403 when it reaches for its own exam. That denial is sealed
into every promoted chain as its own link, so the record attests to what was prevented. A
deterministic Examiner, not a model, scores the draft against that sealed holdout under a
different service account, over 40 labelled attack sessions and 640 legitimate turns, and
applies a three-leg gate: blocked attacks must go up, the benign pass rate must not fall, and
the new version must only narrow authority. A candidate that fails the gate never enters the
record at all.

**The gate holds at 30 of 40, and that is a property of the language rather than a shortfall.**
The sealed holdout carries ten attack sessions for each of four check families. Three families
are expressible as rules over a single conduct event. The fourth is a read and a write inside
one session, which is a self-join and not a field, so no predicate in this DSL reaches it. No
version of the policy can deny those ten without also blocking legitimate work: the one
candidate that caught one of them was refused by the gate for exactly that
(`captures/day5-gate-refuses-the-proposer.txt`). The ceiling sits under the best-evidenced
attack shape in the field — the AppOmni sequence from Inspiration is a privileged read
followed by a write — which is why the session-scoped predicate is first in What's next, and
why `THREATS.md` names this hole twice. The system knows where its own ceiling is and can show
the arithmetic.

Every step is a hash-linked record in a BigQuery chain, append-only by convention, and a hash
chain alone proves little: anyone holding the writer's credentials can rewrite it end to end.
The anchor is the root, sealed at promotion into a Cloud Storage object under a locked 30-day
retention policy and annotated onto the Agent Registry entry. The bucket refuses delete,
overwrite, and removal of the policy itself, from the project owner, and the lock is
irreversible. What the lock buys is narrower than tamper-proof, and `THREATS.md` says so
plainly: a credentialed writer who reseals a rewritten chain to a new certificate still passes
`verify`, so the locked object is the durable witness a rewrite cannot erase, not a gate a
rewrite cannot pass.

**The product is not the detection. The product is the attestation.** A guardrail version is
served as `attested` only while `caseharden verify` re-derives its evidence and its exam from
the raw conduct events and re-walks every link in its chain. When the evidence changes, the version is quarantined: it keeps blocking, but
it loses its standing as justified, and nothing can be promoted on top of it until it
re-derives.

## How I built it

Nine private Cloud Run services in europe-west3. Eight run from one image and differ only by
environment; the ninth is `adk deploy cloud_run --with_ui`, unmodified: the agent surface is
ADK's own and the two tools behind it are the part I wrote. The analyst also gets a local
operator console that reads the chain, the registry and the finding under review, and routes
its one write *through* the unmodified Copilot, so it sits outside the trust boundary: it
offers a verdict and stores nothing itself. It runs against a committed fixture with no
credentials at all; the README carries the full trust-boundary argument.

This is the Fortified Enterprise Fleet track. Its five themes, one row each:

| Track theme | In this entry | Proof |
|---|---|---|
| Corporate agent discovery | the orchestrator reads Agent Registry at boot and names no detector in its source; each entry carries its policy version's chain root | `captures/day7-fleet-proof-all-held.txt` |
| Multi-agent orchestration | one investigation fans out over A2A to four detectors in parallel, each answering with a BigQuery job id | `captures/day4-fleet-proof.txt` |
| Long-term state persistence | Memory Bank precedent ids are read before drafting and sealed into the DRAFT chain link | `infra/110_run_loop.py` |
| Runtime observability | every conduct row and chain link carries a trace id; one fan-out is a 361-span Cloud Trace DAG | `captures/day7-fleet-proof-all-held.txt` |
| Security posture enforcement | the three-leg gate, Model Armor verdicts as DSL predicates, the IAM 403, the locked retention root | `captures/day2-gate-two-sided.txt` |

- **Agent Registry** is the roster and the discovery layer. The orchestrator's source names
  no detector. Each entry carries the chain root of the policy version it was registered
  against, so the platform's own discovery layer carries the audit anchor.
- **Per-agent IAM identities** are load-bearing rather than decorative. `proposer-sa` and
  `examiner-sa` are distinct principals. No principal holds a project-wide BigQuery data role,
  and `holdout_sealed`'s access list has exactly one entry.
- **Model Armor** screens in both directions, and its verdict fields are first-class
  predicates in the policy DSL, so policy composes with it instead of re-implementing it.
- **Memory Bank** holds the fleet's own review history. The Proposer reads it before drafting
  and the memory ids it used are recorded in the chain.
- **BigQuery** holds the conduct events, the sealed holdout, the benign corpus, the chain and
  the policy registry. **Cloud Storage** with a locked retention policy holds the
  certificates. **Gemini 3.5 Flash** only, no Pro. The Examiner and the Notary make no model
  calls at all.

## Challenges I ran into

**Re-attestation was quietly changing which policy the fleet enforced.** Re-pointing a
version at its new certificate went through the promotion path, which marks its own version
active and every other one inactive. Re-attesting an old version therefore put that version
back in force. It happened on the live project and the Policy Server reported it truthfully,
which is the only reason it was caught.

**A deploy script had been writing empty public URLs.** A mangled format argument made every
URL lookup fail, the failure was swallowed by a shell assignment, and four services then
advertised `localhost` in their agent cards.

**Spans did not reach Cloud Trace from Cloud Run, for three days, and the transport was never
the problem.** Four real faults were found and fixed on the way there and none of them was the
cause. It was the sampler: Cloud Run puts a `traceparent` on every inbound request with the
sampled flag off, OpenTelemetry's default sampler honours that, and every request span was
created with a valid context and never recorded. `current_trace_id()` then wrote a real span
id for a trace that was never written, so nothing failed anywhere. `ALWAYS_ON` on the provider
is the whole fix, and what made it findable was emitting one parentless span at container boot:
that span landed while every request span vanished, and the asymmetry separated "the transport
is broken" from "the spans are never recorded".

## Accomplishments I am proud of

The gate refused the real Proposer's real candidate. It caught one more sealed attack than
the active version and blocked two legitimate turns, and the benign leg alone was enough to
throw it out. No fixture was involved.

It happened again on the final live run, and this time nothing passed. The Proposer got a
capped four attempts: three drafts scored no improvement on sealed attacks and the fourth
failed schema validation, so the loop stopped and wrote nothing to the chain — a candidate
that fails the gate never enters the record. Each attempt's feedback named only the failed
leg, never a holdout row, and the run was not re-taken: drafting against the sealed exam
until it passes is the tuning the Proposer and Examiner split exists to prevent. The version
the fleet enforces today is the one the gate let through, not the newest one drafted
(`captures/day8-gate-refuses-v6-no-improvement.txt`).

Every number published is measured. `verify` p95 is 3.66s against a 5s target. 291 tests. 63
mutations broken on purpose and all 63 caught, including one that survived its first run and
now has two tests.

## What I learned

An assertion that cannot fail is worse than no assertion. Three of the defects above were
sitting behind checks that were passing: a trace check that accepted any 32-character string,
a memory check that any earlier run could satisfy, and a distinction between attested and
unattested that was false for every block ever taken.

## What's next for Caseharden

A session-scoped predicate in the DSL. The four check families the detectors cover are
per-turn; the attacks that survive the current policy are the ones that spread their steps
across a session, and the Examiner already has the corpus to score that gate honestly.

Then a second host. Every agent is on Cloud Run today, and putting one on Agent Runtime
would show that the roster and the enforcement callback do not care where a worker lives.

---

## Built with

`google-adk` · Agent Registry · Model Armor · Memory Bank · Vertex AI Gemini 3.5 Flash ·
Cloud Run · BigQuery · Cloud Storage retention lock · Cloud IAM · Cloud Trace · Cloud Build ·
Python · OpenTelemetry

## Try it out

- Repository: https://github.com/japsdeleon/caseharden
- Specification: `docs/PLAN.md` · Daily build log with measured numbers: `BUILD_LOG.md`
- Terminal captures for every claim: `captures/`
- Check the record yourself, no credentials, no network, seconds:
  `python3 -m caseharden.recheck fixtures/v5` — seventeen checks, including a full Examiner
  replay against corpora regenerated from the committed seeded generator
- Open the analyst console on the same fixture, also credential-free:
  `python3 -m caseharden.workbench --fixture fixtures/v5`
- The same recheck runs on GitHub's own runners on every push (Actions tab), so a machine
  that is not mine vouches for the record
- The two guarantees reproduce without trusting this code:
  `captures/day1-proposer-403-on-holdout.txt` (BigQuery refuses the Proposer its own exam) and
  `captures/day1-retention-refuses-delete.txt` (Cloud Storage refuses a delete from the
  project owner)
- Threat model, including ten holes stated plainly: `THREATS.md`

## Clean-room disclosure

No employer code, data, schemas, table names or infrastructure. All data is synthetic and
generated by a seeded script committed to the repository. The build machine also holds an
unrelated employer's Application Default Credentials, so nothing in this project reaches for
ADC without checking the project first, and the guard reads ADC precisely in order to refuse
it.
