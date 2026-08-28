# Devpost submission text

Paste-ready. Section headings match Devpost's own fields.

---

## Elevator pitch (200 characters)

An agent's authority to act is derived from evidence, not granted by config. A guardrail
keeps its authority only while its provenance chain re-derives from raw conduct.

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
the authority-from-attested-evidence model, and states it more generally than this entry does.
Neither addresses what happens after the evidence moves. That is the part this entry builds.

## What it does

Caseharden governs what an enterprise's AI agents may do, and how that answer is allowed to
change.

The friction it removes is specific. A security team tightens a rule that governs an AI agent,
and learns in production whether the tightening broke legitimate work. Caseharden makes that
answer a precondition of the change rather than a consequence of it.

**One human turn sits inside the loop. Everything around it runs unattended.**

A support agent does ordinary work with two tools, a tenant-scoped read and a refund write.
Every turn is screened by Model Armor and written as one structured conduct event to BigQuery.
An orchestrator then reads Agent Registry at container start, names no detector anywhere in its
source, and fans an investigation out over A2A to whatever the roster lists. Four detectors
answer in parallel. Each returns a finding and the BigQuery job id that produced it, so a
reviewer re-runs the query instead of trusting a summary.

The finding reaches a human analyst, who records one verdict in ADK's own chat window. That is
the human turn. From there a Proposer agent reads the fleet's own review history out of Memory
Bank, drafts a guardrail change in a small deny-only DSL, and is refused by BigQuery with a real
403 when it reaches for its own exam. A deterministic Examiner, not a model, scores the draft
against that sealed holdout under a different service account, over 40 labelled attack sessions
and 640 legitimate turns, and applies a three-leg gate: blocked attacks must go up, the benign
pass rate must not fall, and the new version must only narrow authority. A refusal is written to
the chain as its own link, so the record attests to what was prevented.

**The gate holds at 30 of 40, and that is a property of the language rather than a shortfall.**
The sealed holdout carries ten attack sessions for each of four check families. Three families
are expressible as rules over a single conduct event. The fourth is a read and a write inside
one session, which is a self-join and not a field, so no predicate in this DSL reaches it. The
detector finds those sessions. The chain records them. No version of the policy can deny them.
The system knows where its own ceiling is and can show the arithmetic.

Every step is a hash-linked record in a BigQuery chain, append-only by convention, whose root
is sealed into a retention-locked Cloud Storage object and annotated onto the Agent Registry
entry. The lock is what makes a rewrite detectable.

**The product is not the detection. The product is the attestation.** A guardrail version is
served as `attested` only while `caseharden verify` re-derives its evidence and its exam from
the raw conduct events and re-walks every link in its chain. When the evidence changes, the version is quarantined: it keeps blocking, but
it loses its standing as justified, and nothing can be promoted on top of it until it
re-derives.

## How I built it

Nine private Cloud Run services in europe-west3. Eight run from one image and differ only by
environment; the ninth is `adk deploy cloud_run --with_ui`, unmodified: the agent surface is
ADK's own and the two tools behind it are the part I wrote. The analyst also gets a local
operator console, which reads the chain, the registry and the finding under review and takes
attestation from the Policy Server rather than deciding it. Its one write goes *through* the
unmodified Copilot, not around it, so the console is outside the trust boundary by
construction: it offers a verdict and writes nothing itself, and what is stored is decided by
the Copilot service under its own identity. It runs against a committed fixture with no
credentials at all.

- **Agent Registry** is the roster and the discovery layer. The orchestrator's source names
  no detector. Each entry carries the chain root of the policy version it was registered
  against, so the platform's own discovery layer carries the audit anchor.
- **Agent Identity** is load-bearing rather than decorative. `proposer-sa` and `examiner-sa`
  are distinct principals. No principal holds a project-wide BigQuery data role, and
  `holdout_sealed`'s access list has exactly one entry.
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
the active version and blocked two legitimate turns, and that was enough. No fixture was
involved.

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

`google-adk` · Agent Registry · Agent Identity · Model Armor · Memory Bank · Vertex AI Gemini
3.5 Flash · Cloud Run · BigQuery · Cloud Storage retention lock · Cloud IAM · Cloud Build ·
Python · OpenTelemetry

## Try it out

- Repository: https://github.com/japsdeleon/caseharden
- Specification: `docs/PLAN.md` · Daily build log with measured numbers: `BUILD_LOG.md`
- Terminal captures for every claim: `captures/`
- Threat model, including ten holes stated plainly: `THREATS.md`

## Clean-room disclosure

No employer code, data, schemas, table names or infrastructure. All data is synthetic and
generated by a seeded script committed to the repository. The build machine also holds an
unrelated employer's Application Default Credentials, so nothing in this project reaches for
ADC without checking the project first, and the guard reads ADC precisely in order to refuse
it.
