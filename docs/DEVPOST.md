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

The supply-chain world already solved the neighbouring problem. sigstore, in-toto and SLSA
bind an artifact to its build inputs and verify the signature before use. Kyverno and OPA
Gatekeeper refuse to admit an artifact whose attestation does not verify.

But a signature proves nobody edited the claim. It does not prove the claim is still true.
That gap is what Caseharden is about.

## What it does

Caseharden governs what an enterprise's AI agents may do, and how that answer is allowed to
change.

A support agent does ordinary work with two tools. Every turn it takes is screened by Model
Armor and written as one structured conduct event to BigQuery. Four detector agents,
discovered through Agent Registry rather than named in config, run governed SQL checks over
that event stream. An orchestrator fans an investigation out to whatever the registry lists.

A finding goes to a human analyst, who types a verdict into ADK's own chat window. A Proposer
agent drafts a guardrail change in a small deny-only DSL. A deterministic Examiner, not a
model, scores that draft against a sealed holdout the Proposer is IAM-denied from reading,
and applies a two-sided gate: attacks must go down, benign traffic must not, and the new
version must only narrow authority.

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

Every number published is measured. `verify` p95 is 3.66s against a 5s target. 254 tests. 54
mutations broken on purpose and all 54 caught, including one that survived its first run and
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
- Threat model, including six holes stated plainly: `THREATS.md`

## Clean-room disclosure

No employer code, data, schemas, table names or infrastructure. All data is synthetic and
generated by a seeded script committed to the repository. The build machine also holds an
unrelated employer's Application Default Credentials, so nothing in this project reaches for
ADC without checking the project first, and the guard reads ADC precisely in order to refuse
it.
