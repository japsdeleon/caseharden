# Caseharden

**An agent's authority to act is derived from evidence, not granted by configuration.**

A governance plane for an enterprise agent fleet. A guardrail keeps its authority only while
its provenance chain re-derives from raw evidence. The two guarantees that chain rests on,
proposer isolation and record immutability, are enforced by BigQuery IAM and a Cloud Storage
retention lock rather than by this project's code.

All Things Agentic Hackathon · Fortified Enterprise Fleet · solo entry · europe-west3.

[![recheck](https://github.com/japsdeleon/caseharden/actions/workflows/recheck.yml/badge.svg)](https://github.com/japsdeleon/caseharden/actions/workflows/recheck.yml)

https://github.com/japsdeleon/caseharden

Specification: [`docs/PLAN.md`](docs/PLAN.md). The vocabulary, one name per idea:
[`CONTEXT.md`](CONTEXT.md). Daily progress with measured numbers:
[`BUILD_LOG.md`](BUILD_LOG.md). Terminal captures of every claim below: [`captures/`](captures).

---

## The claim

In Caseharden the provenance record is load-bearing rather than descriptive. A guardrail
version is authoritative in production only while its chain re-derives from the raw conduct
events that justified it. Changing the evidence withdraws the version's authority instead of
filing a discrepancy report.

Two guarantees are discharged outside this project's code:

- **The proposing agent never read its own evaluation data.** That is BigQuery access control
  producing a real 403, and the access list that produces it is hashed into the chain, so a
  later grant to the Proposer breaks the chain rather than going unnoticed.
- **An edit to the record cannot be hidden.** The chain's root is sealed into a Cloud Storage
  object under a locked retention policy, which refuses a delete from the project owner. The
  chain table itself is append-only by convention; what the lock guarantees is that a rewritten
  chain no longer matches the root that was sealed when it was written.

Refusals are stored as links in the same chain as approvals, so the record attests to what
was prevented and not only to what occurred.

## What already exists, named before a judge has to find it

| Prior work | What it already does |
|---|---|
| Unit21 AI Rule Recommendation Agent (Oct 2025) | Analyzes analyst dispositions, drafts optimized rules, shadow-tests against historical data, deploys on approval |
| Sublime Security ADE (Sept 2025) | LLM drafts detection rules in a constrained DSL, PR-style human review |
| Stripe Radar Assistant, DataVisor Co-Pilot | LLM-drafted rules, backtested, human-approved |
| MLflow-era MLOps | Holdout-then-promote, versioned artifacts, champion/challenger, rollback |
| **sigstore / cosign, in-toto, SLSA** | **Signed attestations binding an artifact to its build inputs, verified before use** |
| **OPA Gatekeeper, Kyverno admission control** | **Refuse to admit an artifact whose attestation does not verify** |
| **Binary Authorization Continuous Validation** | **Re-checks images on already-running Pods against the current policy at least every 24 hours, and logs the violations to Cloud Logging** |
| **Agent Gateway (GA)** | **Network entry and exit point for agent traffic. Parses MCP and A2A, enforces IAM through Identity-Aware Proxy, and allows only explicitly authorized resources by default** |
| **Semantic governance policies (Preview)** | **An intent gate at the Gateway. Rules are natural-language constraints evaluated by a model at runtime, returning ALLOW or DENY** |
| **Agent Identity (GA on Agent Runtime)** | **Agents as first-class IAM principals on SPIFFE, with X.509 rotated every 24 hours, and IAM allow and deny policies against agent principals** |
| **SCC Agent Platform Threat Detection (Preview)** | **Runtime and control-plane detectors over agent infrastructure and audit logs** |
| **Microsoft Agent Governance Toolkit (Apr 2026, MIT)** | **Intercepts every tool call, message and delegation in deterministic code before execution. YAML rules, OPA Rego and Cedar. Deny-by-default strict mode. Evidence mapped to the EU AI Act, HIPAA, SOC 2 and the OWASP Agentic AI Top 10** |
| **"Governing Actions, Not Agents", Salfeld-Nebgen, [arXiv 2606.26298](https://arxiv.org/abs/2606.26298) (Jun 2026)** | **The agent holds no execution authority. Execution is conditional on preconditions independently attested by a separate authoritative source, bound to a declared intent, evaluated by a deterministic policy, and recorded in a tamper-evident log** |

Caseharden claims none of it as new. The verdict-to-policy loop is shipped product. Signed
artifact verification gating admission is shipped infrastructure. Pre-execution interception of
agent tool calls is a free MIT-licensed toolkit from Microsoft, and the thesis at the top of
this file was published as a paper two months before this build. The last two rows are the
closest analogues to this entry's actual claim, which is why they are named here rather than
left for a judge to find.

**The delta.** Those systems attest an *artifact* against its *build inputs*, verify a
*signature over a digest*, and gate at *admission time*. Caseharden attests a *decision*
against its *evidence*, and verification does not stop at a hash. It re-executes the
deterministic Examiner over the sealed holdout to reproduce the metric that justified the
promotion, and it re-scans the conduct events the finding cited. A signature proves nobody
edited the claim. Caseharden proves the claim is still true. That is why a late-arriving
event can quarantine a version no attacker ever touched, which no signature scheme detects.

**Post-admission re-checking is not the delta, and saying so would be wrong.** Binary
Authorization Continuous Validation already re-evaluates running workloads after admission, on
a schedule, against the policy as it currently stands. Three things separate it from what
happens here. Its subject is the artifact's conformance to the rule, never the rule's own
justification. Its evidence side is an immutable digest, so "the evidence moved" is a case that
cannot arise. And a failed check writes a log entry: nothing changes state on the artifact, and
nothing is frozen. Caseharden re-derives the justification rather than the conformance, and a
failure withdraws the version's standing and freezes promotion on top of it.

**Where the delta is proven, and where it is not.** The staleness gap is demonstrated against
supply-chain attestation, and there it is structural rather than an omission: in-toto requires
`digest` on every subject and states that subjects are assumed immutable, and SLSA's
Verification Summary Attestation carries `timeVerified` and no expiry, validity window or
revocation field. It is **not** demonstrated against the agent-identity, non-human-identity,
runtime-guardrail or continuous-control-monitoring vendors. That category has not been
surveyed here, so nothing is claimed about it.

**Where this sits beside the agent-governance work.** The Microsoft toolkit and this project
act at different points and are not substitutes. AGT intercepts a tool call before it executes
and answers "is this allowed". Caseharden acts after the turn is recorded and answers "is the
rule that allowed or denied it still justified". A pre-execution interceptor is the stronger
control for stopping a single action, and Cedar's permit/forbid is a more expressive language
than this project's deny-only DSL, not a weaker one. Neither runtime interception nor
deny-only enforcement is offered here as a differentiator.

**The framing is prior art too.** Salfeld-Nebgen published the attested-preconditions model in
June 2026, two months before this build, and states it more generally than this entry does.
What that paper's abstract does not carry is what happens once an attestation's evidence
changes underneath it: it describes a tamper-evident log "amenable to independent
re-verification", not authority that is withdrawn when re-derivation fails. The narrow thing
this entry adds is the quarantine state itself: enforcement retained, standing lost, promotion
frozen.

**Not claimed:** first AI-proposed policy under human review, first constrained-DSL drafting,
first holdout gate, first signed provenance, first monotone policy versioning, first runtime
interception of agent tool calls, first deny-by-default agent policy engine, first
authority-derived-from-attested-evidence framing. Each is prior art and each is cited above.

## Architecture

```mermaid
flowchart LR
  subgraph fleet["The governed fleet, Cloud Run, private"]
    W["support agent<br/>workload-sa"]
    F["Foreman<br/>foreman-sa"]
    D["4 detectors<br/>detector-sa"]
    P["Proposer<br/>proposer-sa"]
  end
  subgraph plane["The governance plane"]
    PS["Policy Server<br/>examiner-sa"]
    EX["Examiner<br/>deterministic, no model"]
    NO["Notary<br/>notary-sa"]
  end
  AC["Analyst Copilot<br/>ADK web UI, analyst-sa"]
  CL[("conduct_live")]
  CT[("conduct_train")]
  HO[("holdout_sealed<br/>one reader")]
  CH[("chain.links")]
  RV[("review.decisions")]
  GCS[["retention-locked bucket"]]
  AR{{"Agent Registry"}}

  W -->|"every tool call"| PS
  W -->|"conduct event"| CL
  F -->|"list_agents()"| AR
  F -->|"A2A fan-out"| D
  D -->|"governed SQL"| CL
  AC --> RV
  P -->|"SELECT"| CT
  P -.->|"403, recorded as a link"| HO
  EX -->|"only reader"| HO
  NO --> CH
  NO --> GCS
  NO -->|"reads the human's rows"| RV
  PS -->|"re-derives at serve time"| CH
  PS --> EX
```

Nine private Cloud Run services: four detectors from one template, the workload agent, the
Foreman, the Proposer, the Policy Server, and the Analyst Copilot. Seven are published into
Agent Registry, each entry carrying the chain root of the policy version it was registered
against, so the roster states what each worker's authority rests on and not only where it
lives. The Foreman's source names no detector; the fleet proof greps it to keep that true.

The Analyst Copilot is `adk deploy cloud_run --with_ui`, unmodified. It serves no agent card,
so it is not in the roster: it is a human's window, not a worker the Foreman discovers. What
this entry wrote is the pair of tools behind it.

There is one local page as well, and where it sits matters more than what it looks like.
`python3 -m caseharden.workbench` is an operator console: it runs on the analyst's own
machine, reads the chain, the version registry and the finding under review, and takes the
attestation state from the Policy Server rather than deciding it. It never runs `verify` and
holds no credential for the sealed exam, because the only principal allowed to re-score that
exam is the one the Policy Server runs as, and a second holder of that identity is exactly the
widening chain link 1 exists to expose. Its one write is a message to the unmodified Copilot,
which screens the text through Model Armor and writes the review row itself under
`analyst-sa`. The console offers a verdict and writes nothing itself; what gets stored is
decided by the Copilot service. It has no approve affordance, and it also cannot stop an
operator who types an approval into it, which is why the claim is about what it offers rather
than about what is possible. Deleting the console removes a window, not a control.

```bash
python3 -m caseharden.workbench --fixture fixtures/v5   # a sealed record, no credentials
```

## Measured

Every number here is measured on the live project, not estimated. Sources in
[`BUILD_LOG.md`](BUILD_LOG.md) and [`captures/`](captures).

| | |
|---|---|
| `verify` p95, cold IAM cache | **3.66s** against a 5s target (p50 3.16s, 12 runs) |
| Active version | v5, 9 chain links, root `40cdb5962d49`, attested; each repoint since promotion is in `BUILD_LOG.md` |
| Examiner on the promoted candidate | 29/40 → **30/40** sealed attack sessions, benign 100% → 100% |
| Synthetic corpus | ~40k conduct events; 40 sealed attack sessions across 4 families; 640 benign turns |
| Tests | 313 |
| Mutations broken and caught | 72 of 72 |
| Fleet proof | all 8 sections, 32 assertions ([capture](captures/day7-fleet-proof-all-held.txt)) |
| Cloud Trace | the conduct row's trace id opens a 60-span DAG in the capture above; one fan-out is a 361-span trace spanning the Foreman and all four detectors ([log](BUILD_LOG.md)) |

## The gate, and an honest note about the demo

The promotion gate has three legs and all three are required. Attacks blocked must rise.
Benign pass rate must not fall. The candidate must deny everything the active version denies,
decided from the rule structure rather than by replaying a corpus.

On the day, the deployed Proposer produced a candidate that caught **31 of 40** sealed attack
sessions, one more than the active version, and blocked two legitimate turns. The gate refused
it for benign regression. Three further candidates were refused for no improvement. Nothing
was written to the chain. That transcript is
[`captures/day5-gate-refuses-the-proposer.txt`](captures/day5-gate-refuses-the-proposer.txt).

A second, louder refusal is also kept:
[`policies/v5-candidate-a-overblocking.json`](policies/v5-candidate-a-overblocking.json)
denies every refund, catches 40 of 40 attacks, and drops benign traffic to 94.5%.
**That candidate is hand-written, not model-drafted, and its capture says so in the first
paragraph.** The Examiner's run against it is real.

## Degraded modes

| Condition | Enforcement | Attestation | Promotion |
|---|---|---|---|
| Chain re-derives | in force | `attested` | open |
| A link fails to re-derive | **in force**, block reasons marked unattested | `quarantined`, the failing link and offending id named | frozen |
| Verification cannot run | in force, last known state retained | `unknown` | frozen, alert raised |
| Policy Server unreachable | last fetched policy stays in force, marked unattested | `unknown` | frozen |
| Policy older than the staleness bound | **call refused**, `POLICY-EXPIRED` | `unknown` | frozen |
| Model Armor unavailable and the policy keys on it | **call refused**, `SCREENING-UNAVAILABLE` | never justified | frozen |

Attestation gates authority, not availability. An audit layer that switches off guardrails
when its own paperwork lapses is a worse failure than the one it detects.

## Known limitations

- **No agent runs on Agent Runtime.** An Agent Engine is deployed and backs Memory Bank.
  Every agent is on Cloud Run, which the build plan pre-approved.
- **Verification re-derives two links.** EVIDENCE and EXAM. The others are corroborated when
  they are written and hash-protected afterwards.
- **Append-only is a convention on the chain table, not a platform guarantee.** What makes an
  edit detectable is the sealed root in the retention-locked bucket.
- Full threat model: [`THREATS.md`](THREATS.md).

## Check the record yourself, with no access to my project

`caseharden verify` needs this project's BigQuery, its sealed holdout and two impersonated
service accounts. Only one person can run it. That is a weak position for an entry whose
subject is records you can check for yourself, so the record is also exported and re-checked
by a machine that is not mine.

```bash
python3 -m caseharden.recheck fixtures/v5
```

Seventeen checks, no credentials, no network. Link hashes, the walk, the root against the
certificate that was exported from the retention-locked bucket, the certificate's own list,
the chain's shape, the approval bound to the exam it approved, and the EVIDENCE link's
digests against the material inside it.

The last four are the ones that matter. They **replay the Examiner** over corpora regenerated
from the committed seeded generator and compare the sealed-attack numbers, the benign numbers,
the monotonicity check and the recorded gate verdict to what the chain says. The generator is
deterministic and the Examiner makes no model calls, so an invented catch rate does not
survive, even when every hash has been rebuilt and the certificate forged to match.
`tests/test_recheck.py` does exactly that and asserts the refusal.

What a fixture cannot answer is whether the record was true when it was written. That is what
the live `verify` re-derives against the warehouse, and it is the product.

The badge above is that job, run on GitHub's runners on every push.

## Reproduce it

```bash
bash infra/70_prove_seal.sh          # proposer-sa takes a real 403 on the sealed holdout
bash infra/71_prove_immutability.sh  # the owner is refused delete, overwrite and unlock
bash infra/80_prove_gate.sh          # the gate refuses three ways and passes one
bash infra/90_prove_attestation.sh   # green, quarantine, promotion refused, re-attest, green
python3 infra/100_prove_fleet.py     # the roster, the refusals, the fan-out, the memory
python3 -m caseharden.recheck fixtures/v5   # the sealed record, offline, 17 checks
python3 -m pytest tests -q           # 313 tests, no cloud project needed
python3 tests/mutate_check.py        # 72 mutations; every one must be caught
```

Each of those exits non-zero if the guarantee it tests does not hold. The
workbench is the one thing here that is not a check: it is a server, it runs
until you stop it, and its exit code means nothing.

```bash
python3 -m caseharden.workbench --fixture fixtures/v5   # the same record, in a browser
```

[`infra/README.md`](infra/README.md) has the full numbered sequence from an empty project.

## Clean-room disclosure

This repository contains no employer code, data, schemas, table names, or infrastructure.
All data is synthetic, generated by a seeded script committed to this repository.

Nothing here acts on Application Default Credentials without checking the project first.
`caseharden/creds.py` mints tokens from one pinned gcloud configuration, or from the
container metadata server, and refuses to return credentials for any project but this
one. Every agent module calls its guard at import, and the guard reads ADC precisely in
order to refuse it. ADK and the genai SDK do read ADC directly for model calls, which is
correct inside a container where ADC is the attached service account and is exactly why
the guard runs first everywhere else.

This exists because the machine this was built on also holds an unrelated employer's
ADC, and a library that reaches for it silently succeeds under the wrong identity.
