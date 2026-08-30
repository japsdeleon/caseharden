# CONTEXT

The ubiquitous language of this repository. One name per idea, used the same way in the code,
the commits, the documents and the demo script. If a word below appears in a pull request
meaning something else, the pull request is wrong, not this file.

Read [`README.md`](README.md) for the claim and [`docs/PLAN.md`](docs/PLAN.md) for the
specification. This file is only the vocabulary.

## The sentence the whole vocabulary serves

**An agent's authority to act is derived from evidence, not granted by configuration.**

Every term below exists to keep that sentence checkable. The words that matter most are the
ones that separate *what the record says* from *what is still true*.

## The fleet

The agents. Nine private Cloud Run services, seven of them published to Agent Registry.

| Term | Means | Does not mean |
|---|---|---|
| **Workload agent** | The governed worker. A customer-support agent that handles tickets and asks permission before every tool call. | Not the thing being protected from. It is the thing being governed. |
| **Detector** | One of four read-only agents that scan conduct for one check family. Returns a **finding** and the BigQuery job id that produced it. | Not a rule. A detector observes; it never blocks. |
| **Check family** | The category a detector covers: `cross-tenant`, `scope-escape`, `injected-turn`, `privilege-sequencing`. | Not a policy rule name. A family groups evidence, not enforcement. |
| **Foreman** | The agent that discovers the detectors from the **roster** at container start and fans an investigation out to them over A2A. | Not a scheduler and not a supervisor. It names no detector in its source. |
| **Proposer** | The agent that drafts a **candidate** policy. It can read training conduct, the live conduct window and reviewer precedent. It cannot read the **sealed holdout**. | Not the approver, and not the promoter. It only drafts. |
| **Analyst Copilot** | The human's window. An unmodified ADK web UI where a person records a **verdict** and an **approval**. | Not a member of the fleet. It serves no agent card and the Foreman never discovers it. |
| **Draftsman** | The human's drafting bench. A CLI that grounds rule-rot review, use-case research and overlap checks in stored conduct, every number carrying its BigQuery job id. Drafting side of the wall: it reads conduct and the registry, never the sealed exam. | Not the Curator, and not a fleet member. It suggests; it never grants. |
| **Policy Server** | The service that answers "what is in force, and is it attested". | Not a policy store. It re-derives from the **chain** at serve time. |
| **Roster** | The Agent Registry listing. Each entry carries the **root** of the policy version it was registered against. | Not a service list. A roster entry states what a worker's authority rests on. |

## The evidence

Conduct is what the fleet did. It is the raw material every claim is derived from.

| Term | Means |
|---|---|
| **Conduct event** | One recorded turn or tool call: session, turn index, tenant, tool, amount, screening scores, the decision taken, the policy version in force, the trace id. |
| **`conduct_live`** | The dataset the fleet writes to and the detectors read. The window a promotion cites lives here. |
| **`conduct_train`** | The corpus the Proposer may read when drafting. |
| **`holdout_sealed`** | The **sealed holdout**. Attack sessions and benign turns the gate scores against. One reader. |
| **Sealed holdout** | Held-out evaluation data whose read access is restricted to one service account and hashed into the chain. | 
| **Attack session** | A labelled sequence in the holdout that a correct policy must deny. There are 40, across the four check families. |
| **Benign turn** | A labelled legitimate turn in the holdout that a correct policy must allow. |
| **Finding** | What a detector returned: a family, a count, and a re-runnable BigQuery job id. | 
| **Verdict** | A human's disposition on a finding, recorded through the Copilot into `review.decisions`. |
| **Disposition** | Which of four values a verdict carries. `confirmed abuse`, `benign`, `insufficient evidence`, `escalate`. The Copilot refuses anything else rather than storing it. |
| **Terminal disposition** | The three that end the loop: `benign`, `insufficient evidence`, `escalate`. Only `confirmed abuse` continues into drafting, because a policy version is justified by the finding it came from. Closing on a terminal verdict is an outcome, not a failure. |
| **Review state** | What the console's queue says about one case: `yes`, `no`, `stale`, `blocked`, `escalated`, `unknown`. Derived at read time from `review.decisions` and the case's own revision stamp; never stored. `stale` is a verdict recorded before the evidence was replaced, `blocked` a verdict whose screening did not clear, `escalated` the analyst saying the call was not theirs, and `unknown` a warehouse the console could not reach. Only `yes` means the review is finished. |
| **Approval** | A human's decision to promote a specific version, recorded the same way and bound in the chain to the exam it approved. |

Rows written into `review.decisions` before this vocabulary existed carry free text. They are
not read as the nearest of the four: `infra/110_run_loop.py` refuses such a row and names it,
the way an `unknown` attestation freezes promotion rather than guessing at a state.

## The policy

| Term | Means | Does not mean |
|---|---|---|
| **Policy** | A set of **rules** with a version. The document the Policy Server serves and the workload enforces. | Not configuration. A policy has authority only while its chain re-derives. |
| **Policy line** | A named lineage of policy versions with its own genesis, its own gate baseline, and eventually its own sealed exam. Two exist: `conduct-policy` (enforced, examined) and `payments-policy` (registered, floor only). | Not a **check family** — that word groups detector evidence. A line groups enforcement lineage. |
| **Rule** | One deny, expressed as **predicates** over a closed field vocabulary. | There is no allow verb. A policy cannot grant. |
| **Predicate** | One condition: `equals`, `in_set`, `at_least`, `present`, `outside_declared_scope`, `tenant_mismatch`. | Not arbitrary code. The DSL forbids unknown fields and unknown operators. |
| **Candidate** | A policy version that has been drafted but not promoted. | Not a version in force. A candidate has no authority of any kind. |
| **Active version** | The one version marked active in its **policy line**. What the Policy Server serves for that line. | Not the newest version. A promotion that the gate refuses never becomes active. |
| **Promotion** | Making a candidate the active version. Requires a passing **gate**, a human **approval**, and a written chain. | Not a deploy. |
| **Deny-only** | The property that the DSL has no way to express permission. | Not a convention. `caseharden/dsl.py` has no allow node to write. |
| **Dormant rule** | An active rule the Draftsman's rot report shows denying nothing over the stated window. | Not a retired rule. Retirement widens authority; a dormant rule is stated to a human and keeps enforcing. |

## The gate

The Examiner is deterministic and makes no model calls. It scores a candidate and the active
version against the sealed holdout and returns one verdict over three legs. All three are
required.

| Leg | Requires |
|---|---|
| **CATCH** | The candidate blocks strictly more sealed attack sessions than the active version, and regresses on no family. |
| **BENIGN** | The benign pass rate does not fall. |
| **MONOTONICITY** | The candidate denies everything the active version denies. Decided from the shape of the rules, not by replaying a corpus. |

**Refusal** is a first-class outcome. A refused candidate is written to the chain as a
`DRAFT-REJECTED` link, so the record attests to what was prevented and not only to what
occurred.

## The record

The chain is the provenance record. It is hash-linked, append-only by convention rather than
by a platform guarantee, and its end is sealed outside the project's own control. The seal is
what makes an edit detectable.

| Term | Means |
|---|---|
| **Chain** | The ordered links for one policy version, in `chain.links`. |
| **Link** | One row: version, sequence, **kind**, the hash of the previous link, and a payload. |
| **Kind** | What a link records. Nine of them, listed below. |
| **Root** | The hash of the last link. The chain's identity in one value. |
| **Certificate** | The sealed statement of a root and the links under it, written to a retention-locked Cloud Storage bucket. |
| **Seal** | Writing that certificate. After it, the object cannot be deleted, overwritten or unlocked, including by the project owner. |
| **Re-derive** | Recompute a link's content from the live warehouse and compare it to what the link says. Three kinds are re-derived: `EVIDENCE`, `EVIDENCE-CHANGED` and `EXAM`. |
| **Corroborate** | Check a recorded link against an independent source at the moment it is written, for kinds that cannot be re-derived later. |

### Link kinds

| Kind | Recorded or re-derived | Holds |
|---|---|---|
| `EVIDENCE` | re-derived | The cited conduct window and the sealed holdout's access list |
| `FINDING` | recorded | A detector's result and its BigQuery job id |
| `VERDICT` | recorded | The human's disposition and its Model Armor result |
| `DRAFT` | recorded | The candidate the Proposer emitted |
| `DRAFT-REJECTED` | recorded | A draft that failed schema validation, and the error |
| `HOLDOUT-DENIED` | recorded | BigQuery's 403 to the Proposer, verbatim |
| `EXAM` | re-derived | The Examiner's measurements and the gate verdict |
| `APPROVAL` | recorded | Who approved, and what they approved |
| `EVIDENCE-CHANGED` | re-derived | Supersedes `EVIDENCE` after a successful re-attestation |

## Attestation

**Attestation gates authority, not availability.** This is the single most load-bearing
distinction in the vocabulary. A quarantined version keeps blocking. It loses the right to be
called justified.

| State | Means | Enforcement | Promotion |
|---|---|---|---|
| `attested` | Every re-derived link reproduces from the warehouse right now, every link hash and the sealed root still agree, and the chain's shape is a promotion | in force | open |
| `quarantined` | One of those checks failed, and the break code, the failing link and the offending id are named | **in force**, block reasons marked unattested | frozen |
| `unknown` | Verification could not run | in force, last known state retained | frozen |

| Term | Means | Does not mean |
|---|---|---|
| **Break code** | Why attestation failed: `LINK-HASH`, `EVENT-WINDOW`, `HOLDOUT-ACCESS`, `EXAM-SCORE`, `ROOT-MISMATCH`, `NO-CHAIN`, `NO-CERTIFICATE`, `CHAIN-SHAPE`. | Not an error. A break code is a finding about the record. |
| **Re-attestation** | Re-running the Examiner against the evidence as it now stands, appending an `EVIDENCE-CHANGED` link, and sealing a new certificate beside the old one. | **Never an edit.** Nothing is rewritten and nothing is deleted. Five break codes are refused re-attestation outright — `LINK-HASH`, `ROOT-MISMATCH`, `NO-CHAIN`, `NO-CERTIFICATE`, `CHAIN-SHAPE` — and so is a holdout access list that was widened after the promotion. |
| **Attested reason** | A block whose rule is justified by a chain that currently re-derives. Recorded on the conduct row as `reason_attested`. | Not the same as the block itself. An unattested block still blocks. |
| **Staleness bound** | The age past which the workload refuses to act on a cached policy answer, with `POLICY-EXPIRED`. | Not a cache TTL. Expiry refuses the call; it does not fetch a new one. |
| **`SCREENING-UNAVAILABLE`** | Model Armor is unreachable and a rule in force keys on its output, so the call is refused. | Not a degraded pass. Losing the screener must not become a bypass for the rule it feeds. |

## Words used narrowly

- **Derived trace id.** A SHA-256 over session and turn. A correlation key shared by the
  conduct row, the chain link and the finding. Not a handle Cloud Trace can open. Say
  "derived" whenever it is one.
- **Measured.** Taken from a live run, with the capture committed. Never an estimate. Every
  number in `README.md` under *Measured* has a source in `BUILD_LOG.md` or `captures/`.
- **Proof.** A script under `infra/` that exits non-zero if the guarantee it names does not
  hold. Not an argument.
- **Re-check.** The offline verifier, `caseharden/recheck.py`. Runs on an exported fixture
  with no credentials and no network. Distinct from **verify**, which re-derives against the
  live warehouse and is the product.
- **Clean room.** This repository contains no employer code, data, schemas, table names or
  infrastructure. All data is synthetic and generated by a committed seeded script.

## Where the definitions live

| Vocabulary | File |
|---|---|
| Policy, rule, predicate, field vocabulary | [`caseharden/dsl.py`](caseharden/dsl.py) |
| Link, kind, root, hashing | [`caseharden/chain.py`](caseharden/chain.py) |
| States, break codes, re-attestation | [`caseharden/notary.py`](caseharden/notary.py) |
| Gate legs, holdout scoring | [`caseharden/examiner.py`](caseharden/examiner.py) |
| Attested reason, staleness, screening | [`agents/common/enforcement.py`](agents/common/enforcement.py) |
| Verdict dispositions, which one drafts | [`caseharden/verdicts.py`](caseharden/verdicts.py) |
| Offline re-check | [`caseharden/recheck.py`](caseharden/recheck.py) |
