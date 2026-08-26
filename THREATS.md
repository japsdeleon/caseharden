# THREATS

How Caseharden could be fooled, and which control stops each one.

This file is written the way the build log is: what is confirmed, what is a limit, and what
is not covered at all. Nothing here is hypothetical unless it says so. Where a control is a
Google Cloud behaviour rather than this project's code, that is stated, because those are the
two guarantees the whole entry rests on.

The five entries under **Not covered** are the ones a reviewer should read first.

---

## 1. Tamper with the record

| Attempt | What stops it | Residual |
|---|---|---|
| Edit a chain link's payload in BigQuery | The link hash covers the payload and the next link's hash covers it in turn. `verify` walks the chain and breaks at the edited link. | None for a single link. |
| Rewrite the whole chain, hashes and all | The root is sealed into a retention-locked GCS object at promotion time. A rewritten chain no longer matches its certificate. | The rewrite is detected, not prevented. The chain table has no append-only mode; WRITER on the dataset carries DML delete. |
| Delete the sealed certificate | The bucket's retention policy is **locked**. A delete is refused for the project owner. Proven in `captures/day1-retention-refuses-delete.txt` and again in `90_prove_attestation.sh`. | The lock is irreversible and the bucket cannot be deleted until 30 days after its last write. That is the point, and it is also an operational commitment. |
| Overwrite a certificate with a new one at the same name | Overwrite is a delete plus a create, and the retention policy refuses the delete. `notary-sa` holds `objectCreator` without `objectAdmin`, so the identity that seals cannot delete. | None. A re-attestation writes a new object beside the original. |
| Seal a chain that never happened | `_required_shape` refuses a chain that does not begin with EVIDENCE or that carries no EXAM and no APPROVAL. `_shape_of_payload` refuses a structurally empty FINDING, DRAFT-REJECTED or HOLDOUT-DENIED link, and refuses a HOLDOUT-DENIED link whose HTTP code is not 403. | A caller with the Notary's identity can still write a chain whose *content* is invented within those shapes. See **Not covered 1**. |

## 2. Get the Proposer to see its own exam

| Attempt | What stops it | Residual |
|---|---|---|
| Query `holdout_sealed` as `proposer-sa` | BigQuery access control. The dataset's access list has exactly one entry, `examiner-sa`. The 403 is Google's, not this project's, and the Proposer takes it on every run as a tool call. | None for the direct read. |
| Read it as the project owner | `bigquery.tables.getData` is not part of `roles/owner`, and the inherited `projectReaders` and `projectWriters` entries were stripped from the dataset. The owner is refused. | None. |
| Add `proposer-sa` to the access list later | Chain link 1 hashes the access list. A later grant breaks the chain and quarantines the version, naming the principal granted. `reattest` refuses to clear a widened access list. | The grant is not **prevented**. A project owner can make it; the action leaves a Cloud Audit record and breaks the chain. An IAM deny policy would have prevented it, and this project has no organization, so it cannot create one. |
| Reach the exam through a project-level role instead | Link 1 also hashes every project binding whose role carries `bigquery.tables.getData`, expanded through the IAM API rather than matched by name. | A role inherited from a folder or organization would not appear. This project has no parent, checked with `gcloud projects describe`, so there is nothing to inherit here. The hole is real for any project that has one. |
| Impersonate `examiner-sa` | Link 1 hashes, for every service account on the exam's access list, who may act as it. A new impersonator quarantines the version and the break names the account and the principal. | An unreadable impersonation policy is recorded as `UNREADABLE`, not as nobody. |
| Learn the exam through gate feedback | The run loop passes back only the failing leg and the benign numbers. Holdout counts are never sent to the Proposer. | A determined operator could pass them by hand. The loop is the only path that exists in this repo. |
| Regenerate the holdout from the committed generator | Nothing stops this, and it is deliberate: the generator is seeded and committed so a reviewer can reproduce the corpus. | **This is a real limit.** It becomes exploitable if the Proposer is ever given repo or generator access. It has none. |

## 3. Get a bad policy promoted

| Attempt | What stops it | Residual |
|---|---|---|
| Draft a rule that widens authority | The DSL has no allow verb. `action` is the literal `deny` and nothing else parses. | A candidate can still widen by dropping a rule or adding a predicate to one. That is what the monotonicity leg is for. |
| Drop or narrow an active rule | `structurally_monotonic` decides from the rule structure, not from a corpus replay: every active rule must be carried forward or covered by a candidate rule whose predicate set is a subset. | Conservative on purpose. A candidate expressing the same rule a different way is refused rather than analysed. |
| Score a perfect catch rate by denying everything | The benign leg. Benign pass rate must not fall. A hand-written candidate denying every refund catches 40 of 40 attacks and is refused at 94.5% benign. | None. Both sides of the gate are required. |
| Cite the answer key in a predicate | `label` and `is_attack_event` are not in the feature vocabulary, and `Literal` types reject them at parse time. | None. |
| Name the exact accounts in the exam | `account_id` is deliberately outside the vocabulary. An adversarial pass built exactly that candidate on Day 2. | None. |
| Argue the Examiner into a pass | The Examiner is deterministic code with no model, under its own service account. | None. |
| Promote onto a quarantined version | `parent_basis` is checked inside `seed`, which is what writes a chain, not only in the separate `promote` pre-check. | None. |
| Inject SQL through a rule literal | Literals must match a closed character class at parse time, thresholds must be finite and non-boolean, and the compiler escapes as well. Two engines, Python and BigQuery, are compared by digest over the denied event ids. | None found. |

## 4. Attack the fleet at run time

| Attempt | What stops it | Residual |
|---|---|---|
| Prompt injection in a ticket | Model Armor screens the turn, its verdict fields are first-class predicates in the DSL, and the active policy denies a tool call on a screened injection. | The band-to-score mapping is a judgement, stated in one table in `agents/common/armor.py`. Model Armor reports injection and jailbreak under one band. |
| Take Model Armor down to bypass the rule that depends on it | The callback asks the active policy whether any rule keys on a Model Armor field. If one does and screening failed, the call is refused with `SCREENING-UNAVAILABLE` and the decision is recorded as unattested. | A policy with no screening predicate is unaffected, correctly. |
| Send a turn with no text, so there is nothing to screen | An unscreened turn is labelled `NOT_SCREENED` and both labels refuse. Found by an adversarial pass, which drove a refund through this way. | None. |
| Cut the workload off from the Policy Server | The last fetched policy stays in force, marked unattested. Past `STALE_SECONDS` the call is refused with `POLICY-EXPIRED`, because promotions only narrow and an indefinitely old policy is a permissive one. | None. |
| Call a private service directly | Every service is deployed `--no-allow-unauthenticated`. Callers sign each hop with an identity token minted for that exact service. The fleet proof asserts the refusal on all nine. | The A2A endpoints are private by Cloud Run IAM, not by anything this project built. |
| Write junk into the conduct stream | `conduct_live` is written by `workload-sa`, which holds WRITER on that dataset. | **WRITER carries DML delete.** A compromised workload identity can delete its own conduct history. The cited window's digest would then break, which is detection and not prevention. |

## 5. Attack the human path

| Attempt | What stops it | Residual |
|---|---|---|
| Paste an injection into the analyst's verdict, aimed at the Proposer | Model Armor screens the analyst's text inbound, the result is stored beside the row, and the run refuses to pass the text on when the screening blocked or did not happen. | The Copilot still stores the row. That is deliberate: the record holds what was typed. |
| Have the Proposer's rationale carry an injection to the next reader | The rationale is screened outbound through `sanitizeModelResponse` before an analyst sees it or the chain records it, and the run refuses on a block. | None known. |
| Approve a promotion without a human | The Notary reads `review.decisions` and refuses unless the decision id exists, is the right kind, names the right subject, and, for an approval, records `approved = true`. | See **Not covered 2**. |
| Reuse one approval for a different version | The approval row's subject must equal the version being promoted. Shown in `captures/day5-notary-corroborates-the-bundle.txt`. | None. |
| Rewrite the verdict text after the human typed it | The bundle's verdict text must match the stored row. | None. |

---

## Not covered

These are the holes. Each is a decision, not an oversight.

**1. A bundle is corroborated, not re-derived.** `notary seed --bundle` checks that the cited
BigQuery job exists and completed, that the human rows exist and match, and that the 403
reproduces live. It does not re-run the detector's query. A finding whose rows changed after
the job ran is not detected by verification. Verification re-derives EVIDENCE and EXAM and
claims nothing more; section 2 of the plan says so.

**2. `analyst-sa` can write the review table.** It can therefore write a verdict the chain
will later cite. It cannot alter one after the Notary has read it, because the payload must
match, and it cannot approve a version without a row. But a compromised Copilot is a
compromised human review step.

**3. Trace ids are correlation keys, not handles.** Spans do not reach Cloud Trace from
Cloud Run. The id in a conduct row and in a chain link is a real span id, and Cloud Trace
answers 404 for it. The fleet proof asserts resolution and fails on it rather than claiming
otherwise. Also, the tracing middleware trusts an inbound `traceparent`: a caller that can
reach a private service can attach its spans to a trace of its choosing.

**4. The reach check depends on being able to expand a role.** It needs `iam.roles.get` and
`iam.serviceAccounts.getIamPolicy`. A principal that cannot expand a role sees every custom
role as a possible reader: noisy and safe, in that order. Predefined roles are cached for the
life of the process, so a predefined role's permissions changing under Google would not be
seen until restart. Custom roles are re-expanded every time, because their permission set is
editable at any moment.

**5. `CASEHARDEN_PROJECT` is the comparison target, not a fixed allowlist.** Setting it
redirects what `creds.py` considers correct. On a workstation a mismatch is still caught
against the pinned gcloud configuration's own project. An operator who changes both is not
making a mistake.

---

## Two smaller notes

`roles/bigquery.resourceViewer` on `notary-sa` lets it see every job in the project. It
carries no `bigquery.tables.getData`, checked with the same role expansion `verify` uses, so
it does not widen the exam's reach.

Spans are flushed on the response path. A crash between the tool call and the response loses
that turn's span, on top of the export problem above.
