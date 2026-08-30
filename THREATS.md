# THREATS

How Caseharden could be fooled, and which control stops each one.

This file is written the way the build log is: what is confirmed, what is a limit, and what
is not covered at all. Nothing here is hypothetical unless it says so. Where a control is a
Google Cloud behaviour rather than this project's code, that is stated, because those are the
two guarantees the whole entry rests on.

The ten entries under **Not covered** are the ones a reviewer should read first.

---

## 1. Tamper with the record

| Attempt | What stops it | Residual |
|---|---|---|
| Edit a chain link's payload in BigQuery | The link hash covers the payload and the next link's hash covers it in turn. `verify` walks the chain and breaks at the edited link. | None for a single link. |
| Rewrite the whole chain, hashes and all | The root is sealed into a retention-locked GCS object at promotion time. A rewritten chain no longer matches its certificate. | Bigger than detection-not-prevention: `verify` reads the sealed root through `policy.versions.certificate_uri`, a mutable pointer, and `seal()` writes a new object per root. A writer who rewrites the chain, reseals it to a new certificate and repoints the URI passes `verify`. The locked original survives as the durable witness and the repoint leaves a Cloud Audit trail, but nothing in this code detects the swap. The chain table has no append-only mode; WRITER on the dataset carries DML delete. |
| Delete the sealed certificate | The bucket's retention policy is **locked**. A delete is refused for the project owner. Proven in `captures/day1-retention-refuses-delete.txt` and again in `90_prove_attestation.sh`. | The lock is irreversible and the bucket cannot be deleted until 30 days after its last write. That is the point, and it is also an operational commitment. |
| Overwrite a certificate with a new one at the same name | Overwrite is a delete plus a create, and the retention policy refuses the delete. `notary-sa` holds `objectCreator` without `objectAdmin`, so the identity that seals cannot delete. | None. A re-attestation writes a new object beside the original. |
| Seal a chain that never happened | `_required_shape` refuses a chain that does not begin with EVIDENCE or that carries no EXAM and no APPROVAL. `_shape_of_payload` refuses a structurally empty FINDING, DRAFT-REJECTED or HOLDOUT-DENIED link, and refuses a HOLDOUT-DENIED link whose HTTP code is not 403. | A caller with the Notary's identity can still write a chain whose *content* is invented within those shapes. See **Not covered 1**. |

## 2. Get the Proposer to see its own exam

| Attempt | What stops it | Residual |
|---|---|---|
| Query `holdout_sealed` as `proposer-sa` | BigQuery access control. The dataset's access list has exactly one entry, `examiner-sa`. The 403 is Google's, not this project's. The Proposer is given the read as a tool and told to attempt it; the promotion loop refuses to continue without a 403 payload in the draft, and the Notary re-takes the denial live before sealing the link, so a reported refusal that never happened does not survive. | None for the direct read. |
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
| Rewrite the citation, or claim a disposition the human did not give | The bundle's disposition and its three citation columns must match the stored row, and the row must say `confirmed abuse` before a version is promoted on it. | None for a bundle. A row rewritten before the Notary reads it is **Not covered 2**. |
| Attribute the analyst's own call to a machine that never recommended it | The advisory columns carry `advisory_source`, and the Copilot can only write `SURFACE`: the console then reports the advisory as what the recording surface said was shown, not as what the machine advised. The advisory is corroborated against the stored row before the chain seals it. | The surface's claim is still the surface's claim. Nothing here produces an advisory, so a stored one is unverifiable in substance; what the record fixes is who is on the hook for it. |
| Promote by hand from a verdict that closed the review | `notary seed --bundle` refuses a row whose disposition is terminal, so the driver's branch is not the only thing enforcing it. | Without `--bundle` the seed writes a VERDICT link from its own defaults and corroborates nothing. That path is the pre-Day-5 demo seed and is not how a promotion is made. |

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

**3. The tracing middleware trusts an inbound `traceparent`.** A caller that can reach a
private service can attach its spans to a trace of its choosing. Nothing downstream treats a
trace id as evidence, so this costs correlation rather than integrity, but a trace id in a
conduct row is a pointer supplied by the caller and is not a claim the chain re-derives.

Until Day 7 spans did not reach Cloud Trace at all and this section said so. The cause was the
sampler, not the transport: Cloud Run marks every inbound request unsampled and OpenTelemetry's
parent-based default honoured it, so spans were created with a valid context and never
recorded. `ALWAYS_ON` on the provider fixed it, the fleet proof's resolution assertion now
holds, and the conduct row's trace id opens a 60-span DAG. The `traceparent` trust above is
what remains.

**4. The analyst workbench is an unauthenticated local process holding a `notary-sa` token.**
`caseharden/workbench.py` runs on the analyst's workstation, mints a `notary-sa` access token
to read the chain and the review table, and can send a message to the Analyst Copilot. It
authenticates nobody. Anyone who can execute code as that user can already mint the same
token from the same gcloud configuration, so this widens no grant, but it does put a live
credential in a long-running process. It binds `127.0.0.1` with no flag to change it, refuses
a request whose `Host` is not loopback, so a rebound hostname cannot reach it, and requires
`application/json` on its one write path, so a cross-origin form post cannot. It never calls
`verify` and never obtains `examiner-sa`; attestation is read from the Policy Server. It is
not a control: everything it reads is readable with a terminal, and its write is a message the
Copilot screens and stores under its own identity. What it is is a process worth closing when
a run is over.

**5. The reach check depends on being able to expand a role.** It needs `iam.roles.get` and
`iam.serviceAccounts.getIamPolicy`. A principal that cannot expand a role sees every custom
role as a possible reader: noisy and safe, in that order. Predefined roles are cached for the
life of the process, so a predefined role's permissions changing under Google would not be
seen until restart. Custom roles are re-expanded every time, because their permission set is
editable at any moment.

**6. `CASEHARDEN_PROJECT` is the comparison target, not a fixed allowlist.** Setting it
redirects what `creds.py` considers correct. On a workstation a mismatch is still caught
against the pinned gcloud configuration's own project. An operator who changes both is not
making a mistake.

**7. One detector family has no enforcement path.** The detectors cover four check families.
The policy DSL can express three of them. `privilege-sequencing`, a session that acts on
something it never read, cannot be written as a rule at all: the predicate fields are
`tool_name`, `tenant_id`, `target_tenant_id`, `ma_verdict`, `amount_cents`,
`ma_prompt_injection_score`, `ma_jailbreak_score`, `turn_index` and `declared_scope`, and the
operators are `equals`, `in_set`, `at_least`, `present`, `outside_declared_scope` and
`tenant_mismatch`. There is no `account_id` field, and nothing in the language represents what
a session has already done. A predicate over session history needs state the interpreter does
not carry, and adding one would make the monotonicity check something other than a comparison
of rule shapes.

This is not hypothetical. The v6 run on 2026-08-26 produced exactly that incident: a session
read one account and then tried to refund 6200 cents to another it had never read. Only the
Model Armor injection score stopped the refund. The same sequence carrying a lower score would
have completed, and the verdict asking for the obvious tightening could not be drafted. The
detector reports the pattern, the chain records the finding, and no version of the policy can
deny it. `BUILD_LOG.md` carries the run.

This hole sits under the best-evidenced attack shape in the field, which makes it the first
thing to fix rather than the last. AppOmni Labs' November 2025 ServiceNow demonstration is the
same sequence: an injected turn drives a privileged read, and that read is followed by a write
the requester was never entitled to. The detector families cover that shape. The policy
language does not. `docs/DEVPOST.md` cites the demonstration and `BUILD_LOG.md` records where
it came from.

**8. The sealed exam and the live world are not the same shape.** The Examiner's score is a
prediction about live behaviour, and it is measured on a corpus the live fleet does not produce.
Three differences are known, and none of them bites the active version.

*Conversational turns.* The generator writes a row for every turn, with `tool_name` null on the
roughly sixty percent that call no tool. The live fleet writes through
`before_tool_callback`, which fires only on a tool call, so `conduct_live` holds tool calls and
nothing else. `turn_index` therefore counts turns in the corpora and tool calls in the live
table. It is in `PREDICATE_FIELDS`, so a future candidate may key on it and be scored against a
distribution the fleet does not generate. No rule in v5 uses it.

*Event ids.* The generator hashes session, turn and timestamp. The live path concatenates session
and turn index. Both are unique within a session and nothing joins across the two datasets, so
this costs nothing today. It is recorded because the schema file claimed the hashed form for both
and was wrong about the live one.

*The `privilege-sequencing` family means two different things.* The detector's SQL finds a write
to an account no read in that session touched. The generator's attack in the holdout reads an
account and then writes to that same account. Those are complementary patterns, not one pattern,
so the detector would not flag the holdout's own attack sessions. The gate is unaffected, because
the Examiner replays policy rules against holdout rows and never runs a detector. The consequence
is for anyone closing **Not covered 7**: a session-scoped predicate built to match the detector
would score no improvement on the sealed exam, because the exam's ten attacks are the other
shape. Which of the two patterns that family is meant to be is not decided anywhere in this
repository.

The general form of this hole is that a corpus written by one program is standing in for traffic
produced by another. Only the second and third differences above were found by reading both
programs side by side, which is not a check anything runs.

Day 9 measured the difference rather than describing it. `conduct_train.turns` has 19 columns and
`conduct_live.turns` has 21. Train carries `label` and `is_attack_event`, the generator's ground
truth, which live must never hold. Live carries `attestation_state`, `decision`, `decision_rule`
and `decision_attested`, the enforcement outcome, which the generator does not produce. Both
directions are correct and neither is a defect. The consequence is that a rule or a detector
validated against one table is not thereby validated against the other, and no check compares the
two schemas.

**9. Tools this design has not seen: MCP, delegation, and lists that change.** The enforcement
point is ADK's `before_tool_callback`, which the flow runs through
`agent.canonical_before_tool_callbacks` for every tool. `McpTool` derives from `BaseTool`, so an
MCP tool would be screened, decided and recorded exactly as a local one is, with no change to
this repository. That is the good half and it is verified against the installed ADK rather than
assumed. The rest is not covered.

*Half the check families go blind on a tool this project did not write.* `enforce` reads the
domain fields straight out of the call arguments: `args.get("target_tenant_id")`,
`args.get("account_id")`, `args.get("amount_cents")`. An arbitrary MCP tool does not use those
parameter names, so all three arrive null. `scope-escape` and `injected-turn` still work, because
they key on `tool_name`, `declared_scope` and the Model Armor fields. `cross-tenant` and
`privilege-sequencing` stop working entirely. Governing a third-party tool is therefore an
argument-mapping problem, not a plumbing one, and nothing in this repository maps arguments.

*A tool can appear after the session declared its scope.* MCP servers may send
`tools/list_changed`. `declared_scope` is seeded once, before the first turn. A tool that appears
mid-session is outside the declared scope and `out-of-declared-scope` denies it, which is the
right outcome by luck rather than by design. The DSL cannot express "refuse anything that was not
on the list when the session started", because it has no representation of when the list was
taken.

*Tool names are not unique across servers.* Two MCP servers may both expose `search`. The conduct
row records `tool_name` and not the server that provided it, so a rule keyed on a name gates
both, and a finding cannot say which server was involved. Fixing this needs a new column, which
is the subject of entry 10.

*Delegation is out of scope entirely.* The four detectors assume one workload agent, two tools and
no agent-to-agent calls. The best-evidenced attack in this field, cited in `docs/DEVPOST.md`,
worked through exactly the delegation this design does not model.

**10. A schema change and a tampered row look identical, and telling them apart took a
projection.** Chain link 1 hashes each cited row as `SHA256(TO_JSON_STRING(t))`.
`TO_JSON_STRING` emits a key for every column, including null ones, verified in this project:
`SELECT TO_JSON_STRING(t) FROM (SELECT 1 AS a, CAST(NULL AS STRING) AS b) t` returns
`{"a":1,"b":null}`. Adding a column to `conduct_live.turns` therefore changes the digest of every
row already cited and quarantines every chain in the project at once.

That quarantine is correct and stays. A schema change underneath a cited window genuinely is an
evidence change. What was missing was a migration path, and finding it exposed something worse.

`EVENT-WINDOW` has never been among the break codes that refuse re-attestation, because a
late-arriving event raises it too. So `reattest` re-derived over it and cleared it. That is right
for a late event and wrong for an edited row, and until this was found the two were the same code
path: the repo's own adversarial fixture, a cited `issue_refund` rewritten to another tenant with
its event id preserved, was caught by `verify` and then cleared by `reattest`, which returned the
version to `attested`. The test that was supposed to cover this edited a chain *link*, which
breaks `LINK-HASH`, and no test edited a cited conduct *row*.

The fix is a projection, and the first attempt at it was itself broken. Each evidence link now
records `schema_columns`, the conduct table's columns in schema order. When the digests move,
`reattest` re-derives the rows over the columns the chain was sealed against:
`TO_JSON_STRING(STRUCT(t.a, t.b, ...))` over the full list in order is byte-identical to
`TO_JSON_STRING(t)`, checked against `conduct_live`, 43 rows, zero differing. An unedited row
still digests to its sealed value under a new column; an edited one still does not. The first
version instead treated any moved schema as licence and returned, so adding a column and
rewriting a cited refund in the same edit cleared both. An adversarial pass found that, and
`test_reattest_refuses_an_edit_hidden_behind_a_new_column` now holds it.

A dropped or retyped column is refused outright. The rows cannot be re-derived as the chain saw
them, so nothing about the change is provable either way.

**What is still not covered.** A chain sealed before `schema_columns` existed cannot prove drift,
so every content change under it is refused, including a legitimate schema change. That is
deliberate, and it means the migration has an order: `caseharden refresh` must run on every
version *before* any DDL touches the conduct table. Both live versions were migrated on Day 9.
A project that drifts first has no recovery path in this code, and the operator would have to
promote a new version.

`refresh` writes one `EVIDENCE-CHANGED` link restating evidence that already re-derives, and
refuses unless the event, access and exam-reach digests all match what it just verified. That
last condition is not decoration: `exam_reach` is a live IAM read and is not cached, and an
adversarial pass granted the Proposer `bigquery.dataViewer` between the two reads, so the
restatement recorded the grant as its baseline under a reason claiming nothing had moved.

The cheaper route remains to leave the cited table alone and put new fields in a side table
joined on `event_id`, which does not touch the digest of any cited row. That is still the
recommended shape for the MCP server identity in entry 9, and it costs the detectors a join.

**11. A second policy line exists in the registry and the serving layer, and nowhere else.**
`policy.versions` carries a `policy_id`, registration deactivates only within its own line,
a parent from another line is refused, and the Policy Server answers
`/policy/<line>/active` beside the unchanged `/policy/active`. What a second line does not
have is everything that makes the first one governed: the workload agent still enforces
`conduct-policy` alone, and `payments-policy` has no sealed holdout, so no candidate for it
can be examined and none can be promoted. Its genesis is a human-granted floor — served,
active, and reported by `verify` as carrying no chain — which is exactly the
configuration-granted authority this project exists to replace, held at one deny rule until
the line earns its own exam.

Scaling the *guarantee* across lines is not the open problem. Every rule in every line is
deny-only, so fleet authority is the complement of the union of the active lines' denial
sets; a promotion inside one line replaces that line's contribution with a superset (the
per-line MONOTONICITY leg), and a union of supersets is a superset, under any interleaving
of promotions. The BENIGN leg composes for the same reason: deny predicates do not
interact. What scales linearly and cannot be waved away is the evidence: one sealed
holdout, one access-list attestation and one live 403 per line, because an exam is
domain-specific. Retiring a line would widen authority and is refused the same way
dropping a rule is.

One race is known and left open. Version-name uniqueness across lines is a read before a
write, four BigQuery jobs with no transaction and no primary key, so two concurrent
`genesis` calls claiming the same name in different lines can both insert. The Day 11
genesis guard — a line's first version and nothing after it — sits on the same
read-before-write, so two concurrent geneses for one new line can both pass it. Registry
writes here are one operator at a keyboard; two adversarial reviewers named the race and
the fix (a multi-statement transaction) and it is not built.

---

## Three smaller notes

**A policy accumulates redundant rules, and that is the price of monotonicity.** The active
version carries `tool-call-on-injected-turn`, which denies a tool call at
`ma_prompt_injection_score >= 0.75`, and `tool-call-on-suspected-injection-turn`, which denies
one at `>= 0.5`. The second strictly subsumes the first: every row the first denies, the second
denies as well. Nothing is wrong. The MONOTONICITY leg requires that a candidate carry forward
or narrow every rule the active version holds, so a rule cannot be dropped once a later rule
swallows it. The consequence is that the rule list grows monotonically with the version number
and older rules become dead weight rather than dead code. Nothing measures that growth today,
and a reader who opens `policies/v5-active.json` will see two overlapping injection rules before
they see this paragraph, which is why it is written down here.

`roles/bigquery.resourceViewer` on `notary-sa` lets it see every job in the project. It
carries no `bigquery.tables.getData`, checked with the same role expansion `verify` uses, so
it does not widen the exam's reach.

Spans are flushed on the response path. A crash between the tool call and the response loses
that turn's span, on top of the export problem above.
