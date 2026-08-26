# Build log

One entry per day. Measured numbers only, never estimates.

---

## 2026-08-25 — Day 1

**Exit criterion: both captures reproduce.** Recorded in `captures/`.

### Shipped

Public repo created with the specification and the operating contract under `docs/`.
Employer identifiers were redacted from the handoff before publication.

Personal GCP project `devpost-hackathon-506416`, europe-west3, billing enabled.
Eight APIs enabled. Five service accounts, one per role: `proposer-sa`, `examiner-sa`,
`notary-sa`, `foreman-sa`, `workload-sa`.

Five BigQuery datasets in europe-west3: `conduct_train`, `holdout_sealed`,
`benign_corpus`, `chain`, `policy`. Dataset-scoped grants only. No service account
holds a project-wide BigQuery read.

Certificate bucket `gs://caseharden-certificates-506416`, europe-west3, uniform
bucket-level access, public access prevention enforced, 30-day retention policy,
**locked** (`isLocked: true`). Locking is irreversible, so it sits behind its own
guard in `infra/62_lock_retention.sh` and was run only after explicit sign-off.

Seeded synthetic conduct generator, `generator/generate_conduct.py`, with a self-check.

### Measured

Corpora, counted in BigQuery after load:

| Corpus | Events | Sessions | Window |
|---|---:|---:|---|
| `conduct_train` | 33,118 | 6,004 | 2026-06-01 to 2026-08-15, 76 days, **no labels** |
| `holdout_sealed` | 5,480 | 992 | 2026-08-16 to 2026-08-29, 14 days, labelled |
| `benign_corpus` | 640 | 239 | same 14 days, tool-call turns only |
| **total** | **39,238** | | |

Sealed holdout, by label. `attack events` counts the rows that constitute the
abuse, so a scorer states whether it counted rows or sessions:

| Label | Sessions | Events | Attack events |
|---|---:|---:|---:|
| benign | 952 | 5,259 | 0 |
| cross-tenant-egress | 10 | 55 | 45 |
| injected-turn-tool-call | 10 | 54 | 10 |
| privilege-sequencing | 10 | 55 | 20 |
| scope-violation | 10 | 57 | 10 |

Ten attack sessions per family, so a reported catch rate of "N of 10" is a real count.
`conduct_train` returns 33,118 rows and `label IS NULL` on every one.

Generator digests, seed 20260825: `conduct_train 491fde17383c8f82`,
`holdout_sealed a0a0761ce8853a3a`, `benign_corpus 06e37601b2cafddb`.

### Capture 1 - the Proposer cannot read its own exam

`captures/day1-proposer-403-on-holdout.txt`, from `infra/70_prove_seal.sh`, exit 0.
The script asserts rather than displays: it exits non-zero if any read goes the
wrong way or if the access list is not exactly one entry.

- `proposer-sa` on `conduct_train.turns`: HTTP 200, 33,118 rows.
- `proposer-sa` on `holdout_sealed.turns`: **HTTP 403 PERMISSION_DENIED**.
- `examiner-sa` on `holdout_sealed.turns`: HTTP 200, 5,480 rows.
- **the human project owner** on `holdout_sealed.turns`: **HTTP 403 PERMISSION_DENIED**.

The last one is stronger than the plan asked for. `bigquery.tables.getData` is not
part of `roles/owner`, so once the inherited entries are off the dataset the owner
of the project is refused it too. The access list is one row:

```
OWNER  examiner-sa@devpost-hackathon-506416.iam.gserviceaccount.com
```

The principal is proved from the access token itself rather than asserted by the
script. The Cloud Audit entry names the denied permission:

```
principalEmail proposer-sa@devpost-hackathon-506416.iam.gserviceaccount.com
status.code    7  (PERMISSION_DENIED)
DENIED         bigquery.tables.getData  (DATA_READ)
               on projects/devpost-hackathon-506416/datasets/holdout_sealed/tables/turns
```

### Capture 2 - a sealed certificate cannot be altered

`captures/day1-retention-refuses-delete.txt`, from `infra/71_prove_immutability.sh`, exit 0.
Three attempts, all as the project **owner**, all refused `403 retentionPolicyNotMet`:

- delete the object
- overwrite the object
- remove the retention policy: `has a locked Retention Policy which cannot be removed`

`gcloud storage rm` reports only an opaque `GcsApiError('')`, so the script repeats
each call against the JSON API where the reason is stated. Both are in the capture.

### Adversarial pass

Two independent validators ran against the Day 1 diff. Every finding below was
fixed and re-verified before this entry was written; the captures above are from
the fixed scripts, not the ones that were audited.

Codex, against the generator, found seven defects. Four were corpus leaks that
would have made the promotion gate decorative:

1. `conduct_train` carried the family label on every attack row, and `proposer-sa`
   can read that dataset. The Proposer was one query away from the answer key the
   sealed holdout exists to withhold. Training rows now carry `label: NULL`; the
   base rates stay inside the generator and are never written.
2. Attack `session_id`s spelled out the family, for example `s_hold_scope-violation_00`.
   Session ids are opaque hashes now.
3. Every holdout attack fell before every benign turn on the calendar, so
   `ts <= 2026-08-25` scored 197/197 attacks and 640/640 benign. Attacks and the
   benign corpus now span the same fourteen days.
4. Every privilege-sequencing refund was larger than every benign refund, so
   `amount_cents >= 20000` caught all ten with no false positive. All refunds now
   come from one distribution, and the family's signal is a read and a write on
   the same account in one session, which is only visible by joining.
5. Row scoring and session scoring were undefined, so a row-level scorer would
   have reported 19.6% where the plan says 10 of 10. Rows now carry `is_attack_event`.
6. `check()` never tested privilege-sequencing. Codex proved it by breaking the
   property and watching the check still pass.
7. `check()` used bare asserts, so `python3 -O` reported success while testing
   nothing.

The general form of 3 and 4 is now a test: `no_single_field_separator` fails if any
threshold on any field catches every session of a family while blocking no benign
turn. Each family's own defining field is exempt, since separating there is the
detector working. A twenty-case mutation harness confirms every asserted property
fails when broken; two mutations survived the first attempt and both were real gaps.

The spec validator, against the whole Day 1 diff, found five more:

- The `holdout_sealed` access list still carried `projectOwners` and the creator's
  own owner entry, and it proved the point by reading 5,421 rows as the project
  owner three lines below a capture calling `examiner-sa` the only principal. Fixed
  by reducing the list to one entry.
- `chain` and `policy` kept inherited `projectWriters`. The compute default service
  account holds `roles/editor` and is what Cloud Run uses when no service account is
  named, so the append-only chain was writable by anything deployed carelessly on
  Day 4. Stripped.
- The certificate bucket granted every project editor `storage.objects.create`,
  `storage.objects.delete` and `storage.buckets.setIamPolicy` through legacy
  bindings, against a comment claiming the Notary was the only writer. Removed from
  `projectEditor`; project owners keep theirs or the bucket is unrecoverable.
- No script granted `roles/iam.serviceAccountTokenCreator`, which `roles/owner` does
  not carry, so on a fresh project the seal proof could not mint a token and exited
  before proving anything. Now granted in `10_service_accounts.sh`.
- `71_prove_immutability.sh` issued an unguarded request to remove the retention
  policy. Against a locked bucket that is the proof; against an unlocked one it
  succeeds and strips the protection. It now checks `isLocked` first and stops.

Also fixed: the scripts were renumbered, because sealing the holdout removes the
operator's own write access to it and the old order put the seal before the load.
`20_bigquery.sh` now verifies its security claim instead of printing it, and no
longer swallows dataset failures. `70_prove_seal.sh` asserts the shape of the
access list instead of displaying it and trusting the reader. The access token is
no longer passed in a URL, where it is visible in the local process table.

One thing the audit could not have caught from the code: BigQuery caches dataset
access lists for several minutes. A read the seal is meant to refuse still succeeds
right after the list changes. `70_prove_seal.sh` waits for the new list to be in
force rather than capturing the stale answer as a result.

### Escalated and approved by the entrant, in session

- Rewording section 2's isolation claim from an IAM deny binding to dataset access
  control. The only change to a section 2 claim.
- Locking the retention policy at 30 days. Irreversible.
- Taking the repo private until the employer approval email is sent.

### Carried over

0. **Two demo-script wordings need a decision**, both listed under "Open, and not
   mine to decide" in the Day 2 entry above. Neither changes what the gate does.
1. **Day 3, chain link 1 must include the `holdout_sealed` access list hash.** This
   is the substitute for the deny binding and it is load-bearing, not decorative.
   One pytest: mutate the access list, assert `verify` quarantines.
2. **Employer email** covering code ownership, development infrastructure approval
   and public repo approval is still outstanding. The repo is **private** until it
   is sent, then flips back to public with its commit history intact. This is one
   of the four blocking prerequisites in the handoff.
3. **Day 6, THREATS.md** must record what the seal does not cover: a project owner
   can put an access entry back. That action leaves an audit record, and once link 1
   hashes the access list it also breaks the chain, but it is not prevented.
4. **Cost guardrail** is in place: a EUR 45 budget on the hackathon project alone,
   alerting at 50, 80 and 100 percent of actual spend plus 100 percent of forecast.
   45 EUR is the handoff's own escalation threshold. Note the billing account is
   denominated in **EUR**, while the Devpost credit is quoted in dollars.

---

## 2026-08-26 — Day 2

**Exit criterion: the gate refuses a candidate three different ways and passes one,
scored in BigQuery under `examiner-sa`.** Recorded in
`captures/day2-gate-two-sided.txt`, produced by `infra/80_prove_gate.sh`, which
asserts every outcome and exits non-zero if any of them changes.

### Shipped

`caseharden/dsl.py`. The conduct-policy grammar as a Pydantic model. Six predicates:
`equals`, `in_set`, `at_least`, `present`, `outside_declared_scope`, `tenant_mismatch`.
The last two read Model Armor's verdict fields and the repeated `declared_scope`
column respectively. `action` is the literal `deny` and nothing else parses, so the
grammar cannot express a widening edit. `field` is a closed Literal over the ten
predicate columns the generator declares; `label` and `is_attack_event` are not in it.
Every model sets `extra="forbid"`, so an unknown predicate fails validation with the
offending name in the message rather than being ignored.

`caseharden/interpreter.py`. Two evaluators for one grammar: a Python one and a
BigQuery compiler. The Python evaluator is what pytest runs. The compiler is what
scores against the sealed holdout, because the holdout lives in BigQuery and only
`examiner-sa` may read it.

`caseharden/examiner.py`. Scoring, the three-leg gate, and a CLI with two backends.
`--backend local` replays the seeded corpora. `--backend bq` scores in BigQuery as
`examiner-sa`. Returns catch rate per family, benign pass rate, false-positive cost
in blocked refund value, and the monotonicity result.

`caseharden/bq.py`. Standard library plus the gcloud CLI. No client library, so a
reviewer can read every line between the compiled predicate and the service.

Four committed policies: the active `v3`, an over-blocking candidate, a widening
candidate, and the candidate that passes.

`tests/test_gate.py`, seventeen tests, 0.62s. `generator/mutate_check.py` now breaks
21 generator properties in turn; every one fails when broken.

### Measured

Scored in BigQuery as `examiner-sa` against 5,480 sealed holdout events and the
640-turn benign corpus. Attack sessions per family: 10.

| Candidate | Sealed attack sessions caught | Benign pass rate | Legitimate turns denied | Blocked refund value | Verdict |
|---|---|---|---|---|---|
| `v3`, active | 10/40 | 100.0% | 0 | 0.00 | active |
| A, over-blocking | **37/40** | **68.3%** | 203 | 2007.11 | DENIED, benign regression |
| W, widening | 20/40 | 100.0% | 0 | 0.00 | DENIED, authority widened |
| B | 29/40 | 100.0% | 0 | 0.00 | **GATE PASS** |

Candidate A catches more sealed attacks than the passing candidate on every family
and is refused anyway. That is the two-sided gate doing the only job it has.

Per-family, for the beat at 2:10: candidate A catches the injected-turn family 10/10,
candidate B catches it 9/10. Those are the numbers the demo script names.

The compiled BigQuery predicate and the Python evaluator were run over the same two
corpora and compared on the set of turns each denied: **AGREE**, both corpora. Two
implementations of one grammar are only worth having if they are checked against
each other.

BigQuery job history for the run: 52 SELECT jobs attributed to
`examiner-sa@devpost-hackathon-506416.iam.gserviceaccount.com`, 1 to the operator.

The Proposer asking the Examiner to score its own draft exits 3 with BigQuery's
verbatim `PERMISSION_DENIED`. The seal from Day 1 now has a caller.

### Deviation from the plan, with the reason

The plan specifies the monotonicity check replays the candidate and the active
version **over the benign corpus**. Replaying decides monotonicity for the rows on
hand and for nothing else, and both adversarial passes broke it. The active version
denies nothing in the benign corpus, so "the candidate's denial set is a superset"
is true there for every candidate, including one that widens authority. Adding the
holdout to the replay corpus fixed that instance and not the class: a candidate can
narrow an active rule with a predicate no row in either corpus witnesses, and the
replay still calls it monotone.

Monotonicity is now decided on the policy rather than on rows. A rule denies when
all of its predicates match, so removing predicates broadens a rule and adding them
narrows it. Candidate rule R covers active rule A exactly when R's predicate set is
a subset of A's. If every active rule has such a candidate rule, the candidate's
denial set is a superset of the active version's **on every possible input**. It is
conservative: a candidate that re-expresses a rule differently is refused rather
than analysed, and the remedy is to carry the rule forward unchanged.

The corpus replay is still computed and still printed, as the empirical cross-check
on the structural result. In `--backend bq` it runs as a BigQuery query rather than
against locally regenerated rows, because a real scoring run must read what BigQuery
is serving.

### Known limitation, recorded rather than hidden

The `privilege-sequencing` family is **not expressible** in this grammar. It is a
read that locates an account followed by a write onto that same account; neither
call is anomalous alone, and detecting it needs a session self-join, which no
row-level predicate can express. The passing candidate catches it 0/10 and the
Examiner reports that plainly. Adding a session-scoped predicate is a grammar
change, not a policy change, and it is not in the Day 2 scope.

Candidate A catches 7/10 of that family by accident, because a threshold low enough
to deny a third of legitimate traffic denies most things.

### Adversarial pass

Two engines, briefed with the spec path, the worktree, the base ref and the
instruction to run the suite themselves. Neither was given any of this session's
conclusions. Codex is a different model and is the only independent read available
here; the in-house validator is the same model and is a checklist pass. Both were
told to attack. Codex reported six defects, the validator ten findings plus what it
could not check. Eleven are closed below; three are documentation items, two of
which need a decision that is not mine.

**Both engines, independently: a candidate can pass the gate while detecting
nothing.** Codex built one. It names a set of eleven `account_id` values, catches one
more sealed attack session than the active version, denies no legitimate turn, and
passes all three legs. It generalizes to nothing, because an account id is a
per-call identifier.

`account_id` is out of the predicate vocabulary. The generator's leak check tested
thresholds (`<=`, `>=`) and could not see set membership, which is how an identifier
leaks. `no_value_set_free_pass` is the general form: for every field a candidate may
name a literal on, fail if every session of a family carries a value that no benign
turn carries. It is in the mutation harness, so it fails when broken.

**The validator escaped the replay-based monotonicity check.** It kept the active
scope rule and added one predicate to it, narrowing it. Every out-of-scope call in
both corpora happens to be an `issue_refund`, so no row witnesses the difference and
the replay reported the candidate as monotone. The structural check above refuses
it, and `test_a_widening_the_corpus_cannot_witness_is_still_refused` asserts both
halves: the replay's blind spot, and the refusal.

**A timed-out query read as a clean benign score.** `jobs.query` answers a timeout
with `jobComplete: false`, no rows and no error. The client returned an empty result,
`benign_pass_rate` returned 1.0 for zero turns, and the over-blocking candidate
passed the benign leg. The client now raises on an incomplete or paginated response,
and the gate refuses to rule at all when nothing was scored.

**Closed, one line each.**

- CATCH was summed across families, so a candidate losing nine sessions in one family
  and gaining ten in another read as an improvement. It is now per family as well as
  in total.
- `at_least` accepted `NaN`, `Infinity`, `1e400` and `True`. `1e400` is ordinary valid
  JSON, parses to `inf`, and compiles to a bare `inf` that BigQuery reads as a column
  name. Rejected at parse time now.
- `tenant_mismatch` compared `target_tenant_id != tenant_id` without checking
  `tenant_id`. In BigQuery that is NULL, which does not deny; in Python it was True.
  Both sides are explicit now.
- `--project` and `CASEHARDEN_PROJECT` were interpolated into a backtick-quoted table
  identifier with no validation. A backtick closed the identifier. Validated now.
- A malformed-SQL 400 was reported in the exact words of the IAM 403, including its
  exit code. Exit 3 is the authorization refusal only; anything else exits 4.
- The over-blocking test's docstring claimed a per-family property its assertions did
  not check. Codex broke the property and the test still passed. Asserted now.
- `false_positive_cost_cents` is one of the four outputs the plan names and was
  asserted nowhere. It is pinned at 200711 cents for candidate A.
- The BigQuery compiler had no test in the suite. Every predicate now compiles to a
  pinned string, and the roster is read off the grammar so a new predicate cannot be
  added without compiling it here.
- `dsl.py` claimed the absence of an allow verb made narrowing the only expressible
  edit. The repo's own widening candidate contradicts that. Reworded.

**Open, and not mine to decide.**

1. The plan's video line at 2:10 says "The examiner is two hundred lines of code."
   `interpreter.py` is 187 lines; the Examiner as a whole is 610 across three files.
   Section 3's "about 200 lines of deterministic interpreter" is accurate. The spoken
   line is not, and that beat is untouchable, so it needs a decision rather than an
   edit.
2. The same beat's on-screen numbers, "10 of 10" and "9/10", are the injected-turn
   family row. The overall counts are 37/40 and 29/40. Both readings are true and
   the beat works either way, but the wording should say which.

**Unchecked, stated rather than assumed.** Codex's sandbox is read-only and holds no
GCP credentials, so it ran the local path only. The validator's sandbox blocked
`gcloud auth print-access-token`, so every `--backend bq` claim, the engine-agreement
result, and `infra/80_prove_gate.sh` went unverified by both. Those were re-run here
after the fixes and the capture was retaken.

### Recorded for THREATS.md

The sealed holdout is IAM-sealed in BigQuery and byte-reproducible by anyone holding
the repo, because the generator is committed and seeded. Both are true at once. The
disclosure is deliberate, so a reviewer can regenerate what the measurements were
taken on. It becomes exploitable rather than theoretical if the Proposer is given
repo or generator access on Days 4 and 5, which it must not be.

The Examiner CLI now defaults to `--backend bq`, the path that carries an identity.
`--backend local` reads a locally regenerated holdout under no identity at all and
exists for the test suite.

---

## 2026-08-27 — Day 3

**Exit criterion: the memorable moment is complete on hand-fed links.** Green,
quarantine, promotion refused, re-attest, green again. Recorded in
`captures/day3-attestation-lifecycle.txt`, produced by `infra/90_prove_attestation.sh`,
which asserts six outcomes against the real project and exits non-zero if any of them
changes.

### Shipped

`caseharden/chain.py`, 469 lines. Links, their hashes, the append-only table, the seal
into the retention-locked bucket, and the interface verification re-derives from.

Nine link kinds. Two of them are derivations and seven are records, and `verify` prints
which of the two each link got. `EVIDENCE` states which conduct events justified the
change and which principals could read the sealed exam. `EXAM` states what the Examiner
measured. Both are recomputed against the warehouse as it stands now. `FINDING`,
`VERDICT`, `DRAFT`, `DRAFT-REJECTED`, `HOLDOUT-DENIED` and `APPROVAL` are records,
protected by the hash chain alone. Section 2 claims re-derivation for the evidence and
the exam and for nothing else, so the code says so and a test pins the split.

Link 1 also hashes who could read the sealed exam, by two routes rather than one: the
dataset's access list, and every project-level IAM binding that could carry
`bigquery.tables.getData`. A grant to the Proposer by either route breaks the chain.
That is the substitute for the IAM deny policy this project cannot create, and its
limit is stated in THREATS.md: a deny rule would beat a later grant, while this only
guarantees the grant cannot go unnoticed.

`caseharden/notary.py`, 964 lines. `verify`, `reattest`, `promote`, `genesis`, `seed`
and the certificate renderer behind one CLI.

`verify` walks the hash chain first and stops there if it is broken, because
re-deriving against a payload already shown to be edited answers a question about the
edit. Then it re-scans the cited conduct window, re-reads the exam's access list,
re-runs the Examiner over the sealed holdout, and compares the chain root against the
certificate in the locked bucket. Five break codes name where it stopped:
`LINK-HASH`, `EVENT-WINDOW`, `HOLDOUT-ACCESS`, `EXAM-SCORE`, `ROOT-MISMATCH`.

`promote` and `seed` both refuse to build on a parent that is not attested, and on a
parent that was never a version. The first version is registered explicitly with
`notary genesis`, so "this parent has no chain" cannot be mistaken for "this parent is
the first one".

`reattest` re-derives against the evidence as it now stands and, if the gate still
passes, appends an `EVIDENCE-CHANGED` link that supersedes the previous evidence
statement. The superseded link stays in the chain with the digest it carried at
promotion. It refuses two cases outright: a break that says the record itself was
edited, and an exam access list that has been widened. Without those two refusals
`reattest` is an undo button for the tamper it exists to survive.

`caseharden/policy_server.py`, 201 lines. Three states over a 60-second cache. Every
response carries `checked_s_ago`, so the staleness is stated rather than hidden. The
one branch that must never fall through to attested is the exception path: a version
whose state cannot be established is served `UNKNOWN`, with promotions frozen, the last
state that was actually established, and an `ALERT` line on stderr.

The policy it serves is read out of the chain's effective exam link, not out of
`policy.versions`. The registry copy is compared against it and reported as
`registry_agrees`; a disagreement freezes promotion, because the fleet's configuration
store and the record then describe different documents.

`caseharden/certificate.py`, 74 lines. One chain rendered to a static HTML page, no
JavaScript and no server.

`infra/25_chain_tables.sh` creates `chain.links` and `policy.versions`, grants the
Notary project-scoped `roles/bigquery.metadataViewer`, and then asserts the property
that grant exists for: the Notary reads *who* may read the exam and is still refused
the rows. Bound at project scope on purpose, because a dataset-scoped grant would add
a second entry to `holdout_sealed`'s access list, and that list having exactly one
entry is the artifact a reviewer opens at 1:52.

`infra/tamper.py` streams one ordinary conduct event into a cited window, under
`workload-sa`, which is the identity that writes every other conduct event.

`tests/test_chain.py`, 56 tests, and `tests/test_bq.py`, 20. `python3 -m pytest tests -q` is 93 tests in 2.0s.

### Measured

Verify, timed over 20 runs against the live chain by `infra/measure_verify.py`:

| | p50 | p95 | max | mean |
|---|---:|---:|---:|---:|
| `verify v4`, 8 links, exam re-derived | 2.46s | **2.91s** | 2.91s | 2.43s |

The plan's target was under 5s p95. Two impersonated tokens cost 2.4s more, paid once
per process rather than per call, and not paid at all on Cloud Run where the runtime
supplies the identity.

An earlier figure of 0.84s p95 was measured on a chain that did not re-run the
Examiner, because of the defect described under M1 below. It is recorded here rather
than quietly replaced: the number was real and it was measuring the wrong thing.

The lifecycle, every number taken from the capture:

| Step | Result |
|---|---|
| `genesis v3` | registered as the active version with no chain |
| `seed v4 --parent v3` | parent accepted, 7 links, sealed to the locked bucket |
| `verify v4` | ATTESTED. Re-derived: EVIDENCE, EXAM. Recorded only: FINDING, VERDICT, DRAFT, HOLDOUT-DENIED, APPROVAL |
| `promote v6 --parent v99` | REFUSED, exit 5, "not a version of this policy" |
| Policy Server | `ATTESTED`, promotions `OPEN`, verify 2.54s |
| one streamed event | QUARANTINED at link 1 `EVENT-WINDOW`, offending id named, promotions FROZEN |
| Policy Server, after the cache expired | `QUARANTINED`, `attested: false`, promotions `FROZEN` |
| `promote v5 --parent v4` | REFUSED, exit 5, nothing written to the chain |
| `reattest v4` | link 8 `EVIDENCE-CHANGED`, 423 events, exam re-scored 29/40 at 100%, ATTESTED, new root `ea62e7623db9` |
| link 1 afterwards | still hashes to `7c003202d555`, still cites 422 events |
| `promote v5 --parent v4` again | parent accepted |
| DELETE on the sealed certificate, as project owner | `retentionPolicyNotMet` |

The 403 in link 5 is not a stored string. `seed` runs the Examiner for real under
`proposer-sa` and refuses to write the link on anything other than a live refusal.

### Deviations from the plan, and why

1. **The root is not yet annotated onto the Agent Registry entry.** No registry entries
   exist until Day 4. The root is written to `policy.versions` now and the annotation
   lands with the registry entries it annotates.
2. **The `FINDING` link carries the detector SQL and the session ids it returned, not
   the BigQuery job id or the trace id.** Both are produced by the detector agents,
   which are Day 4. Plumbing a job id through the client today would be plumbing for a
   producer that does not exist yet.
3. **The `VERDICT` link carries no Model Armor screening result.** Model Armor is wired
   on Day 5. The link says so in a field rather than carrying a null that reads as a
   pass.
4. **The Policy Server runs, it is not deployed.** Day 3 asked for it to implement the
   three states, which it does. Cloud Run is Day 4.
5. **`DRAFT-REJECTED` is a declared link kind with no writer.** Section 2 counts a DSL
   parse rejection among the negative links the chain records. `verify` displays one
   and nothing writes one, because the Proposer that would produce it is Day 5.
6. **Nothing marks a block reason as unattested.** Section 3's `quarantined` row says
   block reasons are marked unattested. The version keeps enforcing and the Policy
   Server reports `attested: false`, but the enforcement callback that would carry that
   into a block reason is Day 4.

### Known limitations, recorded rather than papered over

**Append-only is a convention on `chain.links`, not a platform guarantee.** BigQuery
has no append-only table mode and `WRITER` on the dataset carries DML delete. What
makes an edit detectable is the sealed root: a chain rewritten in place, hashes and
all, still disagrees with the certificate in the retention-locked bucket, and
`test_a_re_hashed_chain_still_fails_against_its_sealed_root` pins exactly that.

**A tamper is enforced-but-attested for up to 60 seconds**, the Policy Server's cache
window. Stated in every response as `checked_s_ago`.

**The exam's reach is hashed for BigQuery roles and custom roles only.** A role outside
that set cannot carry `bigquery.tables.getData`, so hashing every project binding would
quarantine versions on unrelated IAM churn. The cost of the narrower set is that it
rests on Google's role definitions being what they say.

**A streamed row cannot be removed by DML for about 90 minutes.** The tamper is one-way
within a rehearsal, which is why `90_prove_attestation.sh` picks a fresh event id when
the default one is already in the window rather than pretending the previous run was
undone.

### Adversarial pass

Two engines, briefed with the plan path, the worktree, the base ref and an
instruction to attack. Neither was given my summary or my conclusions.

Codex found four defects, three of them serious. All four are closed and each was
re-checked by re-running the engine's own reproduction command.

**A cited conduct event could be rewritten without losing attestation.** Link 1
digested the event ids in its window and nothing else, so an insert or a delete broke
the chain and an UPDATE did not. Codex changed a cited event's `tool_name` to
`issue_refund` and its tenant to another tenant, keeping the id, and verification
returned `ATTESTED True OPEN`. That is the entry's central claim failing: the evidence
a version cites is the content of those rows, not the fact that rows with those ids
exist. Link 1 now carries a digest of every cited row's full content, computed in
BigQuery as `SHA256(TO_JSON_STRING(t))` per row over the pruned window. A break now
reports added, removed **and** altered ids separately, so the same attack quarantines
and names `e_00000`.

**A chain that was not a promotion attested.** Nothing required the links to be a
promotion. Codex built a single fabricated `FINDING` link, sealed its own root, and
verification called it `ATTESTED`: no evidence link, no exam, no approval, and nothing
re-derived because there was nothing to re-derive. A hash chain proves its links are
consecutive, not that they say anything. `verify` now requires the grammar before it
considers a root: sequence numbers 1..N with no gaps, `EVIDENCE` first, and an `EXAM`
and an `APPROVAL` present. Break code `CHAIN-SHAPE`.

**The Policy Server could serve a stale green over a fresh quarantine.** Cache entries
were ordered by when a verification finished. Codex raced a slow `ATTESTED` refresh
against a later `QUARANTINED` one; the slow one landed last and won, reopening
promotions for a further 60 seconds. Entries are now ordered by when the verification
started, so an older answer never replaces a newer one.

**The certificate escaping test asserted only an absence.** It checked that the raw
`<script>` string was not in the page, which is also true of a renderer that returns
nothing. It now asserts the escaped form is present, that the page has its doctype and
its heading, and that the hostile payload is built into the chain rather than mutated
in afterwards. The second point matters more than the first: mutating a payload breaks
the link hash, so verification skipped every later link and the hostile string never
reached the renderer at all. The test was passing twice over for the wrong reasons.

On the last of those, Codex's own evidence did not show what it claimed. It stubbed
`render` in the dict returned by `runpy.run_path`, which is a copy of the module
namespace rather than the namespace the test function closes over, so the stub was
never in effect. The finding was correct and the evidence for it was not. Re-checked
here by patching the function's real `__globals__`, where the old test does pass with
a stubbed renderer and the new one does not.

Four more came out of reading the code here rather than from either engine, and are
fixed the same way:

- The link hash is taken over newline-joined fields, and `version` arrives from a
  command-line flag. A version containing newlines could produce the same hash input as
  a different link. Versions are now checked against a regex.
- A version with no sealed certificate was attested on its own say-so. A chain proves
  its internal consistency, so without an anchor, dropping its last link is invisible.
  Missing certificate is now break code `NO-CERTIFICATE`.
- An access-list entry with no member at all, which is what an authorized view is,
  reduced to the same string as any other. Two such entries were interchangeable
  without the digest noticing.
- A malformed payload raised out of `verify` instead of quarantining. It is a
  defective record, not an outage, so it is now `CHAIN-SHAPE` and names its link.

The in-house validator, run against the same brief, found nine more. Its sandbox held
working read-only credentials for the project, so several of its claims are checked
against the live warehouse rather than against a reading of the code.

**The exam stopped being re-derived after the first re-attestation.** This is the worst
one in the day, and the shape of it matters more than the fix. `EVIDENCE-CHANGED`
restates both the evidence and the exam, and verification followed it for the evidence
and not for the exam. So link 6 printed "re-scored under link 8" and link 8 re-scored
nothing. From the demo's own remedy beat onward, a version reported `ATTESTED` while the
Examiner's numbers had moved. The validator moved the holdout twice, re-attested in
between, and got `attested` on the second move. Both link kinds now re-run the Examiner,
and the capture shows link 8 carrying "the Examiner re-scores 29/40 sealed attack
sessions at 100% benign pass, unchanged".

That defect also invalidated the published SLO. The 0.84s p95 was measured on the
post-re-attestation chain, which is the configuration that was skipping the Examiner.
Measured again with the exam actually re-derived, p95 is 2.91s.

**The promotion freeze was advisory.** `promote` verified the parent and wrote nothing.
`seed` wrote the chain, marked the version active, and never looked at the parent at
all. Nothing forced anyone to run `promote` first, and `promote --parent v99` accepted a
version name that had never existed by calling it a genesis version. The check now lives
in `parent_basis`, both commands call it, and `seed` refuses before it writes anything. A
genesis version has to be registered with `notary genesis` to count as one.

**The hashed access list could not see a project-level grant.** Section 2 claims a later
grant to the Proposer breaks the chain. Link 1 hashed the dataset's access list, and a
project-level IAM binding reaches the same table without appearing in that list. This
project demonstrated the gap itself: the Notary reads the exam's metadata through a
project-scoped role and is nowhere in the exam's one-entry access list, which is exactly
the shape `roles/bigquery.dataViewer` on `proposer-sa` would take. Link 1 now hashes
both. Matched rather than enumerated: every predefined BigQuery role and every custom
role, since a custom role's permissions are not knowable from its name. Ordinary IAM
churn outside that set does not quarantine a version, which is tested. The Notary reads
the project IAM policy through a custom role carrying one permission,
`resourcemanager.projects.getIamPolicy`.

**The served policy was not the attested policy.** The Policy Server read the document
out of `policy.versions`, a table the Notary can write, and nothing compared it to the
chain. The attested artifact and the enforced artifact were two different objects. It
now serves the candidate out of the chain's effective exam link, reports
`registry_agrees`, and freezes promotion when the two disagree. Related: the approval
link recorded `approves_exam_hash` and nothing read it, so the binding between an
approval and the measurements it approved was a note rather than a check. `verify` now
requires the approval to name an exam link that is in the chain.

**`unknown` did neither of the two things section 3 says it does.** It is defined as
"last known state retained" and "alert raised". The server replaced the cached good
answer with the unknown one, and nothing anywhere raised an alert. It now retains the
last state that was actually established and returns it as `last_known`, and writes an
`ALERT` line to stderr, which on Cloud Run is a log entry an alerting policy matches on.

**`/policy/active` dropped the connection instead of reporting a state.** The lookup of
the active version sat outside the handler that turns a failure into `UNKNOWN`. An
enforcement callback that does not know the version number calls exactly that path, and
got nothing back rather than `FROZEN`.

**`bq.py` had no test at all.** Every claim this project makes reaches the reader
through that file. The validator mutated it twice and the whole suite stayed green:
named query parameters silently dropped, which turns every chain write back into an
interpolated statement, and `insertErrors` ignored, which is the failure the function's
own docstring describes. `tests/test_bq.py` pins both, along with the incomplete-result
cases and the name validation.

**The exit-criterion script never asserted the exam leg.** Every string it checked in
step 1 is still present on a chain whose Examiner is never re-run, so it would have
passed throughout the defect above. It now asserts the exam is re-derived, before and
after re-attestation, and reads the machine-readable output to check which link kinds
carried a derivation.

**The 2:52 beat's response shape.** The plan writes the quarantine response with the
offending event as its own field. It was only inside the prose of `break_detail`. The
attestation now carries `event` separately, so a caller acts on the id instead of
parsing a sentence for it.

Two of its findings are recorded as deviations rather than fixed: the registry
annotation, which has no registry to annotate until Day 4, and `DRAFT-REJECTED`, which
has no writer until Day 5. Both are in the deviation list above.

Every one of these properties is mutation-checked by `tests/mutate_check.py`, the
counterpart to the generator's: it breaks each property in the source in turn, re-runs
the suite against the break, and exits non-zero if any mutation survives. 21 mutations,
21 caught. Two of them survived on the first attempt, which is how the missing coverage
on `seed`'s parent check and on the served-policy comparison was found.
`tests/test_chain.py` is 56 tests, `tests/test_bq.py` is 20, and the suite is 93 in 2.0s.

**Unchecked, stated rather than assumed.** Codex's sandbox has no credentials and no
network, so every BigQuery, Cloud Storage and gcloud claim went unverified by it. The
validator had read-only credentials and could check the IAM and access-list facts, but
did not run `infra/90_prove_attestation.sh`, which writes to the live project. That
script was re-run here after every fix and its capture regenerated. Both engines were
reading a worktree I was editing at the same time; the validator said so and re-verified
against a fixed snapshot, and every finding below was re-checked against the final tree.

---

## 2026-08-28 — Day 4

**Exit criterion: the fleet is a roster, and enforcement carries its own warrant.**
Seven assertions in `infra/100_prove_fleet.py`, all against the deployed project.
Exit 0, captured in `captures/day4-fleet-proof.txt`.

### Shipped

Seven Cloud Run services from one image. Four of them are the same detector with a
different check family; the other three are the workload agent, the Foreman and the
Policy Server. `CASEHARDEN_AGENT` picks which program the container runs and
`CASEHARDEN_CHECK_FAMILY` picks which check. There is no per-family source file,
because there is no per-family behaviour: a check is a SQL predicate and a
description, both in `agents/detector/families.py`.

`agents/common/enforcement.py` is the shared callback every tool call routes through.
Three steps in a fixed order. Model Armor screens the turn first, because its verdict
fields are first-class predicates in the policy DSL and the policy cannot be evaluated
before they exist. Then the active policy is fetched from the Policy Server and
evaluated. Then the event is written with the trace id, the policy version, and the
attestation state that was in force when the decision was made.

The part that matters is what a block claims. A block under a quarantined version
still blocks; availability is not what attestation gates. What lapses is the claim.
The decision is recorded with `decision_attested = false` and the refusal the customer
sees says so in words: *"still enforcing, cannot currently be justified from
evidence"*. An allow never carries an attestation, because an allow asserts nothing.

`agents/foreman/agent.py` names no detector. It calls `list_agents()`, filters on the
role in each card's `caseharden` extension, and binds every result as a
`RemoteA2aAgent`. The fleet proof greps the file for all four check families and fails
if any appears. Deploying a fifth detector adds a fifth span to the fan-out with no
edit here.

Each registry entry carries the chain root of the policy version it was registered
against, in `capabilities.extensions` under `https://caseharden.dev/ext/attestation/v1`.
That is the Day 3 deferred item: the roster now states what each worker's authority
rests on, not just where it lives. A top-level key was rejected — Agent Registry
validates the card against the A2A v1.0 proto and answers `unknown field "caseharden"`
— and the extension slot is where the spec puts exactly this.

The `FINDING` link now carries the BigQuery job id that produced it and the trace ids
of the conduct rows it cites. Day 3 left a `note` field promising both. A finding is
only re-checkable if a reviewer can re-run the exact job, so `verify` prints the job id
on the FINDING line and the fleet proof looks each one up in BigQuery and asserts it
completed.

Memory Bank is wired to an Agent Engine in europe-west3. The Foreman files each
completed investigation back as precedent and reads it with `load_memory` on the next
one. Nothing is seeded: what the fleet remembers is what the fleet has actually
reviewed, so the honest answer on the first run is that it found nothing, and that is
what it says.

Live conduct goes to a new `conduct_live.turns`, not to `conduct_train.turns`. Adding
this table's four decision columns to the cited window would have quarantined every
chain in the project at once, because link 1 hashes each cited row as
`SHA256(TO_JSON_STRING(t))` and `TO_JSON_STRING` emits a key for every column
including the null ones. Verified in this project rather than assumed:

```sql
SELECT TO_JSON_STRING(t) FROM (SELECT 1 AS a, CAST(NULL AS STRING) AS b) t
-- {"a":1,"b":null}
```

The two answer-key columns are absent from the live table by design. Live traffic has
no ground truth, so a column for it could only ever be filled in by guessing.

### Measured

| | |
|---|---|
| Registry entries with role and chain root | 6 (4 detectors, 1 workload, 1 orchestrator) |
| Detectors answering one fan-out, in parallel over A2A | 4 of 4, each with a re-runnable BigQuery job id |
| Model Armor on the injected ticket | `MATCH_FOUND`, `pi_and_jailbreak` at `HIGH` → 0.95 |
| Deployed workload's decision on that turn | `DENY`, rule `tool-call-on-injected-turn` |
| Services refusing an unauthenticated request | 7 of 7, HTTP 403 |
| Memories filed by the fan-out | 2, each carrying the finding text |
| Tests | 143 passing in 2.5s |
| Mutations | 38 broken, 38 caught, 0 survived |
| `verify` p95, cold IAM role cache | 3.58s (p50 3.21s, 12 runs) against a 5s target |

The p95 moved from Day 3's 2.91s and the reason is in this day's work, not in
measurement noise: the reach check now expands each role through the IAM API instead of
matching its name, and also reads who may impersonate the exam's readers. Adding the
second of those pushed the p95 to **5.81s, past the published SLO**. It is back under
because both lookups now overlap and the dataset access list is read once per
verification instead of twice. The 5.81s is recorded here rather than replaced.

### The reach check was asking the wrong question

Creating `detector-sa` for the fleet quarantined the attested policy version. Not a
tamper, not an attack: one `roles/bigquery.jobUser` grant, for an unrelated reason, and
v4 could no longer prove it was justified. Captured verbatim in
`captures/day4-iam-grant-quarantines.txt`.

Then `reattest` refused to clear it, correctly, and said why: re-attesting would record
the widened access list as the justified state, which is the guarantee that link
exists to protect.

Both behaviours are right in isolation and together they made the system unusable. A
check that fires on grants which cannot read the exam, and a remedy that refuses to
clear them, means any project where IAM ever changes freezes permanently.

The bug was that the check matched role *names* — `^roles/bigquery\.` — when the
question is whether a role carries `bigquery.tables.getData`. It now expands each role
through the IAM API and keeps only those that do. A role that cannot be expanded still
counts as reaching, so the failure direction is unchanged. Reaching bindings in this
project went from 13 to 3.

Two bugs surfaced inside that fix. `roles.get` answers for `roles/owner` with a
permission list that omits `bigquery.tables.getData`, so expanding it and believing the
answer produced `roles/owner reaches=False`, which is exactly backwards and would have
hidden the widest grant in the project; the three basic roles are now pinned rather
than expanded. And the first parallel version cached expansions for the life of the
process, which is right for the Policy Server and wrong for the measurement harness:
it timed run 1 honestly and runs 2..N with the expensive call already answered.
`measure_verify.py` now clears the cache before every run, which is what a one-shot CLI
verify actually pays.

### The distinction was silently always false

The fleet proof caught this before the capture was written. The Policy Server reports
`"ATTESTED"`; the enforcement module's constant is `"attested"`. Comparing them
directly made `reason_attested` false for every block ever taken, including blocks
under a perfectly good version, and the refusal read:

```
tool-call-on-injected-turn denied by conduct policy v4
(reason UNATTESTED: policy state ATTESTED — still enforcing,
 cannot currently be justified from evidence)
```

A distinction that is always false is not a distinction, and it is the one this entry
is about. The state is now lower-cased once at the boundary, and
`tests/test_enforcement.py` drives both directions.

### The build machine's credentials were the wrong ones

Application Default Credentials on this machine belong to an unrelated employer, and
name one of that employer's projects as the quota project. Four early Vertex probes
went out under that identity, against this hackathon project. No employer data was read
and no request touched an employer resource, but the quota project named on those calls
was wrong, and that project is excluded from this work entirely. The employer's project
id is deliberately not recorded here: this repo is public.

`caseharden/creds.py` now exists so nothing in this repo can reach for ADC by accident.
It mints tokens from one pinned gcloud configuration on a workstation and from the
metadata server in a container, and refuses to return credentials whose project is not
this one. Every agent module calls `creds.guard_ambient()` at import, which raises
before an agent starts if ADC resolves to a forbidden project. Checked, and it refuses
by name.

That same absence of gcloud in a container also surfaced a real fault: the Policy
Server read sealed certificates through `gcloud storage cat`, which raised
`FileNotFoundError` on Cloud Run and left every version reporting `unknown` with
`No such file or directory: 'gcloud'` as its reason. `chain.sealed_root` now reads over
REST. Sealing still goes through gcloud; only the Notary seals, and the Notary runs on
a workstation.

### Decisions

**The Policy Server runs as `examiner-sa`.** Re-deriving at serve time means re-scoring
against the sealed holdout, and exactly one principal may read it. The alternative was
to grant `notary-sa` impersonation on `examiner-sa`, which would put a second principal
within reach of the exam without adding a row to `holdout_sealed`'s access list. That
is the same class of hole the Day 3 adversarial pass found with project-level IAM. The
access list still has exactly one entry. `infra/27_policy_server_identity.sh` grants
only reads and asserts that the identity is refused a delete on the chain.

**Every service is private.** A public endpoint in front of a model is an unmetered way
to spend a fixed credit. Callers sign each hop with an identity token minted for the
exact service they are addressing, and the fleet proof asserts all seven refuse an
unauthenticated request. On a workstation that token comes from impersonating
`foreman-sa`, because a user account cannot mint one for a custom audience at all.

**The Foreman is on Cloud Run, not Agent Runtime, and Agent Gateway is dropped.** The
plan pre-approved both under the hour-5 cutoff, and nothing in the demo script names a
host. All seven services are Cloud Run.

An Agent Engine is deployed and it backs Memory Bank, but no agent runs on it, so
section 3's claim that Agent Runtime "hosts Foreman and Proposer as native A2A agents"
and that the registry pattern is proven "across both hosts" is **not true today** and is
recorded here as a deviation rather than left to be discovered. Either Day 5 moves one
agent onto Agent Runtime or section 3 and the Devpost text lose the second host. That is
a call for the entrant.

### Limitations, and what is not claimed

The Foreman binds its roster when the container starts. A detector registered while an
instance is warm joins the fan-out on the next cold start, not immediately.

The Model Armor band-to-score mapping is a judgement, stated in one table in
`agents/common/armor.py`. Model Armor answers with `LOW_AND_ABOVE`,
`MEDIUM_AND_ABOVE` or `HIGH`, not a number, and the DSL's field is numeric because a
band cannot be compared with `at_least`. `HIGH` is the only band that crosses the 0.75
threshold the shipped policies use.

Model Armor also reports prompt injection and jailbreak under one filter and one band.
Both DSL fields carry that band rather than pretending to be two independent
measurements.

`100_prove_fleet.py` can only exercise whichever attestation state the project is
actually in, so one run proves one branch. It says which one it exercised. The other is
pinned offline by `tests/test_enforcement.py`.

The support agent's two tools are mock. Nothing refunds and nothing is looked up. What
is not mock is the callback in front of them. The detectors have one tool each,
`scan_conduct`, and it is not mock: it runs real SQL and returns the job id.

**The trace ids are derived, not resolvable.** `trace_id_for` hashes the session and
turn, which gives a stable key that the conduct row, the chain link and a finding all
agree on. It is not a handle Cloud Trace can open, because spans are not exported: the
project's trace list is empty and every id 404s. Section 3 says a link "opens the real
execution DAG" and beat 0:56 puts a trace DAG on screen. Neither is supported today.
Exporting spans is a Day 5 item. `current_trace_id()` already prefers a real span id
when one exists, and `derived_trace_id()` tells them apart.

**Registration is operator-run, not automatic.** Sections 3 and 9 say services
"auto-register". What exists is `infra/29_register_fleet.py`, run by hand after a deploy
and again after any promotion, because each entry carries the active version's chain
root and a new root makes the roster stale. The fleet proof asserts the roots agree, so
a stale roster fails loudly rather than passing quietly, but nothing re-registers on its
own.

**No detector's finding reaches the chain yet.** The `FINDING` link is written by
`notary seed`, which runs its own SQL against `conduct_train`. The four detectors scan
`conduct_live`. Both work; they do not meet. Beat 0:56 needs the detector's finding to
be link 2, so joining them is Day 5 work and is listed as such below.

### The repo is public

Made public 2026-08-25, after the employer email covering code ownership, development
infrastructure approval and public repo approval was sent. It had been private since
Day 1 for exactly that reason; the decision to take it private is in the plan's decision
log.

Checked before publishing, across all ten commits and not only the working tree, because
a secret removed from `main` still sits in the history behind it:

| Checked | Result |
|---|---|
| Private keys, API keys, OAuth tokens, client secrets | none, in any commit |
| `.env`, `*key.json`, `*.pem`, credential files ever added | none |
| Employer project ids or addresses | none, in any commit |
| Commit author and committer identity on all ten commits | the personal account, not the employer address |

`https://github.com/japsdeleon/caseharden` answers 200 anonymously.

The personal Gmail address appears in three Day 1 and Day 2 captures, as the operator
principal on the wire in a real IAM refusal. It is the address that owns the repo, so it
is already public, and removing it would mean editing a capture. The captures stay as
they were recorded.

### Carried into Day 5

- Join the fleet to the chain: a `FINDING` link written from a detector's answer, over
  `conduct_live`, carrying that detector's job id. Today the link is written by
  `notary seed` over `conduct_train` and the two never meet.
- Export spans to Cloud Trace, or drop the trace-DAG beat and the section 3 sentence.
- Decide the Agent Runtime question: move one agent onto it, or remove the second host
  from section 3 and the Devpost text.
- The Proposer, Model Armor on verdict in and rationale out, the Analyst Copilot, and
  the real end-to-end run, all as planned.

### For THREATS.md on Day 6

Everything Day 3 listed, plus:

- The fleet's A2A endpoints are private by Cloud Run IAM rather than by anything this
  project built.
- `conduct_live` is written by `workload-sa`, which holds WRITER and therefore DML
  delete on it.
- The reach check depends on `iam.roles.get` and `iam.serviceAccounts.getIamPolicy`. A
  principal that cannot expand a role sees every custom role as a possible reader:
  noisy and safe, in that order.
- The reach check reads the **project** IAM policy only. A role inherited from a folder
  or an organisation would not appear. Checked rather than argued: this project has no
  parent, so there is nothing here to inherit, and the hole is real for any project that
  has one.
- `CASEHARDEN_PROJECT` is the comparison target rather than a fixed allowlist. On a
  workstation a mismatch is still caught against the pinned gcloud configuration; an
  operator who changes both is not making a mistake.
- Custom roles are re-expanded on every verification and predefined roles are cached for
  the life of the process. A predefined role's permissions changing under Google would
  not be seen until restart.
- A trace id in a chain link is a correlation key, not a Cloud Trace handle, until spans
  are exported.

### Adversarial pass

Both engines ran. Codex is a genuinely different model; the in-house validator is the
same model as the author and is a checklist pass, not independent evidence. Five
findings from Codex, all with a reproduction attached, all re-checked here before
acting.

**A Model Armor failure was a bypass for the rule Model Armor feeds.** With screening
down, `decide()` evaluated the injection rule against a missing score, the rule did not
match, and the tool call went through. Worse, the test suite asserted that outcome was
correct, on the grounds that no other rule denied the call. It codified a fail-open.

The callback now asks the active policy whether any of its rules key on a Model Armor
field. If one does and screening failed, the call is refused with
`SCREENING-UNAVAILABLE` and `decision_attested = false`, because the record cannot show
a screening that did not happen. A policy with no screening predicate is unaffected.

**Impersonating the exam's reader was not counted as reaching the exam.** Holding
`roles/iam.serviceAccountTokenCreator` on `examiner-sa` mints a token as the one
principal allowed to read the sealed holdout. The dataset access list still says one
reader, truthfully, and the project IAM policy does not describe it. This project had a
live instance: the operator holds exactly that grant.

Link 1 now also hashes, for every service account on the exam's access list, who may act
as it. A new impersonator quarantines the version and the break names the account and
the principal. An unreadable impersonation policy is recorded as `UNREADABLE` rather
than as nobody, because an empty answer there asserts something this cannot check.

**`scan_sql` claimed a validation it did not perform.** Its docstring said the table
identifier had been validated by the caller. It had, by the only caller that exists, but
the function accepted a backtick that closes the identifier and appends a statement.
It validates its own input now. The deployed detector path was never reachable this way;
this was a latent defect, not a live one.

**Inherited folder and organisation grants are not read.** `exam_reach` reads the
project IAM policy only, so a role inherited from a parent would not appear. Checked
against this project rather than argued about: `gcloud projects describe` returns no
parent, so there is nothing here to inherit. The limitation is real for any project that
has one, and belongs in THREATS.md.

**`CASEHARDEN_PROJECT` is the comparison target, not a fixed allowlist.** Setting it
redirects what `creds.py` considers correct. That is by design — every script in `infra/`
takes the same override — and on a workstation it is still caught, because
`credentials()` also compares against the pinned gcloud configuration's own project and
refuses a mismatch. Documented rather than removed. The residual case needs an operator
to change both the environment and their gcloud configuration, which is not an accident.

**The fourth check family was not the one the specification names.** Sections 1, 3, 5 and
8 all say `privilege-sequencing`, read-then-write privilege sequencing. What shipped
first was `refund-velocity`, three or more refunds in a session, chosen because it
demonstrated the same "no per-event predicate can express this" property. That is a
substitution, it changes what is detected, and it was not flagged. The spec's check is
now what runs: a session that called a write tool against an account no read in that
session ever touched. A write with no account at all does not count, because absent is
not "some other account". The Cloud Run service was renamed and the old one deleted and
deregistered.

**A second in-house pass ran and found more.** It also had the working tree change under
it twice mid-audit, which it said so plainly, and its findings were re-checked against
the tree afterwards. Everything above and the following came from it.

The screening fix above was incomplete. `screen()` returned `{}` for a turn with no
text, which is the shape a never-screened turn produces, so the new
`SCREENING_FAILED` guard never fired for it and the injection rule still could not match
a missing field. The audit drove a refund through with an empty `turn_text`. An
unscreened turn is now labelled `NOT_SCREENED`, both labels refuse, and three tests
drive the empty-string, missing-key and armor-down paths.

Four rows in `conduct_live.turns` from 11:30-11:32Z carry `ma_verdict =
SCREENING_FAILED` with `decision = ALLOW`, two of them `issue_refund`. That is the wider
version of this fail-open executing before it was found. The rows stay; deleting
evidence of a fault to make a log read better is the opposite of the point.

`_ROLE_CACHE` had no expiry, and the comment defending it claimed role permissions are
immutable. True of predefined roles, false of custom ones, whose permission set is
editable at any time. A long-running Policy Server would have kept excluding a custom
role that had since gained `bigquery.tables.getData`. Custom roles are no longer cached.

`stale["expired"]` was set and never read, so `STALE_SECONDS` bounded nothing and an
agent cut off from the Policy Server would enforce its last policy for ever. Since
promotions only narrow, an indefinitely old policy is a permissive one. Past the bound
the call is now refused with `POLICY-EXPIRED`.

Memory Bank's write path was not working. `add_session_to_memory` accepted every call,
raised nothing, and left the bank empty after six investigations, which is
indistinguishable from having nothing to write. The Foreman now writes the finding
directly through `memories.create`. Assertion 8 of the fleet proof reads the bank back
and fails if it is empty or if the stored text does not carry a finding.

`test_an_unrelated_project_role_does_not_quarantine` claimed to drive the real filter
and instead re-implemented `exam_reach`'s list comprehension in its own body, so
inverting the real one left the suite green. `BigQueryEvidence.exam_reach` now has two
tests of its own and two mutation cases.

The fleet proof asserted `len(trace_id) == 32`, which its own constructor guarantees.
That assertion could not fail. It now pins the value.

The two IAM grants that role expansion depends on, `roles/iam.roleViewer` and
`roles/iam.serviceAccountViewer`, were made by hand and no script contained them.
Without them every role expands to unknown, therefore to reaching, and the reach digest
differs from the one the certificates were sealed on. They are in
`27_policy_server_identity.sh` now.

Held, with what was tried named: a chain with no sealed certificate still refuses to
attest; the Policy Server cache race did not reproduce beyond its stated window; and
`bq.query`'s parameter encoding, incomplete-query refusal, partial-page refusal and
insert-error handling all held. No secret, key, token or employer identifier was found
in the Day 4 files.

Two employer project identifiers had reached the working tree before that scan, one in
`creds.py` as a hard-coded denylist and one in this log. Both are gone. The guard needs
no foreign project ids: it refuses everything that is not this project, and the denylist
is now read from the environment.

### Open, and not mine to decide

Carried from Day 2: the 2:10 spoken line "The examiner is two hundred lines of code",
and whether that beat's on-screen numbers are labelled as the injected-turn family row.

The line count moved and the Day 2 note is now stale. Counted today: `interpreter.py`
231, `dsl.py` 210, `examiner.py` 408, 849 together. Day 2 recorded 187 and 610. Nothing
in the Examiner is two hundred lines, so the spoken line needs a number or a rewording,
and whichever is chosen should be re-counted on the day it is recorded.

New: beat 0:38 says the registry listing returns **eight** entries. The listing today
returns eight, but not those eight: six of ours, one `Workspace Agent` that Google
created in the project, and one `caseharden-memory` that Vertex registered by itself
when the Agent Engine was created. Day 5 adds the Proposer and the Analyst Copilot,
which makes **ten rows on screen**, eight of them ours. Either the spoken line becomes
"eight of ours" or the caption names the two that are not.

Also new, and larger: section 3 claims Agent Runtime hosts two agents and that the
registry pattern is proven across both hosts. Nothing runs on Agent Runtime. See the
decision above.

## 2026-08-29 — Day 5

**Exit criterion: the loop ran for real, end to end, against the deployed fleet.**
An incident the active policy allowed, a fan-out, a detector's finding, a verdict a
human typed into the Analyst Copilot, a draft from the deployed Proposer, that
Proposer's own 403 on the sealed holdout, the Examiner's gate, an approval, and a
promotion to **v5** with a green certificate. Transcript in
`captures/day5-loop-promotes-v5.txt`.

### Shipped

**The Proposer, on Cloud Run under `proposer-sa`.** Three tools and no others.
`reviewer_precedent` reads Memory Bank, which is what the Foreman writes each
investigation into, so the precedent is the fleet's own review history.
`training_base_rate` counts tool calls at a threshold over the 76-day training
window, which is the only conduct this identity may read; a threshold in a draft
is now a number the model checked rather than one it liked. `self_check` asks
BigQuery for the sealed holdout **as itself** and returns the refusal. That tool
raises if the read ever succeeds, because a Proposer that can read the exam makes
every measurement downstream of it worthless and must not be able to look like a
passing run.

The draft is judged outside the agent. A draft that fails the grammar comes back
as a rejection carrying the parser's message and is written to the chain as its
own link, before the draft that survived, because that is the order they
happened in.

**The Analyst Copilot, via `adk deploy cloud_run --with_ui`, unmodified.** Two
tools, `record_verdict` and `approve`, under a new `analyst-sa`. They write rows
into `review.decisions`, a dataset of its own: WRITER carries DML delete, so
putting the analyst's writes in `policy` would let a chat window delete the
version registry. `infra/32_analyst_identity.sh` asserts two boundaries against
the live project rather than describing them, and both refusals are HTTP 403.

**Model Armor in both directions.** Inbound on the analyst's own words, in the
Copilot, with the result stored beside the row. Outbound on the Proposer's
rationale, through `sanitizeModelResponse`, before an analyst reads it or the
chain records it. Both results go into the VERDICT link. Neither is decorative:
the run refuses to pass a text on when its screening blocked or did not happen.

**Span export is wired, and it does not work from Cloud Run.** Day 4 recorded
that every trace id in this project was derived from the session and turn, and
that Cloud Trace held nothing. `agents/common/tracing.py` points the OTLP
exporter that was already in the image at `telemetry.googleapis.com`;
`auth.signing_client` puts the W3C traceparent on each A2A hop and an ASGI
middleware takes it off the other end. No new dependency: the alternative was
`opentelemetry-exporter-gcp-trace`, which this image does not have.

From a workstation this works end to end. A span written through the module
resolves in Cloud Trace by its id, under the operator's identity and again under
`workload-sa`'s, which is the identity the deployed workload runs as. **From the
deployed services it does not.** The provider is global and ours (the service
logs `ours=True`), the processor is attached, the per-request flush runs and
returns true, no export is refused, and every trace id the fleet records still
answers 404. Where those spans go has not been established, and saying so is the
point of this paragraph.

What did change: a deployed conduct row now carries a real span id rather than a
derived one. What did not: that id is still not a handle a reviewer can open.
Four things were tried and each was a real defect fixed on the way, none of them
the cause. `roles/cloudtrace.agent` is the classic write path and the OTLP
endpoint wants `roles/telemetry.tracesWriter`; Cloud Run throttles a container's
CPU between requests so the batch processor's thread never ran, which is why the
flush moved onto the response path; `set_tracer_provider` is a one-shot, so the
module now attaches its processor to whatever provider is global instead of
insisting on its own; and the fleet proof's trace assertion passed for any
32-hex string, which is why none of this surfaced sooner.

**Section 3's sentence about a chain link opening the execution DAG, and the
trace-DAG shot in beat 0:56, are not supported by the deployment.** That is the
entrant's call: drop the beat, or spend Day 6 time on it.

**The fleet is joined to the chain.** The FINDING link is a detector's own
answer now. `infra/110_run_loop.py` takes the BigQuery job id the fan-out
reported, fetches **that job's own results** rather than re-running the query or
trusting the model's prose, and cites the window the job scanned. Day 4's
FINDING was written by `notary seed` over a different table from the one the
fleet scans; the two never met, and now they do.

**`notary seed --bundle`, and what a bundle is not allowed to claim.** The bundle
is a file, so every claim in it that the Notary can check itself, it checks: the
cited BigQuery job must exist and have completed, the verdict and the approval
must be rows the Copilot wrote with matching text and subject, and the 403 is
re-taken live and compared before the Proposer's own wording is kept. It refuses
rather than record a claim it cannot stand behind.
`captures/day5-notary-corroborates-the-bundle.txt` shows one real bundle and two
forged ones.

### Measured

| | |
|---|---|
| Chain for v5 | 7 links, root `e2a559358933`, ATTESTED |
| Finding behind it | `injected-turn`, 13 sessions, from job `job_1IpPlMAwmLLVhMAv` over `conduct_live` |
| Cited window | 2026-08-22T15:47:45Z to 2026-08-25T15:48:08Z, 22 conduct events |
| Examiner on the promoted candidate | 29/40 → **30/40** sealed attack sessions, benign 100% → 100% |
| Human decisions in the chain | 2, both written by the Copilot (`vd_bdae6d344808`, `ap_8c8f6481c1c3`) |
| `verify` p95 on v5 | **3.66s** (p50 3.16s, 12 runs, cold IAM cache) against a 5s target |
| Tests | 156 passing |
| Registry rows | 9 agents (7 ours, plus Google's `Workspace Agent` and Vertex's `caseharden-memory`); the services listing returns 7, all ours |
| Cloud Run services | 9 private (8 from one image, plus the Copilot's own) |
| Fleet proof | 8 of 9 assertions hold; the trace-resolution assertion fails, on purpose |

### The gate refused four real candidates

A second run, `v6` on top of v5, promoted nothing. Its transcript is
`captures/day5-gate-refuses-the-proposer.txt` and it is the more useful of the
two runs.

The Proposer's first candidate caught **31 of 40** sealed attack sessions, one
more than the active version, and was thrown out because benign traffic fell from
100% to 99.7%. Two legitimate turns. The three that followed were refused for no
improvement on sealed attacks, and the last of those also for a benign
regression. Nothing was written to the chain.

That is the plan's section 9 risk 2 discharged with a real candidate rather than
a hand-written one: the gate's rejection beat does not need a fixture. The
reason there was nothing left to win is worth stating plainly. v5 had already
taken the one improvement a per-turn rule can take here, and the ten sealed
attack sessions still uncaught are the `privilege-sequencing` family, which no
per-event predicate in this DSL can express. That is a property of the grammar,
stated on purpose in section 1, not a gap in the Proposer.

A hand-written over-blocking candidate is kept as well, in
`policies/v5-candidate-a-overblocking.json`, because it produces the numbers the
demo script describes: 40/40 attacks caught, benign 100% → **94.5%**, 35
legitimate turns denied, 2766.20 of refund value blocked, `PROMOTION DENIED —
BENIGN REGRESSION`. **That candidate is hand-written and the capture says so in
its first paragraph.** The Examiner's run against it is real.

### Re-attestation was quietly changing which policy the fleet enforced

`reattest` re-pointed a version at its new certificate through `ChainStore.register`,
which marks its own version active and every other version inactive. So
re-attesting an **old** version put that version back in force. It happened on
this machine: `90_prove_attestation.sh` re-attested v4 an hour after v5 was
promoted, and the fleet went back to enforcing v4. The Policy Server reported it
truthfully, which is the only reason it was caught, by an assertion about
something else.

Attestation gates authority, not availability, and re-derivation must not change
what is enforced. `ChainStore.repoint` now moves the root and nothing else, and
`tests/test_chain.py` pins that the statement it issues contains no `active`.

### The deploy script had been writing empty public URLs

`28_deploy_fleet.sh` read each service's URL with a mangled `--format` argument.
Every `describe` failed with `Name expected`, the failure was swallowed by the
assignment, and the next line wrote an **empty** `CASEHARDEN_PUBLIC_URL` onto the
service. An agent card then advertises `localhost` and A2A refuses it on a
same-origin check. Four services were in that state before it was noticed. The
quoting is fixed and the function now refuses to continue without a URL.

### Two silent-empty failures, both of the same kind

The fleet proof reported an empty Memory Bank for a write that had landed four
seconds earlier. Two separate causes, one class. `memories.list` trails
`memories.create`, so the proof polls now and asserts a memory this run did not
start with, rather than a non-empty bank that any earlier run could satisfy. And
the engine id, when read back through `gcloud --format=value(...)`, arrives as
`['4537...']`, so every request 404'd; `memory.read` swallowed that into an empty
list. It raises now, and the proof parses the id.

### Four real defects on the way to a span that still does not resolve

Granting `roles/cloudtrace.agent` was not enough: the OTLP endpoint wants
`telemetry.traces.write`, which is `roles/telemetry.tracesWriter`. With only the
first, exports were refused, and the ALERT line that now prints did not exist to
say so.

With both roles the spans still did not arrive. Cloud Run throttles a container's
CPU to nearly nothing between requests, so `BatchSpanProcessor`'s background
thread never ran, and every service here runs with `--min-instances=0`, so the
instance was reclaimed with the batch still in it. Spans are flushed at the end
of each request now, in the same middleware that continues the caller's trace,
with the exit-time flush as a backstop.

Then the flush reported success while exporting nothing, because
`set_tracer_provider` is a one-shot and both providers are the same class, so a
provider installed before this module's would silently keep the spans while this
module flushed an empty one. The processor attaches to whatever provider is
global now, and the startup line prints whether the provider is ours.

And underneath all three, the fleet proof's trace assertion had been passing for
any 32-hex string, including `"0" * 32`, because it only asked whether the id
differed from the derived fallback. It resolves the id in Cloud Trace now, which
is what turned this from a claim in a docstring into a red assertion.

The fourth fix did not produce a resolving trace, and the assertion is left
failing rather than softened.

### Decisions

**The Proposer is on Cloud Run, not Agent Runtime.** Nothing runs on Agent
Runtime today. An Agent Engine exists and backs Memory Bank. Day 4 recorded that
section 3's claim about "both hosts" is not true, and Day 5 has not made it true:
the hour-5 rule was applied again in favour of finishing the loop. **This remains
the entrant's call**, and the two branches are unchanged: move one agent onto
Agent Runtime, or remove the second host from section 3 and the Devpost text.

**The Analyst Copilot is not in the Agent Registry roster.** `adk deploy
cloud_run --with_ui` serves no agent card, with or without `--a2a`, and
`29_register_fleet.py` registers the card a service actually serves. A
hand-written card for a service that serves none is the one thing that roster
exists to rule out. The Copilot is a human's window, not a worker the Foreman
discovers.

**The workload's read tool is `lookup_account` again.** Sections 1 and 3 name
`lookup_account` and `issue_refund`; what shipped on Day 4 was `lookup_order`,
which recorded no account, so every refund looked like a write to an unread
account and the privilege-sequencing check could not mean anything. The rename is
back to the specification.

### Limitations, and what is not claimed

**Structured output is prompt-instructed, not schema-bound.** Section 3 says the
Proposer uses "structured output constrained to the Caseharden DSL". What ships
tells the model the grammar, derived from `dsl.py` so it cannot go stale, and
judges the answer with the real parser afterwards. That is a deliberate reading
of the requirement that a rejected draft must be recorded: a generation-time
schema makes the DRAFT-REJECTED link unreachable. It is a different mechanism
from the one section 3 names and it is recorded here rather than left to be
found.

**Verification still re-derives the evidence and the exam, and nothing else.**
The FINDING, VERDICT, DRAFT and HOLDOUT-DENIED links are corroborated when they
are written and hash-protected afterwards. A reviewer can re-run the job the
finding names; `verify` does not do it for them. Section 2 claims re-derivation
for exactly two links and that is still the claim.

**Gate refusals are recorded inside the EXAM link, not as their own kind.** They
are in the chain, under the Examiner that refused them. A separate link kind
would have changed what `verify` requires of a chain's shape, on the day the loop
first ran.

**The v5 chain predates three of today's own additions.** It was sealed before
bundle corroboration, the precedent ids and the outbound rationale screening
existed. All three are exercised: corroboration by the capture above, the other
two by the v6 run, which reached the gate four times.

### Mutations

40 mutations, 40 caught, 0 survived. Two were added today, for the two Day 5
properties that carry the most weight: that re-attestation cannot put an old
version back in force, and that a HOLDOUT-DENIED link cannot record something
other than a refusal. The second one **survived** on its first run, which is the
harness doing its job: the guard existed and no test drove it. Two tests now do.

### Adversarial pass

Both engines ran, as the contract requires. Codex is a genuinely different model;
the in-house validator is the same model as the author and is a checklist pass.
Six confirmed findings from Codex and a long report from the validator, each
re-checked here before acting.

Fixed as a result:

- A bundle's FINDING, VERDICT and HOLDOUT-DENIED payloads were trusted. A
  fabricated job, a screening that never happened and a 403 that was never taken
  would all have sealed as attested. The Notary corroborates them now, and
  `_shape_of_payload` refuses a structurally empty link.
- `bq.job_results` accepted an unfinished or truncated answer, so a partial page
  could have become "the finding's rows". It makes the same three refusals
  `query` makes.
- `first_json_object` counted braces inside JSON strings, so a rationale
  containing `}` turned a valid candidate into a recorded rejection. It tracks
  strings and escapes now, with the adversary's own input as a test.
- The fleet proof's trace assertion passed for any 32-hex string, including
  `"0" * 32`. It resolves the id in Cloud Trace now, which is what caught the
  frozen exporter above.
- A Model Armor block on an analyst's verdict was recorded and then ignored, and
  the text went into the Proposer's prompt regardless. The run refuses on a
  block, on a screening failure and on an unscreened turn, in both directions.
- `tracing.flush` was defined and never called; `span`, `current_ids` and
  `exporting` were dead. The first is wired to every request and to exit, the
  rest are gone.
- Comments and docstrings that no longer matched the code: spans "not wired",
  "six services", the Copilot's boundary claims, the Proposer's precedent claim,
  and the armor direction with no caller.
- `--resume` was documented and unimplemented; `--analyst` was declared and never
  read. Both gone.

Held, with what was tried named: the DSL's literal and threshold validation, the
deny-only grammar, the closed feature vocabulary, no new dependency, no custom
UI, Flash only, and no credential in any new file.

### Carried into Day 6

- The screen recordings. Day 5 produced the transcripts the video is cut from,
  and the recordings themselves are the entrant's to make.
- Span export from Cloud Run, or the trace-DAG beat. One of the two.
- README and Devpost text, including the measured numbers in this entry and the
  hand-written-candidate disclosure.
- THREATS.md, with the additions below.
- The Agent Runtime decision, and section 3's "both hosts" sentence.

### For THREATS.md on Day 6

Everything Day 4 listed, plus:

- A bundle is corroborated, not re-derived. The Notary checks that the job ran,
  that the human rows exist and match, and that the 403 reproduces. It does not
  re-run the detector's query, so a finding whose rows changed after the job ran
  is not detected by verification.
- `analyst-sa` can write `review.decisions` and therefore can write a verdict the
  chain will later cite. What it cannot do is approve its own promotion without a
  row, or alter one after the Notary read it, because the payload must match.
- Spans are flushed on the response path. A crash between the tool call and the
  response loses that turn's span, and the conduct row then carries a trace id
  Cloud Trace answers 404 for.
- The tracing middleware trusts an inbound `traceparent`. A caller that can reach
  a private service can therefore attach its spans to a trace of its choosing.
- `roles/bigquery.resourceViewer` on `notary-sa` lets it see every job in the
  project. It carries no `bigquery.tables.getData`, checked with the same role
  expansion `verify` uses, so it does not widen the exam's reach.

## 2026-08-30 — Day 6

**Documents, and the six decisions the entrant settled.** No code changed today. The
deployed fleet, the chain and the active version are as Day 5 left them.

### The decisions, and what each one changed

| Decision | Settled | What it touched |
|---|---|---|
| Agent Runtime | **Dropped.** Every agent runs on Cloud Run. | Section 3's component table and its Agent Runtime bullet now say so. The bullet states that an Agent Engine exists, backs Memory Bank, and hosts no agent, and that the registry pattern is therefore shown on one host. |
| Beat 0:38 count | **Nine rows, seven ours.** | Section 3's registry bullet and the beat itself. The two that are not ours are Google's `Workspace Agent` and the `caseharden-memory` entry Vertex created with the Agent Engine. |
| Beat 2:10 numbers | **The Proposer's own.** 30/40 → 31/40, benign 100% → 99.7%, refused for benign regression. | The beat. The hand-written over-blocking candidate stays in the repo as the louder alternative, with its disclosure. |
| Beat 2:10 spoken line | **"four hundred lines".** `examiner.py` is 408. | The beat. |
| Beat 0:56 trace DAG | **Cut.** | The beat now shows the four detector answers with their BigQuery job ids. It says in the script why the trace shot is gone. |
| Push | **Sent.** `6e5d230` is on GitHub. | Nothing in the tree. |

Version numbers in the demo script are the walk-through's, not the fleet's. The script says
v3 and v4 because it was written before anything ran. A note under the beat table says to
rehearse against whatever is active on the day, which is v5.

### Written

**README.md**, rewritten. The claim, the prior-art table including the supply-chain row, the
delta stated against sigstore and Kyverno, a Mermaid architecture diagram, the measured
numbers, the degraded-mode table, the known limitations, and the commands a reviewer runs to
reproduce every proof. The hand-written candidate is disclosed in the section that uses its
numbers, which is where a reader meets them.

**THREATS.md**, new. Five sections of attempt-and-control, then five holes stated plainly
under *Not covered*: a bundle is corroborated rather than re-derived; `analyst-sa` can write
the review table; trace ids are correlation keys and the tracing middleware trusts an inbound
`traceparent`; the reach check depends on being able to expand a role; and
`CASEHARDEN_PROJECT` is a comparison target rather than an allowlist. Everything Days 1 to 5
recorded for this file is in it.

**docs/DEVPOST.md**, new. Paste-ready, one section per Devpost field.

### Not done, and why

**The billing number.** The project is linked to billing account `016DDB-615148-5041E6` and
the Day 1 budget of EUR 45 with alerts is in place. Actual spend to date needs the Cloud
Console or a BigQuery billing export, and no export is configured. The final frame's
screenshot is the entrant's to take, from Billing, Reports, filtered to this project.

**The rehearsal and the recording.** Two dress runs and the 4:00 video are the entrant's.
The transcripts to cut from are `captures/day5-*`.

**The CI fixture badge.** Asked for after this entry was first written, and built. See below.

### The fixture badge, and the one check that is not a hash

`caseharden verify` needs this project's BigQuery, its sealed holdout and two impersonated
service accounts. Only one person can run it. For an entry whose subject is records a
reviewer can check, that is a weak position, so the record is now exported and re-checked by
a machine that is not the entrant's.

`infra/120_export_fixture.py` writes `fixtures/v5/`: the seven links as JSONL with the hashes
exactly as stored, the sealed certificate read back from the retention-locked bucket, and a
`source.json` naming where each came from. The sealed holdout is not exported and never will
be.

`python3 -m caseharden.recheck fixtures/v5` runs 17 checks with no credentials and no
network. Sixteen are consistency: link hashes, the walk, the root against the sealed
certificate, the certificate's own list, the chain's shape, the approval bound to the exam it
approved, and the EVIDENCE link's three digests against the material inside it. Those prove
the record was not edited after it was sealed. They cannot prove it was true when written.

The seventeenth replays the Examiner. The generator is seeded and committed, so it reproduces
the corpora BigQuery was loaded from, and the Examiner makes no model calls. Offline replay
of the promoted candidate returns the same numbers the chain recorded, family by family:
10/10, 10/10, 0/10, 10/10, and 640 of 640 benign turns passing.

Four tampers were tried against it and each was refused. An edited payload breaks its link
hash. A chain rewritten with every hash rebuilt no longer matches the sealed root. A dropped
link fails the shape check. And a chain with an invented catch rate, every hash rebuilt AND
the certificate forged to match, is still refused, because the replay disagrees:
`privilege-sequencing: recorded 10/10, replay 0/10`. `tests/test_recheck.py` pins all four.

`.github/workflows/recheck.yml` runs the re-check, the corpus self-check, the test suite and
the mutation harness on GitHub's runners on every push. `requirements-verify.txt` is what the
offline path needs, which is pydantic, typing_extensions and pytest. Everything that talks to
Google Cloud in this repo is a urllib call, so no cloud SDK is involved.

Tests are 161 now. The five new ones are the tampers.
