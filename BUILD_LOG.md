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
