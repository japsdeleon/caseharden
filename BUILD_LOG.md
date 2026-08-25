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
