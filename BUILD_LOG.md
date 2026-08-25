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
| `conduct_train` | 32,687 | 6,004 | 2026-06-01 to 2026-08-15, 76 days |
| `holdout_sealed` | 5,421 | 992 | days 77-90, labelled |
| `benign_corpus` | 640 | 250 | tool-call turns only |
| **total** | **38,748** | | |

Sealed holdout, by label:

| Label | Sessions | Events |
|---|---:|---:|
| benign | 952 | 5,224 |
| cross-tenant-egress | 10 | 51 |
| injected-turn-tool-call | 10 | 44 |
| privilege-sequencing | 10 | 51 |
| scope-violation | 10 | 51 |

Ten attack sessions per family, so a reported catch rate of "N of 10" is a real count.

Generator digests, seed 20260825: `conduct_train a535719af88e4423`,
`holdout_sealed 7d93e8c459918bcb`, `benign_corpus 0d4342ce4d425982`.

### Capture 1 — the Proposer cannot read its own exam

`captures/day1-proposer-403-on-holdout.txt`, produced by `infra/50_prove_seal.sh`.

- `proposer-sa` on `conduct_train.turns`: HTTP 200, 32,687 rows.
- `proposer-sa` on `holdout_sealed.turns`: **HTTP 403 PERMISSION_DENIED**.
- `examiner-sa` on `holdout_sealed.turns`: HTTP 200, 5,421 rows.

The principal is proved from the access token itself rather than asserted by the script.
The Cloud Audit entry names the denied permission:

```
principalEmail proposer-sa@devpost-hackathon-506416.iam.gserviceaccount.com
status.code    7  (PERMISSION_DENIED)
DENIED         bigquery.tables.getData  (DATA_READ)
               on projects/devpost-hackathon-506416/datasets/holdout_sealed/tables/turns
```

### Capture 2 — a sealed certificate cannot be deleted or overwritten

`captures/day1-retention-refuses-delete.txt`, produced by `infra/61_prove_immutability.sh`.

Both attempts are made as the project **owner**, the strongest principal in this project.

```
HTTP 403  retentionPolicyNotMet
Object '.../certificates/day1-seal-check.json' is subject to bucket's retention policy
or object retention and cannot be deleted or overwritten until 2026-09-23T23:03:14
```

`gcloud storage rm` reports this as an opaque `GcsApiError('')`, so the script repeats
the same call against the JSON API, where the reason is stated. Both are in the capture.
Overwrite is refused on the same grounds, so the record cannot be edited either.

The obvious way around an unlocked policy is to clear the policy first and delete
after. That is closed too:

```
HTTP 403  retentionPolicyNotMet
Bucket 'caseharden-certificates-506416' has a locked Retention Policy which cannot be removed.
```

### Decided today

**The isolation guarantee is dataset access control, not an IAM deny binding.** IAM
deny policies need `roles/iam.denyAdmin`, which binds only at organization or folder
scope, and this project has no parent. `iam.denypolicies.create` is also rejected from
custom roles, so there is no project-scoped route to it. Both errors are quoted in
`infra/30_seal_holdout.sh`.

The seal is built the other way instead: no principal holds a project-wide BigQuery
read, `holdout_sealed` has its inherited `projectReaders` and `projectWriters` entries
stripped, and exactly one service account is granted it. The 403 is unchanged and the
audit log still names `bigquery.tables.getData`. What is lost is that a future
owner-level grant would not be overridden.

Section 2 of the plan is reworded to match, and the gap is closed on Day 3 rather than
conceded: the Notary hashes the `holdout_sealed` access list into chain link 1, so
granting the Proposer access later breaks re-derivation and quarantines the version.
The isolation guarantee becomes evidence-derived like everything else, which is closer
to the thesis than the deny binding was.

### Carried over

1. **Day 3, chain link 1 must include the `holdout_sealed` access list hash.** This is
   the substitute for the deny binding and it is load-bearing, not decorative. One
   pytest: mutate the access list, assert `verify` quarantines.
2. Employer email covering code ownership, development infrastructure approval and
   public repo approval is still outstanding. The repo is **private** until it is sent,
   then flips back to public with its commit history intact.
