# infra

Scripts are numbered in the order they must run. The order matters: sealing the
holdout removes the operator's own write access to it, so the corpora load first.

```bash
bash infra/00_enable_apis.sh
bash infra/10_service_accounts.sh
bash infra/20_bigquery.sh
bash infra/25_chain_tables.sh
bash infra/30_load_corpora.sh
bash infra/40_seal_holdout.sh
bash infra/50_bucket.sh
CASEHARDEN_CONFIRM_LOCK=LOCK bash infra/60_lock_retention.sh
```

Then the two Day 1 proofs:

```bash
bash infra/70_prove_seal.sh          # the Proposer takes a real 403 on the holdout
bash infra/71_prove_immutability.sh  # the owner is refused delete, overwrite and unlock
```

Both exit non-zero if the guarantee they test does not hold.

Then the Day 2 proof:

```bash
bash infra/80_prove_gate.sh          # the promotion gate refuses three ways, passes one
```

It runs the real Examiner against the real corpora as `examiner-sa`, asserts every
outcome, and exits non-zero if any of them changes. It also checks the compiled
BigQuery predicate against the Python evaluator on the same rows.

Then the Day 3 proof, which is the whole attestation lifecycle:

```bash
bash infra/90_prove_attestation.sh   # green, quarantine, refused, re-attest, green
```

Six assertions: a sealed version re-derives; the Policy Server serves the live state
rather than a stored one; one ordinary late conduct event quarantines it and names the
event; a promotion onto the quarantined version is refused; re-attestation supersedes
the evidence link without editing it; and the sealed certificate is refused deletion by
the retention policy, asked of the JSON API as the project owner.

`25_chain_tables.sh` also grants the Notary the two reads verification needs and
nothing more: `roles/bigquery.metadataViewer` at project scope, so it can read the
sealed exam's access list without being able to read the exam, and a custom role
carrying `resourcemanager.projects.getIamPolicy`, so link 1 can hash the project-level
bindings that could reach the exam. It then asserts the first of those: the Notary reads
the access list and takes a 403 on the rows. Both are bound at project scope on purpose,
because a dataset-scoped grant would add a second entry to `holdout_sealed`'s access
list, and that list having exactly one entry is the artifact a reviewer opens.

Two helpers it uses, also runnable alone:

```bash
python3 infra/tamper.py --event-id e_88214   # one late conduct event, as workload-sa
python3 infra/measure_verify.py --runs 20    # the verify p50/p95 the README publishes
```

The suite itself is checked the same way:

```bash
python3 tests/mutate_check.py    # breaks each property, asserts the suite notices
```

## Re-running

`00` through `50`, `70`, `80` and `90` are idempotent. Two are not, deliberately:

- `60_lock_retention.sh` locks the retention policy, which cannot be undone. It
  refuses to run without `CASEHARDEN_CONFIRM_LOCK=LOCK`, and re-running it against
  an already-locked bucket fails. It is in the sequence above because
  `71_prove_immutability.sh` cannot prove anything without it.
- `71_prove_immutability.sh` is idempotent against a locked bucket. Against an
  unlocked one its final probe would strip the retention policy, so it detects
  that case and stops instead.

`90_prove_attestation.sh` is idempotent in the sense that it can be re-run, but not in
the sense that it leaves nothing behind. A streamed row cannot be removed by DML for
about 90 minutes, so each run adds one permanent conduct event to the cited window and
one `EVIDENCE-CHANGED` link to the chain. The script picks a fresh event id when the
default one is already in the window, rather than pretending the previous tamper was
undone. To start from seven links again, delete the version's rows from `chain.links`
and `policy.versions` and let the script re-seed. The certificates it sealed stay in
the bucket, because the retention policy refuses to delete them.

## Settings

From `env.sh`. Override with `CASEHARDEN_PROJECT`, `CASEHARDEN_REGION`,
`CASEHARDEN_BUCKET`, `CASEHARDEN_RETENTION` or `CASEHARDEN_OPERATOR` rather than
by editing it.

No script reads a credential file. No script prints an access token, or passes
one in a command argument or a URL, both of which are visible in the local
process table.
