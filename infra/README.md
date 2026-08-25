# infra

Scripts are numbered in the order they must run. The order matters: sealing the
holdout removes the operator's own write access to it, so the corpora load first.

```bash
bash infra/00_enable_apis.sh
bash infra/10_service_accounts.sh
bash infra/20_bigquery.sh
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

## Re-running

`00` through `50`, `70` and `80` are idempotent. Two are not, deliberately:

- `60_lock_retention.sh` locks the retention policy, which cannot be undone. It
  refuses to run without `CASEHARDEN_CONFIRM_LOCK=LOCK`, and re-running it against
  an already-locked bucket fails. It is in the sequence above because
  `71_prove_immutability.sh` cannot prove anything without it.
- `71_prove_immutability.sh` is idempotent against a locked bucket. Against an
  unlocked one its final probe would strip the retention policy, so it detects
  that case and stops instead.

## Settings

From `env.sh`. Override with `CASEHARDEN_PROJECT`, `CASEHARDEN_REGION`,
`CASEHARDEN_BUCKET`, `CASEHARDEN_RETENTION` or `CASEHARDEN_OPERATOR` rather than
by editing it.

No script reads a credential file. No script prints an access token, or passes
one in a command argument or a URL, both of which are visible in the local
process table.
