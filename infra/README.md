# infra

Every script is idempotent and safe to re-run. Run them in order on a fresh project.

```bash
bash infra/00_enable_apis.sh
bash infra/10_service_accounts.sh
bash infra/20_bigquery.sh
bash infra/30_seal_holdout.sh
bash infra/40_load_corpora.sh
bash infra/60_bucket.sh
```

Then the two Day 1 proofs, which are read-only apart from writing one small object:

```bash
bash infra/50_prove_seal.sh          # the Proposer takes a real 403 on the holdout
bash infra/61_prove_immutability.sh  # the owner is refused delete and overwrite
```

`62_lock_retention.sh` is deliberately not in the sequence. It locks the retention
policy, which cannot be undone, and it refuses to run without
`CASEHARDEN_CONFIRM_LOCK=LOCK`.

Settings come from `env.sh`. Override with `CASEHARDEN_PROJECT`, `CASEHARDEN_REGION`,
`CASEHARDEN_BUCKET` or `CASEHARDEN_RETENTION` rather than by editing it.

No script here reads a credential file, and none prints an access token.
