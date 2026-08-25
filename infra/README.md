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

Then Day 4, which deploys the fleet and proves it:

```bash
bash infra/26_conduct_live.sh              # conduct_live.turns and detector-sa
bash infra/27_policy_server_identity.sh    # the reads the Policy Server needs
export CASEHARDEN_MEMORY_ENGINE=$(python3 infra/31_memory_bank.py --id-only)
bash infra/28_deploy_fleet.sh              # one image, seven Cloud Run services
python3 infra/29_register_fleet.py         # publish the six agents into the registry
python3 infra/100_prove_fleet.py           # seven assertions, exit non-zero on any
```

Deploy and register are separate steps because a service has no URL until it exists,
and the registry publishes the agent card a running service actually serves rather than
one written by hand. Re-run `29_register_fleet.py` after any promotion: each entry
carries the chain root of the active version, so a new root makes the roster stale.

`100_prove_fleet.py` asserts: the registry lists one detector per check family and every
entry names the sealed root; the Foreman's source names no check family; all seven
services refuse an unauthenticated request; the deployed workload blocks a tool call on
a screened injection; the refusal claims a justified reason only when the version is
attested; the conduct row carries the trace id, version, state and whether the reason
was attested; all four detectors answer one fan-out with BigQuery job ids that exist and
completed; and the fan-out lands a memory carrying the finding.

The second of those reads local source rather than the deployment, and says so where it
runs. The trace-id assertion pins the value rather than its length, which the
constructor guarantees and which was therefore unfailable.

One run can only exercise whichever attestation state the project is in, and it says
which. The other direction is pinned offline by `tests/test_enforcement.py`.

Two helpers it uses, also runnable alone:

```bash
python3 infra/tamper.py --event-id e_88214   # one late conduct event, as workload-sa
python3 infra/measure_verify.py --runs 20    # the verify p50/p95 the README publishes
python3 infra/drive_agent.py --service caseharden-foreman --text "..."   # one A2A call
```

`measure_verify.py` clears the IAM role cache before every run. Leaving it warm would
time the first run honestly and every run after it with the most expensive call already
answered, then publish the average as the cost of a one-shot `caseharden verify`.

The suite itself is checked the same way:

```bash
python3 tests/mutate_check.py    # breaks each property, asserts the suite notices
```

## Re-running

`00` through `50`, `70`, `80`, `90`, `26` through `31` and `100` are idempotent. Two are
not, deliberately:

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

## Day 4 and the reach check

`26_conduct_live.sh` creates `detector-sa`. On the day it first ran, that one service
account quarantined the attested policy version, because link 1 hashed every
`roles/bigquery.*` binding in the project by name and `roles/bigquery.jobUser` matched.
It grants no access to the sealed exam. `captures/day4-iam-grant-quarantines.txt` has
the output.

The check now expands each role through the IAM API and keeps only roles that carry
`bigquery.tables.getData`. A role that cannot be expanded still counts as reaching, and
the three basic roles are pinned as reaching regardless of what `roles.get` says about
them, because it answers for `roles/owner` with a list that omits the permission.

That expansion is why `notary-sa` and `examiner-sa` hold `roles/iam.roleViewer`, and why
`verify` costs about 0.7s more than it did on Day 3.

## Credentials

Nothing in this repo acts on Application Default Credentials without checking the project
first. `caseharden/creds.py` mints tokens from the gcloud configuration named by
`CASEHARDEN_GCLOUD_CONFIG` (default `caseharden`) on a workstation, and from the metadata
server inside a container, and refuses to hand back credentials whose project is not this
project. The guard itself reads ADC, in order to refuse it. ADK and the genai SDK read
ADC directly for model calls, which is correct in a container and is why the guard runs
at import everywhere else.

`CASEHARDEN_PROJECT` is the comparison target, so setting it changes what counts as
correct. That is deliberate and every script here takes the same override; on a
workstation a mismatch is still caught, because `credentials()` also compares against the
pinned gcloud configuration's own project.

This is not tidiness. The machine this was built on also holds an unrelated employer's
ADC, and any library that calls `google.auth.default()` picks those up silently: the
call succeeds, the identity is wrong, and nothing fails. Every agent module calls
`creds.guard_ambient()` at import so a local run stops rather than proceeding under an
unintended identity.
