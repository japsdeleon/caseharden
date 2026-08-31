# Caseharden — Day 5 handoff

You are the build session for a solo hackathon entry. Days 1 to 4 are built, pushed and
proven. Your job is Day 5. Build, do not redesign.

Read in this order before writing code:

1. `docs/PLAN.md` sections 1 to 5, and section 9. It is the specification.
2. `docs/BUILD_HANDOFF.md`. The operating contract. Every hard constraint in it still holds.
3. `BUILD_LOG.md`, the Day 4 entry. It carries the traps, the deviations and the open decisions.

This file is the state of the world plus what Day 5 has to produce. It does not repeat
the plan.

---

## Where things stand

Repo `~/caseharden`, branch `main`, last commit `650003f`.
Still **private** on GitHub until the employer email is sent.

| Day | Exit criterion | Proof | State |
|---|---|---|---|
| 1 | Proposer takes a real 403; retention refuses delete | `infra/70_prove_seal.sh`, `71_prove_immutability.sh` | green |
| 2 | The gate refuses three ways, passes one | `infra/80_prove_gate.sh` | green |
| 3 | Green, quarantine, refused, re-attest, green | `infra/90_prove_attestation.sh` | green |
| 4 | The fleet is a roster; enforcement carries its own warrant | `python3 infra/100_prove_fleet.py` | green, 8 assertions |

143 tests (`python3 -m pytest tests -q`). 38 mutations, all caught
(`python3 tests/mutate_check.py`). `verify` p95 3.58s cold against a 5s target
(`python3 infra/measure_verify.py --runs 12`).

Run every proof before you change anything. If one is red, find out why before building on it.

## The live project

Project `devpost-hackathon-506416`, region `europe-west3`, BigQuery location `europe-west3`.

Active policy is **v4**, parent v3, sealed root `40522ddaf38a…`. `v3` is the registered
genesis and carries no chain.

Seven Cloud Run services, all private, all from one image
(`europe-west3-docker.pkg.dev/devpost-hackathon-506416/caseharden/fleet:day4`):

```
caseharden-policy                          examiner-sa
caseharden-detector-cross-tenant           detector-sa
caseharden-detector-scope-escape           detector-sa
caseharden-detector-injected-turn          detector-sa
caseharden-detector-privilege-sequencing   detector-sa
caseharden-support-agent                   workload-sa
caseharden-foreman                         foreman-sa
```

URLs follow `https://<service>-menp6o526q-ey.a.run.app`. Do not guess them; read
`status.url`. Cloud Run also answers on a `-602109647023.europe-west3.run.app` form and
advertising the wrong one breaks A2A on a same-origin check.

Six agents registered in Agent Registry. `CASEHARDEN_MEMORY_ENGINE=4537666895645507584`
is the Agent Engine backing Memory Bank.

Datasets: `conduct_train` (the frozen cited window), `conduct_live` (what the fleet
writes), `holdout_sealed` (examiner-sa only), `benign_corpus`, `chain`, `policy`.

## Day 5, from the plan

Section 4, "Aug 29, Day 5", verbatim scope:

- Proposer on Agent Runtime under `proposer-sa`, structured output into the DSL, Memory
  Bank conditioning, schema rejection written to the chain as `DRAFT-REJECTED`.
- Model Armor on verdict in and rationale out, results recorded in the `VERDICT` link.
- Analyst Copilot via `adk deploy cloud_run --with_ui`, verdict and approve as two ADK tools.
- Then run the loop for real: incident, verdict, an over-blocking candidate rejected by
  the gate, a revised candidate promoted to v5 with a green certificate.
- Freeze the ledger and capture screen recordings of the real run, so Day 6 is editing
  rather than performing.

## Day 5 also carries these, from Day 4

**1. Join the fleet to the chain.** Today the `FINDING` link is written by `notary seed`,
which runs its own SQL against `conduct_train`. The four detectors scan `conduct_live`.
Both work and they never meet. Beat 0:56 needs the detector's finding to be link 2, with
that detector's job id. This is the largest carried item.

**2. Export spans to Cloud Trace, or drop the beat.** `trace_id_for()` hashes session and
turn. That is a stable correlation key shared by the conduct row, the chain link and the
finding. It is not a handle Cloud Trace can open: the project's trace list is empty and
every id 404s. `current_trace_id()` already prefers a real span id when one exists and
`derived_trace_id()` tells them apart, so wiring an OTel exporter is the whole job.
Section 3 and beat 0:56 both claim a real execution DAG.

**3. Resolve the Agent Runtime question.** Nothing runs on Agent Runtime. An Agent Engine
exists and backs Memory Bank, but no agent is hosted on it. Section 3 claims it hosts
Foreman and Proposer and that the registry pattern is proven "across both hosts". Day 5
deploys the Proposer, which is the natural place to make that true. If it fights, the
hour-5 rule applies again and section 3 plus the Devpost text lose the second host.

## Decisions that are the entrant's, not yours

Do not settle these. Surface them and wait.

- **Beat 2:10 spoken line**, "The examiner is two hundred lines of code". Nothing is two
  hundred lines. Counted on Day 4: `interpreter.py` 231, `dsl.py` 210, `examiner.py` 408,
  849 together. The Day 2 note said 187 and 610; both grew. Re-count before recording,
  because this is the number the line is about.
- **Beat 2:10 on-screen numbers**, "10 of 10" and "9/10", are the injected-turn family
  row while the overall counts are 37/40 and 29/40. Label or change.
- **Beat 0:38 says eight registry entries.** The listing returns eight today and two are
  not ours: Google's `Workspace Agent` and a `caseharden-memory` that Vertex registered
  itself. Day 5 adds two more of ours, so ten rows will be on screen.
- **Section 3's "both hosts" claim**, if the Proposer does not land on Agent Runtime.

## Traps, each one already paid for

**Application Default Credentials on this machine belong to an unrelated employer.**
Anything calling `google.auth.default()` succeeds under the wrong identity and names an
employer project as the quota project. Never use ADC directly. Use `caseharden/creds.py`,
and call `creds.guard_ambient()` at the top of any new agent module. Every `gcloud` and
`bq` invocation needs `CLOUDSDK_ACTIVE_CONFIG_NAME=caseharden`, which `creds.gcloud_env()`
sets for you.

**Adding a column to `conduct_train` quarantines every chain in the project.** Link 1
hashes each cited row as `SHA256(TO_JSON_STRING(t))` and `TO_JSON_STRING` emits a key for
every column including null ones. That is why live events go to `conduct_live`.

**Any IAM change that touches the exam's reach re-quarantines the active version.** Link 1
hashes project bindings whose role carries `bigquery.tables.getData`, plus who may
impersonate the exam's readers. `reattest` refuses to clear a widened access list, by
design. The remedy is a fresh promotion, not a re-attestation.

**Re-register the fleet after every promotion.** Each registry entry carries the active
root, so a new root makes the roster stale and assertion 1 of the fleet proof fails.
`python3 infra/29_register_fleet.py`.

**The Foreman binds its roster at container start.** A detector registered while an
instance is warm joins on the next cold start. Force one with a `gcloud run services
update --update-env-vars`.

**Agent Registry validates the agent card against the A2A v1.0 proto.** A top-level key is
rejected with `unknown field`. Project metadata goes in `capabilities.extensions`. The
card content is a protobuf Struct, so send the object, not a JSON string.

**ADK's `State` is not a Mapping.** It has `get`, `setdefault`, `to_dict` and no `keys()`,
so `dict(state)` raises `KeyError: 0`.

**ADK needs `GOOGLE_GENAI_USE_VERTEXAI=True`** plus `GOOGLE_CLOUD_PROJECT` and
`GOOGLE_CLOUD_LOCATION`, or it reaches for the Gemini Developer API and answers "No API
key was provided".

**BigQuery refuses `IGNORE NULLS` on an analytic `ARRAY_AGG`.** Use a CTE.

**IAM grants take up to a minute to propagate.** Retry with a wait rather than concluding
the grant failed.

**A user account cannot mint an identity token for a custom audience.** Local calls to
private services impersonate `foreman-sa`; `agents/common/auth.py` does it.

**Cloud Build needs the `Dockerfile` at the repo root.** It is there.

## How to drive things

```bash
python3 -m caseharden.notary verify --version v4
python3 infra/drive_agent.py --service caseharden-foreman --text "Investigate the last 72 hours."
python3 infra/drive_agent.py --service caseharden-support-agent --text "<ticket text>"
curl -H "Authorization: Bearer $TOKEN" https://caseharden-policy-menp6o526q-ey.a.run.app/policy/active
```

Deploy loop: `gcloud builds submit --tag <image> --region=europe-west3`, then
`gcloud run services update <service> --image=<image>`. About 90 seconds a cycle.
`infra/README.md` has the full numbered sequence.

## Working rules, unchanged

Single branch `main`, direct commits, no worktrees and no PR flow. **No `Co-Authored-By`
trailers.** One dated entry per day appended to `BUILD_LOG.md`: what shipped, what the
exit criterion produced, what is carried, measured numbers and never estimates.

After any non-trivial change, run an adversarial pass with both engines before reporting
done: `codex:codex-rescue` (a forwarder, so poll `codex-companion.mjs status|result`
yourself) and the in-house `validator`. Brief them with the spec path and the base ref and
none of your own conclusions. Day 4 shipped two fail-opens that only the second engine
caught, and one of them was written into a test as correct behaviour.

Do not run `tests/mutate_check.py` while another agent is reading the tree; it rewrites
source files in place and restores them, and a concurrent read sees a mutated file.

## First actions

1. Run all four proofs and the test suite. Report anything red before building.
2. Read the Day 4 entry in `BUILD_LOG.md` in full.
3. Confirm with the entrant which way the three open decisions go, or start on the work
   that does not depend on them.
4. Build Day 5 in the order in plan section 4, carried items included.
5. Report the real end-to-end run and the screen recordings, or the failure.
