# Live test plan: scan decisioning (part G)

Status: **written, not run.** Nothing in this file has been executed against GitHub, a real model or the development stack; every "Expected" below is derived from the SPEC (`SPEC.md` sections 5.1 to 5.8) and the as-built notes (17.c to 17.e), and the first run is where each one is confirmed or corrected. Record the result of each case in the table at the end.

Scope: the behaviour the security suite deliberately does NOT cover (ADR-008 AP-7): the floor rule table, real GitHub change detection, real models, the T-29 section in a browser, and the operational paths (kill -9 of a worker, cancel during the call).

## 0. Conventions used in every case

**Repository and pipelines.** Repository `qm-test-2-renamed`, connected in a workspace of the dev tenant. Two pipelines on it, both with the push trigger on branch `dec-test`, the pull request trigger with target branch `dec-test`, scan mode `incremental`, no exclusions, fork policy `skip` (changed only in LT-12):

| Pipeline | Enabled scan types | Why |
|---|---|---|
| `dec-all` | SBOM, SCA, SAST, Secrets | all four: the floor of a mixed change is everything, nothing is addable |
| `dec-nosec` | SBOM, SCA, SAST | Secrets disabled, so a manifest-only change gives the floor SBOM + SCA exactly (SAST addable) |

One push therefore creates two executions (one per pipeline), which is the intended way to compare two floors for the same change. Do **not** edit either pipeline configuration between cases: a changed scan-relevant configuration makes the next run `full` (reason `config_changed`, `pipelines-triggers` SPEC 5.7) and a full run is not decided at all.

**Baseline run (do once).** Create the branch from `main` and push it: `git switch -c dec-test && git push -u origin dec-test`. A new branch is a `full` scan (reason `branch_created`; the pipelines' first request is `first_run`). Expect on T-29 "Full scan: every enabled scan type was selected." and `scan_decisions.diff_source = 'none'`. Every later push to `dec-test` is `incremental` (reason `push`) as long as the configuration is untouched. A force push or a tag is `full` again; do not use them except in LT-15.

**What runs.** Only the SBOM engine ships. A selected SCA, SAST or Secrets scan becomes an `unsupported` task (reason `engine_not_registered`); that is expected and makes an execution with SBOM + another selected type end `partial`, SBOM alone `succeeded`. When the DECIDED set contains **no** type with an engine (for example only SAST, or SAST + Secrets), nothing real ran: the execution ends `failed` / `tasks_unsupported` straight from `preparing`, the decided tasks all `unsupported`, `quota_released_at` set (the unit is given back once), `resolutionEligible` false (owner decision 2026-11-18, executions SPEC 17.ab amendment 3a; case LT-17). A scan type that is **not selected** never has a task and never makes the run partial.

**Reading the result.** `$DB` is a psql connection to the dev database. The URL is in `apps/api/.env` as `DATABASE_URL`; export it without printing it:

```sh
set -a; . apps/api/.env; set +a; export DB="$DATABASE_URL"
```

Latest executions of the repository with their decision (run after every case; the newest rows first):

```sh
psql "$DB" -x -c "
SELECT e.id, p.name AS pipeline, e.scan_kind, e.scan_kind_reason AS kind_reason, e.trust, e.status, e.status_reason,
       e.task_counts, e.quota_consumed, e.quota_released_at IS NOT NULL AS quota_released,
       d.diff_source, d.diff_status, d.changed_total, d.secrets_rule,
       d.floor, d.agent_status, d.agent_provider, d.agent_model, d.agent_additions, d.final_types, d.not_selected, d.agent_usage
FROM executions e
JOIN pipelines p ON p.id = e.pipeline_id AND p.tenant_id = e.tenant_id
JOIN repositories r ON r.id = e.repository_id AND r.tenant_id = e.tenant_id
LEFT JOIN scan_decisions d ON d.execution_id = e.id AND d.tenant_id = e.tenant_id
WHERE r.name = 'qm-test-2-renamed'
ORDER BY e.requested_at DESC LIMIT 4;"
```

Tasks and history of one execution (`:E` = the execution id):

```sh
psql "$DB" -c "SELECT scan_type, status, status_reason, ordinal FROM scan_tasks WHERE execution_id = ':E' ORDER BY ordinal;"
psql "$DB" -c "SELECT seq, type, from_status, to_status, reason, at, left(details::text, 200) AS details FROM execution_events WHERE execution_id = ':E' ORDER BY seq;"
```

The same through the API (the logged-in dev session, `/api/v1`): `GET /executions/{id}` returns `decision`; the DTO deliberately omits the turn count, the tenant id and the record id.

**Reading T-29.** Open the execution from the pipeline's Executions list. The card "Analysis and decision" sits in the left column above the Scans cards. For every case check the five things in "T-29": the summary line, the change summary (class and status counts, lines added and removed, "Show changed paths"), one row per scan type with its chip (`Required` with the rule wording, `Added by the assistant` with the model's reason, `Not selected` with "No matching changes", `Not enabled`), the assistant block (provider and model, tokens and time, summary labelled as model-written; or the fallback note), and that no model text is ever a link, bold or markup.

**Agent statuses.** `not_configured`, `nothing_to_add`, `consent_required`, `skipped_fork`, `ok`, `timeout`, `error`, `invalid_output`, `interrupted`, `cancelled`. All but `ok` mean floor only.

**Floor rules (SPEC 5.3; the Secrets rule is `any_change` only, `SCAN_DECISION_SECRETS_RULE` accepts nothing else).** FL-1 manifest or lockfile changed in any status: SBOM + SCA. FL-2 a code file added, modified or renamed: SAST. FL-3 any file added, modified or renamed (any class): Secrets (a pure deletion never triggers it). FL-4 the diff failed, was truncated or unavailable: every enabled type. FL-6 empty changed set: nothing (zero-scan).

## 1. Setup order (details in "What I need from you")

1. Apply the part E migration to the dev database, restart the dev stack with `EXECUTION_ORCHESTRATOR_ENABLED=true` (already set in `apps/workers/.env`) and the LLM variables of the case group you run.
2. Cases LT-01 to LT-09 first with `LLM_PROVIDER=none` (floor only, deterministic), then the agent cases with Ollama (LT-10), then the hosted-provider cases (LT-11).
3. Between cases wait for the executions to finish (T-28 list) before the next push, so each push produces its own pair of executions.

## 2. Floor cases (provider none)

Environment: `LLM_PROVIDER=none` in both `apps/api/.env` and `apps/workers/.env`. Expected in every row: `agent_status = not_configured`, `agent_provider` null, `agent_additions = []`, `final_types = floor`, T-29 assistant block "Assistant not used" with the fallback note.

### LT-01 package.json only

- **Action.** On `dec-test`, edit one dependency version in `package.json` (nothing else), commit and push.
- **Expected `dec-nosec`.** `scan_kind = incremental`, `diff_status = complete`, `changed_total = 1`; floor `sbom` (FL-1), `sca` (FL-1); final `sbom, sca`; `not_selected` = `sast` (`no_matching_changes`); tasks `sbom` (succeeded), `sca` (`unsupported`); execution `partial`.
- **Expected `dec-all`.** floor `sbom, sca, secrets` (FL-1 and FL-3: a modified file of any class); final the same; not selected `sast`.
- **Verify.** Latest-executions query; compare the two rows; `scan_tasks` of the `dec-nosec` run has no `sast` or `secrets` row.
- **T-29.** Summary "Incremental scan: 1 file changed (1 dependency file). 2 of 3 enabled scan types were selected." (4 of 4 for `dec-all` becomes 3 of 4); SAST chip `Not selected`.

### LT-02 source only

- **Action.** Edit a `.js`/`.py` source file only (no manifest), commit, push.
- **Expected `dec-nosec`.** floor `sast` (FL-2); final `sast`; not selected `sbom`, `sca`; one task, `sast`, `unsupported` (no SAST engine ships). The decided set has no type with an engine, so the expected ending is `failed` / `tasks_unsupported` (owner decision 2026-11-18): task counts `{total 1, unsupported 1}`, `quota_released_at` set, no `running` transition (events `decision_started`, `decision_completed`, `task_unsupported`, `transition preparing->failed`), one `completed` message with `resolutionEligible` false (see LT-17).
- **Expected `dec-all`.** floor `sast, secrets`; final `sast, secrets`; not selected `sbom, sca`; both tasks `unsupported`, so also `failed` / `tasks_unsupported` with the quota unit given back (no engine for either type).
- **T-29.** "1 file changed (1 source file)"; SBOM and SCA `Not selected`.

### LT-03 docs only

- **Action.** Edit `README.md` only, commit, push.
- **Expected `dec-nosec`.** FL-3 applies to a type that is not enabled, so it adds nothing: the floor is EMPTY. Final `[]`, status `succeeded`, `status_reason = no_applicable_scans`, no task, `quota_released_at` set (this is the zero-scan case, see LT-08). With provider none no model is asked.
- **Expected `dec-all`.** floor `secrets` (FL-3); final `secrets`; task `secrets` `unsupported`; the only decided type has no engine, so `failed` / `tasks_unsupported` with the quota unit given back (`succeeded` was the earlier, superseded expectation); not selected `sbom, sca, sast`.
- **T-29.** `dec-all`: "1 file changed (1 documentation file). 1 of 4 enabled scan types were selected."

### LT-04 mixed change

- **Action.** One commit changing `package.json`, one source file and `README.md`.
- **Expected.** Both pipelines: floor is every enabled type (`dec-all` `sbom, sca, sast, secrets`; `dec-nosec` `sbom, sca, sast`); `not_selected = []`; `agent_status = nothing_to_add` is only reported when a provider resolves, with provider none it is `not_configured` (record which one you see).
- **T-29.** "3 files changed ..."; every enabled type `Required`.

### LT-05 removal only (zero-scan): Secrets never runs for a pure deletion

- **Action.** `git rm` one source file and one doc file, commit, push (a pure deletion; no file added or modified).
- **Expected.** `dec-all`: floor `[]` (FL-3 needs an added, modified or renamed file); final `[]`; `succeeded`/`no_applicable_scans`; no task; `quota_released_at` set and the usage counter of the period back by one. Same for `dec-nosec`.
- **T-29.** "No scan applied to these changes." chip "Succeeded", reason "No scan applied", no Scans cards.

### LT-06 (retired)

Retired 2026-11-18: the Secrets rule `strict` was removed by the owner (option B), so there is nothing to test; the id is kept so the other case ids stay stable. LT-05 covers the removal-only behavior: Secrets never runs for a pure deletion.

### LT-07 removal of a manifest

- **Action.** `git rm package-lock.json` (or `package.json`), commit, push.
- **Expected.** FL-1 "in any status": floor `sbom, sca` (not zero-scan), `changed_total = 1`, status `removed` counted in the change summary.

### LT-08 zero-scan and the quota refund

Covered by LT-03 (`dec-nosec`) and LT-05. Verify precisely once:

```sh
psql "$DB" -c "SELECT id, status, status_reason, task_counts, quota_consumed, quota_released_at, finished_at FROM executions WHERE id = ':E';"
psql "$DB" -c "SELECT count(*) AS tasks FROM scan_tasks WHERE execution_id = ':E';"
psql "$DB" -c "SELECT seq, type, from_status, to_status, reason FROM execution_events WHERE execution_id = ':E' ORDER BY seq;"
```

Expected: `succeeded`, `no_applicable_scans`, `task_counts.total = 0`, `quota_released_at` not null, zero tasks, events `decision_started`, `decision_completed`, `transition preparing->running`, `transition running->succeeded` (two transitions, one lease epoch). In the UI the monthly scan usage shows the unit given back (compare the usage page before and after).

### LT-17 decided types all unsupported (failed, quota refunded)

Covered by LT-02 (both pipelines) and LT-03 (`dec-all`). Verify precisely once, on the `dec-nosec` run of LT-02 (`:E`):

```sh
psql "$DB" -c "SELECT id, status, status_reason, task_counts, quota_consumed, quota_released_at, started_at, finished_at FROM executions WHERE id = ':E';"
psql "$DB" -c "SELECT scan_type, status, status_reason FROM scan_tasks WHERE execution_id = ':E' ORDER BY ordinal;"
psql "$DB" -c "SELECT seq, type, from_status, to_status, reason FROM execution_events WHERE execution_id = ':E' ORDER BY seq;"
```

Expected: `failed`, `tasks_unsupported`, `task_counts` all in `unsupported` (here `total 1, unsupported 1`), `quota_released_at` not null, `started_at` null (the execution never ran), one task `sast` `unsupported` / `engine_not_registered`, events `decision_started`, `decision_completed`, `task_unsupported`, `transition preparing->failed` (no `running` transition), the monthly usage back by one. Control (the mixed case, no refund): LT-01 on `dec-nosec` ends `partial` / `tasks_unsupported` with `quota_released_at` null.

### LT-09 no provider on a pipeline run (control)

Any push with `LLM_PROVIDER=none`: every row above already shows it. Additionally confirm `GET /settings/ai` returns `assistant.configured = false`, and the Settings page shows "The analysis assistant is not configured."

## 3. Fork pull request (floor only, agent never called)

### LT-12 fork PR

- **Setup.** A second GitHub account forks `qm-test-2-renamed`. In the platform, an Admin sets the fork policy of `dec-all` to `run_without_credentials` (needs `pipeline.manage_fork_policy`; this publishes a new configuration version, so the next NON-fork run is `full`; run one push first to re-establish the baseline). Use an external or local provider so that "never called" is meaningful: Ollama (LT-10 setup) is the easiest because its server log shows requests.
- **Action (user).** From the fork, branch `fork-pr`, change `package.json` and one source file, open a pull request into `dec-test` of the base repository.
- **Expected.** `trust = untrusted_fork`, `scan_kind = incremental`, `trigger_type = pull_request`; `diff_source` is the pull-request files API; `agent_status = skipped_fork`, `agent_provider` null, `agent_usage` null; final = floor (`sbom, sca, sast, secrets` for `dec-all` since both a manifest and code changed); tasks on queue `scan-untrusted`.
- **Verify.** Latest-executions query (trust column); the Ollama log shows NO request for this execution (compare the request counter before and after); outbox queue: `psql "$DB" -c "SELECT queue, type FROM outbox_messages WHERE payload->>'executionId' = ':E' ORDER BY created_at;"` (every scan task message on `scan-untrusted`). No token anywhere: `psql "$DB" -c "SELECT count(*) FROM execution_logs WHERE execution_id = ':E' AND message ~* '(ghs_|authorization|bearer)';"` is 0.
- **T-29.** Assistant block says the assistant is not used for pull requests from forks.
- **Afterwards.** Set the fork policy back to `skip` (and run one push to re-baseline).

## 4. Agent cases

### LT-10 local Ollama (no consent needed)

- **Environment.** Both `apps/api/.env` and `apps/workers/.env`: `LLM_PROVIDER=ollama`, `LLM_MODEL=<an installed model that supports tool calling>`, `LLM_OLLAMA_BASE_URL=http://127.0.0.1:11434`. Restart API and workers. `GET /settings/ai` now returns `assistant: { configured: true, providerKind: "local" }` and the Settings card says a local model needs no consent.
- **Action A (agent may add).** Repeat LT-01 (package.json only) on `dec-nosec`: addable is `sast`. Expected `agent_status = ok` or `nothing_to_add` never (SAST is addable), `agent_additions` empty or `[{scanType: sast, reason}]`, `final_types` = floor or floor + sast, never smaller than the floor; `agent_provider = ollama`, `agent_model` as configured, `agent_usage` has input/output tokens and latency. T-29 shows the provider and model, the model-written summary and reason as plain text, label "written by the assistant".
- **Action B (nothing to add).** Repeat LT-04 (mixed): every enabled type is in the floor, so `agent_status = nothing_to_add`, no model request (Ollama log shows none).
- **Action C (the chatty-model observation).** Run A five times with different content and record, for each, how many requests Ollama received and the resulting `agent_status`. A model that repeats the `request_scan` call after the tool result gives a duplicate and therefore `invalid_output` (floor only, safe, but an addition is lost). Record the rate. (Open item in `OPEN_DECISIONS.md`.)
- **Verify.** Latest-executions query; the Ollama server log for the number of requests; `execution_events` row `decision_completed` details carry the facts only (no prompt).

### LT-11 hosted provider and the consent toggle

Needs a hosted provider key (see "What I need from you"). Dev only: production refuses the environment secret provider.

1. **Consent off (default).** `LLM_PROVIDER=anthropic` (or `openai`), `LLM_MODEL=<model>`, the key in the workers' environment. `GET /settings/ai` -> `externalConsent: false`, `providerKind: "external"`. Push LT-01 content. Expected `agent_status = consent_required`, `agent_provider` null, floor only, **zero requests at the vendor** (check the vendor's usage page or your key's usage; the worker log line says `consent_required`). T-29 explains that the assistant needs the organization's permission.
2. **Consent on.** As an Admin, Settings > "Analysis assistant", turn the switch on and confirm the dialog. The card now says "On · last changed <time> by <your display name>" (part G: the changer name). Verify the audit entry: `psql "$DB" -c "SELECT action, actor_user_id, metadata, created_at FROM audit_logs WHERE action = 'tenant.llm_consent_changed' ORDER BY created_at DESC LIMIT 2;"` (metadata is `{previous:false,new:true}` only). Push again: `agent_status = ok`, `agent_provider = anthropic`, requests visible at the vendor, usage recorded.
3. **Consent off again.** Turn it off (no dialog). Push again: back to `consent_required`. A second audit entry exists.
4. **Display name.** The "by <name>" part must be the display name only; open the response in the browser tools: `GET /api/v1/settings/ai` has `consentChangedBy: { displayName }` and no id or email.
5. **Wrong key.** Set a deliberately invalid key, consent on, push: `agent_status = error` (HTTP 401 from the vendor), execution still completes with the floor, and neither the key nor the vendor body appears in the worker log or the execution log.

## 5. Lease reclaim and cancel during `preparing`

For these two cases run the pipeline worker alone in its own terminal so that the dev launcher does not hide the exit: stop the dev launcher's pipeline process (do not stop the API or the web apps) and run `pnpm --filter @qmentisai/workers start:pipeline`. The dev launcher's `node --watch` does NOT restart a process that was killed; you restart it by hand.

**A slow model (to open the window).** The decision call is short with a real model, so for LT-13 and LT-14 put a delaying proxy between the worker and Ollama (dev-only helper, nothing is committed): in a scratch directory outside the repository save this as `slow.mjs` and run `node slow.mjs`, then set `LLM_OLLAMA_BASE_URL=http://127.0.0.1:11999` for the pipeline worker only.

```js
import http from "node:http";
http
  .createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () =>
      setTimeout(() => {
        const up = http.request(
          { host: "127.0.0.1", port: 11434, path: req.url, method: req.method, headers: req.headers },
          (r) => {
            res.writeHead(r.statusCode, r.headers);
            r.pipe(res);
          },
        );
        up.end(Buffer.concat(chunks));
      }, 12000),
    );
  })
  .listen(11999, "127.0.0.1");
```

Also set `EXECUTION_LEASE_TTL_SECONDS=20`, `EXECUTION_HEARTBEAT_SECONDS=5` and `SCAN_DECISION_AGENT_TIMEOUT_SECONDS=15` in the pipeline worker environment so the lease expires quickly (the agent timeout must stay below the lease TTL).

### LT-13 reclaim: kill -9 during the decision

- **Action.** Start a watcher in a terminal, then push LT-01 content:

```sh
# kills the pipeline worker the moment decision_started exists and the decision is not yet recorded
while true; do
  r=$(psql "$DB" -Atc "SELECT e.id FROM execution_events v JOIN executions e ON e.id = v.execution_id WHERE v.type = 'decision_started' AND e.status = 'preparing' AND NOT EXISTS (SELECT 1 FROM scan_decisions d WHERE d.execution_id = e.id) ORDER BY v.at DESC LIMIT 1")
  if [ -n "$r" ]; then pkill -9 -f 'src/pipeline/main.js'; echo "killed with $r"; break; fi
  sleep 0.1
done
```

  Then start the pipeline worker again (`pnpm --filter @qmentisai/workers start:pipeline`) and wait for the lease to expire (about 20 s plus a sweep tick of up to 15 s).
- **Expected.** The execution is reclaimed (`lease_epoch` 2, event `reclaimed`), a `scan_decisions` row appears with `agent_status = interrupted`, `agent_provider` null, `agent_additions = []`, `final_types` = the floor recomputed from a fresh diff; tasks equal the floor; the run completes. **The model is not called a second time**: the slow proxy log shows exactly one request for this execution (the one that was in flight when the worker died), none after the restart.
- **Verify.** `execution_events` shows ONE `decision_started` and one `decision_completed`; `scan_decisions` has one row for the execution; the proxy request count.
- **T-29.** The assistant block says the analysis was interrupted and the fixed rules were used; the event list shows "Analysis started" then "Analysis completed".
- **Variant (record present).** Kill later, after `scan_decisions` exists but before tasks are dispatched (very narrow; skip if you cannot hit it): expected no diff request to GitHub and no model request after restart, the tasks equal the recorded `final_types`.

### LT-14 cancel during analysis

- **Action.** With the slow proxy active, push LT-01 content, and as soon as T-29 shows "Analysis in progress." press Cancel (or `POST /api/v1/executions/{id}/cancel` with the session).
- **Expected.** The execution ends `cancelled` (status reason as for any cancel during `preparing`), **no** `scan_decisions` row and no tasks if the cancel won before the unit; `agent_status = cancelled` is only recorded if a record exists. The quota unit is released exactly once (`quota_released_at` set). The proxy shows the abandoned request; no further request follows.
- **Verify.** Latest-executions query; `SELECT count(*) FROM scan_tasks WHERE execution_id = ':E'` is 0.

## 6. Truncation

### LT-15 more than 300 changed files in one push (compare list truncated)

- **Feasibility.** GitHub's compare API lists at most 300 files and the platform treats 300 or more as truncated (CD-5). A push of 300 or more changed files is easy to make with a script: on `dec-test`, `mkdir bulk && for i in $(seq 1 320); do echo $i > bulk/f$i.txt; done && git add bulk && git commit -m bulk && git push`.
- **Expected.** `diff_status = truncated` (or `unavailable`), floor = every enabled type (FL-4, nothing not selected, no partial list), `changed_total = 0` in the record (the total is stored only for a complete diff), T-29 summary "Incremental scan: the list of changed files could not be read completely, so every enabled scan type was selected." With a provider, nothing is addable, so `nothing_to_add`.
- **Clean-up.** `git rm -r bulk` and push (that is a removal-only change: zero-scan under `any_change`, a free control for LT-05).

### LT-16 unreachable base (optional)

Force-push `dec-test` to a different history (`git push --force`): `full`, reason `force_push`; not decided. This is the control that a force push never uses the diff path.

## 7. T-29 browser pass (not yet run: Part F visual verification)

Run once with one agent-added execution (LT-10 A) and once with a zero-scan execution (LT-05): light and dark themes, 1280 and 1440 px, keyboard only (Tab to the card toggle, Enter, "Show more", "View task"), the persisted collapse choice, the live refresh when the decision lands (watch the card move from "Analysis in progress." to the result without reloading), the Events tab wording, and the Settings consent card in its five states. Hostile-string matrix of `SCREENS.md` section 9 (a reason, summary, model name and sample path each containing markup, Markdown, a `javascript:` link, a right-to-left override, a 5000-character word): get these in with a file name for the paths (create files named with `<img src=x onerror=alert(1)>.js` and `**bold**.md`, they are legal on Linux) and, for the model text, with the slow proxy replaced by a tiny stand-in that answers a prepared tool call (ask me for it).

## 8. Results table

| Case | Date | Result (matches expectation / differs) | Notes |
|---|---|---|---|
| LT-01 .. LT-16 | | | |

## What I need from you

1. **Apply the part E migration** to the dev database (I have not): `pnpm --filter @qmentisai/db db:migrate:deploy` with your `DATABASE_URL` (migration `20261118100000_scan_decisions`). Without it the workers fail the decision step. The part B migration (`tenant_llm_settings`) must be applied as well (check with `pnpm --filter @qmentisai/db db:migrate:status`). Part G itself needs no migration.
2. **Restart the dev stack** (API and the pipeline and scan workers): `.env` changes are not picked up by `node --watch`; it only restarts on a source change. Keep `EXECUTION_ORCHESTRATOR_ENABLED=true`, `GITHUB_APP_ENABLED=true` and the same `ARTIFACT_STORE_ROOT` for both workers.
3. **LLM variables, in BOTH `apps/api/.env` and `apps/workers/.env`** (the API only needs them to tell the UI whether an assistant exists and of which kind; the workers use them to call the model). The same values in both, or the Settings card and the executions will disagree.
   - Floor-only cases: `LLM_PROVIDER=none` (or unset).
   - Ollama (LT-10, 12-14): `LLM_PROVIDER=ollama`, `LLM_MODEL=<name of an installed model that supports tool calling>`, `LLM_OLLAMA_BASE_URL=http://127.0.0.1:11434` (default). Tell me the model; I cannot guess one (there is no default model by design). No key and no consent are needed.
   - Hosted (LT-11): `LLM_PROVIDER=anthropic` or `openai`, `LLM_MODEL=<model id>`. **How the key is supplied in development:** the key is a platform secret read from the process environment of the **pipeline worker only** (the scan worker and the API never read it): `LLM_ANTHROPIC_API_KEY=...` or `LLM_OPENAI_API_KEY=...`, or `LLM_ANTHROPIC_API_KEY_FILE=/path/to/a/file/holding/only/the/key` (preferred: keep the file outside the repository with mode 600 and never paste the key into a chat or a commit). Production refuses this environment provider on purpose (ADR-009: `NODE_ENV=production` plus a hosted provider makes the pipeline worker refuse to start) and no KMS or Vault provider exists yet, so a hosted provider is a development-only test today and a real platform secret provider is a prerequisite for production use. Do not set `NODE_ENV=production` for these tests. A local Ollama is unaffected.
   - Optional: `LLM_REQUEST_TIMEOUT_SECONDS` (default 30), `SCAN_DECISION_AGENT_TIMEOUT_SECONDS` (default 20, must stay below `EXECUTION_LEASE_TTL_SECONDS`), `SCAN_DECISION_MAX_TURNS`, `SCAN_DECISION_CONTEXT_PATHS`.
4. **`SCAN_DECISION_SECRETS_RULE`**: leave unset (`any_change`, the only accepted value; any other value, including the removed `strict`, stops the worker at start).
5. **The consent toggle (LT-11)**: an Admin of the dev tenant turns "Allow external AI providers to receive file names of your repositories" on and off in Settings; I need you to tell me when it is on, or do the steps of LT-11 yourself and paste the SQL results.
6. **GitHub actions**, all in `qm-test-2-renamed`: create branch `dec-test` and push it (baseline); the commits of LT-01 to LT-07 and LT-15 (one commit each, pushed one at a time, waiting for the executions to end); a second GitHub account (or a throwaway one) that forks the repository and opens a pull request for LT-12; permission to create two pipelines (`dec-all`, `dec-nosec`) in a workspace and to change the fork policy (Admin).
7. **Per case**, send me: the output of the "latest executions" query, the T-29 screenshot or a description of what each chip says, and for LT-10/11/12/13 the model server or vendor request counts. I will compare each with the "Expected" line and update this table.
8. **For LT-13 and LT-14** the pipeline worker must be run in its own terminal as described in section 5, and the slow proxy started; I need you to run those two cases while I am not touching the stack (they stop a worker).
