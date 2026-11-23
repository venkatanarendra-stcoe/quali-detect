# Findings, Part E2 (Wave 3), UI integration with the real API: as built

**Built:** 2026-11-23 on `6a4734c` (worktree branch `worktree-agent-afc38ebc5883c500d`, not pushed). Writes its notes **only here** (`SPEC.md` 16.4); Part F folds them into `SPEC.md` 17. No edit of `apps/api`, `packages/db`, workers or other `packages/shared` files. Files outside `features/findings/**` that were touched: the realtime client of `features/executions` (named by the task), `features/organization` (AI card, settings page, service, hook) and `app/router.jsx` (alias route).

## 1. What was done, per task

1. **Mock off by default.** `findingsApi` (real) was complete; every path, method and body was checked against the routes in `apps/api/src/modules/findings/routes` and the live answers. `findingsService` is the mock only with `VITE_FINDINGS_MOCK=true` in a development build; `import.meta.env.PROD` forces it off. `pnpm build --force` output was searched: no mock string (`qm-findings-mock`, mock users) is in `apps/tenant-web/dist/assets`. Writes send an `Idempotency-Key` and `expectedRev`. Error mapping added: `FORBIDDEN_TEXT` (`separation_of_duties`, `not_assignee`, `not_reviewer`, `not_requester`, `missing_permission`), `approver_not_eligible`, `invalid_pull_request_url`, `CONFLICT/workspace_archived`, `IDEMPOTENCY_CONFLICT`; the field of a schema refusal is read from `details.issues[0].path` when the server gives no `details.field`. The 409 flow: the mutation refetches the workspace queries, the dialog shows the banner with Reload and keeps the typed text.
   **Mock aligned to the server:** a deleted pipeline disables only `submit_fix` (SPEC 5.13); `canRemediate` needs `finding.remediate`, a card in assigned or in progress on a live pipeline, and ownership unless the caller also assigns; SOD blocks any reviewer of any round or exception requester; same-person reassignment is a 409; start and submit decide the status before the caller; expiry has no slack (180 and 365 days); `record_review` is disabled while a request is pending; `comment` action listed; no advisory for info findings. The date picker offers at most 179 (accepted risk) and 364 (suppression) days, with presets 30, 90 and the maximum.
2. **Realtime.** `realtime-client.js` joins `{ findingsWorkspaceId }`, parses `finding.changed` (ids and enums only) and handles `subscription.ended` with `scope: "findings"`. `useFindingsRealtime(workspaceId)` is mounted on the five pages; a hint only invalidates the workspace's findings queries (400 ms coalesce) and the screens refetch through the API. The 60 s polling stays as the fallback.
3. **Alias `/findings/:findingId`.** `GET /findings/{id}` exists without a workspace and the detail DTO carries `workspaceId`, so `FindingAliasRedirect` resolves it and redirects to the nested route; loading, 404 (unknown, malformed id) and 403 states reuse `QueryErrorState`.
4. **Consent second switch.** `codeSnippetConsent` on `GET`/`PUT /settings/ai`, own switch and copy (excerpts never secrets, secrets never get advice, local needs no consent), usable only while the first consent is on, confirmation dialog, audited-change toast; withdrawing the first shows the second cleared (the server answer replaces the cache). Permission through `useCan`.
5. **SLA settings card** (`FindingsSlaCard`, organization settings): Critical, High, Medium, Low in hours or days, Info shown as "No SLA", validation 1 to 87,600 hours, "not retroactive" copy, Reset to defaults, Save, Sonner feedback, loading, error, unauthorized and read-only states (`tenant_settings.view` / `manage`).
6. **Board card** shows the PR link (only `https`, new tab, `noopener noreferrer`) and the ticket key (mono, not a link); real `canRemediate`; Approvals SOD tooltip uses the server's `disabledReason` of the finding's allowed action (the constant is only a fallback); advisory `pending` ("Advice is being prepared") and `stale` ("Evidence changed since this advice was written. Ask again for fresh advice.") states. **Nav counts (S-5) were not built:** `GET /findings/summary` has `pendingApprovals` and `views.needsReview`, but showing them needs an edit of the sidebar, outside this part's files.
7. **S-1 workaround** in `findingsApi.get` (see 3).

## 2. Verified against the REAL stack

**Setup (isolated, the user's dev DB and stack untouched):** own PostgreSQL 18 cluster (port 55433, `migrate deploy`, `db:seed`, `seed:findings --tenant demo --scale small`), own Redis (56380) and RabbitMQ container (removed afterwards), my own API (3993), outbox relay, findings worker and findings-agent worker with `FINDINGS_INGESTION_ENABLED` and `FINDINGS_AGENT_ENABLED` on in those processes only, Vite on 5193, and a local HTTP stub standing in for the Anthropic API (`LLM_PROVIDER=anthropic` pointed at 127.0.0.1; **no real model, no external network**). Personas: the seeded demo users (admin, manager, lead, analyst, devlead, developer, viewer) with the mock-auth password set in my own environment. Browser: headless Chrome by CDP at 1440 px, light theme only. All processes stopped, container removed.

| Screen or behaviour | Result (real API) |
|---|---|
| T-31 list (analyst, viewer, lead) | renders real rows, counts and filters; viewer read-only |
| T-32 detail SAST and secret evidence | block with highlighted line; secret has no copy button; commit link present |
| Alias route | real id redirects to the nested route; unknown id and malformed id show not found |
| Nested unknown id | not found state |
| T-34 reviews, T-36 board, T-35 approvals | render with real data; viewer gets the unauthorized state on Approvals |
| Review, approve flow (analyst, lead) | Start review (claim), empty submit shows validation, credential-shaped rationale refused with the text kept, decision recorded (Awaiting approval), lead approves (status approved in the DB-backed API) |
| Realtime (two browsers) | lead's open Approvals page showed the analyst's new row 1.7 s after submit (poll is 60 s); the analyst's open detail turned to "Confirmed, unassigned" without a reload |
| Assign, reassign same person | assigned to the developer; reassign to the same person gives the server 409 shown as a sentence |
| Board (developer) | Move to offers only In progress and Fixed; start work and submit fix real; non-https PR link refused; card shows PR link and ticket key; cards that are not theirs are not draggable |
| Deleted pipeline | real `allowedActions`: only `submit_fix` disabled with the pipeline reason, comment and reassign still listed; banner shown |
| T-33 accept risk | date picker max = today+179; 180 refused before sending; 179 accepted by the server; server refuses over 180 days with `details.reason: expiry_out_of_range`; lead approves the request (accepted risk with expiry) |
| SOD | requester sees "Needs another approver", Approve disabled, tooltip reached by Tab with the server's words ("You requested this. Another lead must approve it."), accessible name carries it; API self-approval is 403 `separation_of_duties` |
| 409 stale revision | outbox paused, finding changed behind the UI, submit shows "This finding changed since you opened it", typed text kept, Reload then resubmit succeeds |
| Bulk Start review | three selected, result dialog, all three in review (API) |
| AiAdvisoryCard | pending right after the request, then `consent_blocked` (zero requests to the model), settings link only for the holder of `tenant_settings.manage`; with consent: pending then `ready` (stub) with suggestion, 71 percent, reasoning, "Based on: rule, location and a code excerpt"; stub saw a request with an excerpt only after both consents; stale state after moving the evidence capture time (my own database): "Request again" |
| Consent switches | two switches; second disabled while the first is off; both stored by the server; withdrawing the first cleared the second (server and UI); toast says the change is audited and that code excerpts were turned off too |
| SLA card | 0 and 87,601 hours refused; 96 and 3000 saved on the server; Sonner toast; Days view converts; Reset to defaults saved; analyst gets the unauthorized page |
| Production bundle | built bundle holds no mock marker |

Walk summary: w1 to w5 passed all checks except one test-script selector (PR link attributes read from another card; the rel and target values on the board were correct), and w6 passed 25 of 26, the failure being a 600 ms sampling race for the transient "pending" label (the pending state itself was seen in a separate poll, and in the passing "pending again" check).

### SCREENS 13 matrix, honest status

Run by script on the personas available: Analyst, Lead, Dev Lead, Developer, Admin, Viewer. Not run: the **Manager** persona and "other workspace or tenant" for the UI (there is one tenant and one workspace in the seed; the API check of the identical 404 is the suite's, not mine). Not covered or not done: narrow widths and dark theme against the real API (done on the mock in Wave 1 only), every severity and status in grayscale, 100,000-finding list, the commit link opening the exact commit on GitHub (LT-F5, the seeded repositories are fake), `prefers-reduced-motion` by eye. **No human review and no screen-reader pass was made (LT-F6 stays open).** Keyboard checks done: Tab to the SOD tooltip, `M` on a board card.

## 3. Server defects and gaps found (not fixed: apps/api and packages/db are not mine)

- **S-1 (blocks correct display, worked around in the UI).** `GET /findings/{id}` sets `ETag: W/"finding-<rev>"` from `rev` only, while the DTO also carries the advisory with its `pending` and `stale` states, the per-caller `allowedActions` and the SLA state, which change without a `rev` change. A browser revalidates with `If-None-Match` and Express answers `304`, so the page keeps a stale body (observed: a default-mode `fetch` kept returning `none` for 15 s while `cache: "no-store"` and the API returned `pending` then `consent_blocked`). Proper fix: an ETag over the whole DTO (or `Cache-Control: no-store` on the detail). The UI sends `Cache-Control: no-cache` on the detail read (Express then does not treat the request as fresh).
- **S-2 cold start.** The first request after the API boots returns `500` ("Stream isn't writeable and enableOfflineQueue options is false") until the Redis connection is up. The same error hit the findings-agent worker (one advisory request was dead-lettered as non-retryable and the detail then stayed `pending` for the five-minute window). Retry on a not-yet-connected Redis, or connect before serving.
- **S-3 `PUT /settings/findings-sla` needs 1 to 4 rows**, so "Reset to defaults" cannot delete the stored rows; it stores explicit default hours (the row then reads `isDefault: false`).
- **S-4 pending and `consent_blocked`.** The card of a `consent_blocked` advisory offers no request button; after turning consent on, the user must use More, "Request advisory again". UI choice kept as built; the owner may want a button.
- **S-5 detail conditional GET.** Only a `304` on the detail is implemented through Express `fresh`; the list has no ETag. No action needed beyond S-1.
- **Operational:** the realtime socket answers 404 unless `REALTIME_ENABLED=true`; the API needs `CORS_ALLOWED_ORIGINS` for the Vite origin; list `pageSize` must be 25, 50 or 100.
- The deviations of Part B and C already recorded (writes return the detail DTO, assign is `201`) were confirmed live; nothing else differed between the mock and the server beyond item 1 above.

## 4. Deviations and open decisions

1. Nav counts (S-5, Recommended) not built (needs the sidebar).
2. The realtime hook lives in `features/findings` but uses `useRealtime` of `features/executions`; the client change is in that feature's files because the task named the client.
3. Date picker presets are 30, 90 and 179 or 364 days (SCREENS says 180 and 365).
4. SLA form has an hours or days switch; saving always sends all four rows.
5. Open for the owner: S-1 fix on the server (then the workaround can go), S-2, S-3, whether the `consent_blocked` card gets a request button, and the Manager persona and multi-workspace checks of the matrix.
