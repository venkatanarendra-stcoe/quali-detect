# Screens: scan engines (T-29 "Tools" additions)

Status: **Approved with `SPEC.md` of this module (owner decisions 2026-11-19; degraded wording aligned with SPEC OQ-17 / D-6).** Nothing is built; nothing here has been seen in a browser. This module adds **one section to the scan task cards of T-29** (Execution detail, `docs/modules/executions/SCREENS.md` section 4) and **changes nothing else** on T-29, T-28, the pipeline Executions tab or navigation. Evidence snippets and SCM links are **not** shown on T-29: they surface in the Findings module (T-32, finding detail), where this document only reserves the surface (section 6). Visual rules: `docs/design/DESIGN_SYSTEM.md` and `docs/design/UX_GUIDELINES.md`. Labels: **Confirmed** = the owner's 2026-11-19 brief; **Recommended** = my proposal; **Open** = needs the owner. The screens are **model-free**: no language model is involved, and every string that comes from a tool or from the repository is shown as inert text.

## Decisions applied from the brief

| Id | Effect on the screen | Label |
|---|---|---|
| CB-10 | T-29 shows which tools ran for each scan task and each tool's per-task status and counts: tool name, version, image digest in short form, status, duration, counts by normalized severity, the DB version for SCA, and the failure reason in fixed words | Confirmed |
| CB-10 | Evidence and links surface later in Findings (T-32); this module only reserves and describes them | Confirmed |
| Executions SCREENS C6 / B12 | No placeholder for what does not exist: no Findings tab, no findings links, no Artifacts tab on T-29. An execution created before the ensemble engines has no `tools` in its DTO and shows no Tools section | Confirmed (existing rule) |
| New permission | None. The section needs `execution.view`, like the rest of T-29. The permission key is never shown | Recommended |
| Token rules | Severity colours independent of the accent; mint only for the active navigation item, the focus ring and the page's single primary action (T-29's Retry); Lucide icons; Geist Sans, mono only for identifiers | Confirmed (existing rules) |

## 1. Common rules

- **Inert text everywhere (Confirmed intent, SPEC SE-17/CB-6).** The only tool-derived values on this screen are: tool display name and version (taken from the platform catalog, not from tool output), the short digest (first 8 hex characters after `sha256:`, from the platform lock file), counts (integers), durations (integers), and a failure reason that is a **fixed word code** mapped to text by the frontend (section 3.3). No tool message, stderr, rule text, path or URL from a tool is rendered on T-29. Anything that ever is added later renders as escaped text: no Markdown, no HTML, no auto-linking.
- Status and reason text are never conveyed by colour alone (icon plus text).
- All times use the existing `TimeAgo`/duration helpers; identifiers (digest, version) use the existing `Identifier` mono treatment; copy buttons are offered only where `Identifier` already offers them.
- The section is read-only: no action, no mint button, no link out of the application.

## 2. Placement

Inside each **scan task card** (existing: title, status chip, engine id/profile, attempt, duration, result summary, expandable region). Two additions:

1. **Collapsed card, one summary line** under the existing result summary, only when the DTO has `tools`: plain text built from counts and codes, for example "3 tools" (all succeeded), "3 tools, 1 did not finish (degraded)" (one failed, timed out or unavailable), "2 tools, 1 skipped" (skipped tools are neutral, not a problem). With an icon only for the problem case (TriangleAlert), text always present.
2. **Expanded region, a new sub-section "Tools"** between the existing result summary and the attempts list, plus the **coverage line** (3.4). The existing "View log" button stays and still sets the Logs tab task filter; tool start/end lines appear there as ordinary log lines (fixed words, section 5).

The existing `unsupported` task card is unchanged (no tools; "No engine is available for this scan type yet."). A running task shows the existing indeterminate bar and **no tools list** (tool rows are recorded when a tool finishes; live per-tool progress is Open, SPEC OQ-22). The list appears when the task finishes, through the existing refetch on `scan.task.status_changed`.

## 3. Content of the Tools sub-section

### 3.1 The table

An accessible `<table>` (the app's table primitive, not a `DataTable` with sorting: at most 6 rows, fixed order = catalog order of the scan type) with a visually hidden caption "Tools used for <scan type>". Columns:

| Column | Content | Notes |
|---|---|---|
| Tool | display name (Syft, cdxgen, Trivy, Grype, OSV-Scanner, Semgrep, Bandit, gosec, Gitleaks, detect-secrets; the in-process SBOM-lite adapter reads "SBOM inventory (built in)") | Plain text |
| Version | version string from the catalog | mono |
| Image | `sha256:ab12cd34` (short form) | mono; the full digest is **not** in the DTO; the in-process adapter shows "built in" in plain text |
| Status | outlined chip, icon + text (3.2) | |
| Duration | "41 s", "2 min 3 s" | muted |
| Findings | severity pills for the non-zero counts only (Critical, High, Medium, Low, Info, each with the severity token, icon + text); "None" in muted text when the tool succeeded with zero findings; an em dash when the tool did not produce results | SBOM tools show "Components 412" as a neutral count instead of severity pills (kind `component`, severity info) |
| Data | for SCA tools: "Vulnerability data from 18 Nov 2026" (build date) and the short snapshot id in mono; empty for other tools | If older than the warn tier the cell adds the text "older than 3 days" with a warning icon |

Below the table, when any tool has a reason: a **definition list of reasons** ("Trivy: The tool ran out of time.") built from the fixed-word map; plain text.

### 3.2 Status chips (outlined chip with icon; neutral/success/warning/danger tokens of DESIGN_SYSTEM section on status)

| Status | Text | Icon (Lucide) | Token |
|---|---|---|---|
| `succeeded` | Succeeded | CircleCheck | `--status-success` |
| `partial` | Partial | TriangleAlert | `--status-warning` |
| `failed` | Failed | CircleX | `--status-danger` |
| `timed_out` | Timed out | Clock | `--status-danger` |
| `cancelled` | Cancelled | Ban | `--status-neutral` |
| `skipped` | Skipped | CircleMinus | `--status-neutral` |
| `unavailable` | Unavailable | CircleOff | `--status-warning` |

(The existing Executions screens render Preparing and Running in sky, an open point recorded in executions SCREENS section 11; this module introduces no new colour and does not change that. Whether `partial` and `unavailable` should be warning or neutral is Open for the owner's review of the chips, Recommended as above.)

### 3.3 Fixed-word reasons (Recommended; stable codes from SPEC 5.3)

| Code | Text shown |
|---|---|
| `timeout` | The tool ran out of time. |
| `deadline` | The scan ran out of time. |
| `out_of_memory` | The tool ran out of memory. |
| `exit_code` | The tool stopped with an error. |
| `output_invalid` | The tool's output could not be read. |
| `output_too_large` | The tool's output was too large and was cut. |
| `sandbox_error` | The scan environment could not run the tool. |
| `image_unavailable` | The scanner is not installed on this worker. |
| `db_unavailable` | Vulnerability data is not available. |
| `db_stale` | Vulnerability data is out of date. |
| `capacity` | No capacity was available in time. |
| `config_invalid` | The tool configuration was rejected. |
| `killed` | The tool was stopped. |
| `no_applicable_files` | No files for this tool in this repository. |
| `cancelled` | Cancelled. |
| unknown code | "The tool did not complete." (a code the frontend does not know is never printed) |

### 3.4 Coverage line (below the table)

One sentence, plain text with an icon when it is not the normal case:

| `coverage.state` | Text | Icon |
|---|---|---|
| `complete` | (nothing is shown) | |
| `partial_tools` | "Succeeded with reduced coverage (degraded): 1 of 3 tools did not finish. Results are incomplete, so this run cannot mark findings fixed." | TriangleAlert |
| `gaps` | "No tool supports these languages: Haskell, Elixir. Results are incomplete." (language names come from a fixed platform list; an unknown language shows "other") | TriangleAlert |
| `nothing_to_scan` | "Nothing to scan: no files of this kind were found." | Info |
| `truncated` | "Results were cut at the platform limit." (the existing "Truncated" badge stays too) | TriangleAlert |

This text is consistent with the existing page-level notice for non-eligible runs ("This run did not complete a full scan. It cannot mark findings fixed.") and does not replace it. Note the task and execution status stay `succeeded` for a degraded task ("succeeded (degraded)", SPEC 5.4 row 6, Confirmed D-6); the coverage line is where the tenant sees the degradation, and a degraded result is never eligible to mark findings fixed. The execution status `partial` is not used for this case (owner decision 2026-11-19). A task where all tools failed shows the existing "Failed" treatment (3.5).

### 3.5 A task that failed because no tool succeeded

The existing failed-task treatment applies (chip "Failed", stable reason text "All tools failed" mapped from `tools_failed`, attempts list). The Tools table is shown with each tool's reason, which is the explanation the tenant needs. Retry follows the existing page rules.

## 4. States

| State | Behaviour |
|---|---|
| Loading | The existing T-29 skeletons; no separate skeleton for tools (the section is part of the card's expanded content) |
| Empty / not applicable | No `tools` in the DTO (older executions, `unsupported` tasks, tasks not finished): the Tools sub-section and the summary line are **not rendered**, no placeholder. A task with `tools: []` (cannot happen by SPEC 5.4 except `nothing_to_scan`) shows the coverage line only |
| Error | The page-level error state of T-29 (retry button, correlation id). The tools data is part of the same response, so there is no separate tool error state |
| Unauthorized | The existing no-permission page (workspace visible, no `execution.view`) and the not-found page for hidden workspaces and other tenants; the tools data never loads for them |
| Live | The section updates when the task finishes through the existing hint and refetch; no new socket event is required (SPEC OQ-22) |
| Unknown future values | An unknown status renders the neutral chip "Unknown" and the reason "The tool did not complete."; the page never crashes on an unexpected enum |

## 5. Where else tool information appears

- **Logs tab:** one line per tool at start and end with the tool display name, the fixed status word and counts (task log, redacted by the LogStore); the existing task filter and level filter work unchanged. No tool stdout or stderr is shown (SPEC 12).
- **Events tab:** unchanged (task and execution transitions only; tool runs are not execution events).
- **Analysis and decision card (scan-decisioning):** unchanged.
- **T-28 list and the pipeline Executions tab:** unchanged.

## 6. Reserved for the Findings module (T-32 finding detail; not built by this module)

The Findings module owns the screen. The contract it receives (SPEC 7.2) lets it show, **Recommended** here so the two specs stay aligned:

- **Tool provenance:** chips "Found by Trivy, Grype" with the raw severity each tool reported ("Trivy: High, Grype: High") and the confidence level with its basis in words ("Higher confidence: found by 2 tools").
- **Evidence panel (code findings):** the enclosing function or block with line numbers in a mono, theme-following panel (the same treatment as the Logs panel), the focus lines marked with a non-colour marker (a gutter symbol and the text "lines 55 to 57"), a caption stating whether it is the enclosing block or a window ("Enclosing function, lines 40 to 71" or "Lines 45 to 65"), a "Shortened" note when capped. **Secret findings show the single line with the value replaced by `[REDACTED: type]` or no code at all** with the text "The secret value is never stored."
- **Link:** an external text link "Open in GitHub at this commit" (`rel="noopener noreferrer"`, opens in a new tab, destination shown as text with the host before activation, no tool-supplied URL), present only when the finding has a link; the commit is shown as a short SHA in mono.
- **Everything from the repository or a tool** (snippet, title, path) is escaped text; paths with bidirectional or control characters are shown with those characters escaped (`‮`) and have no link (SPEC 11.2).

## 7. Accessibility

- The Tools sub-section is a region with a heading (h4) inside the card region; the table has a caption, `scope` on headers, and no sortable controls.
- Status, severity and warnings use icon plus text; colour contrast follows the existing tokens (status chips use the status/severity tokens, never the accent).
- Severity pills read as text ("High 3"); the em dash in the Findings column has the accessible name "No results".
- The summary line in the collapsed card is part of the card button's accessible description; the card keeps its `aria-expanded` and focus order (breadcrumb, header actions, timeline, task cards, tab list, active panel) unchanged.
- No new live region: a status change of a task is already announced by the page's polite region; the tool list is read when the card is expanded.
- Reduced motion: no animation is added.
- Keyboard: nothing new to tab to except copy buttons of identifiers; those behave as in the rest of the app.

## 8. Responsive behaviour

At 1280 px the task-card grid has 2 columns, at 1440 px 4 columns (existing). The Tools table lives in the expanded card region and would overflow a narrow card, so below the card width of about 28rem the table is shown as a **stacked list**: each tool is a block with the name and status chip on the first line, the version and short image id (mono) and duration on the second, the findings pills on the third, and the data line last. No horizontal page scroll at either width (existing T-29 rule).

## 9. Copy and tokens summary

Use the sentence-case texts of sections 3.2 to 3.5 verbatim unless the owner edits them. Tokens only (`--status-*`, `--sev-*`, neutral surfaces); no literal hex colours; Lucide icons listed above (names to be verified against the pinned Lucide version at build); Geist Sans for text, mono for the version, the short image id and the snapshot id only.

## 10. Verification matrix (to be run by hand after implementation; nothing is claimed)

Not run. Unchecked until the screen exists:

- Task cards for each scan type with 1, 2 and 3 tools: all tools succeeded; one failed; one timed out; one unavailable (stale data); one skipped; partial; all failed (task `Failed`); `nothing_to_scan`; `gaps`.
- Each status chip and each fixed-word reason text; an unknown code and an unknown status.
- SCA row: data date, short snapshot id, "older than 3 days" warning.
- SBOM tool row showing "Components N" and the in-process "built in" adapter.
- Older execution without tools (no section, no placeholder); `unsupported` task; running task (no list) then finished (list appears after the hint).
- A hostile display name or reason injected in a mock DTO (script tags, bidirectional characters, very long strings, Markdown, a URL): rendered as inert text, never as markup or a link; the page does not break.
- Execution with 1000 findings counts and zero counts; a tool with no results (em dash).
- 1280 and 1440 widths (no horizontal page scroll; stacked list in narrow cards); light and dark themes; reduced motion.
- Keyboard-only run through an expanded card; screen reader reading of the table, caption and chips.
- Not-found page for a hidden workspace and another tenant; no-permission page; the tools never appear for them.
- Logs tab: tool lines appear with the task filter; no stdout/stderr text appears.
- The seven default roles on T-29 (the same open item as executions SCREENS section 10).

## 11. Open items for the owner

1. Chip colours for `partial` and `unavailable` (warning vs neutral).
2. Whether the coverage line should also appear on the collapsed card (Recommended: only the summary line).
3. Live per-tool progress while a task runs (SPEC OQ-22): Recommended not in v1.
4. Whether the digest short form is useful to tenants or should be admin-only (Recommended: show, it is the reproducibility handle; the full digest never leaves the server).
5. The findings-side surface of section 6 belongs to the Findings module; this file only reserves it.
