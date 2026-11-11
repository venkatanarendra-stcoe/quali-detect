# Stitch Screen Registry

**Purpose:** the single authoritative record of every Stitch screen, its validation state and its history. Process rules are in `STITCH_WORKFLOW.md` §6. Module summaries in `TENANT_APPLICATION_DESIGN.md` and `ROOT_CONSOLE_DESIGN.md` point here.

**Rules**
- Append-only. Never delete or rewrite an earlier version's record; add a new version row and update "Current".
- A status of **Approved** requires the evidence listed in `STITCH_WORKFLOW.md` §6.7. Do not set it otherwise.
- Approved screens are frozen (`STITCH_WORKFLOW.md` §6.8).
- Dates are absolute (YYYY-MM-DD).

## Statuses

| Status | Meaning |
|---|---|
| Planned | Not generated yet |
| Generated – Needs Review | Generated; QA not yet run or not yet passed |
| Auto-Correction in Progress | QA found defects; a correction attempt is running |
| Approved | Passed all mandatory checks, or approved manually by the user; frozen |
| Needs Manual Review | Still failing after 3 correction attempts, or a conflict needs a user decision |
| Rejected | Abandoned; kept for history |

## Record template

Copy this block for every new screen. One block per screen; one history row per version.

```
### <Module> — <screen name>
- Project: <projectId>
- Current screen ID: <screenId>
- HTML file ID: <fileId>            Screenshot file ID: <fileId>
- Status: <status>                  Validation: <Passed | Failed | Not run>
- Attempts: <n of 3 corrections used>
- Approval: <date or —>             Method: <Automatic | Manual | —>
- Defects identified: <list or none>
- Corrections performed: <list or none>
- Version history (newest first): <screenId | html | screenshot | status | note>
```

---

## Tenant Application — project `projects/3865828126633177668`

### Overview — Security overview dashboard
- Project: `3865828126633177668`
- Current screen ID: `e4c2f0775e084cd6b019d67597359b7a`
- HTML file ID: `a6cccea6f8f142eb9c0dd9bea75cd681` · Screenshot file ID: `cab6f17d3b5345148496c1c733bbfb58`
- Status: **Approved** · Validation: not run under the automatic workflow (predates it)
- Approval: 2026-11-09 · Method: **Manual** (user review)
- Attempts: not applicable
- Role: approved visual direction for implementation. **Frozen.** Grandfathered: it would not pass the automatic checks as written, so implementers must follow `DESIGN_SYSTEM.md` §9 (known differences: Tailwind default severity hues, Stitch-derived theme values, SLA column off-screen in the render, decorative red and orange dots, unequal bottom cards, Material Symbols).
- Defects identified (at the time): see `DESIGN_SYSTEM.md` §9.
- Corrections performed: two `edit_screens` rounds. The first was verified in the stored files. The second reported success but the stored file IDs did not change, so it is unverified.
- Version history (newest first):

| Screen ID | HTML file | Screenshot file | Status | Note |
|---|---|---|---|---|
| `e4c2f0775e084cd6b019d67597359b7a` | `a6cccea6f8f142eb9c0dd9bea75cd681` | `cab6f17d3b5345148496c1c733bbfb58` | **Approved (manual)** | Result of the first edit round on `062a47dc…` |
| `062a47dc64174a0fa392739adb89e8b7` | `6d1913eef173489d80db107e362e2359` | `5f09bdd72e3d4a7d841530ff05c49e2c` | Superseded | Created by `apply_design_system` with asset `3402573452601737212` |
| `a5544a2875be457ea9fbe1efd074f71f` (canvas instance; the screen resource is no longer listed) | `5cea26eb87104d8dbf46d879fea796ab` | `0a7951af8b4d444da42be9bb41fb70fc` | Superseded | First generation (Stitch's own "Obsidian Precision" theme, Inter, `#00f5a0`). Original screenshot also kept locally |

### Workspaces — Workspaces list
- Project: `3865828126633177668`
- Current screen ID: `db295afd8820481fa92a28227c3b700f`
- HTML file ID: `fb8c083fa0ee4479966f31cd31a1ceae` · Screenshot file ID: `21d1aaed9b52492e91538a20305cbe41`
- Status: **Generated – Needs Review** · Validation: Failed (manual review, 2026-11-09; automatic checks not run)
- Attempts: 0 of 3 under the automatic workflow. One earlier edit is unverified (see below)
- Approval: — · Method: —
- Defects identified (stored render): white search field; bright row dividers; monospace count cells printing units ("14 repos") that wrap; wrapped severity pills and "Last activity"; "Status: All" dropdown conflicting with a "Status: Active" chip; Archived row shown under an Active filter.
- Corrections performed: one `edit_screens` call reported all fixes applied. The stored HTML and screenshot file IDs did not change after several minutes, so **the correction is unverified and is not counted as persisted**.
- Version history: `db295afd…` is the only version.
- Next step: correction only on the user's explicit authorization.

### Workspaces — Workspace details (Overview tab)
- Project: `3865828126633177668`
- Current screen ID (best candidate, attempt 3): `389bb91de5c04c8aaa0b65af87734bba`
- HTML file ID: `05ddc1da537f438c94a83ebc8997b852` · Screenshot file ID: `a21bb8fe06a94dd5b102a26dc390f989`
- Local screenshots (session scratch, temporary): `/tmp/claude-1000/-home-narendra-qmentisai-sec/c6297101-453e-4a34-98a0-d7312090d9fd/scratchpad/stitch-shot/workspace-details.png` (baseline), `…/workspace-details-a1.png`, `…/workspace-details-a2.png`, `…/workspace-details-a3.png`
- Status: **Approved** · Validation: automatic checks Failed on C3, E3 and E5 after 3 of 3 attempts (recorded below); approved manually with those three recorded as accepted frontend implementation requirements. (History: Needs Manual Review on 2026-11-09 before the user's decision.)
- Attempts: **3 of 3 used**
- Approval: 2026-11-09 · Method: **Manual** (user decision, option (b))
- Role: **approved implementation reference** for the Workspace details screen, with the accepted implementation requirements below. **Frozen:** do not edit or regenerate.

**Remaining defects (attempt 3, stored HTML and screenshot):**
1. **C3 (Major):** Pipelines table, row 2, Scan types cell renders "SCA, SBO…" (ellipsis). The 84px column is too narrow for "SCA, SBOM" at 13px.
2. **E3 (Major):** the tab bar items are `div` elements with no `tabindex` or role, so they are not keyboard-focusable. The global focus rule covers only `button`, `a`, `input` and `[tabindex="0"]`.
3. **E5 (Major):** targets under 24×24px: the three policy pencil buttons are 22×22px and the workspace ID copy button is 18×18px.
4. C6 (Minor): in the third override row the label "Lead approval required" abuts its severity pill with no gap; the inherited "Mandatory scans" label and value are tight.
5. B1 (Minor): sidebar count badges are plain text, not the outlined boxes used in the approved dashboard.
6. D (Minor): loading, empty and error states are not depicted (they are specified in the design docs only).
7. Reference-only: Tailwind-free inline CSS (good), Lucide loaded from jsDelivr at a pinned version `0.468.0` (good).

**Validation results (attempt 3):**

| Check | Result | Evidence |
|---|---|---|
| A1–A5 colors and status | Pass | HTML read in full: every hex is on the allowlist; severity and status hexes exact; `rgba(255,135,61,.16)` and `rgba(245,196,81,.16)` are the severity tints |
| A3 hover | Pass | primary hover `#6BEBD0` (matches docs; no Stitch mismatch this time) |
| A6 fonts | Pass | mono only on repository names, branch names, pipeline repository names, workspace ID; counts, tab counts, times, scan types are Geist Sans |
| A7 icons | Pass | Lucide only, pinned `lucide@0.468.0`; no Material Symbols |
| A8 unapproved colors | Pass | no off-allowlist hex, no Tailwind palette classes |
| B1 shell | Pass (Minor: count badges) | full-height sidebar with wordmark row, 48px top bar to its right, exact search placeholder, standard items and order |
| B2–B6 | Pass | sentence-case group labels, no tagline, correct active-nav treatment, mint only on Edit workspace, active nav and focus ring, no dots |
| C1 | Pass | every required section visible; content ends about y=952 of 1024 |
| C2 | Pass | no overflow or overlap |
| C3 | **Fail** | "SCA, SBO…" truncated |
| C4–C5 | Pass | real tables with visible headers and fixed widths; no wrapping |
| C6 | Pass with Minor | consistent 36/44px rows; see defect 4 |
| C7 | Pass | every status is an outlined chip with a Lucide icon and 12px label |
| C8 | Pass | severity pills tinted, no border, icon + 12px label, 20px high |
| C9–C10 | Pass | counts agree (tab counts, summary, "View all N"); no conflicting controls |
| D module checklist | Pass (Minor: states) | all header items, summary, 6 tabs with Overview selected, Information (7 fields), Repositories (6 columns), Pipelines (6), Members (5 attributes), Policies (inherited locked and dimmed, overrides editable, mandatory scans, severity thresholds, review and approval requirements), Activity (5 event types) |
| E1 contrast | Pass | computed: `#7B858C` on `#171B20` 4.59, on `#111418` 4.90, on `#080A0D` 5.26; `#A1ABB2` on `#111418` 7.90; `#FF4D5A` 5.68; `#4ADE80` 10.60; `#F5C451` 11.34 |
| E2 control borders | Pass | `#68737C` on `#080A0D` 3.75 |
| E3 focus | **Fail** | tabs not focusable (defect 2) |
| E4 not color alone | Pass | icon and label on every status and severity |
| E5 targets | **Fail** | defect 3 |

**Correction log (append-only):**

| Attempt | Method | Screen ID | HTML file | Screenshot file | Result |
|---|---|---|---|---|---|
| 0 (baseline) | Initial generation (2026-11-09) | `4f79b4527e47442890babecdea889532` | `085f3b3b5f224976b304e61e87868f9c` | `8b67f27ffb65443a9374fb27b0ef0ce7` | Generated – Needs Review. Defects: Recent activity clipped out of frame (Critical); Pipelines table cells wrap; inconsistent status chips; uppercase sidebar group labels; invented "APPSEC OPS" tagline; policy severity pills without icon at 10px; Stitch hover `#38CBB0`; Material Symbols link and unpinned `lucide@latest`. Verified correct: exact hex values, Lucide rendering, mono scope, mint scope, inherited-versus-override distinction |
| 1 | Replacement generation | `998d283f1ee74feb946c4262b01a2779` | `df20fc6ea46c465ca20d977938db2e10` | `9027a52d65cd486e9235fd51dda54d00` | **Fail.** Fixed: Recent activity now visible; hover `#6BEBD0`. New or remaining defects: tables rendered as bordered row cards with no column headers and blank gaps (Critical); Pipelines count replaced by "3 findings"; monospace on nav counts, tab counts, "N findings", scan-type tags, relative times, policy values and key hint; Material Symbols stylesheet still linked and Lucide `@latest`; off-palette `#E1E4EA`; search placeholder changed to "Search resources, CVEs, rules..." and moved right; top bar `#080A0D`; chips mostly without icons; severity pills bordered, no icon, 10px; cramped header spacing; "Enforced" label added; stretched cards with empty gaps |
| 2 | Replacement generation | `0b5b35fcbadc4d8abb33e44d63a91dba` | `eb4e177236ec4357864321306f02700a` | `896701f7fb4a43f995d5f03d569e9aaf` | **Fail.** Scripted lint of the saved HTML passed: no off-allowlist hex, no Tailwind palette classes, no Material Symbols, pinned `lucide@0.468.0`, no uppercase labels, correct `<title>`, mono only on identifiers, focus-visible rule present. Fixed from attempt 1: real tables with headers, chips with icons, tinted pills with icons, search text, spacing. Remaining: shell changed (full-width top bar above the sidebar; Major); "Default bran…" header truncated; "Security review required" row and Medium pill wrap; Succeeded chip touching the card edge |
| 3 | Replacement generation | `389bb91de5c04c8aaa0b65af87734bba` | `05ddc1da537f438c94a83ebc8997b852` | `a21bb8fe06a94dd5b102a26dc390f989` | **Fail (3 mandatory checks).** Fixed from attempt 2: shell, header truncation, pill wrapping, chip edge. Remaining: C3, E3, E5 above |

Evidence notes: all three attempts were replacement generations, so no `edit_screens` persistence question arose. For attempts 1 and 3 the HTML was returned inline (read in full, not scripted); for attempt 2 it was saved to a file and linted with a script.

**Version history (newest first):** `389bb91d…` (attempt 3, current) · `0b5b35fc…` (attempt 2) · `998d283f…` (attempt 1) · `4f79b452…` (baseline). All four remain in the Stitch project.

**Decision (2026-11-09, user): approve attempt 3 manually.** All four versions and the correction history above are preserved.

**Accepted frontend implementation requirements** (these were the three mandatory failures; they are now requirements for the real frontend, not Stitch fixes):
1. **Scan types:** the pipeline Scan types column displays the complete value (for example "SCA, SBOM") without truncation.
2. **Tabs:** the tab bar is keyboard-accessible: tabs are focusable elements (`button` or link, or `role="tab"` with roving focus) with a visible focus ring.
3. **Target size:** policy edit (pencil) controls and the workspace ID copy control are at least 24×24px (28×28 preferred).

**Minor observations, recorded and non-blocking:** a label abuts its severity pill in the third override row and the inherited "Mandatory scans" label and value are tight (keep at least 8px between label and pill); sidebar count badges are plain text in the Stitch render (implement as outlined boxes like the approved dashboard); loading, empty and error states are not depicted (implement per `UX_GUIDELINES.md` §8).

### Repositories — Repositories list
- Project: `3865828126633177668`
- Current screen ID: `8d39a79572664db28cecd26eeebf992d`
- HTML file ID: `bc05f22e932744fcbfdccdc5f000f969` · Screenshot file ID: `183007f6958c4c96978b22d00452cb11`
- Local screenshots (session scratch, temporary): `…/scratchpad/stitch-shot/repositories-a0.png` (initial), `…/repositories-a1.png` (approved)
- Status: **Approved** · Validation: **Passed** (all mandatory checks; minor items recorded)
- Attempts: **1 of 3** correction attempts used (initial generation + 1 replacement)
- Approval: 2026-11-09 · Method: **Automatic** (`STITCH_WORKFLOW.md` §6.7)
- Role: **approved implementation reference** for the Repositories list, with the notes below. **Frozen:** do not edit or regenerate.
- Module requirements checked (TENANT doc §3.3): table columns Repository (mono), Provider, Default branch (mono), Pipelines, Connection health, Last scan, Open findings, plus a Workspace column for the workspace relationship; primary action Connect repository; row actions (sync, disconnect) via a row-actions button; filters for provider, workspace and health plus search; pagination with rows per page; all four connection states (Healthy, Degraded, Disconnected, Not connected); counts consistent (65 repositories, Showing 1-10 of 65, 10 rows per page).

**Defects found in the initial generation (`c48d5fbe…`, fixed by the replacement):**
1. **E3 (Major):** the top-bar avatar was a `div` with `cursor:pointer` and could not take keyboard focus. Fixed: `<button aria-label="Account menu">`, 28×28px, covered by the global focus ring.
2. B1 (Minor): the sidebar icon set differed from the Workspace Details reference. Fixed by specifying the canonical Lucide set (see `DESIGN_SYSTEM.md` §11); the stored HTML uses exactly those names.
3. C6 (Minor): the table was 984px inside a 990px card interior, leaving a gap at the right edge of the header row. Fixed: table width 990px.

**Validation results (approved version, stored HTML read in full and screenshot reviewed; not scripted, because the HTML came back inline):**

| Check | Result | Evidence |
|---|---|---|
| A1–A5 | Pass | every hex on the allowlist (`#080A0D #0B0D10 #111418 #171B20 #272D33 #68737C #3A434B #F4F7F8 #A1ABB2 #7B858C #40E0C0 #04110E #112625 #6BEBD0 #4ADE80 #F5C451 #FF4D5A`; severity tints `rgba(255,77,90,.16)`, `rgba(255,135,61,.16)`); primary hover `#6BEBD0`; connection chip tones per `DESIGN_SYSTEM.md` §10 |
| A6 | Pass | monospace only on repository names and branch names |
| A7 | Pass | Lucide only, pinned `lucide@0.468.0`; no Material Symbols |
| A8 | Pass | no off-allowlist hex, no Tailwind palette classes |
| B1–B6 | Pass | full-height sidebar with wordmark row, 48px top bar to its right, exact search placeholder, canonical sidebar icons and order, sentence-case group labels, outlined count badges, no tagline, active nav = mint text, `#112625` tint and a 2px mint bar, mint only on Connect repository, active nav and focus ring, no dots |
| C1–C2 | Pass | everything visible in 1280×1024 (content ends about y=632); no overflow or overlap |
| C3–C5 | Pass | real `<table>` with `<thead>`, fixed widths summing to 990px, no truncation or wrapping |
| C6 | Pass | 36px rows, 32px header, consistent padding |
| C7 | Pass | all four connection states are outlined chips with Lucide icons |
| C8 | Pass | tinted severity pills with icons, 12px text, 20px high, no wrapping |
| C9–C10 | Pass | counts agree; no conflicting filters (all "All", no chips) |
| D | Pass | see requirements checked above |
| E1 | Pass | same pairs as the other approved screens: `#7B858C` on `#171B20` 4.59, on `#111418` 4.90; `#A1ABB2` 7.90; `#FF4D5A` 5.68; `#4ADE80` 10.60; `#F5C451` 11.34 |
| E2 | Pass | control borders `#68737C` on `#080A0D` 3.75, on `#111418` 3.81 |
| E3 | Pass | every clickable element is a `button` or `a`; `focus-visible` 2px `#40E0C0` outline, 2px offset |
| E4 | Pass | icon and label on every status and severity |
| E5 | Pass | all buttons are at least 28×28px |

**Minor observations (recorded, non-blocking; implement correctly in the frontend):**
1. "None" in the Open findings column renders in primary text color `#F4F7F8`, because the stored CSS defines `td.text-muted` and the span uses `.text-muted`. The design intent is muted `#7B858C` (as in the Workspaces list). Implement as muted.
2. The row-actions menu (Sync now, Disconnect with typed confirmation) and loading, empty and error states are not depicted. Implement per `UX_GUIDELINES.md` §6 and §8.
3. Bitbucket uses the Lucide `git-pull-request` icon because Lucide has no Bitbucket brand icon; use a proper provider mark or a generic icon in the frontend.
4. The Connect repository wizard is a separate screen, not designed yet.
5. The approved Workspace details and dashboard references use different sidebar icons; the frontend uses the canonical set in `DESIGN_SYSTEM.md` §11.

**Correction log:**

| Attempt | Method | Screen ID | HTML file | Screenshot file | Result |
|---|---|---|---|---|---|
| 0 | Initial generation | `c48d5fbee1a648a5893979e4b63b1c75` | `9441cc6191c64094a43e678f3baf98b2` | `24ddadefb5064583a4fd55948d0782ab` | Fail (E3 avatar `div`; minor: icon set, table 984px) |
| 1 | Replacement generation | `8d39a79572664db28cecd26eeebf992d` | `bc05f22e932744fcbfdccdc5f000f969` | `183007f6958c4c96978b22d00452cb11` | **Pass → Approved (Automatic)** |

**Version history (newest first):** `8d39a795…` (approved) · `c48d5fbe…` (initial). Both remain in the Stitch project.

## Tenant Application — workspace and repository flows (inventory, planned 2026-11-09)

> **2026-11-09 — Stitch screen generation suspended by user decision.** UI work continues code-first in `apps/tenant-web` using the approved screens and `docs/design/` as visual references. The inventory below (F1–F21) is **not** being generated. Status at suspension: F1 attempt 0 `18b25de7…` (Create Workspace step 1; defects: global search border `#272D33`, mono "⌘K" hint, abbreviated summary value) and attempt 1 `99f68535…` (HTML `3a75fec7…`, screenshot `7a0ed2fc…`; fixed those three; one Major remaining: the sidebar wordmark shield icon was mint, check B5). A third generation (attempt 2) was sent and never retrieved or reviewed; if it appears in the project it is unreviewed and unapproved. Nothing from F2–F21 was generated. Existing approved screens (dashboard, Workspace details, Repositories list) remain the visual references.


Requirements: `TENANT_APPLICATION_DESIGN.md` §3b. Execution order as authorized by the user. Update each row (and add a full record above) as a screen is generated and validated.

| # | Screen | Status | Screen ID |
|---|---|---|---|
| F1 | Create Workspace — step 1 Details | Planned | — |
| F2 | Create Workspace — step 2 Members & access | Planned | — |
| F3 | Create Workspace — step 3 Policies | Planned | — |
| F4 | Create Workspace — step 4 Review & create | Planned | — |
| F5 | Connect Repository — provider selection | Planned | — |
| F6 | Connect Repository — authorize GitHub | Planned | — |
| F7 | Connect Repository — authorize GitLab | Planned | — |
| F8 | Connect Repository — authorize Bitbucket | Planned | — |
| F9 | Connect Repository — repository selection | Planned | — |
| F10 | Connect Repository — workspace assignment & configuration | Planned | — |
| F11 | Connect Repository — default branch & permissions | Planned | — |
| F12 | Connect Repository — validation in progress | Planned | — |
| F13 | Connect Repository — success | Planned | — |
| F14 | Connect Repository — failure & recovery | Planned | — |
| F15 | Repository Details — full view (Overview) | Planned | — |
| F16 | Workspace — Members & Groups | Planned | — |
| F17 | Workspace — Policies | Planned | — |
| F18 | Workspace — Activity | Planned | — |
| F19 | Repository — Settings & Access | Planned | — |
| F20 | Repository — Branches & Activity | Planned | — |
| F21 | Repository — Security Overview | Planned | — |

---

## Tenant Application — planned modules (no screens yet)

| # | Module | Status |
|---|---|---|
| 3 | Repositories | Approved (see record above) |
| 4 | Pipelines | Planned |
| 5 | Pipeline execution details | Planned |
| 6 | Scan History | Planned |
| 7 | Findings | Planned |
| 8 | Finding details | Planned |
| 9 | Security Reviews | Planned |
| 10 | Approvals | Planned |
| 11 | Remediation | Planned |
| 12 | Policies | Planned |
| 13 | Reports | Planned |
| 14 | Integrations | Planned |
| 15 | Users, Groups, Roles | Planned |
| 16 | Audit Logs and Settings | Planned |

## Root Console — project `projects/7652438332940652451`

No screens. Generation is deferred until the Tenant Application direction is complete.

| # | Module | Status |
|---|---|---|
| 1 | Platform Dashboard | Planned (deferred) |
| 2 | Tenant Management | Planned (deferred) |
| 3 | Subscription and License Management | Planned (deferred) |
