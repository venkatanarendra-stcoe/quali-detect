# Stitch Workflow

**Status:** Final — revision 4 (adds the automatic QA, correction and approval workflow, §6). Written from observed behavior of the connected Stitch MCP, not from documentation.
**Purpose:** how Claude Code and other AI tools use Stitch for QmentisAI design references, what Stitch can and cannot do, and the registry of projects and screens.

Stitch output is **visual reference only**. It is HTML (Tailwind v3 via CDN, inline styles, Material Symbols) and screenshots. It is not production code and does not define the design system. `DESIGN_SYSTEM.md` does.

---

## 1. Registry

| Item | ID | Notes |
|---|---|---|
| Tenant Application project | `projects/3865828126633177668` | "QmentisAI Tenant Application" |
| Root Console project | `projects/7652438332940652451` | "QmentisAI Root Console". Untouched; no screens yet |
| Shared design system asset (dark) | `assets/3402573452601737212` | "QmentisAI Obsidian (Dark)". Global asset, version 2 |
| Stitch-generated project theme | `assets/a5dfa74503ee433483e71fb3aa65b64b` | "Obsidian Precision" (Inter, `#00f5a0`). **Not approved.** Do not apply |
| **Approved Tenant dashboard** | `screens/e4c2f0775e084cd6b019d67597359b7a` | Approved reference. Do not edit |
| **Approved Workspace details** | `screens/389bb91de5c04c8aaa0b65af87734bba` | Approved manually 2026-11-09 with accepted implementation requirements (registry, TENANT doc §3.2a). Do not edit. Earlier versions `4f79b452…`, `998d283f…`, `0b5b35fc…` kept |
| **Approved Repositories list** | `screens/8d39a79572664db28cecd26eeebf992d` | Approved automatically 2026-11-09 (first screen through the §6 workflow; 1 of 3 correction attempts). Initial version `c48d5fbe…` kept. Do not edit |
| Earlier dashboard versions | `screens/062a47dc64174a0fa392739adb89e8b7`; original `a5544a28…` | Kept for reference; do not delete. See §4 |

The authoritative per-screen records (status, file IDs, validation, defects, corrections, attempts, approval) are in `STITCH_SCREEN_REGISTRY.md`. `TENANT_APPLICATION_DESIGN.md` §4 and `ROOT_CONSOLE_DESIGN.md` §4 hold short module summaries only. Update the registry whenever a screen is generated, corrected or approved.

Pre-existing, unrelated Stitch projects ("Scanyx AppSec Platform Design", "Premium Engineer Portfolio Experience") belong to the user's account. Do not read from or modify them.

---

## 2. Available tools and what they do

| Need | Tool | Observed behavior |
|---|---|---|
| List / inspect projects | `list_projects`, `get_project` | `list_projects` output is large; filter with `jq`. `get_project` returns the project theme and `screenInstances` (screen instance IDs and design-system instances) |
| Create project | `create_project` | Works |
| Generate a screen | `generate_screen_from_text` | Often exceeds the tool timeout (several minutes). **Do not retry.** Poll `list_screens` / `get_project` |
| Edit screens | `edit_screens` | Same timeout behavior. Applies DOM-level operations. May create a new screen or update the stored one; see §4 |
| Variants | `generate_variants` | Available; not yet used |
| Read a screen | `list_screens`, `get_screen` | `list_screens` can return `{}` for several minutes after generation, then the screen appears |
| Download | `download_file` | Takes `html_code.name` or `screenshot.name`. Returns the HTML inline or a base64 PNG (usually too large for the context, so it is saved to a file; decode with `jq -r .image \| base64 -d`) |
| Design systems | `create_design_system`, `update_design_system`, `apply_design_system`, `list_design_systems`, `upload_design_md`, `create_design_system_from_design_md` | See §3 |
| Delete project | `delete_project` | Not used. Needs explicit user confirmation |

`list_design_systems` without `projectId` returns "invalid argument"; always pass the project ID.

---

## 3. Design-system behavior (important)

Observed on 2026-11-09:

1. **Generation ignores a passed design system for the project theme.** Passing `designSystem` to `generate_screen_from_text` did not attach it. Stitch created its own project theme ("Obsidian Precision": Inter, JetBrains Mono labels, `#00f5a0`, FIDELITY variant) and rewrote the prompt. Passing an asset ID is not proof it was applied.
2. **`update_design_system` did not change the project theme.** It returns a session ID and the project theme stayed on Stitch's generated values (tested twice).
3. **`apply_design_system` works per screen.** Applied to a screen instance, it produced a screen whose theme reports Geist (headline, body, label), `customColor #40E0C0`, `overrideNeutralColor #080A0D`, `NEUTRAL`, `ROUND_FOUR`. It creates a new screen resource and repoints the canvas instance to it. The old screen resource disappears from `list_screens` (its screenshot file remains).
4. **Stitch derives its own palette** from the seed and neutral overrides. It produced `primary #3cdebe`, `background #0c0e11`, not the exact inputs.
5. **A design system changes theme tokens only.** Hard-coded values in the generated HTML (including severity hues) come from the prompt text, not from the design system. Without explicit hex values in the prompt, Stitch falls back to Tailwind defaults (for example `#EF4444`, `#F97316`, `#EAB308`, `#64748B`).
6. Stitch has no Geist Mono in its font enum, but its generated HTML loads Geist and Geist Mono from Google Fonts when the prompt asks for them.

**Therefore:** every generation or edit prompt must restate the exact tokens (§5). Verify the result against `DESIGN_SYSTEM.md`, never against the Stitch-reported theme.

---

## 4. Edit and duplicate behavior

- `apply_design_system` replaces the screen resource behind a canvas instance (see §3.3).
- `edit_screens` sometimes returns DOM operations that apply to the stored screen, and sometimes creates a new screen. After the final tool call for the approved dashboard, the stored file IDs did not change, so the second round of edit operations could not be verified from the API. Treat tool success messages as unverified until the screenshot or HTML is re-downloaded and checked.
- **Edits are not reliably visible through the API.** Two `edit_screens` calls (dashboard round 2, Workspaces) returned detailed DOM operations and success text, but `get_screen` kept the same HTML and screenshot file IDs for several minutes afterwards. Whether the edit exists only in the Stitch editor session is not confirmed. The only way to verify is to open the screen in the Stitch editor, or to re-download after a long delay. Do not report an edit as done based on the tool's text.
- Because of this, the most dependable way to get a correct screen is a complete, precise first prompt (§5) rather than relying on later edits. Keep prompts to content that must appear: Stitch tends to add wrapping, units and filters of its own.
- Stitch took initiative on content in the Workspaces generation: it printed units ("14 repos"), used monospace for counts, and drew a white search input. Say explicitly "numbers only", "no monospace except identifiers" and "all inputs dark (#080A0D, border #68737C)".
- Replacement generation is the approach that has worked: three replacement screens for Workspace details were generated and retrieved without any edit-persistence question. Two of the three `generate_screen_from_text` calls returned within the tool timeout; the others timed out and appeared later.
- Dense, pixel-budgeted layout instructions made Stitch collapse tables into bordered row cards (no column headers) and stretch cards with empty gaps. Ask for real `<table>` elements with `<thead>`, forbid `justify-between`/`flex-1`, and give column widths sized for the content. Even with exact widths, a column can still truncate ("SCA, SBO…"); budget more width than the arithmetic suggests.
- What worked for Repositories (first screen to pass the automatic workflow): explicit shell geometry, 'real <table> with <thead>', exact column widths with spare room, content-sized cards, and listing the interactive element types. The first generation had one Major defect (a non-focusable avatar `div`); one replacement fixed it.
- **2026-11-16 (owner decision, Confirmed): the shell has no top bar; the geometry lines below that mention a 48px top bar are historical.** Stitch changes the shell if the prompt is ambiguous (it moved the top bar above the sidebar). State the shell geometry explicitly every time.
- Never delete screens to tidy duplicates. Record them in the registry instead.
- Approved screens are frozen. To iterate, generate a variant or a new screen and register it.

---

## 5. Prompt template for every new screen

Every Tenant screen prompt must include, verbatim:

```
Use the same shell and visual language as the approved QmentisAI Tenant dashboard.
Desktop, dark theme. Flat: no gradients, glows, blurs, shadows. 1px borders.
Exact colors: background #080A0D; sidebar #0B0D10; cards #111418; elevated/hover #171B20;
borders #272D33; control borders #68737C; text #F4F7F8; secondary text #A1ABB2; tertiary #7B858C.
Mint #40E0C0 (never #00F5A0) ONLY on: the single primary button (text #04110E), the active
sidebar item (mint text, #112625 tint, 2px mint left bar, no dot), focus ring, and at most one
key chart/series highlight. No mint dots, borders, progress bars or status colors.
Severity (pill: 16% tint, no border, icon + Geist label): Critical #FF4D5A, High #FF873D,
Medium #F5C451, Low #55A8FF (blue, not gray), Info #9AA6B2.
Status: outlined 1px chip (#3A434B), icon + label; success #4ADE80, danger #FF4D5A, warning #F5C451, else neutral #A1ABB2.
Typography: Geist Sans for ALL UI (nav, headings, breadcrumbs, labels, captions, table headers,
buttons). Geist Mono ONLY for identifiers (repo/branch paths, commit SHAs, fingerprints, file paths, code, logs).
Radius: 4px chips/buttons/inputs, 6px cards. Sidebar 240px, top bar 48px, page padding 24px, rows 36px.
Sidebar: Overview; Engineering: Workspaces, Repositories, Pipelines, Executions, Scan History;
Security: Findings (248), Security Reviews (14), Approvals (6), Remediation, Policies, Reports;
Administration: Users, Groups, Roles & Permissions, Integrations, Audit Logs; footer: Settings, Docs, user.
Highlight the current module in the sidebar.
All table columns must be fully visible without horizontal clipping. Cards in a row have equal height.
No extra KPIs, version badges or invented metrics beyond what is listed below.
```

Then append the screen-specific content from the design doc.

Additional mandatory lines learned from QA (append to every prompt):

```
Sidebar group labels are Geist 12px medium SENTENCE CASE (Engineering, Security, Administration), never uppercase. No taglines, version badges or subtitles under the QmentisAI wordmark.
Icons: Lucide only (outline, 1.75 stroke). No Material Symbols.
The frame is 1280x1024 and ALL required sections must be fully visible inside it: reduce table rows (3 per table) or column count rather than letting any section fall below the frame. No fixed-height container may hide content.
Every status (Active, Healthy, Degraded, Enabled, Disabled, Running, Succeeded, Failed, Invited) is an OUTLINED 1px chip (border #3A434B, 4px radius) with a Lucide icon and Geist label; never plain colored text.
Severity pills: 16% tint, no border, severity Lucide icon + label, 12px text (never smaller than 11px).
Tables: fixed column widths that fit the card without scrolling; no wrapping in any cell; one line per row (two lines only for a name with a small subtitle). Numbers only in count columns (no units), Geist Sans, right-aligned. No monospace except identifiers.
All inputs and dropdowns are dark (#080A0D, 1px #68737C border). Filters must agree with the rows shown.
Do not add any content, labels or metrics that are not listed in the screen description.
Use real <table> elements with a visible <thead> for tabular data; never render table rows as bordered cards.
Do not use justify-between or flex-1 stretching to spread content vertically; cards take natural height.
The sidebar is full height from y=0; the top bar sits to its right (x=240 to 1280), never above it.
Every clickable element (including tabs) is a <button> or <a>; icon buttons are at least 28x28px, never below 24x24px.
Size every table column for its widest content at 13px (about 8px per character plus 16px padding); no ellipsis in headers or in data cells except long free text. Keep at least 8px between a label and an adjacent pill or chip.
Sidebar count badges (248, 14, 6) are Geist 11px in outlined 4px boxes (border #272D33).
Sidebar icons use exactly the canonical Lucide names in DESIGN_SYSTEM.md section 11. The top-bar avatar is a <button> (28x28, aria-label 'Account menu'), never a div. A table is exactly as wide as its card interior.
Every muted element carries its own color #7B858C on the element itself (for example 'None'); do not rely on a parent selector.
```

---

## 6. Automatic QA, correction and approval workflow

**Authority:** from 2026-11-09 the user authorized Claude to review, correct and approve new Stitch screens automatically when they pass every mandatory check below. The user is not asked to approve each screen. Exceptions that always require the user: §6.8 (existing screens), §6.9 (design-system conflicts), and any screen in **Needs Manual Review**.

Authoritative records live in `STITCH_SCREEN_REGISTRY.md`. Statuses: Planned · Generated – Needs Review · Auto-Correction in Progress · Approved · Needs Manual Review · Rejected.

### 6.1 Pipeline for every new screen

1. **Read** the relevant design docs (`DESIGN_SYSTEM.md`, `UX_GUIDELINES.md`, the module spec in `TENANT_APPLICATION_DESIGN.md` or `ROOT_CONSOLE_DESIGN.md`) and `FEATURE_CATALOG.md` / `PRODUCT_REQUIREMENTS.md` where the module needs them. Build the **requirements checklist** for the screen (section D below) before generating.
2. **Generate** with `generate_screen_from_text` (template in §5). On timeout do not retry; poll (§2). Set the registry status to Generated – Needs Review and record the screen ID.
3. **Retrieve the stored HTML** (`download_file` on `html_code.name`).
4. **Capture the stored screenshot** (`download_file` on `screenshot.name`, decode, view).
5. **Review** against §6.3. Record every check as pass or fail with evidence.
6. **List defects** with a severity (§6.4). If none, go to step 10.
7. **Correct** (§6.5). Status: Auto-Correction in Progress.
8. **Retrieve the stored HTML and screenshot again** and confirm the correction is actually present (§6.5).
9. **Repeat from step 5**, up to 3 correction attempts.
10. **Approve** only when §6.7 is satisfied; otherwise set Needs Manual Review. Update the registry in the same turn.

### 6.2 Evidence rules

- The **stored screenshot** is the render of record. The stored HTML is the source for hex values, fonts, icon libraries and structure. Both must agree: everything required must be visible in the screenshot, not merely present in the HTML.
- A tool success message is never evidence. Evidence is the retrieved stored HTML plus the stored screenshot.
- Counted facts: hex values are read from the HTML; contrast ratios are computed (WCAG relative luminance); layout defects (clipping, wrapping, overflow) are judged from the screenshot, using the HTML to explain them (for example a fixed-height `overflow-hidden` container).
- Known limits: `download_file` returns HTML inline or, when the result is large, saves it to a file; which happens is not controllable (a 50KB page was saved to a file, a 44KB page came back inline). When saved, run a script on it (hex allowlist, Tailwind classes, Material Symbols, uppercase, `<title>`, mono usage, focus rules). When inline, review it by reading. There is no independent browser render, so layout is judged from the stored screenshot. State in the validation record which checks were scripted and which were read, instead of claiming mechanical checks that did not run.

### 6.3 Mandatory checks

Each check is Pass or Fail. Any Fail is at least a Major defect (§6.4). "Source" says how it is verified.

**A. Design system**

| ID | Check | Source |
|---|---|---|
| A1 | Surfaces: background `#080A0D`, sidebar `#0B0D10`, cards `#111418`, elevated and table header `#171B20`, borders `#272D33`, control borders `#68737C` | HTML |
| A2 | Text: primary `#F4F7F8`, secondary `#A1ABB2`, muted `#7B858C` (the documented `--subtle-foreground`). A proposed muted value `#6F7A82` fails AA on cards (4.21:1) and elevated surfaces (3.94:1) and is **not** adopted | HTML |
| A3 | Accent: fill `#40E0C0`, text on accent `#04110E`; hover fill `#6BEBD0` (see note below) | HTML |
| A4 | Severity: Critical `#FF4D5A`, High `#FF873D`, Medium `#F5C451`, Low `#55A8FF` (blue), Info `#9AA6B2` | HTML + screenshot |
| A5 | Lifecycle and other status colors and icons exactly as `DESIGN_SYSTEM.md` §10 (success `#4ADE80`, danger `#FF4D5A`, warning `#F5C451`, neutral `#A1ABB2`) | HTML + screenshot |
| A6 | Geist Sans for all UI text; Geist Mono only for repository and branch names, workspace and other IDs, SHAs, fingerprints, file paths, code and terminal output. Never for counts, units, dates, labels, nav | HTML + screenshot |
| A7 | Lucide icons only (`data-lucide`, Lucide SVG). No Material Symbols class, font link or ligature text | HTML |
| A8 | No unapproved colors. Every hex in the HTML must be in the allowlist: `#080A0D #0B0D10 #111418 #171B20 #272D33 #68737C #3A434B #F4F7F8 #A1ABB2 #7B858C #40E0C0 #04110E #112625 #6BEBD0 #FF4D5A #FF873D #F5C451 #55A8FF #9AA6B2 #4ADE80` (alpha tints of severity and status colors allowed). No Tailwind palette classes for color (for example `text-red-500`, `bg-slate-800`) and none of the Tailwind default hexes (for example `#EF4444 #F97316 #EAB308 #22C55E #3B82F6 #64748B #94A3B8`) | HTML |

Note on A3: Stitch tends to render its own hover shade (`#38CBB0` was seen). Hover is not visible in the static render and the real frontend takes hover from the tokens. A hover-only mismatch is classed **Minor** and recorded. This classification is flagged for the user to confirm; until confirmed, a hover mismatch alone does not block approval but must be listed.

Note on A8: the allowlist applies to colors actually used in markup and CSS. Unused entries in a generated Tailwind theme config do not count, but are recorded.

Note on E3 and E5: these are verified from the HTML. Tabs and any clickable element must be a focusable element (`button`, `a`, or `tabindex="0"`) covered by a visible focus style, and icon buttons must be at least 24×24px (28×28 preferred).

**B. Brand consistency**

| ID | Check | Source |
|---|---|---|
| B1 | Same Tenant shell: 240px sidebar with the standard groups and items in the standard order, 48px top bar, workspace switcher, search with ⌘K, bell, theme toggle, avatar, user footer | Screenshot + HTML |
| B2 | Sidebar group labels in sentence case (no `uppercase`, no `text-transform`) | HTML + screenshot |
| B3 | No invented taglines, version badges, mono subtitles or extra branding | Screenshot |
| B4 | Active nav item: mint text and icon, `#112625` tint, 2px mint left bar, no dot or badge | HTML + screenshot |
| B5 | Mint only on the single primary button, the active nav item and focus styles | HTML + screenshot |
| B6 | No decorative dots or accents. The only dot allowed is an unread-notification count badge | Screenshot |

**C. Layout and usability**

| ID | Check | Source |
|---|---|---|
| C1 | Every required section is visible in the intended frame (1280×1024). A section present in the HTML but clipped by the frame is a failure | Screenshot |
| C2 | No horizontal overflow or scrollbars; nothing overlaps | Screenshot + HTML |
| C3 | No unintended clipping or ellipsis. Ellipsis is acceptable only on long free text (descriptions, finding titles), never on identifiers, statuses, dates, numbers or units | Screenshot |
| C4 | Tables: every documented column visible with a readable fixed width; no table inside a narrower scroll container | Screenshot + HTML |
| C5 | No wrapping of labels, values, units, dates, status chips or severity pills | Screenshot |
| C6 | Consistent row heights within a table and consistent card padding, gaps and alignment (4px grid) | Screenshot |
| C7 | Status chips are all outlined 1px chips with icon and label, from the §10 mapping. No plain-text statuses in some rows and chips in others | HTML + screenshot |
| C8 | Severity pills: tinted fill, documented icon, label at 11px or larger (12px preferred), the `--sev-*` colors | HTML + screenshot |
| C9 | Cards in one row have equal height; the page has no large empty region caused by layout | Screenshot |
| C10 | No conflicting or misleading controls: filter dropdowns agree with filter chips and with the rows shown; counts agree across tabs, summary and "View all" | Screenshot + HTML |

**D. Module requirements.** Before generating, derive a checklist from the module spec: every section, table column, action, filter, state and affordance the spec lists. The screen passes D only if every item is present and visible, controls look like controls (primary action, row actions, links, tabs with a selected state, copy buttons, filters), and the sample data is internally consistent and plausible. Requirements that appear only in the prompt (for example a user's explicit request) are part of the checklist. A screen that looks good but omits a required item fails.

**E. Accessibility**

| ID | Check | Source |
|---|---|---|
| E1 | Text contrast per `DESIGN_SYSTEM.md` §5: 4.5:1 for normal text, 3:1 for large text, computed from the hex pairs actually used | Computed |
| E2 | Control borders and focus indicators 3:1 against adjacent colors | Computed |
| E3 | A visible focus style exists on interactive elements (mint ring or border) | HTML |
| E4 | Meaning never rests on color alone (severity and status carry icon and label) | Screenshot |
| E5 | Interactive targets at least 24×24px | HTML |

### 6.4 Defect severity

- **Critical:** a required module section or control is missing or not visible; a forbidden library or the wrong brand color on the primary action; text below 3:1 contrast; overflow or clipping that hides data.
- **Major:** any other failed mandatory check in A–E (for example an unapproved hex, monospace misuse, wrapping, inconsistent chips, missing severity icons, uppercase group labels, invented branding).
- **Minor:** a cosmetic variance that is not covered by a mandatory check (for example a 1–2px alignment drift, a different but valid Lucide icon choice, or a hover-only color mismatch per the A3 note). Minor defects are recorded and do not block approval.

### 6.5 Automatic correction

1. Write a **precise correction list** from the defects (what is wrong, where, expected value).
2. **Prefer a replacement screen**: run a new `generate_screen_from_text` whose prompt is the original prompt plus the corrections stated as explicit requirements, including the observed Stitch tendencies (§4). Use `edit_screens` only for a narrow defect, and only once edit persistence has been verified at least once in this project. Edit persistence is currently **unverified** (§4), so replacement is the default.
3. **Preserve all versions.** A replacement is a new screen with a new ID. The previous screen stays in the project and in the registry history. Do not delete screens or call `apply_design_system` on a screen you want to keep (§3.3).
4. **Verify persistence.** Re-retrieve the stored HTML and screenshot of the new or edited screen. The correction is successful only if the retrieved HTML contains it **and** the screenshot shows it. If the file IDs and content are unchanged after the tool reports success, treat the correction as not persisted.
5. **Attempt count:** the initial generation is attempt 0. Each correction (one generate or edit call plus re-validation) is an attempt. The maximum is **3**.
6. After three failed attempts, set **Needs Manual Review**, record every remaining defect, and stop work on that screen. Continue only after the user decides.

### 6.6 Timing

Generation and edit calls commonly time out or return late. Poll `list_screens` and `get_screen` at intervals of a few minutes. Do not start a second generation for the same screen while one is pending, because it creates duplicates.

### 6.7 Automatic approval criteria

Approve only when **all** hold:

- Every item of the module requirements checklist (D) is present and visible.
- Checks A1–A8, B1–B6, C1–C10 and E1–E5 pass (a hover-only A3 mismatch is allowed as Minor).
- No Critical or Major defect remains; no unintended clipping or overflow.
- The stored screenshot matches the stored HTML.
- No unresolved accessibility or design-system conflict (§6.9).

On approval, in the same turn:

- Set the registry status to **Approved**, method **Automatic**, with the date.
- Record project ID, current screen ID, **HTML file ID** and **screenshot file ID**.
- Record the validation results (each check, evidence, the contrast ratios computed), the correction history and the attempt count, and any Minor defects.
- Mark the screen as an **approved implementation reference**. The real frontend still implements `DESIGN_SYSTEM.md` tokens, not Stitch markup.

### 6.8 Protection of existing screens

- **Approved screens are frozen.** Never edit, regenerate, restyle or call `apply_design_system` on them. The frozen set: Tenant dashboard `e4c2f0775e084cd6b019d67597359b7a` Workspace details `389bb91de5c04c8aaa0b65af87734bba` (both approved manually) and Repositories list `8d39a79572664db28cecd26eeebf992d` (approved automatically), all in project `3865828126633177668`.
- Earlier versions and existing registry records are preserved.
- The Workspaces list (`db295afd…`) and Workspace details (`4f79b452…`) stay **Generated – Needs Review**. They enter this workflow only when the user explicitly authorizes their correction and review.
- This workflow applies automatically to **new** screens only.

### 6.9 Accessibility and design-system conflicts

If a documented color fails a required contrast, or a request conflicts with the documented system:

1. Do **not** silently substitute a different color.
2. Report the conflict with the computed ratios.
3. Propose an accessible token adjustment in `DESIGN_SYSTEM.md` (as a proposal).
4. Apply it to screens only after the user updates the design-system decision.
5. Do not approve the screen while the mandatory requirement is unresolved; set Needs Manual Review if blocked.

Example already found: muted text `#6F7A82` (proposed) fails AA, so the documented `#7B858C` stays.

### 6.10 Registry upkeep

Record, for every screen: module and name, project ID, current screen ID, HTML file ID, screenshot file ID, validation status, defects identified, corrections performed, attempts used, approval date and approval method (Automatic or Manual). Add version rows; never overwrite earlier ones. Use the template in `STITCH_SCREEN_REGISTRY.md`.

## 7. Implementation rule

The real frontend implements `DESIGN_SYSTEM.md` tokens exactly, regardless of the colors, fonts or layout quirks of any Stitch render. Use Stitch screens for layout, hierarchy and density, not for hex values, class names or icon sets.
