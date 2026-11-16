# QmentisAI Design System

**Status:** Final — revision 3. Palette, typography, Tailwind v4 and the Tenant dashboard reference are approved. Frontend implementation started 2026-11-11 (`apps/tenant-web`; tokens in `packages/ui/src/tokens.css`).
**Applies to:** Tenant Application (`apps/tenant-web`) and Root Console (`apps/root-console`)
**Stack (ADR-001, ADR-005):** JavaScript ES Modules, React, Vite, Tailwind CSS, shadcn/ui, Lucide React, Recharts. No TypeScript.

This document is the common design reference for Claude Code and other AI coding tools. Behavior and layout rules live in `UX_GUIDELINES.md`.

> Revision note (2026-11-13, owner decision): the accent is **user-selectable from a fixed palette** (§2.5); **Electric Mint stays the default** and its values are unchanged. The "signal, not a theme" rule is unchanged: whatever accent is chosen appears only on primary action, active navigation and focus (and the other places the mint table in §1 allows), so every "mint" in §1, §2.1 and §6 reads "the accent (mint by default)". Severity, status and pipeline colours are fixed. Indigo is not reinstated.

> Revision note: the earlier navy/indigo direction (`#3B5BDB`) is withdrawn. Nothing in this system uses blue-tinted neutrals or indigo.

---

## 1. Brand direction

**Premium Cybersecurity + AI Engineering.** Obsidian Black, Graphite, Electric Mint, Neutral Slate.

- Neutrals are true neutral with at most a faint green-grey bias in the light theme. No navy, no blue-black.
- **Electric Mint is a signal, not a theme.** It marks the one thing the user should act on or notice.
- Severity colors are independent of the brand and never reuse mint.
- Surfaces are separated by 1 px borders and tonal steps, not shadows or gradients.

### Where mint is allowed

| Allowed | Not allowed |
|---|---|
| Primary buttons (one per view) | Decorative icons, illustrations, dividers |
| Active navigation item (indicator + text) | Card borders, table borders, section headers |
| Keyboard focus ring | Chart series by default (only the primary series) |
| Selected/checked controls (checkbox, switch, radio) | Severity, status, or success indication |
| Links inside body text | Icons in buttons that are not the primary action |
| One key highlight per page (e.g. the headline metric delta, an AI provenance mark) | Backgrounds larger than a chip or a selected row tint |

Rule of thumb: if more than ~5% of a screen's pixels are mint, remove some.

### Audit-log terminal exception (owner-approved, 2026-11-13)

**Decision (owner, 2026-11-13, Confirmed, item 6 option 2):** the audit log (T-19, later R-28) may render as a terminal. Inside the `AuditTerminal` component of `@qmentisai/ui` ONLY, (1) the whole row is set in the mono font and (2) the panel is **always dark in both the light and the dark app theme**. Every other rule is unchanged: mono stays limited to identifiers, code and terminal output everywhere else; the accent (mint by default) is **not** used for terminal text (no green-on-black palette) and keeps its three spots; severity and status tokens keep their meaning. The component has real selectable text (no ASCII art, no canvas), is a native table styled as a log, and shows a prompt line `<tenant-slug>@qmentisai:~$` plus a sticky column header.

**Tokens** (scoped to `.qm-terminal` in `packages/ui/src/terminal.css`; identical in both themes; neutral, no accent hue):

| Token | Value | Use |
|---|---|---|
| `--term-surface` | `#0b0d10` | Panel and row background |
| `--term-header` | `#111418` | Prompt line, sticky column header, footer |
| `--term-text` | `#e6ebee` | Row text |
| `--term-muted` | `#a1abb2` | Column headers, secondary text, command |
| `--term-prompt` | `#f4f7f8` | Prompt label (bold; neutral white, not the accent) |
| `--term-border` | `#272d33` | Row and section separators (decorative) |
| `--term-edge` | `#68737c` | Panel outline (UI boundary) |
| `--term-row-hover` | `#171b20` | Row hover |
| `--term-row-selected` | `#1e2429` | Selected row (plus a 2 px marker and `aria-selected`) |
| `--term-focus` | `#f4f7f8` | Focus ring (2 px outline, neutral) |
| `--term-success` / `--term-failure` / `--term-denied` | `#4ade80` / `#ff4d5a` / `#f5c451` | Result text and icon: the dark-theme `--status-success`, `--status-danger`, `--status-warning` values. They already pass on the panel, so no extra variants were needed |

Results are always an icon plus a text label (check / x / alert-circle + `success` / `failure` / `denied`), never colour alone.

**Measured contrast** (WCAG 2.x relative luminance, script `item6/contrast.mjs` in the working scratchpad; requirement: text >= 4.5:1, focus and UI boundaries >= 3:1):

| Foreground | surface | header | row hover | row selected | Requirement |
|---|---|---|---|---|---|
| `--term-text` `#e6ebee` | 16.20 | 15.37 | 14.40 | 13.05 | 4.5 pass |
| `--term-muted` `#a1abb2` | 8.32 | 7.90 | 7.40 | 6.71 | 4.5 pass |
| `--term-prompt` `#f4f7f8` | 18.07 | 17.15 | 16.07 | 14.56 | 4.5 pass |
| success `#4ade80` | 11.17 | 10.60 | 9.93 | 9.00 | 4.5 pass |
| failure `#ff4d5a` | 5.99 | 5.68 | 5.32 | 4.82 | 4.5 pass (the first selected tone `#232a31` gave 4.47 and was darkened) |
| denied `#f5c451` | 11.95 | 11.34 | 10.62 | 9.63 | 4.5 pass |
| focus ring `#f4f7f8` | 18.07 | 17.15 | 16.07 | 14.56 | 3 pass |
| panel outline `#68737c` | 4.01 (vs surface) | | | | 3 pass |

The panel against the light page canvas (`#f5f7f7`) is 18.10:1 and against the dark canvas (`#080a0d`) is separated by the 1 px `--term-edge` outline. The thin scrollbar thumb inside the panel uses the muted token (`#a1abb2` at 60%). `prefers-reduced-motion` removes the loading pulse and smooth scrolling.

---

## 2. Color tokens

Hex values are the source of truth. All colors are exposed as CSS variables on `:root` (light) and `.dark` (dark). Components must reference tokens, never literals.

### 2.1 Core palette

| Token | Dark | Light | Notes |
|---|---|---|---|
| `--background` | `#080A0D` | `#F5F7F7` | App canvas |
| `--sidebar` | `#0B0D10` | `#FFFFFF` | Navigation rail |
| `--card` | `#111418` | `#FFFFFF` | Cards, tables, panels |
| `--elevated` | `#171B20` | `#EDF1F1` | Popovers, menus, dialogs, hover rows, inputs |
| `--border` | `#272D33` | `#DDE4E3` | Decorative separators |
| `--border-strong` | `#68737C` | `#758483` | Form control edges (needs 3:1) — **derived** |
| `--foreground` | `#F4F7F8` | `#151B1B` | Primary text |
| `--muted-foreground` | `#A1ABB2` | `#586565` | Secondary text |
| `--subtle-foreground` | `#7B858C` | `#6B7777` | Tertiary text, timestamps, placeholders — **derived** |
| `--primary` | `#40E0C0` | `#087F70` | Brand accent (fills) |
| `--primary-foreground` | `#04110E` | `#FFFFFF` | Text/icons on `--primary` — **derived** |
| `--primary-hover` | `#6BEBD0` | `#06695D` | Hover fill — **derived**; light value set by the user on 2026-11-09 (was `#06705F`) |
| `--primary-text` | `#40E0C0` | `#06705F` | Mint as text or icon on tinted/elevated surfaces — **derived** |
| `--primary-tint` | mint 12% over sidebar/card | mint 10% over white | Selected nav item, selected row |
| `--ring` | `#40E0C0` | `#087F70` | Focus ring |

"Derived" values were not in the brief. They exist to meet contrast requirements (section 5) and are proposed for approval.

### 2.2 Severity (independent of brand)

Severity is always rendered as **tinted pill + icon + text label**; color is never the only signal.

| Level | Base (as supplied) | Dark: text/icon | Dark: tint bg | Light: text/icon | Light: tint bg |
|---|---|---|---|---|---|
| Critical | `#FF4D5A` | `#FF4D5A` | base @ 16% | `#B3202D` | base @ 16% over white |
| High | `#FF873D` | `#FF873D` | base @ 16% | `#A8440A` | base @ 16% over white |
| Medium | `#F5C451` | `#F5C451` | base @ 16% | `#7A5800` | base @ 16% over white |
| Low | `#55A8FF` | `#55A8FF` | base @ 16% | `#1257B5` | base @ 16% over white |
| Info | `#9AA6B2` | `#9AA6B2` | base @ 16% | `#47535F` | base @ 16% over white |

The supplied colors are used unchanged in the dark theme and as the tint source in both themes. On light surfaces the supplied colors fail text contrast (Medium is 1.6:1 on white), so light-mode text and icons use the darker derived variants. Charts in light mode use the light text/icon variants as fills.

Tokens: `--sev-critical`, `--sev-critical-fg`, `--sev-critical-bg` (and likewise `high`, `medium`, `low`, `info`).

### 2.3 Status (workflow and system state)

Status is visually different from severity so the two are never confused: **severity = filled tint pill; status = outlined chip with leading icon.** Shape and icon carry the meaning; color supports it.

| Token | Dark | Light | Use |
|---|---|---|---|
| `--status-success` | `#4ADE80` | `#1A7F37` | Succeeded, verified, active |
| `--status-danger` | `#FF4D5A` | `#C62A36` | Failed, rejected, suspended, destructive actions |
| `--status-warning` | `#F5C451` | `#7A5800` | Waiting, degraded, at risk |
| `--status-neutral` | `#A1ABB2` | `#586565` | Queued, cancelled, draft, inactive |
| `--status-active` | `--foreground` | `--foreground` | Running (spinner icon, neutral text; never mint or blue) |

Open item: success green sits near mint in hue. Differences that keep them apart: success is always a check icon in an outlined chip and never a filled control; mint is never used as a status color.

### 2.4 Charts

| Token | Dark | Light | Use |
|---|---|---|---|
| `--chart-1` | `#40E0C0` | `#087F70` | Primary series only |
| `--chart-2` | `#8FA1AD` | `#5E6F78` | Secondary series |
| `--chart-3` | `#5C6B75` | `#8A9AA3` | Tertiary series |
| `--chart-4` | `#C7D1D6` | `#3D4A50` | Reference/comparison |
| `--chart-grid` | `#272D33` | `#DDE4E3` | Gridlines |

Severity charts use the severity tokens, not chart tokens. Distinguish series by position, labels, or pattern as well as color.

---

### 2.5 Selectable accent (user preference)

**Decision (owner, 2026-11-13, Confirmed):** each user may choose the accent from a fixed palette (`ACCENT_KEYS` in `@qmentisai/shared`, stored by the `user-preferences` module): `mint` (default), `violet`, `blue`, `cyan`, `teal`, `emerald`, `amber`, `orange`, `rose`. No indigo, no black or white, no severity or status colour. The picker only changes which colour fills the three allowed spots (primary action, active navigation, focus ring); it is not a theme.

**Implementation:** `packages/ui/src/accents.css`, driven by `data-accent="<key>"` on `<html>` (set by the tenant app's `AccentProvider`; the last value is cached in localStorage and applied pre-paint by `index.html`). Mint has no override (it is `tokens.css`). Every other key re-points `--primary`, `--primary-foreground`, `--primary-hover`, `--primary-text`, `--primary-tint`, `--ring`, `--chart-1` and the sidebar active pair (`--sidebar-active-foreground`, `--sidebar-active-bg`) in light and dark. Rules are scoped `:not([data-app="root"])`, so the Root Console (violet, fixed) ignores the attribute. `[data-accent-preview="<key>"]` applies the same values to a single element (picker swatches, live preview).

**Constraints:** (1) severity, status, pipeline and neutral tokens are never overridden; (2) **amber, orange and rose sit near the warning, high-severity and destructive hues**, so they are used only for the three allowed spots and never for status, severity, success or error indication (severity and status keep their icon plus label, so they remain distinguishable even when the accent is warm); (3) violet in the dark theme is close to the Root Console violet by design of the palette (the apps stay separate by the PLATFORM tag and dark sidebar); (4) teal and cyan are close in hue to mint, differing mainly in hue (see below), so the picker always shows the label and a check mark.

**Measured contrast** (WCAG relative luminance; script `accent/palette.mjs` in the session scratchpad; light surfaces canvas `#F5F7F7`, card `#FFFFFF`, elevated `#EDF1F1`; dark surfaces canvas `#080A0D`, card `#111418`, elevated `#171B20`, tint = accent over the surface). Targets: text on fill >= 4.5, accent text on card / elevated / tint >= 4.5, ring on canvas and card >= 3. Mint is exactly the values of §2.1.

| Accent | Mode | `--primary` | `--primary-foreground` | `--primary-hover` | `--primary-text` | `--primary-tint` | Text on fill | Text on hover | Accent text on card / elevated / tint | Ring on canvas / card | Hue |
|---|---|---|---|---|---|---|---|---|---|---|---|
| mint | light | `#087f70` | `#ffffff` | `#06695d` | `#06705f` | `#e6f2f1` | 4.91 | 6.59 | 6.02 / 5.29 / 5.25 | 4.56 / 4.91 | 172° |
| mint | dark | `#40e0c0` | `#04110e` | `#6bebd0` | `#40e0c0` | `#112625` | 11.58 | 13.21 | 11.12 / 10.41 / 9.52 | 11.93 / 11.12 | 168° |
| violet | light | `#8550e2` | `#ffffff` | `#7335de` | `#7f47e1` | `#f3eefc` | 4.95 | 6.38 | 5.40 / 4.74 / 4.74 | 4.60 / 4.95 | 262° |
| violet | dark | `#a676f9` | `#0e0915` | `#bf9dfb` | `#a676f9` | `#1e1a2c` | 6.16 | 8.83 | 5.79 / 5.42 / 5.31 | 6.21 / 5.79 | 262° |
| blue | light | `#306be8` | `#ffffff` | `#1958e1` | `#1e5de6` | `#eaf0fd` | 4.78 | 5.96 | 5.58 / 4.90 / 4.88 | 4.44 / 4.78 | 221° |
| blue | dark | `#6492f7` | `#090d15` | `#8baef9` | `#6492f7` | `#161d2c` | 6.48 | 8.81 | 6.15 / 5.76 / 5.61 | 6.60 / 6.15 | 221° |
| cyan | light | `#0d79a0` | `#ffffff` | `#0b6484` | `#0c7297` | `#e7f2f6` | 4.93 | 6.62 | 5.43 / 4.77 / 4.76 | 4.58 / 4.93 | 196° |
| cyan | dark | `#74c8e7` | `#091215` | `#97d6ed` | `#74c8e7` | `#18232a` | 10.06 | 11.86 | 9.81 / 9.19 / 8.50 | 10.53 / 9.81 | 196° |
| teal | light | `#0b8089` | `#ffffff` | `#09666d` | `#0a737b` | `#e7f2f3` | 4.71 | 6.70 | 5.60 / 4.92 / 4.90 | 4.38 / 4.71 | 184° |
| teal | dark | `#78dce3` | `#091515` | `#99e5ea` | `#78dce3` | `#182629` | 11.64 | 13.06 | 11.56 / 10.83 / 9.75 | 12.41 / 11.56 | 184° |
| emerald | light | `#0a8049` | `#ffffff` | `#076439` | `#097743` | `#e7f2ed` | 5.00 | 7.26 | 5.63 / 4.95 / 4.91 | 4.65 / 5.00 | 152° |
| emerald | dark | `#7cdeb1` | `#091510` | `#9de7c4` | `#7cdeb1` | `#192623` | 11.49 | 13.02 | 11.38 / 10.66 / 9.64 | 12.21 / 11.38 | 152° |
| amber | light | `#ab5f07` | `#ffffff` | `#8e4e06` | `#9d5707` | `#f7efe6` | 4.80 | 6.48 | 5.53 / 4.86 / 4.85 | 4.47 / 4.80 | 32° |
| amber | dark | `#efb26c` | `#151009` | `#f3c591` | `#efb26c` | `#26211b` | 10.14 | 11.90 | 9.90 / 9.27 / 8.55 | 10.62 / 9.90 | 32° |
| orange | light | `#c54a0d` | `#ffffff` | `#a83f0b` | `#b6440c` | `#f9ede7` | 4.82 | 6.21 | 5.50 / 4.83 / 4.79 | 4.48 / 4.82 | 20° |
| orange | dark | `#f59566` | `#150d09` | `#f8b08c` | `#f59566` | `#271d1a` | 8.57 | 10.59 | 8.24 / 7.72 / 7.34 | 8.85 / 8.24 | 20° |
| rose | light | `#de1b53` | `#ffffff` | `#c31849` | `#cc194c` | `#fce8ee` | 4.79 | 5.92 | 5.51 / 4.84 / 4.70 | 4.45 / 4.79 | 343° |
| rose | dark | `#f5668e` | `#15090d` | `#f88caa` | `#f5668e` | `#27181f` | 6.66 | 8.66 | 6.31 / 5.91 / 5.80 | 6.77 / 6.31 | 343° |

Every pair passes (lowest text pair 4.70, lowest ring pair 4.38). Light values are 600/700-level and darker for amber, orange, rose and cyan so that white text reaches 4.5; dark values are lighter equivalents with a near-black, hue-tinted foreground. The values were derived here (none were supplied) and are **Confirmed (owner, visual sign-off 2026-11-16)** for the eight non-mint accents; mint is unchanged.

---

## 3. CSS variables and shadcn/ui mapping

`apps/*/src/styles/tokens.css` will be generated from this section when frontend work begins (not yet started). One shared source lives in a shared package (for example `packages/ui-tokens`) and is imported by both apps; each app keeps its own shadcn `components.json`.

Important shadcn/ui quirk: shadcn's `--accent` means a neutral hover surface, **not** the brand accent. The brand accent maps to `--primary`.

```css
:root {
  --radius: 0.375rem;               /* 6px; sm = 4px, lg = 8px */

  --background: #F5F7F7;
  --foreground: #151B1B;
  --card: #FFFFFF;
  --card-foreground: #151B1B;
  --popover: #FFFFFF;
  --popover-foreground: #151B1B;
  --primary: #087F70;
  --primary-foreground: #FFFFFF;
  --primary-hover: #06695D;
  --primary-text: #06705F;
  --primary-tint: #E6F2F1;
  --secondary: #EDF1F1;             /* elevated surface */
  --secondary-foreground: #151B1B;
  --muted: #EDF1F1;
  --muted-foreground: #586565;
  --subtle-foreground: #6B7777;
  --accent: #EDF1F1;                /* shadcn hover surface, NOT brand */
  --accent-foreground: #151B1B;
  --destructive: #C62A36;
  --destructive-foreground: #FFFFFF;
  --border: #DDE4E3;
  --border-strong: #758483;
  --input: #758483;
  --ring: #087F70;

  --sidebar: #FFFFFF;
  --sidebar-foreground: #586565;
  --sidebar-active-foreground: #06705F;
  --sidebar-active-bg: #E6F2F1;
  --sidebar-border: #DDE4E3;

  --sev-critical: #FF4D5A; --sev-critical-fg: #B3202D; --sev-critical-bg: #FFE3E5;
  --sev-high:     #FF873D; --sev-high-fg:     #A8440A; --sev-high-bg:     #FFECE0;
  --sev-medium:   #F5C451; --sev-medium-fg:   #7A5800; --sev-medium-bg:   #FDF6E3;
  --sev-low:      #55A8FF; --sev-low-fg:      #1257B5; --sev-low-bg:      #E4F1FF;
  --sev-info:     #9AA6B2; --sev-info-fg:     #47535F; --sev-info-bg:     #EFF1F3;

  --status-success: #1A7F37;
  --status-danger: #C62A36;
  --status-warning: #7A5800;
  --status-neutral: #586565;

  --chart-1: #087F70; --chart-2: #5E6F78; --chart-3: #8A9AA3; --chart-4: #3D4A50;
  --chart-grid: #DDE4E3;
}

.dark {
  --background: #080A0D;
  --foreground: #F4F7F8;
  --card: #111418;
  --card-foreground: #F4F7F8;
  --popover: #171B20;
  --popover-foreground: #F4F7F8;
  --primary: #40E0C0;
  --primary-foreground: #04110E;
  --primary-hover: #6BEBD0;
  --primary-text: #40E0C0;
  --primary-tint: #112625;
  --secondary: #171B20;
  --secondary-foreground: #F4F7F8;
  --muted: #171B20;
  --muted-foreground: #A1ABB2;
  --subtle-foreground: #7B858C;
  --accent: #171B20;
  --accent-foreground: #F4F7F8;
  --destructive: #FF4D5A;
  --destructive-foreground: #1A0407;
  --border: #272D33;
  --border-strong: #68737C;
  --input: #68737C;
  --ring: #40E0C0;

  --sidebar: #0B0D10;
  --sidebar-foreground: #A1ABB2;
  --sidebar-active-foreground: #40E0C0;
  --sidebar-active-bg: #112625;
  --sidebar-border: #272D33;

  --sev-critical-fg: #FF4D5A; --sev-critical-bg: #371D23;
  --sev-high-fg:     #FF873D; --sev-high-bg:     #37261E;
  --sev-medium-fg:   #F5C451; --sev-medium-bg:   #353021;
  --sev-low-fg:      #55A8FF; --sev-low-bg:      #1C2C3D;
  --sev-info-fg:     #9AA6B2; --sev-info-bg:     #272B31;

  --status-success: #4ADE80;
  --status-danger: #FF4D5A;
  --status-warning: #F5C451;
  --status-neutral: #A1ABB2;

  --chart-1: #40E0C0; --chart-2: #8FA1AD; --chart-3: #5C6B75; --chart-4: #C7D1D6;
  --chart-grid: #272D33;
}
```

(`--sev-*` base colors are theme-independent and defined once on `:root`.)

### 3.1 Tailwind integration

**Decision: Tailwind CSS v4, CSS-first configuration.** There is no `tailwind.config.js`; legacy v3 configuration is not used. Pin the exact v4 version at setup (dependency policy) and record it in `TECH_STACK.md`.

Each app has one stylesheet entry (`src/index.css`) structured like this:

```css
@import "tailwindcss";
@import "@qmentisai/ui-tokens/tokens.css";   /* the :root and .dark blocks from §3 */

@custom-variant dark (&:is(.dark *));

@theme inline {
  --font-sans: "Geist Variable", ui-sans-serif, system-ui, sans-serif;
  --font-mono: "Geist Mono Variable", ui-monospace, SFMono-Regular, monospace;

  --radius-sm: 4px;  --radius-md: 6px;  --radius-lg: 8px;

  --color-background: var(--background);
  --color-foreground: var(--foreground);
  --color-card: var(--card);
  --color-card-foreground: var(--card-foreground);
  --color-popover: var(--popover);
  --color-popover-foreground: var(--popover-foreground);
  --color-primary: var(--primary);
  --color-primary-foreground: var(--primary-foreground);
  --color-primary-hover: var(--primary-hover);
  --color-primary-text: var(--primary-text);
  --color-primary-tint: var(--primary-tint);
  --color-secondary: var(--secondary);
  --color-secondary-foreground: var(--secondary-foreground);
  --color-muted: var(--muted);
  --color-muted-foreground: var(--muted-foreground);
  --color-subtle-foreground: var(--subtle-foreground);
  --color-accent: var(--accent);
  --color-accent-foreground: var(--accent-foreground);
  --color-destructive: var(--destructive);
  --color-destructive-foreground: var(--destructive-foreground);
  --color-border: var(--border);
  --color-border-strong: var(--border-strong);
  --color-input: var(--input);
  --color-ring: var(--ring);
  --color-sidebar: var(--sidebar);
  --color-sidebar-foreground: var(--sidebar-foreground);
  --color-sidebar-active: var(--sidebar-active-bg);
  --color-sidebar-active-foreground: var(--sidebar-active-foreground);
  --color-sidebar-border: var(--sidebar-border);
  --color-sev-critical: var(--sev-critical);  --color-sev-critical-fg: var(--sev-critical-fg);  --color-sev-critical-bg: var(--sev-critical-bg);
  /* high, medium, low, info follow the same three-token pattern */
  --color-status-success: var(--status-success);  /* danger, warning, neutral likewise */
  --color-chart-1: var(--chart-1);  /* chart-2 … chart-4 likewise */
}

@layer base {
  * { border-color: var(--border); }
  body { background: var(--background); color: var(--foreground); font-family: var(--font-sans); }
}
```

Utilities such as `bg-card`, `text-muted-foreground`, `border-border`, `bg-primary`, `text-sev-high-fg` and `bg-sev-high-bg` then work in both themes. Because v4 resolves colors from the CSS variables, opacity modifiers use `color-mix`, so `bg-primary/10` works with hex tokens. Prefer the explicit `--primary-tint` token for selected states so the result is identical in both themes.

Dark mode: class strategy (`.dark` on `<html>`), with three user states: Light, Dark, System (default System). Persist the choice per user.

### 3.2 shadcn/ui configuration (to apply at frontend setup)

- `components.json`: style `new-york`, `rsc: false`, `tsx: false`, `tailwind.config: ""` (empty, because Tailwind v4 has no config file), `tailwind.css: "src/index.css"`, `baseColor: neutral`, `cssVariables: true`, icon library `lucide`. Confirm the exact keys against the shadcn/ui CLI version in use at setup; they are not verified here.
- Replace the generated token block with section 3 values.
- Components are copied into each app; shared presentational components move to a shared package only once both apps use them.
- Do not hand-edit generated component colors; adjust tokens or add a variant.

---

## 4. Typography, spacing, shape

| Item | Value |
|---|---|
| UI font | **Geist Sans** for UI, headings, labels, buttons, forms and general text. Fallback `ui-sans-serif, system-ui, sans-serif`. **Approved.** |
| Code font | **Geist Mono** for code, commit SHAs, file paths, technical identifiers, fingerprints and terminal output. Fallback `ui-monospace, SFMono-Regular, monospace`. **Approved.** Use JetBrains Mono only if Geist Mono cannot be loaded (for example, Stitch's font list has no Geist Mono). |
| Font loading | Self-host via `@fontsource-variable/geist` and `@fontsource-variable/geist-mono` (pinned versions) when frontend work starts. Exposed as `--font-sans` and `--font-mono` |
| Scale | page title 20/28 semibold · section 16/24 semibold · body 14/20 · table 13/20 · caption 12/16 · metric 28/32 semibold, tabular numerals |
| Numbers | `font-variant-numeric: tabular-nums` in tables, metrics, durations |
| Spacing | 4 px base: 4, 8, 12, 16, 24, 32. Page padding 24, card padding 16, form gap 16 |
| Radius | 4 (inputs, badges, buttons) · 6 (cards, popovers) · 8 (dialogs). No pill-shaped containers; chips use 4 |
| Elevation | Dark: borders only. Light: borders plus `0 1px 2px rgb(21 27 27 / 0.06)` on popovers and dialogs |
| Motion | 120–150 ms opacity/color transitions only. Honor `prefers-reduced-motion` |
| Icons | Lucide, 16 px in controls and tables, 20 px in nav, stroke 1.75. Icons are `--muted-foreground` by default |

---

## 5. Accessibility and contrast

Standard: WCAG 2.2 AA. Requirements:

- Body and small text ≥ 4.5:1; large text (≥ 18.66 px bold or 24 px) ≥ 3:1.
- UI component boundaries (inputs, checkboxes) and focus indicators ≥ 3:1 against adjacent colors.
- Information is never conveyed by color alone (icon + label on every severity and status).
- Focus: 2 px `--ring` outline with 2 px offset, always visible; never removed.
- Minimum target size 24×24 px (32 px for table row actions on touch layouts).

Measured ratios (WCAG relative luminance, computed from the hex values):

| Pair | Dark | Light |
|---|---|---|
| Foreground on background / card / elevated | 18.4 / 17.2 / 16.1 | 16.2 / 17.4 / 15.3 |
| Muted-foreground on background / card / elevated | 8.5 / 7.9 / 7.4 | 5.6 / 6.1 / 5.3 |
| Subtle-foreground on card | 4.9 | 4.6 |
| Supplied accent as text on background / card / elevated | 11.9 / 11.1 / 10.4 | 4.56 / 4.91 / **4.31 ✗** |
| `--primary-text` (`#06705F`) on card / elevated | n/a | 6.0 / 5.3 |
| `--primary-foreground` on `--primary` fill | 11.6 | 4.9 |
| `--border-strong` on card | 3.8 | 3.9 |
| `--border` on card (decorative only) | 1.33 | 1.29 |
| Severity text/icon on its tint | 4.7–8.1 | 5.2–7.0 |

Findings that shaped the tokens:
1. The supplied light accent `#087F70` passes on background and white (4.56 and 4.91) but fails on the elevated surface (4.31). Small text on elevated or tinted surfaces uses `--primary-text`.
2. The supplied severity colors fail on white (1.6–3.3:1) and cannot be used as light-theme text. Derived darker variants are used there.
3. The supplied `--border` values are intentionally subtle (≈1.3:1). They are for separators only; interactive control edges use `--border-strong`.
4. White text on `#FF4D5A` is 3.25:1, so destructive filled buttons use dark text in the dark theme.

---

## 6. Component conventions

Base components come from shadcn/ui. Product components below are built once and reused by both apps; do not create parallel versions.

| Component | Rule |
|---|---|
| `Button` | One `primary` (mint fill) per view. Others `secondary`, `outline`, `ghost`. `destructive` uses `--destructive`. Height 32 (default), 28 (compact), 36 (form) |
| `SeverityBadge` | Tinted fill, icon (shield-alert / triangle / circle-dot variants) + label, 20 px high |
| `StatusBadge` | Outlined, leading icon + label. Used for finding, pipeline, execution, tenant, subscription states |
| `ScanProgress` | Thin 4 px bar, neutral track; fill `--foreground`-toned, mint only for the currently running primary task |
| `SlaIndicator` | Text + icon: on track / due soon (warning) / breached (danger) with time remaining |
| `QuotaMeter` | Neutral bar; turns warning ≥ 80%, danger ≥ 100% (thresholds configurable, values open) |
| `ProvenanceTag` | Small tag "AI-assisted" / "Human decision" with icon; mint is allowed here as the one highlight |
| `EvidenceBlock` | Mono font, `--elevated` background, line numbers, secrets rendered as `••••` with a redaction label |
| `DataTable` | TanStack Table, 36 px rows (32 compact), sticky header, hover `--elevated`, selected `--primary-tint` |
| `PageHeader` | Breadcrumb, title, status chip, actions (primary right-aligned) |
| `EmptyState`, `ErrorState`, `UnauthorizedState`, `Skeleton` | Mandatory for every data view (AGENT_INSTRUCTIONS §7) |

---

## 7. Shared vs app-specific

Shared (tokens package + generic components): colors, type, spacing, radius, Button/Input/Table/Dialog/Drawer/Tabs/Badge, severity and status badges, empty/error states.

App-specific: navigation, layouts, permission models, feature components. Per FRONTEND_ARCHITECTURE.md the apps must not share business navigation or permissions.

**Root Console differentiation** — **changed 2026-11-11 on the user's instruction** (this section previously said the Root Console "does not use a different color theme"). The Root Console now has its own theme: a **violet** brand accent (replacing mint) and a sidebar that is **always dark**, implemented as an opt-in override under `<html data-app="root">` in `packages/ui/src/root-theme.css`; tenant tokens are untouched. Neutrals, severity colors and status colors are identical to the tenant app, and the "no indigo/blue-tinted neutrals" rule still holds for neutrals (violet is an accent only: primary action, active navigation, focus, links). The violet values (light `#6d28d9`, hover/text `#5b21b6`, tint `#f0eafb`; dark `#a78bfa`, hover `#c4b5fd`, tint `#232233`; sidebar indicator `#a78bfa`, active text `#c4b5fd`) were **derived here because none were supplied** and are **Recommended until approved**; measured contrast is in the file header (all ≥ 4.5:1 for text, ≥ 3:1 for focus). Other cues are unchanged: a persistent "PLATFORM" tag in the top bar, no workspace switcher, a distinct sidebar header ("QmentisAI Platform"), and confirmation-by-typing for tenant lifecycle actions. New cue: an **environment strip** across the top.

---

## 8. Stitch mapping

Stitch design systems accept one color mode, a seed color with overrides, a roundness preset, headline/body/label fonts from a fixed list, and free-form `designMd`. The planned mapping (not yet created):

| Stitch field | Value |
|---|---|
| `colorMode` | DARK (primary); a separate LIGHT system for light renders |
| `customColor` / `overridePrimaryColor` | `#40E0C0` (dark), `#087F70` (light) |
| `overrideNeutralColor` | `#080A0D` (dark), `#F5F7F7` (light) |
| `colorVariant` | `NEUTRAL` or `MONOCHROME` (to be tested; must not tint surfaces blue) |
| `roundness` | `ROUND_FOUR` |
| Fonts | `GEIST` headline and body; label font `GEIST` (Stitch has no Geist Mono, so mono text in Stitch screens is approximated with `JETBRAINS_MONO` or left to the prompt) |
| `designMd` | Sections 1, 2.2, 2.3 and the mint usage table, so severity colors and mint restraint are explicit |

Stitch output is HTML and screenshots used as visual reference only. It is not production code. See `STITCH_WORKFLOW.md` for what Stitch actually applies; in short, Stitch derives its own palette from these inputs, so exact values must come from this document.

---

## 9. Approved visual reference

| Item | Value |
|---|---|
| Approved screen | Tenant Application dashboard ("Security overview") |
| Stitch project | `QmentisAI Tenant Application`, `projects/3865828126633177668` |
| Stitch screen | `e4c2f0775e084cd6b019d67597359b7a` |
| Status | Approved as the visual direction for implementation. Do not edit. |
| Earlier versions kept | `a5544a28…` / `062a47dc…` (design system applied to the first generation). Reference only. |

**Binding rule:** the real frontend implements the tokens in §2–§4 exactly. Where the Stitch render differs from this document, this document wins. Known differences in the approved render that must NOT be copied:

| In the Stitch render | Implement as |
|---|---|
| Severity hues are Tailwind defaults (`#EF4444`, `#F97316`, `#EAB308`) and Low is slate (`#64748B`) | `--sev-*` tokens (§2.2): `#FF4D5A`, `#FF873D`, `#F5C451`, `#55A8FF` (Info `#9AA6B2`) |
| Stitch's derived theme (`#3cdebe`, `#0c0e11`) | `#40E0C0` and `#080A0D` |
| Red dot on the SLA breaches card, orange dot on the notification bell | No decorative dots. A bell badge appears only for unread count |
| Needs-attention table: SLA column pushed off-screen, status chip touching the card edge | All five columns (Severity, Finding, Pipeline, Status, SLA) always visible; table card at least 8 of 12 columns |
| Bottom cards of unequal height | Cards in one row stretch to equal height |
| Material Symbols icons | Lucide React |
| Tailwind v3 via CDN, inline styles | Tailwind v4 CSS-first, tokens from §3 |

What the approved render defines and should be reproduced: shell proportions (240 px sidebar, 48 px top bar), grouped sidebar with Geist sentence-case group labels, mint active-nav treatment (tint plus 2 px left bar), five equal metric cards on one line each, mint trend line with a neutral value callout, severity distribution bars on a dark track, dense 36 px table rows, outlined status chips, neutral progress bar, Geist everywhere except identifiers.

---

## 10. Lifecycle status mapping

Statuses use the outlined chip (§2.3) with a Lucide icon and a Geist label. Only three semantic colors exist for status text and icon: success, danger and warning; everything else is neutral. Mint is never used.

### Findings

| Status | Icon | Tone | Meaning |
|---|---|---|---|
| New | `circle-dot` | neutral | Detected, not yet triaged |
| In Review | `eye` | neutral | Security Analyst reviewing |
| Confirmed (TP) | `shield-alert` | danger | Marked true positive |
| False Positive | `shield-off` | neutral (muted) | Marked false positive |
| Pending Approval | `clock` | warning | Awaiting Lead approval |
| Assigned | `user-check` | neutral | Assigned to a developer |
| In Remediation | `wrench` | neutral | Fix in progress |
| Awaiting Verification | `scan-search` | warning | Fix claimed, not yet verified by a covering scan |
| Fixed (verified) | `circle-check` | success | Verified by a later scan |
| Accepted Risk | `shield-check` | neutral | Risk accepted for a defined period (show expiry) |
| Suppressed | `eye-off` | neutral (muted) | Hidden by approved suppression |

These are Recommended labels until the Findings module specification is approved. "Fixed" must never be shown for a finding that was merely absent from an incremental scan.

### Executions and scan tasks

| Status | Icon | Tone |
|---|---|---|
| Queued | `clock` | neutral |
| Running | `loader-circle` (spinning, static under reduced motion) | neutral |
| Succeeded | `circle-check` | success |
| Failed | `circle-x` | danger |
| Cancelling | `loader-circle` | warning |
| Cancelled | `ban` | neutral |
| Waiting for approval | `hourglass` | warning |

### Other

| Domain | Statuses (tone) |
|---|---|
| Workspace | Active (success, `circle-check`), Archived (neutral, `archive`) |
| Pipeline state | Enabled (neutral, `circle-check`), Disabled (neutral muted, `pause-circle`). Added 2026-11-09 so the pipeline state chip is defined in one place; last-execution results use the Executions mapping above |
| Integration health | Healthy (success, `circle-check`), Degraded (warning, `triangle-alert`), Disconnected (danger, `circle-x`), Not connected (neutral, `unplug`) |
| User | Active (success), Invited (neutral), Suspended (danger), Deactivated (neutral) |
| Tenant (Root Console) | Active (success), Trial (neutral), Suspended (danger), Deactivated (neutral) |
| Subscription / license | Active (success), Expiring (warning), Expired (danger), Pending (neutral) |

Success text and icon: `--status-success`; danger: `--status-danger`; warning: `--status-warning`; neutral: `--status-neutral`. The chip border stays `#3A434B` (dark) or `--border-strong` (light) in every tone; tone applies to icon and, for danger and warning, to text.

---

## 11. Navigation icons (Lucide, canonical)

Stitch references vary in sidebar icons, so the frontend uses this fixed set (Recommended; verified in the approved Repositories reference). Icon size 16 px, stroke 1.75. Inactive `--muted-foreground`; active `--sidebar-active-foreground`.

| Item | Lucide icon | Item | Lucide icon |
|---|---|---|---|
| Overview | `layout-grid` | Policies | `scale` |
| Workspaces | `boxes` | Reports | `file-text` |
| Repositories | `git-branch` | Users | `users` |
| Pipelines | `workflow` | Groups | `users-round` |
| Executions | `play` | Roles & Permissions | `key` |
| Scan History | `history` | Integrations | `cable` |
| Findings | `shield-alert` | Audit Logs | `scroll-text` |
| Security Reviews | `file-search` | Settings | `settings` |
| Approvals | `clipboard-check` | Docs | `book-open` |
| Remediation | `wrench` | Wordmark | `shield` |
