/**
 * Design token metadata shared by both apps. Colors live in `tokens.css` (CSS variables, light + dark); apps import
 * `@qmentisai/ui/preset.css` after `@import "tailwindcss"`. See docs/design/DESIGN_SYSTEM.md.
 */
export const THEMES = Object.freeze(["light", "dark", "system"]);

export const LAYOUT = Object.freeze({ sidebarWidth: 240, topbarHeight: 48 });

/** Severity levels in display order (colors: --sev-* tokens). */
export const SEVERITIES = Object.freeze(["critical", "high", "medium", "low", "info"]);
