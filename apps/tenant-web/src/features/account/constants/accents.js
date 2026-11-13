import { ACCENT_KEYS } from "@qmentisai/shared";

/** Display names of the accent palette (colour values live in packages/ui/src/accents.css, keyed by the same keys). */
export const ACCENT_LABELS = Object.freeze({
  mint: "Mint",
  violet: "Violet",
  blue: "Blue",
  cyan: "Cyan",
  teal: "Teal",
  emerald: "Emerald",
  amber: "Amber",
  orange: "Orange",
  rose: "Rose",
});

/** Swatches in palette order: `{ key, label }`. */
export const ACCENT_OPTIONS = Object.freeze(
  ACCENT_KEYS.map((key) => Object.freeze({ key, label: ACCENT_LABELS[key] ?? key })),
);
