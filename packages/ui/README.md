# @qmentisai/ui

Design tokens and the Tailwind v4 preset shared by both frontends.

- `src/tokens.css`: CSS variables for light and dark (`.dark`), from `docs/design/DESIGN_SYSTEM.md` §2-§4.
- `src/preset.css`: `@theme inline` mapping that exposes the tokens as Tailwind utilities. Use `@import "tailwindcss"; @import "@qmentisai/ui/preset.css";`.
- `src/root-theme.css`: the Root Console theme (violet accent, always-dark sidebar), active only under `<html data-app="root">`; import it after `preset.css`. Tenant tokens are not affected.
- shadcn/ui components are copied into each app (`components.json`), per the design system; generic shared components move here only once both apps use them.

Business navigation, layouts and permission models stay inside each app; only generic pieces live here (see `docs/architecture/FRONTEND_ARCHITECTURE.md`).
