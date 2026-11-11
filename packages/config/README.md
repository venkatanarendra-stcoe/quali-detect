# @qmentisai/config

Shared tooling configuration.

- `@qmentisai/config/eslint/base`: ESLint flat config for Node.js/shared packages.
- `@qmentisai/config/eslint/react`: base + React, hooks and a11y rules for `.jsx` code.
- `@qmentisai/config/prettier`: Prettier options (the root `prettier.config.js` re-exports it).

Use in a package: `import config from "@qmentisai/config/eslint/base"; export default config;` in `eslint.config.js`.
