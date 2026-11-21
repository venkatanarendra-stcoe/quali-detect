import js from "@eslint/js";
import prettier from "eslint-config-prettier";
import globals from "globals";

/**
 * Base ESLint flat config for Node.js / shared packages (JavaScript ES Modules only).
 * @type {import("eslint").Linter.Config[]}
 */
export default [
  {
    ignores: [
      "**/dist/**",
      "**/build/**",
      "**/node_modules/**",
      "**/.turbo/**",
      "**/coverage/**",
      // deliberately vulnerable source of the SAST fixtures (SPEC scan-engines 17.v); never executed, only scanned
      "**/fixtures/scan-engines/sast/tree/**",
    ],
  },
  js.configs.recommended,
  {
    files: ["**/*.{js,mjs}"],
    languageOptions: { ecmaVersion: "latest", sourceType: "module", globals: { ...globals.node } },
    rules: {
      "no-unused-vars": ["warn", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      "prefer-const": "error",
      "no-var": "error",
      eqeqeq: ["error", "always"],
    },
  },
  prettier,
];
