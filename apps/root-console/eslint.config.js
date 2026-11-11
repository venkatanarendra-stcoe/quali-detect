import config from "@qmentisai/config/eslint/react";

/**
 * The Root Console must not use tenant navigation or the tenant permission model (docs/architecture/FRONTEND_ARCHITECTURE.md).
 * The package root of @qmentisai/shared carries both, so only the platform entry point may be imported.
 */
const restricted = {
  files: ["src/**/*.{js,jsx}"],
  rules: {
    "no-restricted-imports": [
      "error",
      {
        paths: [
          {
            name: "@qmentisai/shared",
            message:
              "Import from @qmentisai/shared/platform: the package root exposes tenant navigation and tenant permissions.",
          },
          {
            name: "@qmentisai/tenant-web",
            message: "The Root Console must not depend on the Tenant Application.",
          },
        ],
        patterns: [
          {
            group: ["@qmentisai/shared/src/*", "**/tenant-web/**", "@qmentisai/tenant-web/*"],
            message: "Do not reach into tenant code or shared internals.",
          },
        ],
      },
    ],
  },
};

export default [...config, restricted];
