import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

/**
 * Builds the Secrets scan fixture tree (docs/modules/scan-engines/SPEC.md 17.x, part I). EVERY value here is OBVIOUSLY FAKE: it carries the
 * word FIXTURE or FAKE, it was invented for this repository, and it is not a credential of any service. The values are ASSEMBLED AT RUN
 * TIME from fragments, so no source file of the repository contains a contiguous token shape (a real secret scanner, or a push protection
 * rule, never sees one in the repository, and the tree only exists in a temporary directory while a test or a live run needs it).
 */

const j = (...parts) => parts.join("");

/** The fake values by name (the canary of the suite: none of them may reach a finding, a log, an artifact or a database row). */
export const FAKE = Object.freeze({
  aws: j("AKI", "A", "QMFIXTURE", "FAKEKEY"),
  awsSecret: j("qmFixture", "FakeSecretAccessKey", "0123456789", "abcdEF"),
  stripe: j("sk_", "test_", "QMFIXTUREFAKE", "0123456789abcd"),
  slack: j("xox", "b-", "123456789012-", "123456789012-", "QMFIXTUREFAKEslack", "00000000"),
  github: j("gh", "p_", "QmFixtureFakeTokenValue", "0123456789abcdefghij"),
  password: j("Fixture", "Pw", "-FAKE-", "9f3a7c"),
  dbUrl: j("postgres://", "fixtureuser:", "FixtureFakePw9x", "@db.internal:5432/app"),
  apiKey: j("qm_fixt_", "api_key_", "7c1e9a4b52d08f36", "a1b2c3d4"),
  pemBody: j(
    "QMFIXTUREFAKEKEYBODY",
    "Zm9yIHRlc3RpbmcgdXNlIG9ubHk",
    "gbm90IGEgcmVhbCBrZXk",
    "QmFzZTY0RmFrZUZpeHR1cmU",
  ),
  jwt: j(
    "ey",
    "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
    "eyJzdWIiOiJmaXh0dXJlIiwibmFtZSI6IkZBS0UifQ.",
    "ZmFrZS1maXh0dXJlLXNpZ25hdHVyZS12YWx1ZQ",
  ),
});

const pem = () =>
  [
    j("-----BEGIN ", "RSA PRIVATE KEY-----"),
    ...Array.from({ length: 5 }, (_, i) => `${FAKE.pemBody}${i}${FAKE.pemBody.slice(0, 20)}`),
    j("-----END ", "RSA PRIVATE KEY-----"),
    "",
  ].join("\n");

/** The planted tree: file path to text. */
export function secretsTreeFiles() {
  return {
    "config/aws.env": `AWS_ACCESS_KEY_ID=${FAKE.aws}\nAWS_SECRET_ACCESS_KEY=${FAKE.awsSecret}\nREGION=eu-west-1\n`,
    "keys/server.pem": pem(),
    "web/app.js": `// fixture\nconst stripe = "${FAKE.stripe}";\nexport const ok = 1;\n`,
    "web/slack.js": `const hook = { token: "${FAKE.slack}" };\nexport default hook;\n`,
    "ci/deploy.yml": `env:\n  GITHUB_TOKEN: ${FAKE.github}\n`,
    "svc/db.py": `DB_URL = "${FAKE.dbUrl}"\npassword = "${FAKE.password}"\n`,
    "svc/settings.py": `API_KEY = "${FAKE.apiKey}"\n`,
    "auth/token.txt": `bearer ${FAKE.jwt}\n`,
    "node_modules/pkg/leak.js": `module.exports = "${FAKE.aws.replace("QMFIXTURE", "QMVENDORX")}";\n`,
    "safe/ok.js": "export const answer = 42;\n",
    "safe/readme.md": "Nothing secret here.\n",
    // inline suppressions: neither tool may honour them
    "allow/allowed.js": `const t = "${FAKE.stripe.replace("FAKE", "ALLOW")}"; // gitleaks:allow\n`,
    "allow/allowed.py": `SECRET = "${FAKE.apiKey.replace("fixt", "pragma")}"  # pragma: allowlist secret\n`,
  };
}

/** Hostile repository configuration planted next to the secrets (a tool that honours any of it hides a finding). */
export function plantedConfigFiles(fingerprintLines = []) {
  return {
    ".gitleaks.toml": "[allowlist]\npaths = ['''.*''']\nregexes = ['''.*''']\n",
    ".gitleaksignore": `${fingerprintLines.join("\n")}\n`,
    ".secrets.baseline": '{"version":"1.5.0","plugins_used":[],"filters_used":[],"results":{}}\n',
    ".pre-commit-config.yaml": "repos: []\n",
    ".gitignore": "*\n",
    ".gitattributes": "* -diff\n",
    "setup.cfg": "[detect-secrets]\nexclude-files = .*\n",
  };
}

/**
 * Writes a file map under `root` (directories created, files 0644 in 0755 directories so a non-root container can read them).
 * @param {string} root @param {Record<string, string>} files
 */
export function writeTree(root, files) {
  for (const [name, text] of Object.entries(files)) {
    const file = path.join(root, name);
    mkdirSync(path.dirname(file), { recursive: true, mode: 0o755 });
    writeFileSync(file, text, { mode: 0o644 });
  }
}
