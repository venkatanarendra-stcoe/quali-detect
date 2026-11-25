// DEVELOPMENT TOOL (live end-to-end, docs/modules/scan-engines/E2E_RESULT.md): builds a small repository with KNOWN planted problems
// and a manifest of what was planted, so a real scan can be compared with it.
//
//   node apps/workers/scripts/eng-e2e/build-fixture.js --out /tmp/qm-e2e/fixture-local --mode local
//   node apps/workers/scripts/eng-e2e/build-fixture.js --out ~/qm-e2e-fixtures/qm-fixture --mode push
//
// SCA: lockfiles of three ecosystems (npm, PyPI, Go) with old, publicly vulnerable versions. SAST: the Opengrep/Bandit fixture sources of
// the security suite (JavaScript, TypeScript, Python, Go). Secrets: `local` mode plants the provider-shaped FAKE values of the suite
// (assembled at run time from fragments, obviously fake, never contiguous in any source file); `push` mode plants ONLY values that no
// provider's push protection recognises (generic assignments and entropy strings), so a push of the folder is not refused. Every
// secret is fake and belongs to no service.
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { secretsTreeFiles } from "../../../api/test/security/fixtures/scan-engines/secrets/tree-builder.js";

const { values } = parseArgs({
  options: { out: { type: "string" }, mode: { type: "string", default: "local" } },
});
if (!values.out || !["local", "push"].includes(values.mode))
  throw new Error("--out <dir> --mode local|push");
const out = path.resolve(values.out);
const here = path.dirname(fileURLToPath(import.meta.url));
const sastTree = path.resolve(here, "../../../api/test/security/fixtures/scan-engines/sast/tree");

const files = {};
// ---- SCA --------------------------------------------------------------------------------------------------------------------------
const npm = { lodash: "4.17.20", minimist: "1.2.5", express: "4.17.1" };
files["package.json"] =
  `${JSON.stringify({ name: "qm-fixture", version: "1.0.0", private: true, dependencies: npm }, null, 2)}\n`;
files["package-lock.json"] = `${JSON.stringify(
  {
    name: "qm-fixture",
    version: "1.0.0",
    lockfileVersion: 2,
    requires: true,
    packages: {
      "": { name: "qm-fixture", version: "1.0.0", dependencies: npm },
      ...Object.fromEntries(
        Object.entries(npm).map(([n, v]) => [
          `node_modules/${n}`,
          { version: v, resolved: `https://registry.npmjs.org/${n}/-/${n}-${v}.tgz` },
        ]),
      ),
    },
    dependencies: Object.fromEntries(
      Object.entries(npm).map(([n, v]) => [
        n,
        { version: v, resolved: `https://registry.npmjs.org/${n}/-/${n}-${v}.tgz` },
      ]),
    ),
  },
  null,
  2,
)}\n`;
const pypi = { django: "3.2.4", pyyaml: "5.3", requests: "2.19.0" };
files["requirements.txt"] = `${Object.entries(pypi)
  .map(([n, v]) => `${n}==${v}`)
  .join("\n")}\n`;
const go = {
  "github.com/gin-gonic/gin": "v1.7.0",
  "golang.org/x/crypto": "v0.0.0-20210921155107-089bfa567519",
};
files["go.mod"] = `module example.com/qmfixture\n\ngo 1.17\n\nrequire (\n${Object.entries(go)
  .map(([n, v]) => `\t${n} ${v}`)
  .join("\n")}\n)\n`;

// ---- SAST -------------------------------------------------------------------------------------------------------------------------
const sast = {};
const walk = (dir, rel = "") => {
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) walk(p, path.posix.join(rel, name));
    else {
      let text = readFileSync(p, "utf8");
      // push mode: no provider-shaped token may sit in a file that goes to GitHub (push protection), so the Stripe-shaped literal of the
      // suite's Python fixture becomes a generic assignment; the Bandit / Opengrep hardcoded-credential rules still match it
      if (values.mode === "push")
        text = text.replace("sk_live_abcdefghijklmnop", "qm_fixt_api_key_abcdefghijklmnop");
      sast[path.posix.join("src", rel, name)] = text;
    }
  }
};
walk(sastTree);
Object.assign(files, sast);
const SINK =
  /db\.query|\.execute\(|cp\.exec|execSync|os\.system|subprocess\.call|eval\(|new Function|unserialize|pickle\.loads|yaml\.load|createHash\("md5"|hashlib\.md5|md5\.New|createCipher|exec\.Command|fmt\.Sprintf\("SELECT|readFile\(|open\(request|os\.Open/;
const sinks = [];
// `src/safe/*` are the CLEAN CONTROLS (parameterised query, constant eval): they must NOT be flagged, so they are not planted sinks
for (const [file, text] of Object.entries(sast).filter(([f]) => !f.startsWith("src/safe/")))
  text
    .split("\n")
    .forEach(
      (line, i) =>
        SINK.test(line) && sinks.push({ file, line: i + 1, code: line.trim().slice(0, 80) }),
    );
const hardcoded = [];
for (const [file, text] of Object.entries(sast))
  text
    .split("\n")
    .forEach(
      (line, i) =>
        /(dbPassword|API_KEY|password)\s*=\s*"/.test(line) && hardcoded.push({ file, line: i + 1 }),
    );

// ---- Secrets ----------------------------------------------------------------------------------------------------------------------
let secrets;
if (values.mode === "local") {
  secrets = Object.fromEntries(
    Object.entries(secretsTreeFiles()).filter(([name]) => !name.startsWith("allow/") || true),
  );
} else {
  const j = (...p) => p.join("");
  secrets = {
    "config/app.env": `DB_PASSWORD=${j("Fixture", "Pw", "-FAKE-", "9f3a7c")}\nSECRET_KEY=${j("qm_fixt_", "secret_key_", "7c1e9a4b52d08f36", "a1b2c3d4e5f6")}\n`,
    "svc/settings.py": `API_KEY = "${j("qm_fixt_", "api_key_", "7c1e9a4b52d08f36", "a1b2c3d4")}"\npassword = "${j("Fixture", "Pw", "-FAKE-", "2b8d41")}"\n`,
    "safe/ok.js": "export const answer = 42;\n",
  };
}
Object.assign(files, secrets);
const secretFiles = Object.keys(secrets).filter((f) => !f.startsWith("safe/"));

for (const [name, text] of Object.entries(files)) {
  const file = path.join(out, name);
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o755 });
  writeFileSync(file, text, { mode: 0o644 });
}
const manifest = {
  mode: values.mode,
  sca: {
    npm: Object.entries(npm).map(([n, v]) => `${n}@${v}`),
    PyPI: Object.entries(pypi).map(([n, v]) => `${n}==${v}`),
    Go: Object.entries(go).map(([n, v]) => `${n} ${v}`),
    components: Object.keys(npm).length + Object.keys(pypi).length + Object.keys(go).length,
  },
  sast: {
    files: Object.keys(sast),
    plantedSinkLines: sinks.length,
    hardcodedCredentialLines: hardcoded.length,
    sinks,
    hardcoded,
  },
  secrets: { files: secretFiles, plantedFiles: secretFiles.length },
};
writeFileSync(
  path.join(path.dirname(out), `${path.basename(out)}.manifest.json`),
  `${JSON.stringify(manifest, null, 2)}\n`,
);
console.log(
  JSON.stringify({
    out,
    mode: values.mode,
    files: Object.keys(files).length,
    scaComponents: manifest.sca.components,
    sastSinkLines: sinks.length,
    hardcodedCredentialLines: hardcoded.length,
    secretFiles: secretFiles.length,
  }),
);
