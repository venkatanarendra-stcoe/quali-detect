/**
 * Runner for the security regression suite (ADR-008): `pnpm test:security`.
 *
 * 1. Gets a DISPOSABLE PostgreSQL database:
 *    - SECURITY_TEST_DATABASE_URL, if set. Its database name must contain "test"; the suite refuses anything else so it can
 *      never run against a real database. The URL is never printed.
 *    - otherwise an ephemeral local cluster (initdb/pg_ctl from PG_BIN_DIR, /usr/lib/postgresql/*, or PATH) on a free port
 *      in a temporary directory, deleted afterwards.
 * 2. Applies the migrations and the seed (the demo tenant is tenant A).
 * 3. Starts the API as a child process with a clean environment (random mock passwords and MFA code, no Redis, no broker).
 * 4. Runs test/security/security.test.js against it over HTTP and tears everything down.
 *
 * Exit codes: 0 all checks passed, 1 a check failed, 2 the environment is not usable (message explains how to fix).
 * (pnpm reports 1 for any non-zero exit of a script; run this file with node to see the difference.)
 */
import { execFileSync, spawn } from "node:child_process";
import { randomBytes, randomInt } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const apiDir = path.resolve(here, "..");
const repoRoot = path.resolve(here, "../../..");
const log = (message) => console.log(`[security-suite] ${message}`);
const cleanups = [];
let apiOutput = [];

class EnvironmentError extends Error {}

const freePort = () =>
  new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });

function findPostgresBin() {
  const has = (dir) => existsSync(path.join(dir, "initdb")) && existsSync(path.join(dir, "pg_ctl"));
  if (process.env.PG_BIN_DIR && has(process.env.PG_BIN_DIR)) return process.env.PG_BIN_DIR;
  const root = "/usr/lib/postgresql";
  if (existsSync(root)) {
    const versions = readdirSync(root)
      .filter((v) => /^\d+$/.test(v))
      .sort((a, b) => Number(b) - Number(a));
    for (const v of versions) if (has(path.join(root, v, "bin"))) return path.join(root, v, "bin");
  }
  for (const dir of (process.env.PATH ?? "").split(path.delimiter)) if (dir && has(dir)) return dir;
  return null;
}

async function provisionDatabase() {
  const external = process.env.SECURITY_TEST_DATABASE_URL;
  if (external) {
    let name;
    try {
      name = new URL(external).pathname.replace(/^\//, "");
    } catch {
      throw new EnvironmentError("SECURITY_TEST_DATABASE_URL is not a valid URL.");
    }
    if (!/test/i.test(name)) {
      throw new EnvironmentError(
        `Refusing to run against database "${name}": the suite only runs on a disposable database whose name contains "test".`,
      );
    }
    log(`using the disposable database "${name}" from SECURITY_TEST_DATABASE_URL`);
    return external;
  }
  const bin = findPostgresBin();
  if (!bin) {
    throw new EnvironmentError(
      'No PostgreSQL server binaries found (initdb, pg_ctl). Install PostgreSQL or set PG_BIN_DIR, or point SECURITY_TEST_DATABASE_URL at an empty database whose name contains "test".',
    );
  }
  const dir = mkdtempSync(path.join(os.tmpdir(), "qmentis-security-pg-"));
  const port = await freePort();
  const run = (cmd, args) =>
    execFileSync(path.join(bin, cmd), args, {
      stdio: "pipe",
      env: { PATH: process.env.PATH, LANG: "C" },
    });
  log(`starting an ephemeral PostgreSQL on 127.0.0.1:${port}`);
  run("initdb", ["-D", dir, "-A", "trust", "-U", "postgres", "--no-sync"]);
  cleanups.push(() => {
    try {
      run("pg_ctl", ["-D", dir, "-m", "immediate", "stop"]);
    } catch {
      /* already stopped */
    }
    rmSync(dir, { recursive: true, force: true });
  });
  run("pg_ctl", [
    "-D",
    dir,
    "-o",
    `-p ${port} -c listen_addresses=127.0.0.1 -c unix_socket_directories='' -c fsync=off`,
    "-l",
    path.join(dir, "server.log"),
    "-w",
    "start",
  ]);
  run("createdb", [
    "-h",
    "127.0.0.1",
    "-p",
    String(port),
    "-U",
    "postgres",
    "qmentis_security_test",
  ]);
  return `postgresql://postgres@127.0.0.1:${port}/qmentis_security_test`;
}

function pnpm(args, env) {
  try {
    execFileSync("pnpm", args, {
      cwd: repoRoot,
      env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env },
      stdio: "pipe",
    });
  } catch (error) {
    throw new EnvironmentError(
      `"pnpm ${args.join(" ")}" failed:\n${String(error.stdout ?? "")}${String(error.stderr ?? "")}`.trim(),
    );
  }
}

async function startApi(env) {
  const port = await freePort();
  const child = spawn(process.execPath, ["src/server.js"], {
    cwd: apiDir,
    env: {
      PATH: process.env.PATH,
      NODE_ENV: "test",
      API_HOST: "127.0.0.1",
      API_PORT: String(port),
      LOG_LEVEL: "warn",
      ...env,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const collect = (chunk) => {
    apiOutput.push(...String(chunk).split("\n").filter(Boolean));
    apiOutput = apiOutput.slice(-60);
  };
  child.stdout.on("data", collect);
  child.stderr.on("data", collect);
  cleanups.push(() => child.kill("SIGTERM"));
  const baseUrl = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 120; i += 1) {
    if (child.exitCode !== null)
      throw new EnvironmentError(`The API exited during startup (code ${child.exitCode}).`);
    try {
      if ((await fetch(`${baseUrl}/health`)).ok) return baseUrl;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new EnvironmentError("The API did not become healthy within 30 seconds.");
}

/** Starts the local GitHub stand-in (no network) and returns the App settings the API and the tests need. */
async function startGitHub() {
  const { generateKeyPairSync } = await import("node:crypto");
  const { startGitHubStub } = await import("../test/security/helpers/github-stub.js");
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const clientId = "Iv1.suite";
  const clientSecret = randomBytes(12).toString("hex");
  const stub = await startGitHubStub({ publicKeyPem: publicKey, clientId, clientSecret });
  cleanups.push(() => stub.close());
  return {
    stub,
    privateKey,
    clientId,
    clientSecret,
    webhookSecret: randomBytes(16).toString("hex"),
  };
}

async function main() {
  const databaseUrl = await provisionDatabase();
  log("applying migrations and seed");
  pnpm(["--filter", "@qmentisai/db", "db:migrate:deploy"], { DATABASE_URL: databaseUrl });
  pnpm(["--filter", "@qmentisai/db", "db:seed"], { DATABASE_URL: databaseUrl });

  // Random per run: nothing in this suite depends on, or leaks, a fixed credential.
  const tenantPassword = randomBytes(12).toString("hex");
  const platformPassword = randomBytes(12).toString("hex");
  const mfaCode = String(randomInt(100000, 1000000));
  log("starting the local GitHub stub");
  const gh = await startGitHub();
  log("starting the API");
  const baseUrl = await startApi({
    GITHUB_APP_ENABLED: "true",
    GITHUB_APP_ID: "12345",
    GITHUB_APP_CLIENT_ID: gh.clientId,
    GITHUB_APP_SLUG: "qmentis-suite",
    GITHUB_API_BASE_URL: gh.stub.url,
    GITHUB_WEB_BASE_URL: gh.stub.url,
    GITHUB_OAUTH_REDIRECT_URI: "http://localhost:5173/integrations/github/callback",
    GITHUB_APP_PRIVATE_KEY: gh.privateKey,
    GITHUB_APP_CLIENT_SECRET: gh.clientSecret,
    GITHUB_APP_WEBHOOK_SECRET: gh.webhookSecret,
    SCM_SYNC_FAILURES_BEFORE_DISCONNECT: "3",
    // Lifetime of a workspace-link state: 3 s so SCM-033 can prove that an expired state is refused (production default: 600).
    SCM_LINK_STATE_TTL_SECONDS: "3",
    DATABASE_URL: databaseUrl,
    MOCK_AUTH_PASSWORD: tenantPassword,
    MOCK_PLATFORM_AUTH_PASSWORD: platformPassword,
    MOCK_PLATFORM_MFA_CODE: mfaCode,
    // Short progressive-throttle curve so the THR checks can reach the cap in seconds (production defaults are in
    // config and ADR-010): 3 free failures, then waits of 1 s, 2 s, 4 s (cap). IP counters tolerate 6x the free attempts.
    AUTH_THROTTLE_LOGIN_FREE_ATTEMPTS: "3",
    AUTH_THROTTLE_LOGIN_BASE_DELAY_SECONDS: "1",
    AUTH_THROTTLE_LOGIN_CAP_SECONDS: "4",
    AUTH_THROTTLE_MFA_FREE_ATTEMPTS: "3",
    AUTH_THROTTLE_MFA_BASE_DELAY_SECONDS: "1",
    AUTH_THROTTLE_MFA_CAP_SECONDS: "4",
    AUTH_THROTTLE_IP_FREE_MULTIPLIER: "6",
    // Per-route limits: the checks sign in and create things far more often than a person would. The AUTH window is
    // short (5 s) so the dedicated RATE check can exhaust it and the suite carries on a few seconds later.
    RATE_LIMIT_MAX: "100000",
    RATE_LIMIT_AUTH_MAX: "200",
    RATE_LIMIT_AUTH_WINDOW_MS: "5000",
    RATE_LIMIT_WRITE_MAX: "5000",
    // Restore window of deactivated tenants: 4 s so the RST checks can cross it (production default: see config).
    TENANT_DEACTIVATION_RETENTION_SECONDS: "4",
  });

  log("running the checks");
  const code = await new Promise((resolve) => {
    const tests = spawn(
      process.execPath,
      ["--test", "--test-reporter=spec", "test/security/security.test.js"],
      {
        cwd: apiDir,
        env: {
          PATH: process.env.PATH,
          SECURITY_API_URL: baseUrl,
          SECURITY_ORIGIN: "http://localhost:5173",
          SECURITY_TENANT_PASSWORD: tenantPassword,
          SECURITY_PLATFORM_PASSWORD: platformPassword,
          SECURITY_MFA_CODE: mfaCode,
          // Direct database access for the SEC checks (secret storage has no HTTP surface yet); same disposable database.
          SECURITY_DATABASE_URL: databaseUrl,
          SECURITY_GITHUB_STUB_URL: gh.stub.url,
          SECURITY_GITHUB_WEBHOOK_SECRET: gh.webhookSecret,
          // The suite runs the scm worker's handlers in-process against the stub (no broker needed): it needs the App credentials.
          SECURITY_GITHUB_CLIENT_ID: gh.clientId,
          SECURITY_GITHUB_CLIENT_SECRET: gh.clientSecret,
          SECURITY_GITHUB_PRIVATE_KEY: gh.privateKey,
          PGSSLMODE: process.env.PGSSLMODE ?? "",
        },
        stdio: "inherit",
      },
    );
    tests.on("exit", (exitCode) => resolve(exitCode ?? 1));
  });
  if (code !== 0 && apiOutput.length > 0) {
    console.error("\n[security-suite] last API log lines:");
    for (const line of apiOutput.slice(-25)) console.error(`  ${line.slice(0, 240)}`);
  }
  return code;
}

async function teardown() {
  for (const cleanup of cleanups.reverse()) {
    try {
      await cleanup();
    } catch {
      /* best effort */
    }
  }
}

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, async () => {
    await teardown();
    process.exit(130);
  });
}

let exitCode = 1;
try {
  exitCode = await main();
} catch (error) {
  if (error instanceof EnvironmentError) {
    console.error(`[security-suite] ${error.message}`);
    exitCode = 2;
  } else {
    console.error(error);
    exitCode = 1;
  }
} finally {
  await teardown();
}
process.exit(exitCode);
