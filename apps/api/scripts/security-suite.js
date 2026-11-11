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

async function main() {
  const databaseUrl = await provisionDatabase();
  log("applying migrations and seed");
  pnpm(["--filter", "@qmentisai/db", "db:migrate:deploy"], { DATABASE_URL: databaseUrl });
  pnpm(["--filter", "@qmentisai/db", "db:seed"], { DATABASE_URL: databaseUrl });

  // Random per run: nothing in this suite depends on, or leaks, a fixed credential.
  const tenantPassword = randomBytes(12).toString("hex");
  const platformPassword = randomBytes(12).toString("hex");
  const mfaCode = String(randomInt(100000, 1000000));
  log("starting the API");
  const baseUrl = await startApi({
    DATABASE_URL: databaseUrl,
    MOCK_AUTH_PASSWORD: tenantPassword,
    MOCK_PLATFORM_AUTH_PASSWORD: platformPassword,
    MOCK_PLATFORM_MFA_CODE: mfaCode,
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
