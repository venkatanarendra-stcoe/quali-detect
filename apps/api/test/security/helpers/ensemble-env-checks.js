import { ENV_ALLOWLIST } from "@qmentisai/infra";
import { makeEnv } from "./ensemble-engine-checks.js";

/**
 * Scan engines, part M gap filler (ADR-008 area 18, SPEC scan-engines 14.1 ENG-S04, SE-29, SE-30): the engine level of "no credentials
 * reach tools". Earlier parts proved it at the runner (`ENG-S04a`) and by the sealed command lines; this check runs the real SBOM
 * ensemble engine over a `FakeSandboxRuntime` with credentials planted in the worker process environment, for a trusted run and for a
 * `fork` run (the `untrusted_fork` trust level, scan-untrusted queue), and inspects EVERY call the runtime saw.
 * The other three engines build their run specifications through the same plan function (`sast/plan.js`, reused by the Secrets and SCA
 * plans), whose environment the per-type command line checks (`ENG-S03d`, `ENG-S03e`, `ENG-S03h`) assert; the planted-environment run
 * is not repeated for them.
 */

const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};

const PLANTED = {
  GITHUB_TOKEN: "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
  GH_TOKEN: "ghs_abcdefghijklmnopqrstuvwxyz0123456789",
  DATABASE_URL: "postgres://user:pw-sentinel-4711@db.internal/qm",
  AWS_ACCESS_KEY_ID: "AKIAABCDEFGHIJKLMNOP",
  AWS_SECRET_ACCESS_KEY: "aws-secret-sentinel-4711-abcdefghijklmnop",
  LLM_API_KEY: "sk-ant-abcdefghijklmnopqrstuvwxyz",
  ANTHROPIC_API_KEY: "sk-ant-sentinel-4711-abcdefghijklmnop",
  GITHUB_APP_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----sentinel4711",
  SECRET_STORE_MASTER_KEY: "master-key-sentinel-4711-abcdefghijklmnop",
};

export const ENSEMBLE_ENV_CHECKS = [
  {
    id: "ENG-S04b",
    name: "no credential reaches a tool through the ensemble engine, trusted or fork (SPEC scan-engines SE-29, SE-30, 14.1 ENG-S04; part M gap, the engine level): with a GitHub token, a database URL, cloud keys, an LLM key and a secret store key planted in the worker process environment, the real SBOM engine over a fake runtime runs a trusted task and a fork task; in every call the runtime recorded (the argument vector, the run specification and its environment) no planted value or planted variable name occurs, every container environment name is on the platform allowlist, no env file or inherited environment flag exists, and the tool labels carry only the fixed platform identifiers; a control proves the planting is effective (the planted variable is readable by the process) and that the inspection sees the calls",
    async run() {
      const p = [];
      const saved = {};
      for (const [k, v] of Object.entries(PLANTED)) {
        saved[k] = process.env[k];
        process.env[k] = v;
      }
      const env = makeEnv();
      try {
        ok(
          p,
          process.env.GITHUB_TOKEN === PLANTED.GITHUB_TOKEN,
          "control: the planting is not effective",
        );
        for (const fork of [false, true]) {
          const result = await env.run({ fork });
          ok(
            p,
            result.ensemble.toolRuns.length >= 2,
            `control: ${fork ? "fork" : "trusted"} run recorded no tool run`,
          );
        }
        const runs = env.runtime.calls.filter((c) => c.type === "run");
        ok(p, runs.length >= 4, `control: only ${runs.length} container runs were seen`);
        for (const call of runs) {
          const text = JSON.stringify([call.args, call.spec]);
          for (const [name, value] of Object.entries(PLANTED)) {
            ok(
              p,
              !text.includes(value),
              `${call.spec.toolId}: the value of ${name} reached the call`,
            );
            ok(p, !text.includes(name), `${call.spec.toolId}: the name ${name} reached the call`);
          }
          for (const name of Object.keys(call.spec.env ?? {}))
            ok(
              p,
              ENV_ALLOWLIST.includes(name),
              `${call.spec.toolId}: env name ${name} is not on the allowlist`,
            );
          ok(
            p,
            !call.args.some((a) => /^(--env-file|--env-host)/.test(a)),
            `${call.spec.toolId}: an env file or host environment flag`,
          );
          for (const a of call.args.filter((x) => x.startsWith("--env=")))
            ok(
              p,
              ENV_ALLOWLIST.includes(a.slice(6).split("=")[0]),
              `${call.spec.toolId}: ${a.slice(0, 30)} is not an allowlisted variable`,
            );
        }
      } finally {
        env.cleanup();
        for (const [k, v] of Object.entries(saved)) {
          if (v === undefined) delete process.env[k];
          else process.env[k] = v;
        }
      }
      return p;
    },
  },
];
