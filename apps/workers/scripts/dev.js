// Dev launcher: runs the five workers of the local stack (pipeline, scan, scm, outbox, scheduler) side by side, each under
// `node --watch` so it restarts on a change, with every output line prefixed by the worker name. No dependency: a few lines of
// child_process instead of `concurrently`. `analysis`, `notification` and `usage` are not part of the default stack; start them
// with `pnpm --filter @qmentisai/workers dev:<name>`, or choose the set here: `WORKERS=pipeline,scan pnpm dev`.
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const DEFAULT = ["pipeline", "scan", "scm", "outbox", "scheduler"];
const ALLOWED = [
  "pipeline",
  "analysis",
  "scan",
  "notification",
  "usage",
  "scheduler",
  "outbox",
  "scm",
  "dbrefresh",
  "findings",
];
const names = (process.env.WORKERS ? process.env.WORKERS.split(",") : DEFAULT)
  .map((n) => n.trim())
  .filter(Boolean);
const unknown = names.filter((n) => !ALLOWED.includes(n));
if (unknown.length > 0) {
  console.error(`unknown worker(s): ${unknown.join(", ")} (allowed: ${ALLOWED.join(", ")})`);
  process.exit(1);
}

const children = names.map((name) => {
  const child = spawn(
    process.execPath,
    ["--watch", "--env-file-if-exists=.env", `src/${name}/main.js`],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  for (const stream of [child.stdout, child.stderr]) {
    createInterface({ input: stream }).on("line", (line) => console.log(`[${name}] ${line}`));
  }
  child.on("exit", (code, signal) => console.log(`[${name}] exited (${signal ?? code})`));
  return child;
});

let stopping = false;
function stop(signal) {
  if (stopping) return;
  stopping = true;
  for (const child of children) child.kill(signal);
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on("SIGINT", () => stop("SIGINT"));
process.on("SIGTERM", () => stop("SIGTERM"));
console.log(`workers: ${names.join(", ")}`);
