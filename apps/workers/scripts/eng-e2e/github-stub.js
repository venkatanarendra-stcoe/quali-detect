// DEVELOPMENT TOOL: a 40-line stand-in for the three GitHub API calls the pipeline worker makes to fetch a repository (installation
// token, ref to commit, tarball), serving a LOCAL tree. Start the pipeline worker with GITHUB_API_BASE_URL=http://127.0.0.1:<port>.
// The commit sha is the sha1 of the tree's tarball, so the same tree always has the same commit. Nothing leaves this machine.
//   node apps/workers/scripts/eng-e2e/github-stub.js --tree /tmp/qm-e2e/fixture-local --port 4010
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import http from "node:http";
import { parseArgs } from "node:util";

if (process.env.NODE_ENV === "production") throw new Error("refused: a development tool");
const { values } = parseArgs({
  options: { tree: { type: "string" }, port: { type: "string", default: "4010" } },
});
if (!values.tree) throw new Error("--tree <dir> is required");
const tarOf = (top) =>
  spawnSync(
    "tar",
    [
      "-czf",
      "-",
      "--sort=name",
      "--mtime=2026-01-01",
      "--owner=0",
      "--group=0",
      "--numeric-owner",
      "--transform",
      `s,^\\.,${top},`,
      "-C",
      values.tree,
      ".",
    ],
    { maxBuffer: 1 << 30 },
  ).stdout;
const sha = createHash("sha1").update(tarOf("x")).digest("hex");
const send = (res, code, body, type = "application/json") => {
  res.writeHead(code, { "content-type": type });
  res.end(body);
};
http
  .createServer((req, res) => {
    const url = new URL(req.url, "http://x");
    const log = `${req.method} ${url.pathname}`;
    let m;
    if (
      req.method === "POST" &&
      /^\/app\/installations\/[^/]+\/access_tokens$/.test(url.pathname)
    ) {
      req.resume();
      return req.on("end", () =>
        send(
          res,
          201,
          JSON.stringify({
            token: "ghs_localstubtoken0000000000000000000000",
            expires_at: new Date(Date.now() + 3600e3).toISOString(),
          }),
        ),
      );
    }
    if ((m = url.pathname.match(/^\/repos\/([^/]+)\/([^/]+)\/commits\/refs\/(?:heads|tags)\/.+$/)))
      return send(res, 200, JSON.stringify({ sha }));
    if ((m = url.pathname.match(/^\/repos\/([^/]+)\/([^/]+)\/tarball\/([0-9a-f]{40})$/)))
      return send(res, 200, tarOf(`${m[1]}-${m[2]}-${m[3].slice(0, 7)}`), "application/x-gzip");
    console.log(`${log} -> 404`);
    send(res, 404, JSON.stringify({ message: "Not Found" }));
  })
  .listen(Number(values.port), "127.0.0.1", () =>
    console.log(JSON.stringify({ listening: Number(values.port), tree: values.tree, commit: sha })),
  );
