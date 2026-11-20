import { gzipSync } from "node:zlib";

/**
 * A tiny sample repository for the ENG-L20 live check (docs/modules/scan-engines/ENG_L20_RUNBOOK.md). It covers the package
 * families the SBOM adapters make assumptions about: scoped npm, mixed-case PyPI names with `_` and `.`, Go modules with upper
 * case letters and a `v` prefix, Maven, a Debian and an Alpine package database. The content is inert text: nothing here is ever
 * executed, the tools only read it. The archive is built in memory as a GitHub-style tar.gz (one top directory) so the SAME
 * extractor as production (`extractTarGz`) lays it out on disk.
 */

const lockEntry = (name, version) => ({
  version,
  resolved: `https://registry.npmjs.org/${name}/-/x-${version}.tgz`,
});

const rootLock = {
  name: "eng-l20-sample",
  version: "1.0.0",
  lockfileVersion: 3,
  requires: true,
  packages: {
    "": {
      name: "eng-l20-sample",
      version: "1.0.0",
      dependencies: { lodash: "4.17.20", express: "4.18.2", "@babel/core": "7.20.0" },
    },
    "node_modules/lodash": lockEntry("lodash", "4.17.20"),
    "node_modules/express": lockEntry("express", "4.18.2"),
    "node_modules/@babel/core": lockEntry("@babel/core", "7.20.0"),
    "node_modules/@types/node": { ...lockEntry("@types/node", "18.0.0"), dev: true },
  },
};

const webLock = {
  name: "web",
  version: "1.0.0",
  lockfileVersion: 3,
  requires: true,
  packages: {
    "": { name: "web", version: "1.0.0", dependencies: { lodash: "4.17.20" } },
    "node_modules/lodash": lockEntry("lodash", "4.17.20"),
  },
};

const DPKG_STATUS = [
  "Package: curl",
  "Status: install ok installed",
  "Architecture: amd64",
  "Version: 7.88.1-10+deb12u5",
  "Maintainer: Example <example@example.invalid>",
  "Description: command line tool for transferring data",
  "",
  "Package: libssl3",
  "Status: install ok installed",
  "Architecture: amd64",
  "Source: openssl",
  "Version: 3.0.11-1~deb12u2",
  "Maintainer: Example <example@example.invalid>",
  "Description: Secure Sockets Layer toolkit",
  "",
].join("\n");

const APK_INSTALLED = [
  "C:Q1abcdefghijklmnopqrstuvwxyz0=",
  "P:busybox",
  "V:1.36.1-r5",
  "A:x86_64",
  "S:1",
  "I:1",
  "T:Size optimized toolbox",
  "U:https://busybox.net/",
  "L:GPL-2.0-only",
  "",
  "",
].join("\n");

const GO_MOD = [
  "module example.invalid/sample",
  "",
  "go 1.21",
  "",
  "require (",
  "\tgithub.com/BurntSushi/toml v1.3.2",
  "\tgolang.org/x/text v0.14.0",
  ")",
  "",
].join("\n");

/** Repository-relative path to file content. Order is the order in the archive. */
export const SAMPLE_FILES = Object.freeze({
  "README.md": "# ENG-L20 sample tree\n\nInert fixture for the SBOM fidelity check.\n",
  "package.json": `${JSON.stringify(rootLock.packages[""], null, 2)}\n`,
  "package-lock.json": `${JSON.stringify(rootLock, null, 2)}\n`,
  "web/package-lock.json": `${JSON.stringify(webLock, null, 2)}\n`,
  "py/requirements.txt":
    "Django==3.2.0\nPyYAML==6.0\ntyping_extensions==4.8.0\nzope.interface==5.5.2\nRequests==2.31.0\n",
  "go/go.mod": GO_MOD,
  "go/go.sum":
    "github.com/BurntSushi/toml v1.3.2 h1:o7IhLm0Msx3BaB+n3Ag7L8EVlByGnpq14C4YWiu/gL8=\ngithub.com/BurntSushi/toml v1.3.2/go.mod h1:CxXYINrC8qIiEnFrOxCa7Jy5BFHlXnUU2pbicEuybxQ=\ngolang.org/x/text v0.14.0 h1:ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ALU0bI+0zXKWiQ=\ngolang.org/x/text v0.14.0/go.mod h1:18ZOQIKpY8NJVqYksKHtTdi31H5itFRjB5/qKTNYzSU=\n",
  "java/pom.xml": `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>invalid.example</groupId>
  <artifactId>sample</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.17.1</version>
    </dependency>
  </dependencies>
</project>
`,
  "etc/os-release":
    'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n',
  "var/lib/dpkg/status": DPKG_STATUS,
  "lib/apk/db/installed": APK_INSTALLED,
});

const BLOCK = 512;
const octal = (value, width) => `${value.toString(8).padStart(width - 1, "0")}\0`;

function header(name, size, type) {
  const buf = Buffer.alloc(BLOCK);
  buf.write(name, 0, 100, "utf8");
  buf.write(octal(type === "5" ? 0o755 : 0o644, 8), 100, "ascii");
  buf.write(octal(0, 8), 108, "ascii");
  buf.write(octal(0, 8), 116, "ascii");
  buf.write(octal(size, 12), 124, "ascii");
  buf.write(octal(0, 12), 136, "ascii");
  buf.write("        ", 148, "ascii");
  buf.write(type, 156, "ascii");
  buf.write("ustar\0", 257, "ascii");
  buf.write("00", 263, "ascii");
  let sum = 0;
  for (const byte of buf) sum += byte;
  buf.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
  return buf;
}

/**
 * @param {Record<string, string>} [files] repository-relative path to text (default {@link SAMPLE_FILES})
 * @param {string} [topDir] the single top-level directory GitHub puts around a tarball
 * @returns {Buffer} a tar.gz
 */
export function buildSampleTarGz(files = SAMPLE_FILES, topDir = "eng-l20-sample-0000000") {
  const parts = [header(`${topDir}/`, 0, "5")];
  const dirs = new Set();
  for (const rel of Object.keys(files)) {
    const segments = rel.split("/").slice(0, -1);
    for (let i = 1; i <= segments.length; i += 1) dirs.add(segments.slice(0, i).join("/"));
  }
  for (const dir of [...dirs].sort()) parts.push(header(`${topDir}/${dir}/`, 0, "5"));
  for (const [rel, text] of Object.entries(files)) {
    const body = Buffer.from(text, "utf8");
    parts.push(header(`${topDir}/${rel}`, body.length, "0"), body);
    const pad = (BLOCK - (body.length % BLOCK)) % BLOCK;
    if (pad) parts.push(Buffer.alloc(pad));
  }
  parts.push(Buffer.alloc(BLOCK * 2));
  return gzipSync(Buffer.concat(parts));
}
