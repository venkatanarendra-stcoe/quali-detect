import { isSafeRelativePath } from "@qmentisai/shared";

/**
 * Provider permalinks (docs/modules/scan-engines/SPEC.md 5.13.3, D-19, 17.a.8; part J). ONE pure function builds a commit-pinned link to a file and
 * a line or a range. The host is a FIXED per-provider constant (never from a tool, a finding, the repository's `html_url` or any user input);
 * the provider name is looked up in a closed table (an unknown provider has no formatter and gives `null`); the full name, the commit and the
 * path are validated before any of them is placed in the URL; every path segment is percent-encoded one by one. A finding is still valid
 * without a link (`url = null`).
 *
 * Formats (verified against the official pages in 17.a.8; the live range check is ENG-L17, on the owner's machine):
 * - GitHub:    `https://github.com/{owner}/{repo}/blob/{sha}/{path}#L{a}` and `#L{a}-L{b}` (two L's, Confirmed D-19);
 * - GitLab:    `https://gitlab.com/{group}/{project}/-/blob/{sha}/{path}#L{a}` and `#L{a}-{b}` (nested groups allowed);
 * - Bitbucket: `https://bitbucket.org/{workspace}/{repo}/src/{sha}/{path}#{filename}-{a}` (only the single-line anchor is documented: a range
 *   links to its START line).
 * Only GitHub is a wired provider today (`enum ScmProvider { github }`); the others are formats for a future adapter.
 */

/** A 40-hex commit (never a branch or a tag). */
const SHA = /^[0-9a-f]{40}$/;
/** One segment of an owner, group, project or repository name: the conservative alphabet all three providers accept. */
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const MAX_LINE = 10_000_000;
const MAX_URL = 2000;

/** The provider table: host, how many name segments a full name has, how to place the commit, how to write the line anchor. */
const PROVIDERS = Object.freeze({
  github: Object.freeze({
    host: "github.com",
    minSegments: 2,
    maxSegments: 2,
    base: (name) => `${name}/blob`,
    anchor: (_file, a, b) => (b > a ? `#L${a}-L${b}` : `#L${a}`),
  }),
  gitlab: Object.freeze({
    host: "gitlab.com",
    minSegments: 2,
    maxSegments: 6,
    base: (name) => `${name}/-/blob`,
    anchor: (_file, a, b) => (b > a ? `#L${a}-${b}` : `#L${a}`),
  }),
  bitbucket: Object.freeze({
    host: "bitbucket.org",
    minSegments: 2,
    maxSegments: 2,
    base: (name) => `${name}/src`,
    // the range form is not documented: the start line only
    anchor: (file, a) => `#${file}-${a}`,
  }),
});

/** The provider names that have a formatter. */
export const PERMALINK_PROVIDERS = Object.freeze(Object.keys(PROVIDERS));

// zero-width, bidirectional override/isolate and BOM code points (built from numbers so the source holds no invisible character)
const INVISIBLE = new RegExp(
  `[${[
    [0x200b, 0x200f],
    [0x202a, 0x202e],
    [0x2060, 0x2069],
    [0xfeff, 0xfeff],
  ]
    .map(([a, b]) => String.fromCodePoint(a) + "-" + String.fromCodePoint(b))
    .join("")}]`,
  "u",
);

/** Encodes one URL path segment: everything except the unreserved characters is percent-encoded (also `!'()*`). */
const encode = (segment) =>
  encodeURIComponent(segment).replace(
    /[!'()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  );

const isLine = (n) => Number.isInteger(n) && n >= 1 && n <= MAX_LINE;

/**
 * Whether a path may be put in a link: a safe relative path (no `..`, `.`, empty segment, backslash, control character or leading slash) and
 * no bidirectional-override or zero-width character.
 * @param {unknown} value
 */
export function isLinkablePath(value) {
  return isSafeRelativePath(value) && !INVISIBLE.test(/** @type {string} */ (value));
}

/**
 * The permalink of a file (and a line or a range), or `null` when ANY input is not valid or the provider has no formatter. Never throws.
 * @param {{ provider: string, repoFullName: string, commitSha: string, path: string, startLine?: number, endLine?: number } | null | undefined} input
 * @returns {string | null}
 */
export function buildPermalink(input) {
  try {
    const { provider, repoFullName, commitSha, path, startLine, endLine } = input ?? {};
    if (typeof provider !== "string" || !Object.hasOwn(PROVIDERS, provider)) return null;
    const p = PROVIDERS[provider];
    if (typeof commitSha !== "string" || !SHA.test(commitSha)) return null;
    if (!isLinkablePath(path)) return null;
    if (typeof repoFullName !== "string") return null;
    const names = repoFullName.split("/");
    if (names.length < p.minSegments || names.length > p.maxSegments) return null;
    if (!names.every((n) => NAME.test(n) && n !== "." && n !== ".." && !n.endsWith(".")))
      return null;
    if (startLine !== undefined && !isLine(startLine)) return null;
    if (
      endLine !== undefined &&
      (!isLine(endLine) || startLine === undefined || endLine < startLine)
    )
      return null;
    const segments = /** @type {string} */ (path).split("/");
    const url =
      `https://${p.host}/${p.base(names.map(encode).join("/"))}/${commitSha}/${segments.map(encode).join("/")}` +
      (startLine === undefined
        ? ""
        : p.anchor(encode(segments[segments.length - 1]), startLine, endLine ?? startLine));
    return url.length <= MAX_URL ? url : null;
  } catch {
    return null;
  }
}

/**
 * The `scmRef` and `url` of a finding from the recorded repository facts and the finding's location (SPEC 5.13.3). A finding with no
 * location path, or a repository without a pinned commit or a formatter, gets `{ scmRef: null, url: null }`. A component finding with no
 * line (SBOM, SCA) links to the manifest file only.
 * @param {{ provider?: string, fullName?: string, commitSha?: string | null } | null | undefined} repo the repository facts of the platform
 * @param {{ path?: string, startLine?: number, endLine?: number } | undefined} location
 * @returns {{ scmRef: object | null, url: string | null }}
 */
export function scmLinkOf(repo, location) {
  const none = { scmRef: null, url: null };
  if (!repo || !location?.path) return none;
  const url = buildPermalink({
    provider: repo.provider ?? "",
    repoFullName: repo.fullName ?? "",
    commitSha: repo.commitSha ?? "",
    path: location.path,
    startLine: location.startLine,
    endLine: location.endLine,
  });
  if (url === null) return none;
  return {
    // the stored reference only ever names the wired provider (the shared finding schema)
    scmRef:
      repo.provider === "github"
        ? {
            provider: "github",
            repoFullName: repo.fullName,
            commitSha: repo.commitSha,
            path: location.path,
            ...(location.startLine === undefined ? {} : { startLine: location.startLine }),
            ...(location.endLine === undefined ? {} : { endLine: location.endLine }),
          }
        : null,
    url,
  };
}
