import { Check, Copy, ExternalLink, Info, WrapText } from "lucide-react";
import { useId, useState } from "react";
import { Button } from "@/components/ui/button.jsx";
import { cn } from "@/lib/cn.js";
import { Identifier, TimeAgo, Untrusted } from "./finding-bits.jsx";

const PROVIDER_NAME = { github: "GitHub" };
/** A context line the platform could not mask is stored as exactly this marker (scan engines SE-42). */
const WITHHELD = "[line withheld]";
const isHttps = (url) => typeof url === "string" && /^https:\/\/[^\s]+$/.test(url);

/** The commit-pinned link, shown only when the DTO carries a validated https URL (SCREENS 6, Evidence). @param {{ link: any }} props */
export function CommitLink({ link }) {
  if (!link || !isHttps(link.url))
    return <span className="text-sm text-muted-foreground">No link available</span>;
  return (
    <a
      href={link.url}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1.5 rounded-sm text-sm font-medium underline underline-offset-2 outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      View at commit <span className="font-mono">{link.commitShort}</span> on{" "}
      {PROVIDER_NAME[link.provider] ?? link.provider}
      <ExternalLink aria-hidden="true" className="size-3.5" />
      <span className="sr-only">(opens in a new tab)</span>
    </a>
  );
}

/** One line of code: number gutter, focus marker (tint + left bar + screen-reader text), inert text. */
function Line({ n, text, focus, wrap }) {
  return (
    <div
      className={cn(
        "flex border-l-2",
        focus ? "border-foreground bg-secondary" : "border-transparent",
      )}
    >
      <span
        aria-hidden="true"
        className="w-12 shrink-0 pr-3 text-right text-xs leading-6 text-subtle-foreground select-none"
      >
        {n}
      </span>
      <code
        className={cn(
          "min-w-0 flex-1 pr-3 font-mono text-[13px] leading-6",
          wrap ? "break-all whitespace-pre-wrap" : "whitespace-pre",
        )}
      >
        {focus ? <span className="sr-only">highlighted line {n}: </span> : null}
        {text === WITHHELD ? (
          <span className="text-muted-foreground italic">
            {WITHHELD}
            <span className="sr-only"> (this line could not be masked safely)</span>
          </span>
        ) : text === "" ? (
          " "
        ) : (
          text
        )}
      </code>
    </div>
  );
}

/**
 * The inert code region: a keyboard-focusable, horizontally scrollable block, never HTML. `copyable` is false for secrets (SCREENS 6:
 * no copy-snippet button).
 * @param {{ evidence: any, label: string, copyable: boolean, maxHeight?: string }} props
 */
export function CodeBlock({ evidence, label, copyable, maxHeight = "20rem" }) {
  const [wrap, setWrap] = useState(false);
  const [copied, setCopied] = useState(false);
  const id = useId();
  const lines = (evidence.snippet ?? "").split("\n");
  const first = evidence.startLine ?? 1;
  const hasFocus = evidence.focusStart != null && evidence.focusEnd != null;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
        <span id={id}>
          {evidence.language ? <span className="font-mono">{evidence.language}</span> : null}
          {evidence.nodeKind ? (
            <>
              {" "}
              · enclosing{" "}
              <span className="font-mono">{evidence.nodeKind.replaceAll("_", " ")}</span>
            </>
          ) : null}
          {hasFocus ? (
            <>
              {" "}
              ·{" "}
              {evidence.focusEnd !== evidence.focusStart
                ? `highlighted lines ${evidence.focusStart} to ${evidence.focusEnd}`
                : `highlighted line ${evidence.focusStart}`}
            </>
          ) : null}
        </span>
        <span className="flex items-center gap-1">
          <Button size="sm" variant="ghost" aria-pressed={wrap} onClick={() => setWrap((v) => !v)}>
            <WrapText aria-hidden="true" />
            Wrap lines
          </Button>
          {copyable ? (
            <Button
              size="sm"
              variant="ghost"
              onClick={() =>
                navigator.clipboard?.writeText(evidence.snippet ?? "").then(() => {
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1500);
                })
              }
            >
              {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
              {copied ? "Copied" : "Copy snippet"}
            </Button>
          ) : null}
        </span>
      </div>
      {/* a scrollable region must be keyboard focusable (WCAG 2.1.1); the DataTable does the same */}
      <div
        role="region"
        aria-label={label}
        // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
        tabIndex={0}
        style={{ maxHeight }}
        className="qm-scroll overflow-auto rounded-md border border-border bg-card py-2 outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <div className="w-max min-w-full">
          {lines.map((text, index) => {
            const n = first + index;
            return (
              <Line
                key={n}
                n={n}
                text={text}
                wrap={wrap}
                focus={hasFocus && n >= evidence.focusStart && n <= evidence.focusEnd}
              />
            );
          })}
        </div>
      </div>
      {evidence.truncated ? (
        <p className="text-xs text-muted-foreground">Excerpt shortened.</p>
      ) : null}
    </div>
  );
}

/**
 * Evidence of a finding (T-32 Evidence tab and the review panel, `compact`): link, location, then SCA component and advisories, a
 * SAST function block with focus lines, a secret's masked line, or the explanation of a missing, purged or shortened excerpt.
 * @param {{ finding: any, compact?: boolean }} props
 */
export function EvidencePanel({ finding, compact = false }) {
  const { evidence, link, location, scanType } = finding;
  const isSecret = scanType === "secrets";
  const range =
    location?.startLine != null
      ? `lines ${location.startLine}${location.endLine && location.endLine !== location.startLine ? ` to ${location.endLine}` : ""}`
      : null;
  return (
    <div className="space-y-4">
      <div className="space-y-2 text-sm">
        <CommitLink link={link} />
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-muted-foreground">
          {location?.path ? <Identifier value={location.path} max={32} copy label="path" /> : null}
          {range ? <span>{range}</span> : null}
          <span className="inline-flex gap-1">
            captured <TimeAgo value={finding.lastSeenAt} />
          </span>
        </div>
      </div>

      {scanType === "sca" ? (
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 rounded-md border border-border bg-card p-4 text-sm">
          <dt className="text-muted-foreground">Component</dt>
          <dd className="font-mono">
            {finding.component
              ? `${finding.component.name}@${finding.component.version ?? "?"}`
              : "—"}
          </dd>
          <dt className="text-muted-foreground">Ecosystem</dt>
          <dd>{finding.component?.ecosystem ?? "—"}</dd>
          <dt className="text-muted-foreground">Fixed versions</dt>
          <dd className="font-mono">{finding.fix?.fixedVersions?.join(", ") || "None known"}</dd>
          <dt className="text-muted-foreground">Advisories</dt>
          <dd className="flex flex-wrap gap-x-3 font-mono">
            {finding.advisories.length
              ? finding.advisories.map((a) => <span key={a.id}>{a.id}</span>)
              : "—"}
          </dd>
        </dl>
      ) : !evidence ? (
        <p className="flex items-center gap-1.5 text-sm text-muted-foreground">
          <Info aria-hidden="true" className="size-4" />
          No code excerpt is available for this finding.
        </p>
      ) : evidence.purged ? (
        <p className="flex items-center gap-1.5 text-sm text-muted-foreground">
          <Info aria-hidden="true" className="size-4" />
          The code excerpt was removed after the retention period; the link and line numbers remain.
        </p>
      ) : (
        <>
          <CodeBlock
            evidence={evidence}
            copyable={!isSecret}
            label={isSecret ? "Masked line preview" : "Code excerpt"}
            maxHeight={compact ? "12rem" : "24rem"}
          />
          {isSecret ? (
            <p className="flex items-center gap-1.5 text-sm text-muted-foreground">
              <Info aria-hidden="true" className="size-4 shrink-0" />
              <Untrusted>The value is never stored. Rotate it if it is real.</Untrusted>
            </p>
          ) : null}
        </>
      )}
    </div>
  );
}
