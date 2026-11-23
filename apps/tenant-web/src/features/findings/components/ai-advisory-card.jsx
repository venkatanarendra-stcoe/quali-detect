import { CircleHelp, Info, Loader2, ShieldAlert, ShieldOff, Sparkles } from "lucide-react";
import { useId, useState } from "react";
import { Link } from "react-router";
import { Button } from "@/components/ui/button.jsx";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { cn } from "@/lib/cn.js";
import { SUGGESTION_LABELS } from "../constants/index.js";
import { TimeAgo } from "./finding-bits.jsx";

const SUGGESTION_ICON = {
  likely_true_positive: ShieldAlert,
  likely_false_positive: ShieldOff,
  uncertain: CircleHelp,
};
const BAND_WORD = { high: "High", medium: "Medium", low: "Low" };

const EGRESS_TEXT = {
  snippet: "Based on: rule, location and a code excerpt",
  metadata: "Based on: rule and location only",
  local: "Based on: rule, location and a code excerpt, processed on this deployment",
  none: "Based on: rule and location only",
};

/** A plain meter: a neutral track and fill (never a status colour), the number and the band in words. */
function ConfidenceMeter({ value, band }) {
  const id = useId();
  const word = band ? BAND_WORD[band] : null;
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-baseline gap-x-2">
        <span id={id} className="text-xs font-medium text-muted-foreground">
          Confidence
        </span>
        <span className="text-sm font-medium tabular-nums">
          {value}%{word ? ` · ${word}` : ""}
        </span>
        <span className="text-xs text-subtle-foreground">(model-reported, not calibrated)</span>
      </div>
      <div
        role="meter"
        aria-labelledby={id}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={value}
        aria-valuetext={`${value} percent${word ? `, ${word.toLowerCase()} confidence` : ""}, model-reported, not calibrated`}
        className="h-1.5 w-full max-w-60 overflow-hidden rounded-full bg-secondary"
      >
        <div className="h-full bg-muted-foreground" style={{ width: `${value}%` }} />
      </div>
    </div>
  );
}

function Reasoning({ text }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const long = text.length > 280 || text.split("\n").length > 5;
  return (
    <div className="space-y-1">
      <div className="text-xs font-medium text-muted-foreground">Reasoning</div>
      <p id={id} className={cn("text-sm break-words whitespace-pre-wrap", !open && "line-clamp-5")}>
        {text}
      </p>
      {long ? (
        <button
          type="button"
          aria-expanded={open}
          aria-controls={id}
          onClick={() => setOpen((v) => !v)}
          className="rounded-sm text-xs font-medium underline underline-offset-2 outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {open ? "Show less" : "Show more"}
        </button>
      ) : null}
    </div>
  );
}

/**
 * The advisory of the false-positive agent, shown as ADVICE (SCREENS 8, owner decision D-6). A fixed neutral card: no mint, no
 * severity or status colour, always the chip "Advisory — requires a human decision". It never changes another control and never
 * preselects the decision (it is not even rendered inside the decision form).
 * `onRequest` re-requests advice (the host passes it only for holders of `finding.review`).
 * @param {{ advisory: { status: string, suggestion?: string, confidence?: number, confidenceBand?: string, reasoning?: string,
 *   provider?: string, model?: string, egressLevel?: string, generatedAt?: string, stale: boolean },
 *   secret?: boolean, onRequest?: () => void, requesting?: boolean, requestDisabledReason?: string | null, readOnlyNote?: string }} props
 */
export function AiAdvisoryCard({
  advisory,
  secret = false,
  onRequest,
  requesting = false,
  requestDisabledReason = null,
}) {
  const can = useCan();
  const titleId = useId();
  const status = advisory?.status ?? "none";
  const SuggestionIcon = SUGGESTION_ICON[advisory?.suggestion] ?? CircleHelp;
  const canManageAi = can("tenant_settings.manage");
  const requestButton = onRequest ? (
    requestDisabledReason ? (
      <Tooltip>
        <TooltipTrigger asChild>
          <span tabIndex={0} role="button" aria-disabled="true" className="inline-flex rounded-sm">
            <Button size="sm" variant="secondary" disabled aria-hidden="true" tabIndex={-1}>
              {status === "none" ? "Request advice" : "Request again"}
            </Button>
          </span>
        </TooltipTrigger>
        <TooltipContent>{requestDisabledReason}</TooltipContent>
      </Tooltip>
    ) : (
      <Button size="sm" variant="secondary" onClick={onRequest} disabled={requesting}>
        {status === "none" ? "Request advice" : "Request again"}
      </Button>
    )
  ) : null;

  return (
    <section
      aria-labelledby={titleId}
      aria-busy={status === "pending" || undefined}
      data-advisory-status={status}
      className="space-y-3 rounded-md border border-border bg-card p-4 text-card-foreground"
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <h3 id={titleId} className="flex items-center gap-1.5 text-sm font-semibold">
          <Sparkles aria-hidden="true" className="size-4 text-muted-foreground" />
          AI advisory
        </h3>
        <span className="inline-flex items-center rounded-sm border border-dashed border-border-strong px-1.5 py-0.5 text-xs font-medium text-muted-foreground">
          Advisory — requires a human decision
        </span>
      </div>

      {status === "none" && !secret ? (
        <div className="flex flex-wrap items-center gap-3">
          <p className="text-sm text-muted-foreground">
            No advice has been requested for this finding.
          </p>
          {requestButton}
        </div>
      ) : null}

      {status === "pending" ? (
        <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 aria-hidden="true" className="size-4 animate-spin motion-reduce:animate-none" />
          Advice is being prepared. You can continue without it.
        </p>
      ) : null}

      {status === "ready" ? (
        <div className="space-y-3">
          <p className="text-xs text-muted-foreground">
            Written by a language model. It can be wrong. It never approves, rejects or changes a
            finding.
          </p>
          <div>
            <span className="inline-flex items-center gap-1.5 rounded-sm border border-border-strong px-2 py-1 text-sm font-medium">
              <SuggestionIcon aria-hidden="true" className="size-4 text-muted-foreground" />
              {SUGGESTION_LABELS[advisory.suggestion] ?? "Uncertain"}
            </span>
          </div>
          {typeof advisory.confidence === "number" ? (
            <ConfidenceMeter value={advisory.confidence} band={advisory.confidenceBand} />
          ) : null}
          {advisory.reasoning ? <Reasoning text={advisory.reasoning} /> : null}
          <div className="space-y-1 text-xs text-muted-foreground">
            <p>{EGRESS_TEXT[advisory.egressLevel] ?? EGRESS_TEXT.metadata}</p>
            <p className="flex flex-wrap items-center gap-x-2">
              {advisory.provider ? (
                <span className="font-mono">
                  {advisory.provider}
                  {advisory.model ? ` · ${advisory.model}` : ""}
                </span>
              ) : null}
              {advisory.generatedAt ? (
                <span className="inline-flex gap-1">
                  generated <TimeAgo value={advisory.generatedAt} />
                </span>
              ) : null}
            </p>
            {secret ? (
              <p>
                Secret details are never sent to the assistant. This advice uses the rule and file
                path only.
              </p>
            ) : null}
          </div>
          {advisory.stale ? (
            <div className="flex flex-wrap items-center gap-3 text-sm">
              <span className="flex items-center gap-1.5 text-muted-foreground">
                <Info aria-hidden="true" className="size-4" />
                Evidence changed since this advice was written.
              </span>
              {requestButton}
            </div>
          ) : null}
        </div>
      ) : null}

      {status === "failed" ? (
        <div className="flex flex-wrap items-center gap-3">
          <p className="flex items-center gap-1.5 text-sm text-muted-foreground">
            <Info aria-hidden="true" className="size-4 shrink-0" />
            No advice is available right now. You can continue without it.
          </p>
          {requestButton}
        </div>
      ) : null}

      {status === "consent_blocked" ? (
        <p className="text-sm text-muted-foreground">
          AI advice is turned off for your organization.{" "}
          {canManageAi ? (
            <Link
              className="font-medium text-foreground underline underline-offset-2"
              to="/settings"
            >
              Review AI settings
            </Link>
          ) : null}
        </p>
      ) : null}

      {status === "not_configured" && !secret ? (
        <p className="text-sm text-muted-foreground">
          The AI assistant isn&apos;t set up for this deployment.
        </p>
      ) : null}

      {secret && status !== "ready" ? (
        <p className="flex items-center gap-1.5 text-sm text-muted-foreground">
          <Info aria-hidden="true" className="size-4 shrink-0" />
          Secret details are never sent to the assistant, so no advice is produced for secret
          findings.
        </p>
      ) : null}
    </section>
  );
}
