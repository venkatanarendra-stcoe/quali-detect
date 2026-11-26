import { REPORT_TEMPLATE_BY_ID } from "@qmentisai/shared";
import { CircleCheck, CircleX, Clock, Hourglass, Loader } from "lucide-react";
import { Badge } from "@/components/ui/badge.jsx";
import { absoluteTime } from "@/features/executions/components/execution-bits.jsx";
import { REPORT_STATUS_LABELS } from "../constants/index.js";
import { dayLabel } from "../schemas/format.js";

const STATUS_ICON = {
  queued: Clock,
  running: Loader,
  ready: CircleCheck,
  failed: CircleX,
  expired: Hourglass,
};
const STATUS_TONE = {
  queued: "neutral",
  running: "neutral",
  ready: "success",
  failed: "danger",
  expired: "neutral",
};

/** Queued, Running, Ready, Failed, Expired: an outlined chip with an icon and the word (never colour alone). @param {{ status: string }} props */
export function ReportStatusChip({ status }) {
  const Icon = STATUS_ICON[status] ?? Clock;
  return (
    <Badge tone={STATUS_TONE[status] ?? "neutral"} data-status={status}>
      <Icon
        aria-hidden="true"
        className={status === "running" ? "animate-spin motion-reduce:animate-none" : undefined}
      />
      {REPORT_STATUS_LABELS[status] ?? status}
    </Badge>
  );
}

/** The template title; an unknown id (a template of a newer version) is shown as plain escaped text. */
export const templateTitle = (id) => REPORT_TEMPLATE_BY_ID[id]?.title ?? id;

/** "30 Oct to 28 Nov", "as of 30 Oct" or "—". @param {{ period: { from: string, to: string } | null, asOfDay: string | null }} report */
export function periodText(report) {
  if (report.asOfDay) return `as of ${dayLabel(report.asOfDay)}`;
  if (report.period) return `${dayLabel(report.period.from)} to ${dayLabel(report.period.to)}`;
  return "—";
}

/** "Available until 14:02 tomorrow" for a ready report. @param {string | null} expiresAt */
export function availableUntil(expiresAt) {
  if (!expiresAt) return "";
  return `Available until ${absoluteTime(expiresAt, { dateStyle: "medium", timeStyle: "short" })}`;
}
