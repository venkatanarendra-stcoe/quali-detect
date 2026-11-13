import { CircleX, PauseCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge.jsx";
import { LinkHealth } from "./link-health.jsx";

/** Reason texts for a revoked or suspended installation (SPEC repositories-github §16.2). */
const REASON = {
  uninstalled: "Uninstalled on GitHub",
  suspended: "Suspended on GitHub",
  not_found_on_github: "No longer found on GitHub",
};
const RECOVERY = {
  revoked: "Install the App again from this workspace's Integrations page.",
  suspended: "Unsuspend it on GitHub.",
};

/** True for a link whose installation cannot be used (revoked or suspended). */
export const isLinkBroken = (link) => link.status === "revoked" || link.status === "suspended";
/** True for a revoked link (the App is gone; nothing can work until it is installed again). */
export const isLinkRevoked = (link) => link.status === "revoked";

const day = (value) =>
  value ? new Date(value).toLocaleDateString(undefined, { dateStyle: "medium" }) : null;
const moment = (value) =>
  value
    ? new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })
    : null;

/** "Uninstalled on GitHub, 12 Nov 2026, 08:01" (reason and date), or null for a link that is neither. */
export function statusSummary(link) {
  if (!isLinkBroken(link)) return null;
  const reason = REASON[link.statusReason] ?? (link.status === "revoked" ? "Revoked" : "Suspended");
  const at = moment(link.statusChangedAt);
  return at ? `${reason}, ${at}` : reason;
}

/**
 * Status chip of an installation or workspace link: "Revoked · <date>" / "Suspended · <date>" with an icon, otherwise the
 * health pill. Never colour alone. @param {{ link: { status: string, health: string, statusChangedAt?: string|null } }} props
 */
export function LinkStatus({ link }) {
  if (!isLinkBroken(link)) return <LinkHealth status={link.health} />;
  const revoked = link.status === "revoked";
  const Icon = revoked ? CircleX : PauseCircle;
  const date = day(link.statusChangedAt);
  return (
    <Badge tone={revoked ? "danger" : "warning"} title={statusSummary(link) ?? undefined}>
      <Icon aria-hidden="true" />
      {revoked ? "Revoked" : "Suspended"}
      {date ? ` · ${date}` : ""}
    </Badge>
  );
}

/** Reason and recovery sentence for a revoked or suspended link; renders nothing otherwise. */
export function LinkStatusNotice({ link }) {
  if (!isLinkBroken(link)) return null;
  return (
    <p role="status" className="rounded-md border border-border-strong bg-secondary p-3 text-sm">
      <span className="font-medium">{statusSummary(link)}.</span>{" "}
      {link.status === "revoked"
        ? "Its repositories are disconnected. "
        : "Its repositories are paused. "}
      {RECOVERY[link.status]}
    </p>
  );
}
