import { CircleAlert, CircleCheck, CircleDot, CircleX, PauseCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge.jsx";

const HEALTH = {
  healthy: { label: "Healthy", tone: "success", icon: CircleCheck },
  connected: { label: "Connected", tone: "success", icon: CircleCheck },
  degraded: { label: "Degraded", tone: "warning", icon: CircleAlert },
  suspended: { label: "Suspended", tone: "warning", icon: PauseCircle },
  revoked: { label: "Revoked", tone: "danger", icon: CircleX },
  unlinked: { label: "Unlinked", tone: "neutral", icon: CircleDot },
  not_connected: { label: "Not connected", tone: "neutral", icon: CircleDot },
  not_available: { label: "Not available yet", tone: "neutral", icon: CircleDot },
  not_configured: { label: "Not configured", tone: "neutral", icon: CircleDot },
};

/** Outlined health/status pill with an icon and text (never color alone). @param {{ status: string }} props */
export function LinkHealth({ status }) {
  const {
    label,
    tone,
    icon: Icon,
  } = HEALTH[status] ?? { label: status, tone: "neutral", icon: CircleDot };
  return (
    <Badge tone={tone}>
      <Icon aria-hidden="true" />
      {label}
    </Badge>
  );
}
