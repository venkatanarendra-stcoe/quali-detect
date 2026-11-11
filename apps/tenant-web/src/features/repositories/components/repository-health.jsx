import { CircleAlert, CircleCheck, CircleDot, CircleX, PauseCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge.jsx";

const HEALTH = {
  healthy: { label: "Healthy", tone: "success", icon: CircleCheck },
  degraded: { label: "Degraded", tone: "warning", icon: CircleAlert },
  error: { label: "Unavailable", tone: "danger", icon: CircleX },
  disconnected: { label: "Disconnected", tone: "neutral", icon: CircleDot },
  disabled: { label: "Disabled", tone: "neutral", icon: PauseCircle },
};

/** Health pill for a repository: icon + text, never color alone. A disabled repository shows "Disabled". */
export function RepositoryHealth({ repository }) {
  const key =
    repository.health !== "disconnected" && !repository.enabled ? "disabled" : repository.health;
  const { label, tone, icon: Icon } = HEALTH[key] ?? HEALTH.healthy;
  return (
    <Badge tone={tone} title={repository.healthReason ?? undefined}>
      <Icon aria-hidden="true" />
      {label}
    </Badge>
  );
}
