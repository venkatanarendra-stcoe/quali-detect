import { Ban, CircleCheck, CircleDot, CircleX } from "lucide-react";
import { Badge } from "@/components/ui/badge.jsx";

// DESIGN_SYSTEM.md §10: Active success, Trial neutral, Suspended danger, Deactivated neutral. Icon + text, never color alone.
const STATUS = {
  active: { label: "Active", tone: "success", icon: CircleCheck },
  trial: { label: "Trial", tone: "neutral", icon: CircleDot },
  suspended: { label: "Suspended", tone: "danger", icon: CircleX },
  deactivated: { label: "Deactivated", tone: "neutral", icon: Ban },
};

/** @param {{ status: string }} props */
export function TenantStatusChip({ status }) {
  const {
    label,
    tone,
    icon: Icon,
  } = STATUS[status] ?? { label: status, tone: "neutral", icon: CircleDot };
  return (
    <Badge tone={tone}>
      <Icon aria-hidden="true" />
      {label}
    </Badge>
  );
}
