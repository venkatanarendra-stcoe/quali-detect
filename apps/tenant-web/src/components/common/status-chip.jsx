import { Archive, CircleCheck, CircleDot, CircleX, Clock } from "lucide-react";
import { Badge } from "@/components/ui/badge.jsx";

const STATUS = {
  active: { label: "Active", tone: "success", icon: CircleCheck },
  archived: { label: "Archived", tone: "neutral", icon: Archive },
  invited: { label: "Invited", tone: "neutral", icon: Clock },
  suspended: { label: "Suspended", tone: "danger", icon: CircleX },
  trial: { label: "Trial", tone: "neutral", icon: CircleDot },
};

/** Outlined status chip with icon + text (never color alone). Unknown statuses render neutral. @param {{ status: string }} props */
export function StatusChip({ status }) {
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
