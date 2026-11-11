import { Inbox } from "lucide-react";
import { StateLayout } from "./state-layout.jsx";

/** "No data yet" / "no results". @param {{ title: string, description?: string, icon?: any, actions?: any }} props */
export function EmptyState({ title, description, icon = Inbox, actions }) {
  return (
    <StateLayout icon={icon} title={title} actions={actions}>
      {description ? <p>{description}</p> : null}
    </StateLayout>
  );
}
