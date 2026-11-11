import { ShieldOff } from "lucide-react";
import { Link } from "react-router";
import { Button } from "@/components/ui/button.jsx";
import { StateLayout } from "./state-layout.jsx";

/** 403: the resource is visible but the action or page is not permitted (T-05). The backend enforces independently. */
export function UnauthorizedState({
  description = "You don't have permission to view this page. Ask an administrator if you need access.",
}) {
  return (
    <StateLayout
      icon={ShieldOff}
      title="You don't have access"
      role="alert"
      actions={
        <Button asChild variant="secondary">
          <Link to="/">Go to start</Link>
        </Button>
      }
    >
      <p>{description}</p>
    </StateLayout>
  );
}
