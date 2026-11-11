import { ShieldOff } from "lucide-react";
import { Link } from "react-router";
import { Button } from "@/components/ui/button.jsx";
import { StateLayout } from "./state-layout.jsx";

/** 403: signed in, but the platform permission for this page is missing. The API enforces independently. */
export function UnauthorizedState({
  description = "Your platform role does not include access to this page.",
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
