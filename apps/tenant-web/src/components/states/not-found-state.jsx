import { SearchX } from "lucide-react";
import { Link } from "react-router";
import { Button } from "@/components/ui/button.jsx";
import { StateLayout } from "./state-layout.jsx";

/**
 * 404 (T-05). The same text is used for "does not exist" and "not visible to you", so the page never confirms that
 * something exists (docs/AUTHORIZATION.md §5.9).
 */
export function NotFoundState() {
  return (
    <StateLayout
      icon={SearchX}
      title="Page not found"
      actions={
        <Button asChild variant="secondary">
          <Link to="/">Go to start</Link>
        </Button>
      }
    >
      <p>This page doesn&apos;t exist or isn&apos;t available to you.</p>
    </StateLayout>
  );
}
