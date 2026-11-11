import { SearchX } from "lucide-react";
import { Link } from "react-router";
import { Button } from "@/components/ui/button.jsx";
import { StateLayout } from "./state-layout.jsx";

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
      <p>This page doesn&apos;t exist.</p>
    </StateLayout>
  );
}
