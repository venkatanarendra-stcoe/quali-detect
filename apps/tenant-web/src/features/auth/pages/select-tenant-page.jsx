import { Shield } from "lucide-react";
import { Button } from "@/components/ui/button.jsx";
import { useAuthActions } from "../hooks/use-auth-actions.js";
import { TenantChoices } from "../components/tenant-choices.jsx";

/** Choose the organization (active tenant) after sign-in, or when the account has none yet. */
export function SelectTenantPage() {
  const { logout } = useAuthActions();
  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-4">
      <div className="w-full max-w-md space-y-4">
        <div className="flex items-center gap-2">
          <Shield aria-hidden="true" className="size-5" strokeWidth={1.75} />
          <span className="text-base font-semibold">QmentisAI</span>
        </div>
        <h1 className="text-xl leading-7 font-semibold">Choose an organization</h1>
        <TenantChoices />
        <Button variant="ghost" onClick={() => logout.mutate()}>
          Sign out
        </Button>
      </div>
    </main>
  );
}
