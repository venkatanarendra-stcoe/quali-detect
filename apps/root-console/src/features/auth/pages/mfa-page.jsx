import { zodResolver } from "@hookform/resolvers/zod";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { useNavigate, useSearchParams } from "react-router";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Label } from "@/components/ui/label.jsx";
import { environment } from "@/lib/environment.js";
import { AuthCard } from "../components/auth-card.jsx";
import { FormError } from "../components/form-error.jsx";
import { safeNextPath } from "../components/route-guards.jsx";
import { useAuthActions } from "../hooks/use-auth-actions.js";
import { mfaSchema } from "../schemas/schemas.js";

/**
 * Mandatory MFA (step 2 of 2, MOCK verifier). The server issues a new session only after a correct code; until then no
 * platform data is available, so skipping this screen (for example by typing a URL) leads back here.
 */
export function MfaPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const { verifyMfa, logout } = useAuthActions();
  const [formError, setFormError] = useState(null);
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm({ resolver: zodResolver(mfaSchema), defaultValues: { code: "" } });

  const onSubmit = handleSubmit(async ({ code }) => {
    setFormError(null);
    try {
      await verifyMfa.mutateAsync(code);
      navigate(safeNextPath(params.get("next")), { replace: true });
    } catch (error) {
      setFormError(error);
    }
  });

  return (
    <AuthCard
      title="Verify it's you"
      description="Step 2 of 2. Platform access always requires a verification code."
    >
      <form onSubmit={onSubmit} noValidate className="space-y-4">
        <div className="space-y-1.5">
          <Label htmlFor="code">Verification code</Label>
          <Input
            id="code"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            className="font-mono tracking-[0.4em]"
            aria-invalid={Boolean(errors.code)}
            aria-describedby={errors.code ? "code-error" : "code-hint"}
            {...register("code")}
          />
          {errors.code ? (
            <p id="code-error" className="text-xs text-status-danger">
              {errors.code.message}
            </p>
          ) : (
            <p id="code-hint" className="text-xs text-subtle-foreground">
              Enter the 6-digit code.
            </p>
          )}
        </div>
        <FormError error={formError} />
        <Button type="submit" size="lg" className="w-full" disabled={verifyMfa.isPending}>
          {verifyMfa.isPending ? "Verifying…" : "Verify and continue"}
        </Button>
        <Button type="button" variant="ghost" className="w-full" onClick={() => logout.mutate()}>
          Use a different account
        </Button>
      </form>
      {environment.id === "development" ? (
        <p className="mt-4 text-xs text-subtle-foreground">
          Mock verification: the code is configured on the API (
          <span className="font-mono">MOCK_PLATFORM_MFA_CODE</span>).
        </p>
      ) : null}
    </AuthCard>
  );
}
