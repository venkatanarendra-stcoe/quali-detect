import { zodResolver } from "@hookform/resolvers/zod";
import { Shield } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { useNavigate, useSearchParams } from "react-router";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Label } from "@/components/ui/label.jsx";
import { describeError, isApiError } from "@/lib/api/index.js";
import { safeNextPath } from "../components/route-guards.jsx";
import { useAuthActions } from "../hooks/use-auth-actions.js";
import { loginSchema } from "../schemas/login-schema.js";

/** T-01: sign in. Errors are generic by design (the server never says whether the email exists). */
export function LoginPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const { login } = useAuthActions();
  const [formError, setFormError] = useState(null);
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm({ resolver: zodResolver(loginSchema), defaultValues: { email: "", password: "" } });

  const onSubmit = handleSubmit(async (values) => {
    setFormError(null);
    try {
      await login.mutateAsync(values);
      navigate(safeNextPath(params.get("next")), { replace: true });
    } catch (error) {
      setFormError(error);
    }
  });

  const retryAfter =
    isApiError(formError) && formError.code === "RATE_LIMITED"
      ? formError.details?.retryAfterSeconds
      : null;

  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-4">
      <div className="w-full max-w-sm rounded-md border border-border bg-card p-6">
        <div className="mb-6 flex items-center gap-2">
          <Shield aria-hidden="true" className="size-5 text-foreground" strokeWidth={1.75} />
          <span className="text-base font-semibold">QmentisAI</span>
        </div>
        <h1 className="text-xl leading-7 font-semibold">Sign in</h1>
        <p className="mt-1 mb-4 text-sm text-muted-foreground">
          Use your work account to continue.
        </p>

        {params.get("reason") === "expired" ? (
          <p
            role="status"
            className="mb-4 rounded-sm border border-border-strong bg-secondary px-3 py-2 text-sm"
          >
            Your session ended. Sign in again to continue.
          </p>
        ) : null}

        <form onSubmit={onSubmit} noValidate className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              autoComplete="username"
              aria-invalid={Boolean(errors.email)}
              aria-describedby={errors.email ? "email-error" : undefined}
              {...register("email")}
            />
            {errors.email ? (
              <p id="email-error" className="text-xs text-status-danger">
                {errors.email.message}
              </p>
            ) : null}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              autoComplete="current-password"
              aria-invalid={Boolean(errors.password)}
              aria-describedby={errors.password ? "password-error" : undefined}
              {...register("password")}
            />
            {errors.password ? (
              <p id="password-error" className="text-xs text-status-danger">
                {errors.password.message}
              </p>
            ) : null}
          </div>

          {formError ? (
            <div
              role="alert"
              className="rounded-sm border border-border-strong bg-secondary px-3 py-2 text-sm"
            >
              <p className="text-status-danger">{describeError(formError)}</p>
              {retryAfter ? (
                <p className="mt-1 text-xs text-muted-foreground">
                  Try again in about {Math.max(1, Math.ceil(retryAfter / 60))} minute(s).
                </p>
              ) : null}
              {isApiError(formError) && formError.correlationId ? (
                <p className="mt-1 text-xs text-subtle-foreground">
                  Reference <span className="font-mono">{formError.correlationId}</span>
                </p>
              ) : null}
            </div>
          ) : null}

          <Button type="submit" size="lg" className="w-full" disabled={login.isPending}>
            {login.isPending ? "Signing in…" : "Sign in"}
          </Button>
        </form>
      </div>
    </main>
  );
}
