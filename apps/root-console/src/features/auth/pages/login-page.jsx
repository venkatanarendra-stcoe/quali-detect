import { zodResolver } from "@hookform/resolvers/zod";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Label } from "@/components/ui/label.jsx";
import { AuthCard } from "../components/auth-card.jsx";
import { FormError } from "../components/form-error.jsx";
import { useAuthActions } from "../hooks/use-auth-actions.js";
import { loginSchema } from "../schemas/schemas.js";

/** Platform sign-in (step 1 of 2). Errors are generic: the server never says whether the account exists. */
export function LoginPage() {
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
      await login.mutateAsync(values); // the route guards then send the user to the MFA screen
    } catch (error) {
      setFormError(error);
    }
  });

  return (
    <AuthCard
      title="Platform sign in"
      description="Step 1 of 2. Verification follows after your password."
    >
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
        <FormError error={formError} />
        <Button type="submit" size="lg" className="w-full" disabled={login.isPending}>
          {login.isPending ? "Signing in…" : "Continue"}
        </Button>
      </form>
    </AuthCard>
  );
}
