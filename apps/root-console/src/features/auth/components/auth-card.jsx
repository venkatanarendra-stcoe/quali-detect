import { Shield } from "lucide-react";
import { EnvironmentStrip } from "@/components/layout/environment-strip.jsx";

/** Centered card used by the login and MFA screens; the environment strip stays visible so the target is never ambiguous. */
export function AuthCard({ title, description, children }) {
  return (
    <div className="flex min-h-screen flex-col bg-background">
      <EnvironmentStrip />
      <main className="flex flex-1 items-center justify-center p-4">
        <div className="w-full max-w-sm rounded-md border border-border bg-card p-6">
          <div className="mb-6 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield aria-hidden="true" className="size-5" strokeWidth={1.75} />
              <span className="text-base font-semibold">QmentisAI Platform</span>
            </div>
            <span className="rounded-sm border border-border-strong px-1.5 py-0.5 text-[11px] font-semibold tracking-wider text-muted-foreground">
              PLATFORM
            </span>
          </div>
          <h1 className="text-xl leading-7 font-semibold">{title}</h1>
          <p className="mt-1 mb-4 text-sm text-muted-foreground">{description}</p>
          {children}
        </div>
      </main>
    </div>
  );
}
